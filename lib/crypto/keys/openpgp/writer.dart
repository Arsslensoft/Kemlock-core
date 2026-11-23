// Making OpenPGP keys, and protecting their secret parts for export.
//
// Three forms are made:
//
// - version 4, the form GnuPG 2.4 makes and every OpenPGP program reads:
//   an EdDSA (Ed25519) primary key that certifies and signs with an ECDH
//   (Curve25519) subkey that encrypts, or RSA 4096 for both. The user ID
//   gets a positive certification and the subkey a binding signature,
//   both SHA-512, with the subpackets GnuPG writes;
// - for GnuPG 2.5: the same Ed25519 primary key with, in place of the
//   Curve25519 subkey, a LibrePGP version 5 Kyber-768 with X25519 subkey,
//   bound by a version 4 signature;
// - RFC 9980's standard post-quantum key: version 6, an ML-DSA-65+Ed25519
//   primary key and an ML-KEM-768+X25519 subkey, with a direct-key
//   signature carrying the key's flags and preferences, version 6
//   signatures over SHA-512 with a 32-byte salt.
//
// An encryption subkey needs no primary key binding signature of its own.
// Every key may carry an expiry, on the self-signature that has the key
// flags and on the subkey binding.
//
// On export a secret key packet is protected the way RFC 9580 lets new
// keys be: S2K usage 254, AES-256 in CFB mode, Iterated and Salted S2K
// over SHA-256, and the SHA-1 of the secret material inside.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:pointycastle/export.dart' as pc;

import '../../bytes.dart';
import '../../ml_dsa.dart';
import '../../ml_kem.dart';
import '../algorithms.dart';
import '../key_error.dart';
import 'agent_key.dart';
import 'key_info.dart';
import 'packets.dart';
import 's2k.dart';
import 'signatures.dart';

export 's2k.dart' show iteratedSaltedS2k, iteratedSaltedS2kCount;

/// The key types the generate sheet offers for PGP keys.
enum PgpKeyType {
  /// EdDSA (Ed25519) primary key with an ECDH (Curve25519) subkey, as
  /// GnuPG's default.
  ed25519,

  /// RSA 4096 for the primary key and the subkey.
  rsa4096,

  /// RFC 9980's: a version 6 ML-DSA-65+Ed25519 primary key with an
  /// ML-KEM-768+X25519 subkey. Read by Sequoia and the other programs that
  /// follow RFC 9980.
  pqStandard,

  /// LibrePGP's, as GnuPG 2.5 reads it: the Ed25519 primary key with a
  /// version 5 Kyber-768 with X25519 subkey. Its signatures stay Ed25519.
  pqGnupg,
}

const _oidEd25519Legacy = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
const _oidCurve25519Legacy = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// The curve OID GnuPG gives the X25519 half of a Kyber key: 1.3.101.110.
const _oidX25519 = [0x2b, 0x65, 0x6e];

/// A new transferable secret key for [userId] (`Name <email>`), its
/// creation time [created] (now by default), unprotected, expiring
/// [expirySeconds] after it was made when given.
///
/// [random] and [rsa] stand in for the platform's secure random source and
/// for RSA key generation, so that tests can make the same key twice.
Future<Uint8List> generatePgpKey({
  required String userId,
  required PgpKeyType type,
  DateTime? created,
  int? expirySeconds,
  Uint8List Function(int length)? random,
  RsaMaterial Function(int bits)? rsa,
}) async {
  final bytes = random ?? randomBytes;
  final time = ((created ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000);
  if (expirySeconds != null && expirySeconds <= 0) throw ArgumentError.value(expirySeconds, 'expirySeconds', 'must be positive');
  if (type == PgpKeyType.pqStandard) return _generateStandard(userId, time, expirySeconds, bytes);
  final header = [
    4,
    ...[time >>> 24, time >>> 16, time >>> 8, time].map((b) => b & 0xff),
  ];

  final List<int> primaryPublic;
  final List<int> primarySecret;
  final List<int> subPublic;
  final List<int> subSecret;
  final Future<List<int>> Function(List<int> digest) sign;
  switch (type) {
    case PgpKeyType.ed25519 || PgpKeyType.pqGnupg:
      final seed = bytes(32);
      final ed = await ed25519Material(seed);
      primaryPublic = [
        ...header,
        22,
        _oidEd25519Legacy.length,
        ..._oidEd25519Legacy,
        ...mpiOfBytes([0x40, ...ed.publicKey]),
      ];
      primarySecret = mpiOfBytes(seed);
      // The Curve25519 secret is stored big-endian: the clamped native
      // scalar, reversed, as GnuPG and OpenPGP.js store it.
      final scalar = bytes(32);
      scalar[0] &= 0xf8;
      scalar[31] = (scalar[31] & 0x7f) | 0x40;
      final x = await x25519Material(scalar);
      if (type == PgpKeyType.ed25519) {
        subPublic = [
          ...header,
          18,
          _oidCurve25519Legacy.length,
          ..._oidCurve25519Legacy,
          ...mpiOfBytes([0x40, ...x.publicKey]),
          // KDF parameters: SHA-256 and AES-128, as GnuPG sets for Curve25519.
          3, 1, 8, 7,
        ];
        subSecret = mpiOfBytes(scalar.reversed.toList());
      } else {
        final kyber = _kyberSubkey(time, scalar, x.publicKey, bytes(64));
        subPublic = kyber.public;
        subSecret = kyber.agentKey;
      }
      sign = (digest) => signEdDsa(seed, digest);
    case PgpKeyType.rsa4096:
      final primary = _openPgpOrder((rsa ?? generateRsa)(4096));
      final sub = _openPgpOrder((rsa ?? generateRsa)(4096));
      primaryPublic = [...header, 1, ...mpi(primary.n), ...mpi(primary.e)];
      primarySecret = _rsaSecret(primary);
      subPublic = [...header, 1, ...mpi(sub.n), ...mpi(sub.e)];
      subSecret = _rsaSecret(sub);
      sign = (digest) async => signRsa(primary, digest);
    case PgpKeyType.pqStandard:
      throw StateError('made above');
  }

  final primaryKey = parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, primaryPublic, oldFormat: true)).single);
  final subKey = parseKeyPacket(readPackets(writePacket(PgpTag.publicSubkey, subPublic, oldFormat: true)).single);
  final uid = utf8.encode(userId);
  final (:certification, :bindings) = await pgpSelfSignatures(
    primary: primaryKey,
    userId: uid,
    primaryFlags: PgpKeyFlag.certify | PgpKeyFlag.sign,
    subkeys: [(subKey, PgpKeyFlag.encryptCommunications | PgpKeyFlag.encryptStorage)],
    time: time,
    expirySeconds: expirySeconds,
    sign: sign,
  );
  final binding = bindings.single;

  final subSecretBody = subKey.version == 5
      ? [...subPublic, ..._agentSecret(subSecret)]
      : [...subPublic, 0, ...subSecret, ..._checksum(subSecret)];
  return concatBytes([
    writePacket(PgpTag.secretKey, [...primaryPublic, 0, ...primarySecret, ..._checksum(primarySecret)], oldFormat: true),
    writePacket(PgpTag.userId, uid, oldFormat: true),
    writePacket(PgpTag.signature, certification, oldFormat: true),
    writePacket(PgpTag.secretSubkey, subSecretBody, oldFormat: true),
    writePacket(PgpTag.signature, binding, oldFormat: true),
  ]);
}

/// LibrePGP's Kyber-768 with X25519 as a version 5 subkey made at [time]
/// (seconds), from the clamped X25519 [scalar], its [x25519Public] key and
/// the 64-byte ML-KEM [mlKemSeed]: its [public] body (the curve, the
/// point, the ML-KEM-768 key with a 4-byte count) and its secret as
/// gpg-agent keeps it, the only form GnuPG 2.5 imports a Kyber secret in.
({List<int> public, Uint8List agentKey}) _kyberSubkey(int time, List<int> scalar, List<int> x25519Public, Uint8List mlKemSeed) {
  final mlKem = MlKem768.keygen(mlKemSeed);
  final material = [
    _oidX25519.length,
    ..._oidX25519,
    ...mpiOfBytes([0x40, ...x25519Public]),
    ..._be32(mlKem.publicKey.length),
    ...mlKem.publicKey,
  ];
  return (
    public: [5, ..._be32(time), 8, ..._be32(material.length), ...material],
    agentKey: writeAgentKyberKey(
      q: [0x40, ...x25519Public],
      d: scalar.reversed.toList(),
      p: mlKem.publicKey,
      s: mlKem.secretKey,
      seed: mlKemSeed,
    ),
  );
}

/// What follows a version 5 public key body whose secret is the agent key
/// [agentKey]: S2K usage 255, the count of the S2K fields, no cipher, the
/// GNU extension's mode 1003, then the agent key with its count.
List<int> _agentSecret(List<int> agentKey) => [255, 7, 0, 101, 0, 0x47, 0x4e, 0x55, 3, ..._be32(agentKey.length), ...agentKey];

/// RFC 9980's standard key (design decision 1): version 6 packets in the
/// new format, the secrets as RFC 9980 keeps them (the two seeds of each
/// key), a direct-key signature with the key's flags, expiry, features and
/// preferences, a positive certification of the user ID and the subkey's
/// binding, all version 6 over SHA-512.
Future<Uint8List> _generateStandard(String userId, int time, int? expirySeconds, Uint8List Function(int length) bytes) async {
  final created = _be32(time);
  List<int> keyBody(int algorithm, List<int> material) => [6, ...created, algorithm, ..._be32(material.length), ...material];

  final edSeed = bytes(32);
  final mlDsaSeed = bytes(MlDsa65.seedLength);
  final ed = await ed25519Material(edSeed);
  final mlDsa = MlDsa65.keygen(mlDsaSeed);
  final primaryPublic = keyBody(30, [...ed.publicKey, ...mlDsa.publicKey]);

  final xSecret = bytes(32);
  final mlKemSeed = bytes(64);
  final x = await x25519Material(xSecret);
  final mlKem = MlKem768.keygen(mlKemSeed);
  final subPublic = keyBody(35, [...x.publicKey, ...mlKem.publicKey]);

  final primaryKey = parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, primaryPublic)).single);
  final subKey = parseKeyPacket(readPackets(writePacket(PgpTag.publicSubkey, subPublic)).single);
  final uid = utf8.encode(userId);
  final timeSubpacket = subpacket(2, created);
  final issuer = subpacket(33, [6, ...primaryKey.fingerprint]);
  final expiry = expirySeconds == null ? const <int>[] : subpacket(9, _be32(expirySeconds));
  Future<List<int>> sign(List<int> digest) => signComposite(edSeed, mlDsa.secretKey, digest);
  Future<Uint8List> signature(int type, List<int> data, List<int> hashed) =>
      makeSignature(type: type, signer: primaryKey, data: data, hashed: hashed, sign: sign, salt: bytes(32));

  final direct = await signature(0x1f, hashedKey(primaryKey), [
    ...timeSubpacket,
    ...issuer,
    ...subpacket(27, [PgpKeyFlag.certify | PgpKeyFlag.sign]),
    ...expiry,
    ...subpacket(30, [0x01 | 0x08]), // features: SEIPD versions 1 and 2
    ...subpacket(11, [9, 7]), // AES-256, AES-128
    ...subpacket(39, [9, 2]), // AEAD: AES-256 with OCB
    ...subpacket(21, [10, 14, 8]), // SHA-512, SHA3-512, SHA-256
  ]);
  final certification = await signature(
    0x13,
    [...hashedKey(primaryKey), ...hashedUserId(uid)],
    [
      ...timeSubpacket,
      ...issuer,
      ...subpacket(25, [1]), // the primary user ID
    ],
  );
  final binding = await signature(
    0x18,
    [...hashedKey(primaryKey), ...hashedKey(subKey)],
    [
      ...timeSubpacket,
      ...issuer,
      ...subpacket(27, [PgpKeyFlag.encryptCommunications | PgpKeyFlag.encryptStorage]),
      ...expiry,
    ],
  );

  // Version 6 secret key packets, unprotected: usage 0, then the secrets
  return concatBytes([
    writePacket(PgpTag.secretKey, [...primaryPublic, 0, ...edSeed, ...mlDsaSeed]),
    writePacket(PgpTag.signature, direct),
    writePacket(PgpTag.userId, uid),
    writePacket(PgpTag.signature, certification),
    writePacket(PgpTag.secretSubkey, [...subPublic, 0, ...xSecret, ...mlKemSeed]),
    writePacket(PgpTag.signature, binding),
  ]);
}

List<int> _be32(int v) => [v >>> 24 & 0xff, v >>> 16 & 0xff, v >>> 8 & 0xff, v & 0xff];

/// The self-signatures of a new key: the positive certification of
/// [userId] by [primary], with [primaryFlags] and the preferences GnuPG
/// writes, and a binding of each of [subkeys] with its flags, all made at
/// [time] (seconds), expiring [expirySeconds] after it when given, and
/// signed by [sign] over a SHA-512 digest. A subkey
/// that signs would need a back-signature too; none of the keys Kemlock
/// makes has one. [generatePgpKey] signs with the new key's secret, an
/// OpenPGP card with its own (openspec: add-openpgp-card, design decision
/// 11).
Future<({Uint8List certification, List<Uint8List> bindings})> pgpSelfSignatures({
  required KeyPacket primary,
  required List<int> userId,
  required int primaryFlags,
  required List<(KeyPacket, int)> subkeys,
  required int time,
  int? expirySeconds,
  required Future<List<int>> Function(List<int> digest) sign,
}) async {
  final timeSubpacket = subpacket(2, [time >>> 24 & 0xff, time >>> 16 & 0xff, time >>> 8 & 0xff, time & 0xff]);
  final issuer = subpacket(33, [4, ...primary.fingerprint]);
  final expiry = expirySeconds == null ? const <int>[] : subpacket(9, _be32(expirySeconds));
  final certification = await makeSignature(
    type: 0x13,
    signer: primary,
    data: [...hashedKey(primary), ...hashedUserId(userId)],
    hashed: [
      ...issuer,
      ...timeSubpacket,
      ...subpacket(27, [primaryFlags]),
      ...expiry,
      ...subpacket(11, [9, 8, 7]), // AES-256, AES-192, AES-128
      ...subpacket(21, [10, 9, 8, 11]), // SHA-512, SHA-384, SHA-256, SHA-224
      ...subpacket(22, [2, 3, 1]), // ZLIB, BZip2, ZIP
      ...subpacket(30, [0x01]), // features: SEIPD version 1
      ...subpacket(23, [0x80]), // keyserver preferences: no-modify
    ],
    sign: sign,
  );
  final bindings = [
    for (final (subkey, flags) in subkeys)
      await makeSignature(
        type: 0x18,
        signer: primary,
        data: [...hashedKey(primary), ...hashedKey(subkey)],
        hashed: [
          ...issuer,
          ...timeSubpacket,
          ...subpacket(27, [flags]),
          ...expiry,
        ],
        sign: sign,
      ),
  ];
  return (certification: certification, bindings: bindings);
}

/// What a new version 4 key packet made at [time] (seconds) holds: its
/// [public] body, and what follows it in a secret key packet,
/// unprotected ([secret]: usage 0, the secret MPIs and their checksum).
/// For [PgpKeyType.ed25519] an EdDSA (Ed25519) key when it [signs], else an
/// ECDH (Curve25519) key with GnuPG's KDF parameters; RSA 4096 for
/// [PgpKeyType.rsa4096]. These are the keys [generatePgpKey] makes; a new
/// subkey of a key in the vault is one. [sign] signs a SHA-512 digest with
/// it, for a signing key's back-signature.
///
/// The post-quantum ones (openspec: add-post-quantum-pgp, design decision
/// 14), which encrypt only: for [PgpKeyType.pqStandard] an
/// ML-KEM-768+X25519 key (algorithm 35), version 4 as RFC 9980 allows;
/// for [PgpKeyType.pqGnupg] LibrePGP's Kyber-768 with X25519 as a version
/// 5 subkey, its secret in gpg-agent's form. For a key of [version] 6 the
/// subkey is version 6 too, and only [PgpKeyType.pqStandard]:
/// ML-KEM-768+X25519 to encrypt, ML-DSA-65+Ed25519 (algorithm 30) to sign.
/// Throws an [ArgumentError] for any other pairing.
Future<({List<int> public, List<int> secret, Future<List<int>> Function(List<int> digest) sign})> newPgpKeyMaterial(
  PgpKeyType type, {
  required bool signs,
  required int time,
  int version = 4,
}) async {
  if (version == 6 && type != PgpKeyType.pqStandard) throw ArgumentError.value(type, 'type', 'a version 6 key takes version 6 subkeys');
  if (signs && (type == PgpKeyType.pqGnupg || (type == PgpKeyType.pqStandard && version != 6))) {
    throw ArgumentError.value(type, 'type', 'does not sign on a version $version key');
  }
  Future<List<int>> Function(List<int> digest) notSigning() =>
      (_) => throw ArgumentError('an encryption key does not sign');
  List<int> body(int algorithm, List<int> material) =>
      version == 6 ? [6, ..._be32(time), algorithm, ..._be32(material.length), ...material] : [4, ..._be32(time), algorithm, ...material];
  switch (type) {
    case PgpKeyType.pqStandard when signs:
      final edSeed = randomBytes(32);
      final mlDsaSeed = randomBytes(MlDsa65.seedLength);
      final ed = await ed25519Material(edSeed);
      final mlDsa = MlDsa65.keygen(mlDsaSeed);
      return (
        public: body(30, [...ed.publicKey, ...mlDsa.publicKey]),
        secret: [0, ...edSeed, ...mlDsaSeed],
        sign: (List<int> digest) => signComposite(edSeed, mlDsa.secretKey, digest),
      );
    case PgpKeyType.pqStandard:
      final xSecret = randomBytes(32);
      final mlKemSeed = randomBytes(64);
      final x = await x25519Material(xSecret);
      final mlKem = MlKem768.keygen(mlKemSeed);
      final secret = [...xSecret, ...mlKemSeed];
      // Version 6 has no checksum after unprotected material
      return (
        public: body(35, [...x.publicKey, ...mlKem.publicKey]),
        secret: version == 6 ? [0, ...secret] : [0, ...secret, ..._checksum(secret)],
        sign: notSigning(),
      );
    case PgpKeyType.pqGnupg:
      final scalar = randomBytes(32);
      scalar[0] &= 0xf8;
      scalar[31] = (scalar[31] & 0x7f) | 0x40;
      final x = await x25519Material(scalar);
      final kyber = _kyberSubkey(time, scalar, x.publicKey, randomBytes(64));
      return (public: kyber.public, secret: _agentSecret(kyber.agentKey), sign: notSigning());
    case PgpKeyType.ed25519 || PgpKeyType.rsa4096:
      break;
  }
  final header = [
    4,
    ...[time >>> 24, time >>> 16, time >>> 8, time].map((b) => b & 0xff),
  ];
  final List<int> public;
  final List<int> secret;
  Future<List<int>> Function(List<int> digest) sign = (_) => throw ArgumentError('an encryption key does not sign');
  switch (type) {
    case PgpKeyType.ed25519 when signs:
      final seed = randomBytes(32);
      final ed = await ed25519Material(seed);
      public = [
        ...header,
        22,
        _oidEd25519Legacy.length,
        ..._oidEd25519Legacy,
        ...mpiOfBytes([0x40, ...ed.publicKey]),
      ];
      secret = mpiOfBytes(seed);
      sign = (digest) => signEdDsa(seed, digest);
    case PgpKeyType.ed25519:
      final scalar = randomBytes(32);
      scalar[0] &= 0xf8;
      scalar[31] = (scalar[31] & 0x7f) | 0x40;
      final x = await x25519Material(scalar);
      public = [
        ...header,
        18,
        _oidCurve25519Legacy.length,
        ..._oidCurve25519Legacy,
        ...mpiOfBytes([0x40, ...x.publicKey]),
        3, 1, 8, 7, // KDF parameters: SHA-256 and AES-128
      ];
      secret = mpiOfBytes(scalar.reversed.toList());
    case PgpKeyType.rsa4096:
      final rsa = _openPgpOrder(generateRsa(4096));
      public = [...header, 1, ...mpi(rsa.n), ...mpi(rsa.e)];
      secret = _rsaSecret(rsa);
      if (signs) sign = (digest) async => signRsa(rsa, digest);
    case PgpKeyType.pqStandard || PgpKeyType.pqGnupg:
      throw StateError('made above');
  }
  return (public: public, secret: [0, ...secret, ..._checksum(secret)], sign: sign);
}

/// OpenPGP wants p < q and u = p^-1 mod q; PKCS#1 has p > q and
/// q^-1 mod p, so the primes swap.
RsaMaterial _openPgpOrder(RsaMaterial key) =>
    key.p < key.q ? key : RsaMaterial.fromPrimes(n: key.n, e: key.e, d: key.d, p: key.q, q: key.p);

/// d, p, q and u = p^-1 mod q.
List<int> _rsaSecret(RsaMaterial key) => [...mpi(key.d), ...mpi(key.p), ...mpi(key.q), ...mpi(key.p.modInverse(key.q))];

/// The sum of the secret octets, modulo 65536, of an unprotected v4 key.
List<int> _checksum(List<int> secret) {
  var sum = 0;
  for (final b in secret) {
    sum = (sum + b) & 0xffff;
  }
  return [sum >> 8, sum & 0xff];
}

// ─── Protection for export ────────────────────────────────────────────────────

/// The coded count of Iterated and Salted S2K used on export: 0xf0, 33.5 MB
/// of SHA-256, about 0.2 seconds per key on a laptop.
const defaultS2kCount = 0xf0;

/// [transferableKey] with each unprotected secret key packet protected by
/// [passphrase]: S2K usage 254, AES-256 in CFB mode under Iterated and
/// Salted S2K with SHA-256, a fresh salt and IV each. Version 4, 5 and 6
/// packets are all handled, in their own layouts; a Kyber secret in
/// gpg-agent's form gets the agent's own protection instead.
/// Other packets are copied as they are: a secret key packet protected by
/// a passphrase of its own stays behind it, and GnuPG's stub, which holds
/// no secret, stays a stub.
Uint8List protectPgpKey(Uint8List transferableKey, String passphrase, {int s2kCount = defaultS2kCount}) {
  final out = BytesBuilder(copy: false);
  for (final packet in readPackets(transferableKey)) {
    if (packet.tag != PgpTag.secretKey && packet.tag != PgpTag.secretSubkey) {
      out.add(packet.encoded);
      continue;
    }
    final key = parseKeyPacket(packet);
    if (key.isStub || key.passphraseProtected) {
      out.add(packet.encoded);
      continue;
    }
    out.add(protectSecretKeyPacket(packet, passphrase, s2kCount: s2kCount));
  }
  return out.toBytes();
}

/// The unprotected secret key packet [packet] protected by [passphrase] as
/// [protectPgpKey] protects each, written in its own header format: for a
/// new secret subkey of a key that keeps its own passphrase. A Kyber
/// secret in gpg-agent's form stays in it, both halves protected as
/// gpg-agent protects a key, which GnuPG 2.5 imports. Throws an
/// [ArgumentError] when the packet is protected already.
Uint8List protectSecretKeyPacket(PgpPacket packet, String passphrase, {int s2kCount = defaultS2kCount}) {
  final key = parseKeyPacket(packet);
  final agent = key.agentKey;
  if (agent != null) {
    if (key.passphraseProtected) throw ArgumentError('a secret key packet is protected already');
    final protected = protectAgentKyberKey(agent, utf8.encode(passphrase), random: randomBytes, protectedAt: DateTime.now());
    final head = Uint8List.sublistView(packet.body, 0, packet.body.length - agent.length - 4);
    return writePacket(packet.tag, [...head, ..._be32(protected.length), ...protected], oldFormat: packet.oldFormat);
  }
  final secret = key.plainSecret;
  if (secret == null) throw ArgumentError('a secret key packet is protected already');
  final salt = randomBytes(8);
  final iv = randomBytes(16);
  final s2k = [3, 8, ...salt, s2kCount]; // Iterated and Salted, SHA-256
  final aesKey = iteratedSaltedS2k(utf8.encode(passphrase), salt, s2kCount);
  final encrypted = cfb(true, aesKey, iv, Uint8List.fromList([...secret, ...hash.sha1.convert(secret).bytes]));
  final parameters = switch (key.version) {
    6 => [254, 1 + 1 + s2k.length + iv.length, 9, s2k.length, ...s2k, ...iv],
    // LibrePGP counts the fields to the IV, then the secret material
    5 => [254, 1 + s2k.length + iv.length, 9, ...s2k, ...iv, ..._be32(encrypted.length)],
    _ => [254, 9, ...s2k, ...iv],
  };
  return writePacket(packet.tag, [...key.publicBody, ...parameters, ...encrypted], oldFormat: packet.oldFormat);
}

// ─── Card stubs ───────────────────────────────────────────────────────────────

/// The S2K usage, cipher and GNU extension S2K of a stub, before its mode.
const _gnuStub = [0xff, 0x00, 0x65, 0x00, 0x47, 0x4e, 0x55];

/// The transferable secret key GnuPG writes for a key whose secret parts
/// are on an OpenPGP card (openspec: add-openpgp-card, design decision
/// 4): [transferablePublicKey] with each key packet made a secret key
/// packet with no secret in it. A key whose fingerprint is among
/// [onCard] gets the stub that says "divert to card" and names the card
/// by [cardAid], its 16-byte application identifier; any other gets the
/// stub that says it has no secret here. User IDs and signatures are
/// copied as they are, and every packet keeps its header format.
Uint8List cardStubKey(Uint8List transferablePublicKey, {required List<int> cardAid, required List<List<int>> onCard}) {
  if (cardAid.isEmpty || cardAid.length > 16) throw ArgumentError.value(cardAid.length, 'cardAid', 'must be 1 to 16 bytes');
  bool held(Uint8List fingerprint) => onCard.any((f) => f.length == fingerprint.length && _equal(f, fingerprint));
  final out = BytesBuilder(copy: false);
  for (final packet in readPackets(transferablePublicKey)) {
    final tag = switch (packet.tag) {
      PgpTag.publicKey => PgpTag.secretKey,
      PgpTag.publicSubkey => PgpTag.secretSubkey,
      PgpTag.secretKey || PgpTag.secretSubkey => throw ArgumentError('a stub is made from a public key'),
      _ => null,
    };
    if (tag == null) {
      out.add(packet.encoded);
      continue;
    }
    final key = parseKeyPacket(packet);
    final stub = held(key.fingerprint) ? [..._gnuStub, 0x02, cardAid.length, ...cardAid] : [..._gnuStub, 0x01];
    out.add(writePacket(tag, [...key.publicBody, ...stub], oldFormat: packet.oldFormat));
  }
  return out.toBytes();
}

/// The serial a card stub names for each of its secret key packets that
/// is on a card, by the packet's fingerprint in upper-case hexadecimal;
/// empty for a key with no such packet.
Map<String, Uint8List> cardStubSerials(Uint8List transferableKey) {
  final out = <String, Uint8List>{};
  for (final packet in readPackets(transferableKey)) {
    if (packet.tag != PgpTag.secretKey && packet.tag != PgpTag.secretSubkey) continue;
    final key = parseKeyPacket(packet);
    final rest = Uint8List.sublistView(packet.body, key.publicBody.length);
    // Usage 254 or 255, any cipher, S2K type 101 with any hash, "GNU", mode 2
    final divert =
        rest.length >= 9 &&
        (rest[0] == 0xfe || rest[0] == 0xff) &&
        rest[2] == 0x65 &&
        _equal(rest.sublist(4, 7), _gnuStub.sublist(4)) &&
        rest[7] == 0x02;
    if (!divert) continue;
    final length = rest[8];
    if (rest.length < 9 + length) continue;
    out[[for (final b in key.fingerprint) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase()] = Uint8List.fromList(
      rest.sublist(9, 9 + length),
    );
  }
  return out;
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// AES in CFB mode with a 16-byte IV and no resynchronisation, as secret
/// key packets use it.
Uint8List cfb(bool encrypt, Uint8List key, Uint8List iv, Uint8List data) {
  final aes = pc.AESEngine()..init(true, pc.KeyParameter(key));
  final out = Uint8List(data.length);
  final register = Uint8List.fromList(iv);
  final stream = Uint8List(16);
  for (var i = 0; i < data.length; i += 16) {
    aes.processBlock(register, 0, stream, 0);
    final n = data.length - i < 16 ? data.length - i : 16;
    for (var j = 0; j < n; j++) {
      out[i + j] = data[i + j] ^ stream[j];
    }
    register.setAll(0, Uint8List.sublistView(encrypt ? out : data, i, i + n));
  }
  return out;
}

/// The user ID GnuPG writes for [name] and [email]. Throws an
/// [ArgumentError] naming the field that is empty, or the name when the
/// two make a user ID over [maxUserIdLength] bytes, which no key is read
/// with.
String pgpUserId(String name, String email) {
  if (name.trim().isEmpty) throw ArgumentError.value(name, 'name', 'must not be empty');
  if (email.trim().isEmpty) throw ArgumentError.value(email, 'email', 'must not be empty');
  final userId = '${name.trim()} <${email.trim()}>';
  if (utf8.encode(userId).length > maxUserIdLength) throw ArgumentError.value(name, 'name', 'makes a user ID over $maxUserIdLength bytes');
  return userId;
}

/// Throws [KeyProblem.damaged] unless [data] is a key whose
/// self-signatures all verify; for keys Kemlock made, before handing them
/// out.
Future<void> checkSelfSignatures(Uint8List data) async {
  check(await verifySelfSignatures(data), 'OpenPGP: a self-signature does not verify');
}
