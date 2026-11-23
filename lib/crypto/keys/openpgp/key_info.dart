// What an OpenPGP key holds, read from its packets (RFC 9580 sections 5.2,
// 5.5 and 10.1): version 4 and 6 key packets, and the version 5 subkeys
// of LibrePGP that GnuPG 2.5 puts its Kyber keys in; user IDs, subkeys, the
// key flags and expiry of their self-signatures, fingerprints, and whether
// the secret parts are protected. Nothing here decrypts secret key
// material: a protected key is kept as its bytes.
//
// The post-quantum algorithms of RFC 9980 (30 to 36) and LibrePGP's Kyber
// (8) are read, named and measured; [PgpKey.usable] says which of them the
// app can use.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../der.dart';
import '../key_error.dart';
import 'packets.dart';

/// Key flags (RFC 9580 section 5.2.3.29), the first octet.
abstract final class PgpKeyFlag {
  static const certify = 0x01;
  static const sign = 0x02;
  static const encryptCommunications = 0x04;
  static const encryptStorage = 0x08;
  static const authenticate = 0x20;
}

/// One key of an OpenPGP key: the primary key or a subkey.
class PgpKey {
  const PgpKey({
    required this.version,
    required this.fingerprint,
    required this.algorithm,
    this.bits,
    required this.created,
    this.expires,
    this.flags,
    required this.hasSecret,
    required this.protected,
    this.stub = false,
    required this.revoked,
    this.usable = true,
    this.features,
  });

  /// 4 or 6, or 5 for a LibrePGP subkey.
  final int version;

  /// 20 bytes (SHA-1) for version 4, 32 (SHA-256) for versions 5 and 6.
  final Uint8List fingerprint;

  /// As GnuPG names it in `gpg --list-keys`: `ed25519`, `cv25519`,
  /// `rsa3072`, `nistp256`, `mld65`, `mlk768`, `ky768_cv25519`, ...; the
  /// RFC's name for SLH-DSA, which GnuPG does not name; or `algorithm <n>`
  /// for one neither names.
  final String algorithm;

  /// Key size of an RSA, DSA or Elgamal key.
  final int? bits;

  final DateTime created;

  /// When its latest self-signature says it expires; null if never.
  final DateTime? expires;

  /// The [PgpKeyFlag]s of its latest self-signature; null if it has none.
  final int? flags;

  /// Whether the packet holds the secret part (a secret key packet).
  final bool hasSecret;

  /// Whether the secret part is protected by a passphrase (or is a
  /// GnuPG stub with no secret in it).
  final bool protected;

  /// Whether the packet holds no secret: GnuPG's stub for a secret kept
  /// elsewhere, as `gpg --export-secret-subkeys` writes the primary key, or
  /// on a card.
  final bool stub;

  /// Whether the key revoked itself (or the primary key revoked this
  /// subkey).
  final bool revoked;

  /// Whether the app can do this key's work with it. False for the
  /// post-quantum algorithms it reads, keeps and shows but does not use
  /// (ML-DSA-87+Ed448, SLH-DSA, ML-KEM-1024+X448, and Kyber with another
  /// curve than X25519, brainpoolP256r1 and brainpoolP384r1), and for an
  /// algorithm it cannot name.
  final bool usable;

  /// The first octet of the features its self-signatures announce
  /// (subpacket 30: 0x01 for SEIPD version 1, 0x08 for version 2), for the
  /// primary key; null when they announce none, and for a subkey.
  final int? features;

  /// The fingerprint in upper-case hexadecimal, as GnuPG prints it.
  String get fingerprintHex => _hex(fingerprint);

  /// The key ID: the last 8 bytes of a version 4 fingerprint, the first 8
  /// of a version 5 or 6 one.
  Uint8List get keyId => version == 4 ? Uint8List.sublistView(fingerprint, 12) : Uint8List.sublistView(fingerprint, 0, 8);

  bool get canCertify => (flags ?? 0) & PgpKeyFlag.certify != 0;
  bool get canSign => (flags ?? 0) & PgpKeyFlag.sign != 0;
  bool get canEncrypt => (flags ?? 0) & (PgpKeyFlag.encryptCommunications | PgpKeyFlag.encryptStorage) != 0;
  bool get canAuthenticate => (flags ?? 0) & PgpKeyFlag.authenticate != 0;
}

/// An OpenPGP key: its primary key, user IDs and subkeys.
class PgpKeyInfo {
  const PgpKeyInfo(this.primary, this.userIds, this.subkeys, {this.mainUserIndex});

  final PgpKey primary;

  /// In the order of their packets.
  final List<String> userIds;

  final List<PgpKey> subkeys;

  /// Which of [userIds] the key marks as its main one: the user ID whose
  /// latest self-certification has the primary user ID flag, the latest
  /// such when several do, as GnuPG takes it. Null when none is marked.
  final int? mainUserIndex;

  /// The key's main user ID ([mainUserIndex]), or its first; null for a key
  /// without one.
  String? get mainUserId => userIds.isEmpty ? null : userIds[mainUserIndex ?? 0];

  /// [userIds] with the main one first, the others in their order.
  List<String> get userIdsMainFirst => [
    ?mainUserId,
    for (final (i, user) in userIds.indexed)
      if (i != (mainUserIndex ?? 0)) user,
  ];

  int get version => primary.version;

  Uint8List get fingerprint => primary.fingerprint;

  /// Whether it carries secret parts.
  bool get isSecret => primary.hasSecret || subkeys.any((k) => k.hasSecret);

  /// Whether it keeps its own passphrase: it is a secret key, and every
  /// secret part it holds is protected by one. GnuPG's stubs hold none, so
  /// a key of stubs alone, its secrets on a card, keeps nothing in the
  /// clear; but a stub protects nothing either, so a key with a part in the
  /// clear does not keep its own passphrase, whatever else it holds. The
  /// vault keeps a key that does as it is and never asks for that
  /// passphrase.
  bool get protected {
    final packets = [primary, ...subkeys].where((k) => k.hasSecret);
    return packets.isNotEmpty && packets.every((k) => k.stub || k.protected);
  }

  /// Whether some of its secret parts are protected by a passphrase of
  /// their own while others are in the clear.
  bool get partlyProtected => !protected && [primary, ...subkeys].any((k) => k.hasSecret && !k.stub && k.protected);
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase();

// ─── Reading ──────────────────────────────────────────────────────────────────

/// The longest user ID read, in bytes: GnuPG's own limit. A user ID is a
/// name and an address, shown on every screen that names the key, and a
/// key may otherwise bring a megabyte of one.
const maxUserIdLength = 2048;

/// A transferable key read from packets: what it holds, and how many bytes
/// of the input it took (a file may hold several keys; the first is read).
class PgpTransferableKey {
  const PgpTransferableKey(this.info, this.packets, this.length);

  final PgpKeyInfo info;

  /// The packets of this key, as given.
  final List<PgpPacket> packets;

  /// The bytes the key took at the start of the input.
  final int length;
}

/// Reads the first transferable key (secret or public) in [data].
///
/// Throws [KeyFormatException]: [KeyProblem.unsupportedKeyType] for key
/// packets of version 3, a version 5 primary key, or a version 4 key of an
/// algorithm whose public part can't be measured; [KeyProblem.damaged] for anything that
/// isn't a well-formed key, including a version 4 key with no user ID, a
/// subkey with no binding signature after it (a key cut short between
/// packets, mostly), and a user ID over [maxUserIdLength].
PgpTransferableKey readTransferableKey(Uint8List data) {
  final packets = readPackets(data);
  check(packets.isNotEmpty && (packets.first.tag == PgpTag.secretKey || packets.first.tag == PgpTag.publicKey), 'OpenPGP: not a key');

  final primary = parseKeyPacket(packets.first);
  final primarySigs = <PgpSignature>[];
  final userIds = <String>[];
  final userIdSigs = <List<PgpSignature>>[];
  final subkeys = <KeyPacket>[];
  final subkeySigs = <List<PgpSignature>>[];
  List<PgpSignature> current = primarySigs;
  var hasUserAttribute = false;
  var used = packets.first.encoded.length;
  var count = 1;
  for (final packet in packets.skip(1)) {
    if (packet.tag == PgpTag.secretKey || packet.tag == PgpTag.publicKey) break;
    switch (packet.tag) {
      case PgpTag.signature:
        current.add(parseSignature(packet.body));
      case PgpTag.userId:
        check(packet.body.length <= maxUserIdLength, 'OpenPGP: a user ID over $maxUserIdLength bytes');
        userIds.add(utf8.decode(packet.body, allowMalformed: true));
        userIdSigs.add(current = []);
      case PgpTag.userAttribute:
        // A photo: its signatures are kept in the bytes and not read.
        hasUserAttribute = true;
        current = [];
      case PgpTag.secretSubkey || PgpTag.publicSubkey:
        check(packet.tag == PgpTag.publicSubkey || packets.first.tag == PgpTag.secretKey, 'OpenPGP: secret subkey of a public key');
        subkeys.add(parseKeyPacket(packet));
        subkeySigs.add(current = []);
      case PgpTag.trust || PgpTag.marker || PgpTag.padding:
        break;
      default:
        // Tags 40 to 63 may be skipped (RFC 9580 section 4.3); the others
        // don't belong in a key.
        check(packet.tag >= 40, 'OpenPGP: packet ${packet.tag} in a key');
    }
    used += packet.encoded.length;
    count++;
  }

  check(primary.version == 6 || userIds.isNotEmpty || hasUserAttribute, 'OpenPGP: a version 4 key without a user ID');
  check(subkeySigs.every((sigs) => sigs.isNotEmpty), 'OpenPGP: a subkey without a binding signature');

  // A version 3 signature carries no subpackets, so no issuer the reader sees: it would count as the key's
  // own, unchecked, and a made-up revocation would mark the key revoked. Nothing is read from one, as
  // [trimPublicKey] keeps none.
  bool isSelf(PgpSignature s) => s.version != 3 && s.issuedBy(primary.fingerprint);
  final selfCerts = [
    for (final (i, sigs) in userIdSigs.indexed)
      for (final s in sigs)
        if (isSelf(s) && s.type >= 0x10 && s.type <= 0x13) (i, s),
  ];
  final directKey = [
    for (final s in primarySigs)
      if (isSelf(s) && s.type == 0x1f) s,
  ];
  // The primary key's flags and expiry: from its latest direct-key
  // signature when that has them, else from the latest self-certification
  // of the primary user ID (the one marked so, or any).
  final latestDirect = _latest(directKey);
  final primaryCerts = selfCerts.where((c) => c.$2.primaryUserId).toList();
  final latestCert = _latest([for (final c in primaryCerts.isEmpty ? selfCerts : primaryCerts) c.$2]);
  final flagsFrom = latestDirect?.flags != null ? latestDirect : latestCert;
  final expiryFrom = latestDirect?.keyExpiry != null ? latestDirect : latestCert;
  final featuresFrom = latestDirect?.features != null ? latestDirect : latestCert;

  final primaryKey = primary.describe(
    flags: flagsFrom?.flags,
    expiry: expiryFrom?.keyExpiry,
    revoked: primarySigs.any((s) => isSelf(s) && s.type == 0x20),
    features: featuresFrom?.features,
  );
  // The main user ID: of those whose latest self-certification is marked
  // primary, the one marked last
  int? mainUserIndex;
  int? mainAt;
  for (var i = 0; i < userIds.length; i++) {
    final cert = _latest([
      for (final c in selfCerts)
        if (c.$1 == i) c.$2,
    ]);
    if (cert == null || !cert.primaryUserId) continue;
    if (mainAt == null || (cert.created ?? 0) > mainAt) (mainUserIndex, mainAt) = (i, cert.created ?? 0);
  }

  final subkeyInfos = <PgpKey>[];
  for (final (i, sub) in subkeys.indexed) {
    final binding = _latest([
      for (final s in subkeySigs[i])
        if (isSelf(s) && s.type == 0x18) s,
    ]);
    subkeyInfos.add(
      sub.describe(flags: binding?.flags, expiry: binding?.keyExpiry, revoked: subkeySigs[i].any((s) => isSelf(s) && s.type == 0x28)),
    );
  }
  return PgpTransferableKey(PgpKeyInfo(primaryKey, userIds, subkeyInfos, mainUserIndex: mainUserIndex), packets.take(count).toList(), used);
}

PgpSignature? _latest(List<PgpSignature> sigs) {
  PgpSignature? best;
  for (final s in sigs) {
    if (best == null || (s.created ?? 0) >= (best.created ?? 0)) best = s;
  }
  return best;
}

/// The transferable public key of a transferable secret key: each secret
/// key packet becomes the public key packet it starts with, in the same
/// header format, and the user IDs and signatures stay as they were, which
/// is what `gpg --export` gives. Trust packets are dropped.
Uint8List transferablePublicKey(List<PgpPacket> packets) {
  final out = BytesBuilder(copy: false);
  for (final p in packets) {
    switch (p.tag) {
      case PgpTag.secretKey || PgpTag.secretSubkey:
        final key = parseKeyPacket(p);
        out.add(writePacket(p.tag == PgpTag.secretKey ? PgpTag.publicKey : PgpTag.publicSubkey, key.publicBody, oldFormat: p.oldFormat));
      case PgpTag.trust:
        break;
      default:
        out.add(p.encoded);
    }
  }
  return out.toBytes();
}

// ─── Key packets ──────────────────────────────────────────────────────────────

/// A key packet taken apart: the public part, and the secret part when it
/// is a secret key packet.
class KeyPacket {
  KeyPacket._(
    this.packet,
    this.version,
    this.createdSeconds,
    this.algorithm,
    this.publicBody,
    this.name,
    this.bits,
    this.s2kUsage,
    this.agentKey,
  );

  final PgpPacket packet;
  final int version;
  final int createdSeconds;
  final int algorithm;

  /// The body of the matching public key packet: version through the
  /// public key material.
  final Uint8List publicBody;

  /// GnuPG's name for the algorithm, and the size where it has one.
  final String name;
  final int? bits;

  /// The S2K usage octet of a secret key packet (0 when unprotected); null
  /// for a public key packet.
  final int? s2kUsage;

  bool get isSecret => s2kUsage != null;

  /// The secret part of a version 5 packet in GnuPG's own form (S2K usage
  /// 255 with the GNU extension's mode 1003): gpg-agent's canonical
  /// S-expression of the key, as GnuPG 2.5 exports a Kyber key. Null for
  /// any other packet.
  final Uint8List? agentKey;

  /// Whether the secret part is behind a passphrase: protected, and not a
  /// GnuPG S-expression with nothing protected in it.
  bool get passphraseProtected {
    final usage = s2kUsage ?? 0;
    if (usage == 0) return false;
    final agent = agentKey;
    return agent == null || _contains(agent, _protectedKey);
  }

  /// Whether this secret key packet holds no secret: GnuPG's stub, S2K type
  /// 101 with "GNU" and mode 1 (1001, the secret is elsewhere) or 2 (1002,
  /// on a card). Mode 3, gpg-agent's form of a key, holds one.
  bool get isStub {
    final usage = s2kUsage;
    if (usage != 254 && usage != 255) return false;
    final body = packet.body;
    // The usage, the count of versions 5 and 6, the cipher, and the S2K's own length of version 6
    final at = publicBody.length + (version == 4 ? 2 : 3) + (version == 6 && usage != 255 ? 1 : 0);
    return at + 6 <= body.length &&
        body[at] == 101 &&
        body[at + 2] == 0x47 &&
        body[at + 3] == 0x4e &&
        body[at + 4] == 0x55 &&
        (body[at + 5] == 1 || body[at + 5] == 2);
  }

  /// The algorithm-specific public key material: the public body after
  /// its version, creation time, algorithm and (versions 5 and 6) length.
  Uint8List get publicMaterial => Uint8List.sublistView(publicBody, version == 4 ? 6 : 10);

  /// v4: SHA-1 over 0x99, a 2-byte length and the public body; v5 and v6:
  /// SHA-256 over 0x9a or 0x9b, a 4-byte length and the public body.
  Uint8List get fingerprint {
    final n = publicBody.length;
    final prefix = version == 4
        ? [0x99, n >> 8, n & 0xff]
        : [version == 5 ? 0x9a : 0x9b, n >>> 24, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
    final digest = version == 4 ? hash.sha1 : hash.sha256;
    return Uint8List.fromList(digest.convert([...prefix, ...publicBody]).bytes);
  }

  /// The key ID: the last 8 bytes of a version 4 fingerprint, the first 8
  /// of a version 5 or 6 one.
  Uint8List get keyId {
    final f = fingerprint;
    return version == 4 ? Uint8List.sublistView(f, 12) : Uint8List.sublistView(f, 0, 8);
  }

  /// The secret key material of an unprotected secret key packet, without
  /// the 2-byte checksum version 4 puts after it or the 4-byte count
  /// version 5 puts before it; null otherwise.
  Uint8List? get plainSecret {
    if (s2kUsage != 0) return null;
    final start = publicBody.length + 1 + (version == 5 ? 4 : 0);
    final end = version == 4 ? packet.body.length - 2 : packet.body.length;
    return Uint8List.sublistView(packet.body, start, end);
  }

  /// Whether the app can do this key's work with it: see [PgpKey.usable].
  bool get usable => switch (algorithm) {
    31 || 32 || 33 || 34 || 36 => false,
    8 => name == 'ky768_cv25519' || name == 'ky768_bp256' || name == 'ky1024_bp384',
    _ => !name.startsWith('algorithm '),
  };

  PgpKey describe({int? flags, int? expiry, required bool revoked, int? features}) => PgpKey(
    version: version,
    fingerprint: fingerprint,
    algorithm: name,
    bits: bits,
    created: DateTime.fromMillisecondsSinceEpoch(createdSeconds * 1000, isUtc: true),
    expires: expiry == null || expiry == 0 ? null : DateTime.fromMillisecondsSinceEpoch((createdSeconds + expiry) * 1000, isUtc: true),
    flags: flags,
    hasSecret: isSecret,
    protected: passphraseProtected,
    stub: isStub,
    revoked: revoked,
    usable: usable,
    features: features,
  );
}

/// Takes a key packet (secret or public, key or subkey) apart. Throws
/// [KeyProblem.unsupportedKeyType] for versions other than 4 and 6, but for
/// LibrePGP's version 5 in a subkey, and [KeyProblem.damaged] when the
/// packet is broken.
KeyPacket parseKeyPacket(PgpPacket packet) {
  final body = packet.body;
  final r = _Reader(body);
  final version = r.byte();
  final subkey = packet.tag == PgpTag.secretSubkey || packet.tag == PgpTag.publicSubkey;
  if (version == 5 && !subkey) throw const KeyFormatException(KeyProblem.unsupportedKeyType, 'LibrePGP version 5 primary key');
  if (version != 4 && version != 5 && version != 6) throw KeyFormatException(KeyProblem.unsupportedKeyType, 'OpenPGP version $version');
  final created = r.uint32();
  final algorithm = r.byte();
  final String name;
  int? bits;
  if (version != 4) {
    final length = r.uint32();
    final materialStart = r.pos;
    (name, bits) = _material(algorithm, r, measured: true);
    // A post-quantum key's parts have fixed sizes, which the length must be
    check(!_fixedSize.contains(algorithm) || r.pos - materialStart == length, 'OpenPGP: key material length');
    // The length tells where the material ends, known algorithm or not.
    r.pos = materialStart;
    r.skip(length);
  } else {
    (name, bits) = _material(algorithm, r, measured: false);
  }
  final publicEnd = r.pos;
  int? usage;
  Uint8List? agentKey;
  if (packet.tag == PgpTag.secretKey || packet.tag == PgpTag.secretSubkey) {
    usage = r.byte();
    if (usage == 0) {
      // Unprotected: v4 ends with a 2-byte sum of the secret octets.
      check(!r.isEmpty || version == 6, 'OpenPGP: no secret material');
      if (version == 5) check(r.uint32() == body.length - r.pos, 'OpenPGP: secret key material length');
      if (version == 4) {
        check(body.length - r.pos >= 2, 'OpenPGP: no checksum');
        var sum = 0;
        for (var i = r.pos; i < body.length - 2; i++) {
          sum = (sum + body[i]) & 0xffff;
        }
        check(sum == ((body[body.length - 2] << 8) | body[body.length - 1]), 'OpenPGP: secret key checksum');
      }
    } else if (version != 4) {
      // v5 and v6 count their S2K parameters, so their end is known whatever
      // they are; v5 counts its secret material too
      final s2k = r.bytes(r.byte());
      if (version == 5) check(r.uint32() == body.length - r.pos, 'OpenPGP: secret key material length');
      check(!r.isEmpty, 'OpenPGP: no secret material');
      // A cipher octet, then S2K type 101 with "GNU" and mode 3 (1003)
      if (version == 5 && usage == 255 && s2k.length == 7 && s2k[1] == 101 && _contains(s2k, const [0x47, 0x4e, 0x55, 3])) {
        agentKey = Uint8List.sublistView(body, r.pos);
      }
    } else {
      check(!r.isEmpty, 'OpenPGP: no secret material');
    }
  }
  return KeyPacket._(packet, version, created, algorithm, Uint8List.sublistView(body, 0, publicEnd), name, bits, usage, agentKey);
}

/// `21:protected-private-key`, which an agent key holds when a part of it
/// is behind a passphrase.
final _protectedKey = utf8.encode('21:protected-private-key');

bool _contains(List<int> data, List<int> part) {
  outer:
  for (var i = 0; i + part.length <= data.length; i++) {
    for (var j = 0; j < part.length; j++) {
      if (data[i + j] != part[j]) continue outer;
    }
    return true;
  }
  return false;
}

/// The algorithms of RFC 9980, whose public parts have fixed sizes.
const _fixedSize = {30, 31, 32, 33, 34, 35, 36};

/// Reads the public key material of [algorithm] and gives GnuPG's name for
/// it. For a version 5 or 6 key ([measured]) an algorithm it doesn't know
/// is fine, since the packet gives the material's length; for version 4
/// it can't be read past.
(String, int?) _material(int algorithm, _Reader r, {required bool measured}) {
  switch (algorithm) {
    case 1 || 2 || 3:
      final n = r.mpiBits();
      r.mpiBits();
      return ('rsa$n', n);
    case 17:
      final p = r.mpiBits();
      r
        ..mpiBits()
        ..mpiBits()
        ..mpiBits();
      return ('dsa$p', p);
    case 16 || 20:
      final p = r.mpiBits();
      r
        ..mpiBits()
        ..mpiBits();
      return ('elg$p', p);
    case 18 || 19 || 22:
      final curve = r.curveOid();
      r.mpiBits();
      if (algorithm == 18) {
        final kdf = r.byte();
        check(kdf >= 3, 'OpenPGP: ECDH parameters');
        r.skip(kdf);
      }
      return (_curveNames[curve] ?? curve, null);
    case 25:
      r.skip(32);
      return ('cv25519', null);
    case 26:
      r.skip(56);
      return ('cv448', null);
    case 27:
      r.skip(32);
      return ('ed25519', null);
    case 28:
      r.skip(57);
      return ('ed448', null);
    // RFC 9980: the classical public key, then the post-quantum one
    case 30:
      r.skip(32 + 1952);
      return ('mld65', null);
    case 31:
      r.skip(57 + 2592);
      return ('mld87', null);
    case 32:
      r.skip(32);
      return ('SLH-DSA-SHAKE-128s', null);
    case 33:
      r.skip(32);
      return ('SLH-DSA-SHAKE-128f', null);
    case 34:
      r.skip(64);
      return ('SLH-DSA-SHAKE-256s', null);
    case 35:
      r.skip(32 + 1184);
      return ('mlk768', null);
    case 36:
      r.skip(56 + 1568);
      return ('mlk1024', null);
    // LibrePGP's Kyber: a curve, its point, and the ML-KEM key with a
    // 4-byte count
    case 8 when measured:
      final curve = r.curveOid();
      r.mpiBits();
      final mlKem = r.uint32();
      r.skip(mlKem);
      final size = switch (mlKem) {
        1184 => 768,
        1568 => 1024,
        _ => throw const KeyFormatException(KeyProblem.damaged, 'OpenPGP: Kyber key length'),
      };
      return ('ky${size}_${_kyberCurveNames[curve] ?? curve}', null);
    default:
      if (!measured) throw KeyFormatException(KeyProblem.unsupportedKeyType, 'OpenPGP algorithm $algorithm');
      return ('algorithm $algorithm', null);
  }
}

/// GnuPG's names for the curves of ECDSA, ECDH and EdDSA keys.
const _curveNames = {
  '1.3.6.1.4.1.11591.15.1': 'ed25519',
  '1.3.6.1.4.1.3029.1.5.1': 'cv25519',
  '1.3.101.113': 'ed448',
  '1.3.101.111': 'cv448',
  '1.2.840.10045.3.1.7': 'nistp256',
  '1.3.132.0.34': 'nistp384',
  '1.3.132.0.35': 'nistp521',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolP256r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolP384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolP512r1',
  '1.3.132.0.10': 'secp256k1',
};

/// GnuPG's short names for the curves of a Kyber key (`ky768_bp256`).
const _kyberCurveNames = {
  '1.3.101.110': 'cv25519',
  '1.3.6.1.4.1.3029.1.5.1': 'cv25519',
  '1.3.101.111': 'cv448',
  '1.3.36.3.3.2.8.1.1.7': 'bp256',
  '1.3.36.3.3.2.8.1.1.11': 'bp384',
  '1.3.36.3.3.2.8.1.1.13': 'bp512',
  '1.2.840.10045.3.1.7': 'nistp256',
  '1.3.132.0.34': 'nistp384',
  '1.3.132.0.35': 'nistp521',
};

// ─── Signatures ───────────────────────────────────────────────────────────────

/// A signature packet taken apart, with the subpackets a key's
/// self-signatures carry.
class PgpSignature {
  PgpSignature._(this.body, this.version, this.type, this.publicKeyAlgorithm, this.hashAlgorithm, this.hashedEnd, this.salt, this.material);

  /// The whole packet body.
  final Uint8List body;
  final int version;
  final int type;
  final int publicKeyAlgorithm;
  final int hashAlgorithm;

  /// Where the hashed part (version through the hashed subpackets) ends in
  /// [body].
  final int hashedEnd;

  /// A version 6 signature's salt.
  final Uint8List? salt;

  /// The algorithm-specific signature after the 2-byte hash prefix.
  final Uint8List material;

  /// The hashed and the unhashed subpacket areas, without their lengths,
  /// as given: empty for a version 3 signature. A change to a key copies a
  /// self-signature's subpackets from them (`readSubpackets`).
  Uint8List hashedArea = Uint8List(0);
  Uint8List unhashedArea = Uint8List(0);

  int? created;

  /// Seconds after [created] at which the signature itself expires
  /// (subpacket 3); null or 0 for never.
  int? signatureExpiry;
  int? keyExpiry;
  int? flags;
  Uint8List? issuerFingerprint;
  Uint8List? issuerKeyId;
  bool primaryUserId = false;

  /// The first octet of the features subpacket (30), hashed.
  int? features;

  /// Whether the hashed part holds a subpacket marked critical of a type
  /// this app does not read. RFC 9580 section 5.2.3.7 says such a
  /// signature must be taken as invalid.
  bool unknownCritical = false;

  /// The signatures embedded in it (subpacket 32), as packet bodies: a
  /// signing subkey's binding carries its 0x19 back-signature so.
  final List<Uint8List> embedded = [];

  /// Whether it names [fingerprint] as its issuer (by fingerprint or key
  /// ID), or names no issuer at all, as some self-signatures don't.
  bool issuedBy(Uint8List fingerprint) {
    final fpr = issuerFingerprint;
    if (fpr != null) return _same(fpr, fingerprint);
    final id = issuerKeyId;
    if (id != null) {
      final keyId = fingerprint.length == 20 ? Uint8List.sublistView(fingerprint, 12) : Uint8List.sublistView(fingerprint, 0, 8);
      return _same(id, keyId);
    }
    return true;
  }
}

/// Takes a version 4 or 6 signature apart; a version 3 signature gives
/// one with no subpackets, which no key property is read from.
PgpSignature parseSignature(Uint8List body) {
  final r = _Reader(body);
  final version = r.byte();
  if (version == 3) {
    check(r.byte() == 5, 'OpenPGP: v3 signature');
    final type = r.byte();
    r.skip(12);
    final pkAlgo = r.byte();
    final hashAlgo = r.byte();
    r.skip(2);
    return PgpSignature._(body, version, type, pkAlgo, hashAlgo, 0, null, Uint8List.sublistView(body, r.pos));
  }
  check(version == 4 || version == 6, 'OpenPGP: signature version $version');
  final type = r.byte();
  final pkAlgo = r.byte();
  final hashAlgo = r.byte();
  final hashed = r.bytes(version == 6 ? r.uint32() : r.uint16());
  final hashedEnd = r.pos;
  final unhashed = r.bytes(version == 6 ? r.uint32() : r.uint16());
  r.skip(2); // the left 16 bits of the hash
  Uint8List? salt;
  if (version == 6) salt = r.bytes(r.byte());
  final sig = PgpSignature._(body, version, type, pkAlgo, hashAlgo, hashedEnd, salt, Uint8List.sublistView(body, r.pos));
  check(sig.material.isNotEmpty, 'OpenPGP: empty signature');
  sig
    ..hashedArea = hashed
    ..unhashedArea = unhashed;
  _subpackets(hashed, sig, hashed: true);
  _subpackets(unhashed, sig, hashed: false);
  return sig;
}

void _subpackets(Uint8List data, PgpSignature sig, {required bool hashed}) {
  final r = _Reader(data);
  while (!r.isEmpty) {
    final first = r.byte();
    final int length;
    if (first < 192) {
      length = first;
    } else if (first < 255) {
      length = ((first - 192) << 8) + r.byte() + 192;
    } else {
      length = r.uint32();
    }
    check(length >= 1, 'OpenPGP: empty subpacket');
    final content = r.bytes(length);
    final type = content[0] & 0x7f;
    final value = Uint8List.sublistView(content, 1);
    if (hashed && content[0] & 0x80 != 0 && !_readSubpackets.contains(type)) sig.unknownCritical = true;
    // Only the hashed area is trusted for what the key says of itself; the
    // issuer may be in either.
    switch (type) {
      case 2 when hashed && value.length == 4:
        sig.created = _readUint32(value);
      case 3 when hashed && value.length == 4:
        sig.signatureExpiry = _readUint32(value);
      case 32:
        sig.embedded.add(value);
      case 9 when hashed && value.length == 4:
        sig.keyExpiry = _readUint32(value);
      case 27 when hashed && value.isNotEmpty:
        sig.flags = value[0];
      case 25 when hashed && value.length == 1:
        sig.primaryUserId = value[0] != 0;
      case 30 when hashed && value.isNotEmpty:
        sig.features = value[0];
      case 33 when value.length >= 21:
        sig.issuerFingerprint = Uint8List.sublistView(value, 1);
      case 16 when value.length == 8:
        sig.issuerKeyId = value;
    }
  }
}

/// The subpacket types whose meaning this app honours or that only state
/// a preference, so that one marked critical does not void the signature:
/// creation time, signature and key expiry, the preferences, the issuer,
/// the primary user ID, key flags, the signer's user ID, the reason for a
/// revocation, features, an embedded signature and the issuer fingerprint.
const _readSubpackets = {2, 3, 7, 9, 11, 16, 21, 22, 23, 25, 27, 28, 29, 30, 32, 33, 34};

int _readUint32(Uint8List v) => (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

class _Reader {
  _Reader(this._bytes);

  final Uint8List _bytes;
  int pos = 0;

  bool get isEmpty => pos >= _bytes.length;

  int byte() {
    check(pos < _bytes.length, 'OpenPGP: cut short');
    return _bytes[pos++];
  }

  int uint16() => (byte() << 8) | byte();

  int uint32() => (uint16() << 16) | uint16();

  void skip(int n) {
    check(n >= 0 && n <= _bytes.length - pos, 'OpenPGP: length past the end');
    pos += n;
  }

  Uint8List bytes(int n) {
    final start = pos;
    skip(n);
    return Uint8List.sublistView(_bytes, start, pos);
  }

  /// An MPI's bit count, skipping its bytes.
  int mpiBits() {
    final bits = uint16();
    skip((bits + 7) >> 3);
    return bits;
  }

  /// A curve OID: a length octet (not 0 or 255) and the DER content.
  String curveOid() {
    final length = byte();
    check(length != 0 && length != 0xff, 'OpenPGP: curve OID length');
    return decodeOid(bytes(length));
  }
}
