// OpenPGP signatures over keys (RFC 9580 section 5.2.4): the data a
// certification, a binding or a direct-key signature hashes, in versions 4
// and 6, and making and checking EdDSA (legacy and Ed25519) and RSA
// PKCS#1 v1.5 signatures, checking ECDSA ones on NIST P-256 and P-384,
// and checking RFC 9980's composite ML-DSA-65+Ed25519, which is good only
// when both of its parts are. Kemlock checks the self-signatures of the
// keys it generates, and of keys it reads when asked.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart' as c;

import '../../bytes.dart';
import '../../keccak.dart';
import '../../ml_dsa.dart';
import '../algorithms.dart';
import '../der.dart';
import '../key_error.dart';
import 'key_info.dart';
import 'packets.dart';
import 'rsa.dart' as rsa_;

export 'rsa.dart' show signRsa;

/// Hash algorithm IDs (RFC 9580 section 9.5) and their digests and DER
/// object identifiers.
final _hashes = <int, (List<int> Function(List<int>), String)>{
  2: ((d) => hash.sha1.convert(d).bytes, '1.3.14.3.2.26'),
  8: ((d) => hash.sha256.convert(d).bytes, '2.16.840.1.101.3.4.2.1'),
  9: ((d) => hash.sha384.convert(d).bytes, '2.16.840.1.101.3.4.2.2'),
  10: ((d) => hash.sha512.convert(d).bytes, '2.16.840.1.101.3.4.2.3'),
  11: ((d) => hash.sha224.convert(d).bytes, '2.16.840.1.101.3.4.2.4'),
  12: (sha3_256, '2.16.840.1.101.3.4.2.8'),
  14: (sha3_512, '2.16.840.1.101.3.4.2.10'),
};

const hashSha512 = 10;

/// The hashes a composite signature may be made over: RFC 9980 section
/// 5.2.3 asks for a digest of 256 bits or more.
const pqSignatureHashes = {8, 9, 10, 12, 14};

/// The sizes of a composite ML-DSA-65+Ed25519 key and signature: the
/// Ed25519 part first, then the ML-DSA-65 part.
const _compositePublicLength = 32 + MlDsa65.publicKeyLength;
const _compositeSignatureLength = 64 + MlDsa65.signatureLength;

/// A key packet as it goes into a signature: 0x99 and a 2-byte length for
/// version 4, 0x9a or 0x9b and a 4-byte length for versions 5 and 6, then
/// its public body. A version 4 binding signature hashes a version 5
/// subkey this way too, as GnuPG does.
Uint8List hashedKey(KeyPacket key) {
  final body = key.publicBody;
  final n = body.length;
  final prefix = key.version == 4 ? [0x99, n >> 8, n & 0xff] : [key.version == 5 ? 0x9a : 0x9b, ..._be32(n)];
  return Uint8List.fromList([...prefix, ...body]);
}

/// A user ID as it goes into a certification: 0xb4 and a 4-byte length.
Uint8List hashedUserId(List<int> userId) => Uint8List.fromList([0xb4, ..._be32(userId.length), ...userId]);

/// The signature's own hashed part and the trailer after it: version,
/// 0xff, and the hashed part's length.
Uint8List _trailer(int version, Uint8List hashedPart) => Uint8List.fromList([...hashedPart, version, 0xff, ..._be32(hashedPart.length)]);

List<int> _be32(int v) => [v >>> 24 & 0xff, v >>> 16 & 0xff, v >>> 8 & 0xff, v & 0xff];

// ─── Checking ─────────────────────────────────────────────────────────────────

/// Whether [signature], made by [signer], is good over [data] (the keys
/// and user ID it covers, built with [hashedKey] and [hashedUserId]).
/// False for an algorithm or hash this app doesn't check.
Future<bool> verifySignature(PgpSignature signature, KeyPacket signer, List<int> data) async {
  final digestOf = _hashes[signature.hashAlgorithm]?.$1;
  if (digestOf == null || signature.version != signer.version) return false;
  return verifyDigest(signature, signer, digestOf([...?signature.salt, ...data, ...signatureTrailer(signature)]));
}

/// What a signature hashes after the data it covers: its own hashed part,
/// then its version, 0xff and that part's length.
Uint8List signatureTrailer(PgpSignature signature) =>
    _trailer(signature.version, Uint8List.sublistView(signature.body, 0, signature.hashedEnd));

/// Whether [signature], made by [signer], is good for [digest]: the hash,
/// by the signature's own algorithm, of its salt, the data and
/// [signatureTrailer]. Signatures over data are checked this way, the data
/// having been hashed as it streamed past.
Future<bool> verifyDigest(PgpSignature signature, KeyPacket signer, List<int> digest) async {
  if (signature.version != signer.version || !rsa_.hashOids.containsKey(signature.hashAlgorithm)) return false;
  // The two bytes before the signature are the digest's first two.
  final prefixAt = signature.body.length - signature.material.length - 2 - (signature.salt == null ? 0 : signature.salt!.length + 1);
  if (signature.body[prefixAt] != digest[0] || signature.body[prefixAt + 1] != digest[1]) return false;
  final matches = switch ((signature.publicKeyAlgorithm, signer.algorithm)) {
    (22, 22) || (27, 27) || (19, 19) || (30, 30) || (1 || 3, 1 || 2 || 3) => true,
    _ => false,
  };
  if (!matches) return false;
  return verifySignatureMaterial(signer, signature.hashAlgorithm, digest, signature.material);
}

/// The size in bits of the modulus of [key], an RSA key, as the number it
/// is, whatever bit count the packet puts before it; 0 for one that can't
/// be read, and null for a key of another algorithm.
int? rsaModulusBits(KeyPacket key) {
  if (key.algorithm != 1 && key.algorithm != 2 && key.algorithm != 3) return null;
  try {
    return bytesToBigInt(_Reader(key.publicMaterial).mpi()).bitLength;
  } on KeyFormatException {
    return 0;
  }
}

/// Whether [material], the algorithm-specific part of a signature by
/// [signer] in its own algorithm, is good for [digest], made with
/// [hashAlgorithm]: what [verifyDigest] checks, when there is no packet
/// yet, as for what a card answers (openspec: add-openpgp-card). EdDSA
/// (legacy and Ed25519), RSA, ECDSA on NIST P-256 and P-384, and RFC
/// 9980's composite ML-DSA-65+Ed25519.
Future<bool> verifySignatureMaterial(KeyPacket signer, int hashAlgorithm, List<int> digest, Uint8List material) async {
  final oid = rsa_.hashOids[hashAlgorithm];
  if (oid == null) return false;
  try {
    switch (signer.algorithm) {
      case 22 || 27:
        final public = _ed25519Public(signer);
        final m = _Reader(material);
        final sig = signer.algorithm == 27 ? m.bytes(64) : Uint8List.fromList([...m.mpiFixed(32), ...m.mpiFixed(32)]);
        return await c.Ed25519().verify(
          digest,
          signature: c.Signature(sig, publicKey: c.SimplePublicKey(public, type: c.KeyPairType.ed25519)),
        );
      case 1 || 2 || 3:
        final k = _Reader(signer.publicMaterial);
        final n = bytesToBigInt(k.mpi());
        final e = bytesToBigInt(k.mpi());
        final s = bytesToBigInt(_Reader(material).mpi());
        // Numbers no real key has would only make modPow slow.
        if (n.bitLength > maxRsaBits || e.bitLength > 64 || s >= n) return false;
        return rsaVerifyPkcs1(RsaPublicHalf(n, e), oid, digest, s);
      case 19:
        final k = _Reader(signer.publicMaterial);
        final curve = EcCurve.byOid(k.curveOid());
        if (curve == null) return false;
        final point = k.mpi();
        final m = _Reader(material);
        final r = bytesToBigInt(m.mpi());
        final s = bytesToBigInt(m.mpi());
        return ecdsaVerifyDigest(EcPublicHalf(curve, point), digest, r, s);
      case 30:
        return await verifyComposite(signer.publicMaterial, material, digest, hashAlgorithm: hashAlgorithm);
      default:
        return false;
    }
  } on KeyFormatException {
    return false;
  }
}

/// Whether [material], a composite ML-DSA-65+Ed25519 signature (the 64
/// bytes of Ed25519, then ML-DSA-65's), signs [digest] under [public], the
/// composite public key, over [hashAlgorithm]: refused before either part
/// runs for a hash under 256 bits, and good only when both parts are
/// (RFC 9980 section 5.2.3). ML-DSA is checked with an empty context.
Future<bool> verifyComposite(Uint8List public, Uint8List material, List<int> digest, {required int hashAlgorithm}) async {
  if (!pqSignatureHashes.contains(hashAlgorithm)) return false;
  if (public.length != _compositePublicLength || material.length != _compositeSignatureLength) return false;
  final ed25519 = await c.Ed25519().verify(
    digest,
    signature: c.Signature(
      Uint8List.sublistView(material, 0, 64),
      publicKey: c.SimplePublicKey(Uint8List.sublistView(public, 0, 32), type: c.KeyPairType.ed25519),
    ),
  );
  final mlDsa = MlDsa65.verify(Uint8List.sublistView(public, 32), digest, Uint8List.sublistView(material, 64));
  return ed25519 && mlDsa;
}

/// The Ed25519 public key of an EdDSA (legacy, 0x40-prefixed) or Ed25519
/// key packet.
Uint8List _ed25519Public(KeyPacket key) {
  final r = _Reader(key.publicMaterial);
  if (key.algorithm == 27) return r.bytes(32);
  check(r.curveOid() == '1.3.6.1.4.1.11591.15.1', 'OpenPGP: EdDSA curve');
  final point = r.mpi();
  check(point.length == 33 && point[0] == 0x40, 'OpenPGP: EdDSA point');
  return Uint8List.sublistView(point, 1);
}

/// Checks every self-signature of the first transferable key in [data]:
/// the certifications of its user IDs, its direct-key signatures and
/// revocations, and its subkeys' bindings. True when there is at least one
/// and all are good; signatures by other keys aren't checked.
Future<bool> verifySelfSignatures(Uint8List data) async {
  final key = readTransferableKey(data);
  final primary = parseKeyPacket(key.packets.first);
  final primaryBytes = hashedKey(primary);
  List<int>? covered = primaryBytes;
  var checked = 0;
  for (final packet in key.packets.skip(1)) {
    switch (packet.tag) {
      case PgpTag.userId:
        covered = [...primaryBytes, ...hashedUserId(packet.body)];
      case PgpTag.userAttribute:
        covered = null; // a photo's signatures aren't checked
      case PgpTag.secretSubkey || PgpTag.publicSubkey:
        covered = [...primaryBytes, ...hashedKey(parseKeyPacket(packet))];
      case PgpTag.signature:
        final signature = parseSignature(packet.body);
        if (covered == null || !signature.issuedBy(primary.fingerprint) || signature.version == 3) continue;
        if (!await verifySignature(signature, primary, covered)) return false;
        checked++;
    }
  }
  return checked > 0;
}

/// Whether [binding], the binding signature of the signing [subkey], holds
/// a primary key binding signature (type 0x19) that the subkey made over
/// the two keys: without one, anybody could attach another person's
/// signing subkey to their own key.
Future<bool> verifyBackSignature(KeyPacket primary, KeyPacket subkey, PgpSignature binding) async {
  final covered = [...hashedKey(primary), ...hashedKey(subkey)];
  for (final body in binding.embedded) {
    try {
      final back = parseSignature(body);
      if (back.type == 0x19 && await verifySignature(back, subkey, covered)) return true;
    } on KeyFormatException {
      continue;
    }
  }
  return false;
}

// ─── Making ───────────────────────────────────────────────────────────────────

/// The salt length a version 6 signature over [hashAlgorithm] carries
/// (RFC 9580 section 9.5): 16 bytes for SHA-256, SHA-224 and SHA3-256, 24
/// for SHA-384, 32 for SHA-512 and SHA3-512.
int signatureSaltLength(int hashAlgorithm) => switch (hashAlgorithm) {
  9 => 24,
  10 || 14 => 32,
  _ => 16,
};

/// A signature packet body of [type] by [signer] over [data], with the
/// [hashed] subpackets: version 6 for a version 6 signer, with [salt] (or
/// a fresh one of the length the hash takes) and the [unhashed]
/// subpackets unhashed; version 4 for any other, with the issuer's key ID
/// then the [unhashed] subpackets unhashed. The hash is SHA-512 unless
/// [hashAlgorithm] says another. [sign] signs the digest and gives the
/// algorithm's signature fields.
Future<Uint8List> makeSignature({
  required int type,
  required KeyPacket signer,
  required List<int> data,
  required List<int> hashed,
  List<int> unhashed = const [],
  required Future<List<int>> Function(List<int> digest) sign,
  int hashAlgorithm = hashSha512,
  Uint8List? salt,
}) async {
  final hashedPart = signatureHashedPart(type: type, signer: signer, hashed: hashed, hashAlgorithm: hashAlgorithm);
  final saltOf = signer.version == 6 ? (salt ?? randomBytes(signatureSaltLength(hashAlgorithm))) : null;
  final digest = _hashes[hashAlgorithm]!.$1(Uint8List.fromList([...?saltOf, ...data, ...signatureTrailerOf(hashedPart)]));
  return finishSignature(hashedPart: hashedPart, signer: signer, digest: digest, sign: sign, salt: saltOf, unhashed: unhashed);
}

/// The hashed part of a signature of [type] by [signer]: version through
/// the [hashed] subpackets, their length in 4 bytes for version 6 and in
/// 2 for version 4.
Uint8List signatureHashedPart({required int type, required KeyPacket signer, required List<int> hashed, int hashAlgorithm = hashSha512}) =>
    Uint8List.fromList([
      if (signer.version == 6) ...[
        6,
        type,
        signer.algorithm,
        hashAlgorithm,
        ..._be32(hashed.length),
      ] else ...[
        4,
        type,
        signer.algorithm,
        hashAlgorithm,
        hashed.length >> 8,
        hashed.length & 0xff,
      ],
      ...hashed,
    ]);

/// What a signature with [hashedPart] hashes after its data: the hashed
/// part, then its version, 0xff and the hashed part's length.
Uint8List signatureTrailerOf(Uint8List hashedPart) => _trailer(hashedPart[0], hashedPart);

/// The signature packet body for [hashedPart] and the [digest] of
/// [salt], the data and [signatureTrailerOf]: version 6 with the salt and
/// the [unhashed] subpackets unhashed, or version 4 with the issuer's key
/// ID and then the [unhashed] subpackets unhashed.
Future<Uint8List> finishSignature({
  required Uint8List hashedPart,
  required KeyPacket signer,
  required List<int> digest,
  required Future<List<int>> Function(List<int> digest) sign,
  List<int> unhashed = const [],
  Uint8List? salt,
}) async {
  if (hashedPart[0] == 6) {
    if (salt == null) throw ArgumentError('a version 6 signature needs its salt');
    return Uint8List.fromList([
      ...hashedPart,
      ..._be32(unhashed.length),
      ...unhashed,
      digest[0],
      digest[1],
      salt.length,
      ...salt,
      ...await sign(digest),
    ]);
  }
  final area = [...subpacket(16, signer.fingerprint.sublist(12)), ...unhashed];
  return Uint8List.fromList([...hashedPart, area.length >> 8, area.length & 0xff, ...area, digest[0], digest[1], ...await sign(digest)]);
}

/// A composite ML-DSA-65+Ed25519 signature of [digest] (RFC 9980 section
/// 5.2.2): the Ed25519 signature by [ed25519Seed], then the ML-DSA-65
/// signature by [mlDsaSecretKey], the expanded key, with an empty
/// context; hedged unless [randomness] makes ML-DSA deterministic.
Future<List<int>> signComposite(Uint8List ed25519Seed, Uint8List mlDsaSecretKey, List<int> digest, {Uint8List? randomness}) async {
  final algorithm = c.Ed25519();
  final ed25519 = await algorithm.sign(digest, keyPair: await algorithm.newKeyPairFromSeed(ed25519Seed));
  return [...ed25519.bytes, ...MlDsa65.sign(mlDsaSecretKey, digest, randomness: randomness)];
}

/// One signature subpacket: its length, [type] (with the critical bit when
/// [critical]), and [data], the length in the shortest form that holds it.
Uint8List subpacket(int type, List<int> data, {bool critical = false}) {
  final length = data.length + 1;
  final header = length < 192
      ? [length]
      : length < 8384
      ? [((length - 192) >> 8) + 192, (length - 192) & 0xff]
      : [0xff, ..._be32(length)];
  return Uint8List.fromList([...header, critical ? type | 0x80 : type, ...data]);
}

/// One subpacket of a signature's hashed or unhashed area (RFC 9580
/// section 5.2.3.7).
class Subpacket {
  const Subpacket(this.type, this.data, {this.critical = false});

  /// Its type, without the critical bit.
  final int type;
  final Uint8List data;

  /// Whether the signature is void for a reader that does not know [type].
  final bool critical;

  /// As it goes into an area.
  Uint8List get encoded => subpacket(type, data, critical: critical);

  @override
  String toString() => 'Subpacket($type${critical ? ', critical' : ''}, ${data.length} bytes)';
}

/// The subpackets of a hashed or unhashed [area] (`PgpSignature.hashedArea`),
/// in their order. Throws [KeyProblem.damaged] for a length past the end or
/// an empty subpacket.
List<Subpacket> readSubpackets(Uint8List area) {
  final out = <Subpacket>[];
  var pos = 0;
  int byte() {
    check(pos < area.length, 'OpenPGP: cut short');
    return area[pos++];
  }

  while (pos < area.length) {
    final first = byte();
    final int length;
    if (first < 192) {
      length = first;
    } else if (first < 255) {
      length = ((first - 192) << 8) + byte() + 192;
    } else {
      length = (byte() << 24) | (byte() << 16) | (byte() << 8) | byte();
    }
    check(length >= 1 && length <= area.length - pos, 'OpenPGP: subpacket length');
    final type = area[pos];
    out.add(Subpacket(type & 0x7f, Uint8List.sublistView(area, pos + 1, pos + length), critical: type & 0x80 != 0));
    pos += length;
  }
  return out;
}

/// An area holding [subpackets], each in the shortest length form, which
/// is the form every program at hand writes.
Uint8List writeSubpackets(Iterable<Subpacket> subpackets) => Uint8List.fromList([for (final s in subpackets) ...s.encoded]);

/// An Ed25519 signature of [digest] as the two MPIs of an EdDSA (legacy)
/// signature.
Future<List<int>> signEdDsa(Uint8List seed, List<int> digest) async {
  final algorithm = c.Ed25519();
  final signature = await algorithm.sign(digest, keyPair: await algorithm.newKeyPairFromSeed(seed));
  return [...mpiOfBytes(signature.bytes.sublist(0, 32)), ...mpiOfBytes(signature.bytes.sublist(32))];
}

/// An MPI: the bit count in two bytes, then the number's bytes.
Uint8List mpi(BigInt value) {
  final bytes = bigIntToBytes(value);
  return Uint8List.fromList([value.bitLength >> 8, value.bitLength & 0xff, ...bytes]);
}

/// The MPI of a big-endian octet string, leading zeros dropped.
Uint8List mpiOfBytes(List<int> bytes) => mpi(bytesToBigInt(bytes));

class _Reader {
  _Reader(this._bytes);

  final Uint8List _bytes;
  int _pos = 0;

  Uint8List bytes(int n) {
    check(n <= _bytes.length - _pos, 'OpenPGP: cut short');
    final out = Uint8List.sublistView(_bytes, _pos, _pos + n);
    _pos += n;
    return out;
  }

  Uint8List mpi() {
    final head = bytes(2);
    return bytes(((head[0] << 8 | head[1]) + 7) >> 3);
  }

  /// An MPI holding an octet string of [length], zeros put back in front.
  Uint8List mpiFixed(int length) {
    final value = mpi();
    check(value.length <= length, 'OpenPGP: MPI too long');
    return Uint8List(length)..setAll(length - value.length, value);
  }

  String curveOid() {
    final length = bytes(1)[0];
    check(length != 0 && length != 0xff, 'OpenPGP: curve OID length');
    return decodeOid(bytes(length));
  }
}
