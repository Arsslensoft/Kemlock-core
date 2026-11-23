// PKCS#8 private keys (RFC 5208, and RFC 5958's version 2 with a public
// key), SPKI public keys (RFC 5280), PKCS#1 RSA keys (RFC 8017) and SEC1 EC
// keys (RFC 5915), for the algorithms in `algorithms.dart`. Written as
// OpenSSL 3 writes them, so `openssl pkey` and Kemlock give the same bytes
// for the same key; the tests compare them.
//
// ML-KEM and ML-DSA keys use the encodings of the IETF LAMPS drafts that
// OpenSSL 3.5 implements: the public key is the BIT STRING of the SPKI, and
// the private key is one of a seed (`[0] IMPLICIT OCTET STRING`), the
// expanded key (`OCTET STRING`), or both (`SEQUENCE { seed, expanded }`).
// OpenSSL's older "bare" forms, the seed or the expanded key with no
// wrapping, are read too: their lengths tell them apart.

import 'dart:typed_data';

import 'algorithms.dart';
import 'der.dart';
import 'key_error.dart';

/// The parts of a PKCS#8 `PrivateKeyInfo`, unencrypted. Throws
/// [KeyProblem.damaged] when they don't form a key, and
/// [KeyProblem.unsupportedKeyType] for a multi-prime RSA key.
///
/// An algorithm this app doesn't know gives [OtherMaterial]; so does an EC
/// key on a curve other than P-256 and P-384, under the curve's identifier.
Future<KeyMaterial> readPkcs8(Uint8List der) async {
  checkSize(der.length);
  final r = readSequence(der);
  final version = r.smallInteger();
  check(version == 0 || version == 1, 'PKCS#8: version $version');
  final algorithm = r.sequence();
  final oid = algorithm.oid();
  final parameters = algorithm.isEmpty ? null : algorithm.read();
  algorithm.done();
  final privateKey = r.octetString();
  r.optional(contextTag(0)); // attributes: kept in the bytes, not read
  Uint8List? publicKey;
  if (version == 1) {
    final bits = r.optionalContent(contextTag(1, constructed: false));
    if (bits != null) {
      check(bits.isNotEmpty && bits[0] == 0, 'PKCS#8: public key with unused bits');
      publicKey = Uint8List.sublistView(bits, 1);
    }
  }
  r.done();

  switch (oid) {
    case oidRsaEncryption:
      check(parameters == null || (parameters.tag == tagNull && parameters.content.isEmpty), 'PKCS#8: RSA parameters');
      return readPkcs1(privateKey);
    case oidEcPublicKey:
      // Named curves only; explicit parameters make it an unknown key.
      if (parameters == null || parameters.tag != tagOid) return const OtherMaterial(oidEcPublicKey);
      final curveOid = decodeOid(parameters.content);
      final curve = EcCurve.byOid(curveOid);
      if (curve == null) return OtherMaterial(curveOid);
      return readSec1(privateKey, curve: curve, publicKey: publicKey);
    case oidEd25519:
      _checkNoParameters(parameters);
      return ed25519Material(_curvePrivateKey(privateKey), publicKey);
    case oidX25519:
      _checkNoParameters(parameters);
      return x25519Material(_curvePrivateKey(privateKey), publicKey);
    default:
      final pq = PqParameters.byOid(oid);
      if (pq == null) return OtherMaterial(oid);
      _checkNoParameters(parameters);
      return _readPq(pq, privateKey, publicKey);
  }
}

PqMaterial _readPq(PqParameters pq, Uint8List privateKey, Uint8List? publicKey) {
  if (privateKey.length == pq.seedLength) return pqMaterial(pq, seed: privateKey, publicKey: publicKey);
  if (privateKey.length == pq.expandedLength) return pqMaterial(pq, expanded: privateKey, publicKey: publicKey);
  final r = DerReader(privateKey);
  final element = r.read();
  r.done();
  switch (element.tag) {
    case 0x80: // seed [0]
      return pqMaterial(pq, seed: element.content, publicKey: publicKey);
    case tagOctetString:
      return pqMaterial(pq, expanded: element.content, publicKey: publicKey);
    case tagSequence:
      final both = DerReader(element.content);
      final seed = both.octetString();
      final expanded = both.octetString();
      both.done();
      return pqMaterial(pq, seed: seed, expanded: expanded, publicKey: publicKey);
    default:
      throw const KeyFormatException(KeyProblem.damaged, 'PQ: private key form');
  }
}

/// How an ML-KEM or ML-DSA private key is written: OpenSSL's `seed-only`,
/// `priv-only` and `seed-priv` (its default).
enum PqForm { seed, expanded, both }

void _checkNoParameters(DerElement? parameters) => check(parameters == null, 'PKCS#8: unexpected parameters');

/// RFC 8410's `CurvePrivateKey`: an OCTET STRING inside the OCTET STRING.
Uint8List _curvePrivateKey(Uint8List privateKey) {
  final r = DerReader(privateKey);
  final key = r.octetString();
  r.done();
  return key;
}

/// A PKCS#1 `RSAPrivateKey`. Throws [KeyProblem.damaged] when its numbers
/// don't belong together.
RsaMaterial readPkcs1(Uint8List der) {
  checkSize(der.length);
  final r = readSequence(der);
  final version = r.smallInteger();
  if (version == 1) throw const KeyFormatException(KeyProblem.unsupportedKeyType, 'multi-prime RSA');
  check(version == 0, 'PKCS#1: version $version');
  final m = RsaMaterial(
    n: r.integer(),
    e: r.integer(),
    d: r.integer(),
    p: r.integer(),
    q: r.integer(),
    dp: r.integer(),
    dq: r.integer(),
    qinv: r.integer(),
  );
  r.done();
  return checkedRsa(m);
}

/// A SEC1 `ECPrivateKey`. Inside PKCS#8 the [curve] comes from the
/// algorithm identifier; on its own the key names it in its parameters.
/// The result is [OtherMaterial] for a curve this app doesn't know.
KeyMaterial readSec1(Uint8List der, {EcCurve? curve, Uint8List? publicKey}) {
  checkSize(der.length);
  final r = readSequence(der);
  check(r.smallInteger() == 1, 'SEC1: version');
  final d = r.octetString();
  final parameters = r.optional(contextTag(0));
  var keyCurve = curve;
  if (parameters != null) {
    final curveOid = parameters.oid();
    parameters.done();
    final named = EcCurve.byOid(curveOid);
    if (named == null) return OtherMaterial(curveOid);
    check(curve == null || named == curve, 'SEC1: curve differs from PKCS#8');
    keyCurve = named;
  }
  final pointReader = r.optional(contextTag(1));
  final point = pointReader?.bitString();
  pointReader?.done();
  r.done();
  check(keyCurve != null, 'SEC1: no curve');
  check(d.length <= keyCurve!.size, 'SEC1: scalar too long');
  if (point != null && publicKey != null) check(_equal(point, publicKey), 'SEC1: two public keys');
  return ecMaterial(keyCurve, d, point ?? publicKey);
}

// ─── Writing ──────────────────────────────────────────────────────────────────

/// [m] as PKCS#8 `PrivateKeyInfo`, version 0, as `openssl pkey` writes it;
/// an ML-KEM or ML-DSA key in [pqForm], both seed and expanded key by
/// default, or the expanded key alone when there is no seed.
Uint8List writePkcs8(KeyMaterial m, {PqForm pqForm = PqForm.both}) => switch (m) {
  RsaMaterial() => _privateKeyInfo(_algorithm(oidRsaEncryption, derNull()), writePkcs1(m)),
  EcMaterial() => _privateKeyInfo(
    _algorithm(oidEcPublicKey, derOid(m.curve.oid)),
    // OpenSSL leaves the curve out here, since the algorithm names it, and
    // keeps the public point.
    derSequence([derSmallInteger(1), derOctetString(m.d), derTlv(contextTag(1), derBitString(m.point))]),
  ),
  Ed25519Material() => _privateKeyInfo(_algorithm(oidEd25519), derOctetString(m.seed)),
  X25519Material() => _privateKeyInfo(_algorithm(oidX25519), derOctetString(m.privateKey)),
  PqMaterial(:final parameters, :final seed, :final expanded) => _privateKeyInfo(_algorithm(parameters.oid), switch (seed == null
      ? PqForm.expanded
      : pqForm) {
    PqForm.seed => derTlv(0x80, seed!),
    PqForm.expanded => derOctetString(expanded),
    PqForm.both => derSequence([derOctetString(seed!), derOctetString(expanded)]),
  }),
  OtherMaterial() => throw ArgumentError('a key of an unknown algorithm is kept as it was read'),
};

/// A key on a curve this app doesn't know, from SEC1 to PKCS#8, as OpenSSL
/// converts it: the curve moves from the SEC1 parameters to the algorithm
/// identifier, and the scalar and public point stay as they were.
Uint8List wrapSec1(String curveOid, Uint8List sec1) {
  final r = readSequence(sec1);
  final version = r.read().encoded;
  final d = r.read().encoded;
  r.optional(contextTag(0));
  final rest = [for (; !r.isEmpty;) r.read().encoded];
  return _privateKeyInfo(_algorithm(oidEcPublicKey, derOid(curveOid)), derSequence([version, d, ...rest]));
}

Uint8List _privateKeyInfo(Uint8List algorithm, Uint8List privateKey) =>
    derSequence([derSmallInteger(0), algorithm, derOctetString(privateKey)]);

Uint8List _algorithm(String oid, [Uint8List? parameters]) => derSequence([derOid(oid), ?parameters]);

/// [m] as PKCS#1 `RSAPrivateKey`.
Uint8List writePkcs1(RsaMaterial m) => derSequence([
  derSmallInteger(0),
  for (final v in [m.n, m.e, m.d, m.p, m.q, m.dp, m.dq, m.qinv]) derInteger(v),
]);

/// [half] as SPKI `SubjectPublicKeyInfo`, as `openssl pkey -pubout` writes it.
Uint8List writeSpki(PublicHalf half) => switch (half) {
  RsaPublicHalf(:final n, :final e) => derSequence([
    _algorithm(oidRsaEncryption, derNull()),
    derBitString(derSequence([derInteger(n), derInteger(e)])),
  ]),
  EcPublicHalf(:final curve, :final point) => derSequence([_algorithm(oidEcPublicKey, derOid(curve.oid)), derBitString(point)]),
  RawPublicHalf(:final algorithm, :final bytes) => derSequence([_algorithm(_rawOid(algorithm)), derBitString(bytes)]),
};

String _rawOid(KeyAlgorithm algorithm) => switch (algorithm) {
  KeyAlgorithm.ed25519 => oidEd25519,
  KeyAlgorithm.x25519 => oidX25519,
  _ => PqParameters.byAlgorithm(algorithm)?.oid ?? (throw ArgumentError.value(algorithm, 'algorithm', 'has no raw public key')),
};

/// The public half in an SPKI, or null for an algorithm this app doesn't
/// know. Throws [KeyProblem.damaged] when the structure is broken.
PublicHalf? readSpki(Uint8List der) {
  checkSize(der.length);
  final r = readSequence(der);
  final algorithm = r.sequence();
  final oid = algorithm.oid();
  final parameters = algorithm.isEmpty ? null : algorithm.read();
  algorithm.done();
  final bits = r.bitString();
  r.done();
  switch (oid) {
    case oidRsaEncryption:
      final key = readSequence(bits);
      final n = key.integer();
      final e = key.integer();
      key.done();
      return RsaPublicHalf(n, e);
    case oidEcPublicKey:
      if (parameters == null || parameters.tag != tagOid) return null;
      final curve = EcCurve.byOid(decodeOid(parameters.content));
      if (curve == null) return null;
      check(bits.length == 1 + 2 * curve.size && bits[0] == 4, 'SPKI: EC point');
      return EcPublicHalf(curve, Uint8List.fromList(bits));
    case oidEd25519 || oidX25519:
      check(bits.length == 32, 'SPKI: key length');
      return RawPublicHalf(oid == oidEd25519 ? KeyAlgorithm.ed25519 : KeyAlgorithm.x25519, Uint8List.fromList(bits));
    default:
      final pq = PqParameters.byOid(oid);
      if (pq == null) return null;
      check(parameters == null && bits.length == pq.publicKeyLength, 'SPKI: key length');
      return RawPublicHalf(pq.algorithm, Uint8List.fromList(bits));
  }
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
