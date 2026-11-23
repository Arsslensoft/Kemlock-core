// The key algorithms the vault knows, their object identifiers, and the
// arithmetic the readers need to get a public half from a private one:
// EC points through pointycastle, Ed25519 and X25519 through cryptography,
// ML-KEM and ML-DSA through `ml_kem.dart` and `ml_dsa.dart`.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;
import 'package:pointycastle/export.dart' as pc;

import '../bytes.dart';
import '../ml_dsa.dart';
import '../ml_kem.dart';
import 'der.dart';
import 'key_error.dart';

const oidRsaEncryption = '1.2.840.113549.1.1.1';
const oidEcPublicKey = '1.2.840.10045.2.1';
const oidEd25519 = '1.3.101.112';
const oidX25519 = '1.3.101.110';
const oidMlKem768 = '2.16.840.1.101.3.4.4.2';
const oidMlKem1024 = '2.16.840.1.101.3.4.4.3';
const oidMlDsa65 = '2.16.840.1.101.3.4.3.18';

/// An algorithm the vault knows, by the name `VaultKey.algorithm` stores
/// (design decision 1). A key of any other algorithm is kept as "other",
/// under its object identifier.
enum KeyAlgorithm {
  ed25519('ed25519'),
  x25519('x25519'),
  ecdsaP256('ecdsa-p256'),
  ecdsaP384('ecdsa-p384'),
  rsa('rsa'),
  mlKem768('ml-kem-768'),
  mlKem1024('ml-kem-1024'),
  mlDsa65('ml-dsa-65');

  const KeyAlgorithm(this.id);

  /// `ed25519`, `ecdsa-p256`, ... as stored.
  final String id;

  /// Whether OpenSSH has a key type for it.
  bool get hasSshForm => this == ed25519 || this == ecdsaP256 || this == ecdsaP384 || this == rsa;

  /// Whether it is a key exchange (X25519, ML-KEM) rather than a signature.
  bool get isExchange => this == x25519 || this == mlKem768 || this == mlKem1024;
}

/// The sizes of a post-quantum algorithm's seed, expanded private key and
/// public key, and its identifier.
enum PqParameters {
  mlKem768(KeyAlgorithm.mlKem768, oidMlKem768, 64, MlKem768.secretKeyLength, MlKem768.publicKeyLength),
  mlKem1024(KeyAlgorithm.mlKem1024, oidMlKem1024, 64, MlKem1024.secretKeyLength, MlKem1024.publicKeyLength),
  mlDsa65(KeyAlgorithm.mlDsa65, oidMlDsa65, MlDsa65.seedLength, MlDsa65.secretKeyLength, MlDsa65.publicKeyLength);

  const PqParameters(this.algorithm, this.oid, this.seedLength, this.expandedLength, this.publicKeyLength);

  final KeyAlgorithm algorithm;
  final String oid;
  final int seedLength;
  final int expandedLength;
  final int publicKeyLength;

  static PqParameters? byOid(String oid) => values.where((p) => p.oid == oid).firstOrNull;

  static PqParameters? byAlgorithm(KeyAlgorithm algorithm) => values.where((p) => p.algorithm == algorithm).firstOrNull;

  /// The key pair from [seed]: ML-KEM's `d || z`, ML-DSA's xi.
  ({Uint8List publicKey, Uint8List secretKey}) keygen(Uint8List seed) => switch (this) {
    mlKem768 => MlKem768.keygen(seed),
    mlKem1024 => MlKem1024.keygen(seed),
    mlDsa65 => MlDsa65.keygen(seed),
  };
}

/// The NIST curves of ECDSA keys the vault knows.
enum EcCurve {
  p256('1.2.840.10045.3.1.7', 'nistp256', 32, KeyAlgorithm.ecdsaP256),
  p384('1.3.132.0.34', 'nistp384', 48, KeyAlgorithm.ecdsaP384);

  const EcCurve(this.oid, this.sshName, this.size, this.algorithm);

  final String oid;

  /// The curve's name in OpenSSH key types: `ecdsa-sha2-<sshName>`.
  final String sshName;

  /// Bytes in a scalar or a coordinate.
  final int size;

  final KeyAlgorithm algorithm;

  pc.ECDomainParameters get domain => switch (this) {
    p256 => pc.ECCurve_secp256r1(),
    p384 => pc.ECCurve_secp384r1(),
  };

  static EcCurve? byOid(String oid) => values.where((c) => c.oid == oid).firstOrNull;

  static EcCurve? bySshName(String name) => values.where((c) => c.sshName == name).firstOrNull;
}

// ─── Public halves ────────────────────────────────────────────────────────────

/// The public half of a key, as SPKI and the SSH wire format carry it.
sealed class PublicHalf {
  const PublicHalf();

  KeyAlgorithm get algorithm;
}

final class RsaPublicHalf extends PublicHalf {
  const RsaPublicHalf(this.n, this.e);

  final BigInt n;
  final BigInt e;

  @override
  KeyAlgorithm get algorithm => KeyAlgorithm.rsa;
}

final class EcPublicHalf extends PublicHalf {
  const EcPublicHalf(this.curve, this.point);

  final EcCurve curve;

  /// Uncompressed: `04 || x || y`.
  final Uint8List point;

  @override
  KeyAlgorithm get algorithm => curve.algorithm;
}

/// A public key that is a byte string in both SPKI and SSH: Ed25519 and
/// X25519.
final class RawPublicHalf extends PublicHalf {
  const RawPublicHalf(this.algorithm, this.bytes);

  @override
  final KeyAlgorithm algorithm;

  final Uint8List bytes;
}

// ─── Private halves ───────────────────────────────────────────────────────────

/// A private key's parts, whichever format it came in.
sealed class KeyMaterial {
  const KeyMaterial();

  /// Null for an algorithm the vault doesn't know.
  PublicHalf? get publicHalf;
}

final class RsaMaterial extends KeyMaterial {
  const RsaMaterial({
    required this.n,
    required this.e,
    required this.d,
    required this.p,
    required this.q,
    required this.dp,
    required this.dq,
    required this.qinv,
  });

  /// The parts from n, e, d, p and q, with the CRT values worked out.
  /// Throws [KeyProblem.damaged] unless they belong together.
  factory RsaMaterial.fromPrimes({required BigInt n, required BigInt e, required BigInt d, required BigInt p, required BigInt q}) {
    _checkRsa(n, e, d, p, q);
    return RsaMaterial(n: n, e: e, d: d, p: p, q: q, dp: d % (p - BigInt.one), dq: d % (q - BigInt.one), qinv: q.modInverse(p));
  }

  final BigInt n, e, d, p, q, dp, dq, qinv;

  int get bits => n.bitLength;

  @override
  RsaPublicHalf get publicHalf => RsaPublicHalf(n, e);
}

/// The largest RSA modulus read, in bits. Real keys stop at 16384; a file
/// with bigger numbers would only make the checks below run for minutes.
const maxRsaBits = 16384;

/// The smallest RSA modulus, in bits, whose signatures are taken as worth
/// anything, PGP's and SSH's alike: a smaller one can be factored, by
/// whoever spends enough on it, and its factors sign anything. 2048 is
/// where NIST has drawn the line since 2014 (SP 800-131A); RSA-829 is
/// factored, a 1024-bit modulus is within reach of a state, and ssh-keygen's
/// own floor of 1024 leaves that one in. A signature by a smaller key is
/// called weak, never good.
const minRsaSignatureBits = 2048;

/// Throws [KeyProblem.damaged] unless n = p * q, e is an odd number above
/// one, and d undoes e; [KeyProblem.unsupportedKeyType] for a modulus over
/// [maxRsaBits].
void _checkRsa(BigInt n, BigInt e, BigInt d, BigInt p, BigInt q) {
  if (n.bitLength > maxRsaBits) throw KeyFormatException(KeyProblem.unsupportedKeyType, 'RSA ${n.bitLength}');
  check(e.bitLength <= n.bitLength && d.bitLength <= n.bitLength && p.bitLength <= n.bitLength && q.bitLength <= n.bitLength, 'RSA: sizes');
  check(p > BigInt.one && q > BigInt.one && p.gcd(q) == BigInt.one && p * q == n, 'RSA: n is not p * q');
  check(e > BigInt.one && e.isOdd && d > BigInt.zero && d < n, 'RSA: exponent out of range');
  // e * d = 1 modulo p - 1 and q - 1, so decryption undoes encryption.
  check((e * d) % (p - BigInt.one) == BigInt.one && (e * d) % (q - BigInt.one) == BigInt.one, 'RSA: d does not match e');
}

/// Checks RSA parts read whole from a file (PKCS#1 carries the CRT values
/// too): throws [KeyProblem.damaged] unless they belong together.
RsaMaterial checkedRsa(RsaMaterial m) {
  _checkRsa(m.n, m.e, m.d, m.p, m.q);
  check(m.dp == m.d % (m.p - BigInt.one) && m.dq == m.d % (m.q - BigInt.one) && (m.qinv * m.q) % m.p == BigInt.one, 'RSA: CRT values');
  return m;
}

final class EcMaterial extends KeyMaterial {
  const EcMaterial(this.curve, this.d, this.point);

  final EcCurve curve;

  /// The private scalar, [EcCurve.size] bytes.
  final Uint8List d;

  /// The public point, uncompressed.
  final Uint8List point;

  @override
  EcPublicHalf get publicHalf => EcPublicHalf(curve, point);
}

final class Ed25519Material extends KeyMaterial {
  const Ed25519Material(this.seed, this.publicKey);

  /// The 32-byte private key of RFC 8032.
  final Uint8List seed;
  final Uint8List publicKey;

  @override
  RawPublicHalf get publicHalf => RawPublicHalf(KeyAlgorithm.ed25519, publicKey);
}

final class X25519Material extends KeyMaterial {
  const X25519Material(this.privateKey, this.publicKey);

  /// The 32-byte scalar of RFC 7748, as stored (not clamped).
  final Uint8List privateKey;
  final Uint8List publicKey;

  @override
  RawPublicHalf get publicHalf => RawPublicHalf(KeyAlgorithm.x25519, publicKey);
}

/// An ML-KEM or ML-DSA key: its seed when the file had it, and always the
/// expanded private key and the public key, worked out from the seed when
/// the file had only that.
final class PqMaterial extends KeyMaterial {
  const PqMaterial(this.parameters, this.seed, this.expanded, this.publicKey);

  final PqParameters parameters;
  final Uint8List? seed;
  final Uint8List expanded;
  final Uint8List publicKey;

  @override
  RawPublicHalf get publicHalf => RawPublicHalf(parameters.algorithm, publicKey);
}

/// A PKCS#8 key of an algorithm the vault doesn't know.
final class OtherMaterial extends KeyMaterial {
  const OtherMaterial(this.oid);

  /// The algorithm's identifier, dotted; for an EC key on another curve,
  /// the curve's.
  final String oid;

  @override
  PublicHalf? get publicHalf => null;
}

// ─── Arithmetic ───────────────────────────────────────────────────────────────

/// The EC key with scalar [d] (big-endian, any length up to the curve's)
/// and, when the file carried it, its public [point]. Throws
/// [KeyProblem.damaged] for a scalar out of range or a point that isn't
/// d * G.
EcMaterial ecMaterial(EcCurve curve, Uint8List d, [Uint8List? point]) {
  final domain = curve.domain;
  final scalar = bytesToBigInt(d);
  check(scalar > BigInt.zero && scalar < domain.n, 'EC: scalar out of range');
  final derived = (domain.G * scalar)!;
  final uncompressed = derived.getEncoded(false);
  if (point != null) {
    final compressed = point.isNotEmpty && point[0] != 4;
    check(_equal(point, compressed ? derived.getEncoded() : uncompressed), 'EC: public point does not match');
  }
  return EcMaterial(curve, bigIntToBytes(scalar, curve.size), uncompressed);
}

/// The Ed25519 key with the 32-byte [seed]. When the file carried a public
/// key, [publicKey], it must be the one the seed gives.
Future<Ed25519Material> ed25519Material(Uint8List seed, [Uint8List? publicKey]) async {
  check(seed.length == 32, 'Ed25519: seed length');
  final pair = await c.Ed25519().newKeyPairFromSeed(seed);
  final derived = Uint8List.fromList((await pair.extractPublicKey()).bytes);
  check(publicKey == null || _equal(publicKey, derived), 'Ed25519: public key does not match');
  return Ed25519Material(Uint8List.fromList(seed), derived);
}

/// The X25519 key with the 32-byte [privateKey], checked against
/// [publicKey] when the file carried one.
Future<X25519Material> x25519Material(Uint8List privateKey, [Uint8List? publicKey]) async {
  check(privateKey.length == 32, 'X25519: key length');
  final pair = await c.X25519().newKeyPairFromSeed(privateKey);
  final derived = Uint8List.fromList((await pair.extractPublicKey()).bytes);
  check(publicKey == null || _equal(publicKey, derived), 'X25519: public key does not match');
  return X25519Material(Uint8List.fromList(privateKey), derived);
}

/// The ML-KEM or ML-DSA key with [seed], [expanded] private key, or both,
/// and [publicKey] when the file carried one. Throws [KeyProblem.damaged]
/// for a length that isn't the algorithm's, an expanded key that isn't the
/// one the seed gives, or one that fails its own checks (ML-KEM's hash of
/// the public key, ML-DSA's t0 and tr).
PqMaterial pqMaterial(PqParameters parameters, {Uint8List? seed, Uint8List? expanded, Uint8List? publicKey}) {
  check(seed != null || expanded != null, 'PQ: no key');
  check(seed == null || seed.length == parameters.seedLength, 'PQ: seed length');
  check(expanded == null || expanded.length == parameters.expandedLength, 'PQ: expanded key length');
  final Uint8List secret;
  final Uint8List public;
  if (seed != null) {
    final pair = parameters.keygen(seed);
    check(expanded == null || _equal(expanded, pair.secretKey), 'PQ: seed and expanded key differ');
    (secret, public) = (pair.secretKey, pair.publicKey);
  } else {
    secret = Uint8List.fromList(expanded!);
    public = _publicFromExpanded(parameters, secret);
  }
  check(publicKey == null || _equal(publicKey, public), 'PQ: public key does not match');
  return PqMaterial(parameters, seed == null ? null : Uint8List.fromList(seed), secret, public);
}

Uint8List _publicFromExpanded(PqParameters parameters, Uint8List expanded) {
  try {
    switch (parameters) {
      case PqParameters.mlDsa65:
        return MlDsa65.publicKeyOf(expanded);
      case PqParameters.mlKem768 || PqParameters.mlKem1024:
        // dk = dk_PKE || ek || H(ek) || z, with dk_PKE 384 * k bytes.
        final pkeLength = parameters.expandedLength - parameters.publicKeyLength - 64;
        final ek = Uint8List.fromList(Uint8List.sublistView(expanded, pkeLength, pkeLength + parameters.publicKeyLength));
        // Decapsulating checks H(ek); encapsulating checks ek's coefficients.
        final cipherText = parameters == PqParameters.mlKem768
            ? MlKem768.encapsulate(ek, Uint8List(32)).cipherText
            : MlKem1024.encapsulate(ek, Uint8List(32)).cipherText;
        parameters == PqParameters.mlKem768 ? MlKem768.decapsulate(cipherText, expanded) : MlKem1024.decapsulate(cipherText, expanded);
        return ek;
    }
  } on ArgumentError catch (e) {
    throw KeyFormatException(KeyProblem.damaged, 'PQ: ${e.message}');
  }
}

// ─── Signatures ───────────────────────────────────────────────────────────────

/// An ECDSA signature of [message] by [key], hashed with the curve's hash
/// (SHA-256 for P-256, SHA-384 for P-384). The nonce is the deterministic
/// one of RFC 6979, so the same key and message always give the same
/// signature and no random source is used.
({BigInt r, BigInt s}) ecdsaSign(EcMaterial key, List<int> message) {
  final signer = _ecdsaSigner(key.curve, deterministic: true)
    ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(pc.ECPrivateKey(bytesToBigInt(key.d), key.curve.domain)));
  final signature = signer.generateSignature(Uint8List.fromList(message)) as pc.ECSignature;
  return (r: signature.r, s: signature.s);
}

/// Whether ([r], [s]) is [key]'s ECDSA signature of [message], hashed with
/// the curve's hash. False, never an error, for an `r` or `s` outside 1 to
/// n - 1 and for a public point that is not on the curve.
bool ecdsaVerify(EcPublicHalf key, List<int> message, BigInt r, BigInt s) => _ecdsaCheck(key, message, r, s, hashed: false);

/// Whether ([r], [s]) is [key]'s ECDSA signature of [digest], a hash made
/// already with whatever hash the signature names, as OpenPGP signs one:
/// it is cut to the curve's size as ECDSA cuts it. False as for
/// [ecdsaVerify].
bool ecdsaVerifyDigest(EcPublicHalf key, List<int> digest, BigInt r, BigInt s) => _ecdsaCheck(key, digest, r, s, hashed: true);

bool _ecdsaCheck(EcPublicHalf key, List<int> message, BigInt r, BigInt s, {required bool hashed}) {
  final domain = key.curve.domain;
  if (r < BigInt.one || r >= domain.n || s < BigInt.one || s >= domain.n) return false;
  final point = key.point;
  if (point.length != 1 + 2 * key.curve.size || point[0] != 4) return false;
  final pc.ECPoint q;
  try {
    q = domain.curve.decodePoint(point)!;
  } on Object {
    return false;
  }
  // The curves' cofactor is one, so a point on the curve is in the group.
  final x = q.x, y = q.y;
  if (q.isInfinity || x == null || y == null || y * y != x * x * x + domain.curve.a! * x + domain.curve.b!) return false;
  final signer = (hashed ? pc.ECDSASigner() : _ecdsaSigner(key.curve, deterministic: false))
    ..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(q, domain)));
  return signer.verifySignature(Uint8List.fromList(message), pc.ECSignature(r, s));
}

/// The point [encoded] holds, uncompressed (0x04, x, y), when it is a point
/// of [domain]'s curve other than infinity; null for anything else.
///
/// pointycastle's `decodePoint` builds a point from any x and y, and never
/// asks whether it is on the curve. Multiplying a private scalar with a
/// point from outside that is on another curve, where it has a small order,
/// gives the scalar away a few bits at a time to whoever sees whether the
/// result opened something. The curves here have cofactor one, so a point on
/// the curve is in the group.
pc.ECPoint? pointOnCurve(pc.ECDomainParameters domain, Uint8List encoded) {
  final size = (domain.curve.fieldSize + 7) ~/ 8;
  if (encoded.length != 1 + 2 * size || encoded[0] != 4) return null;
  final pc.ECPoint? q;
  try {
    q = domain.curve.decodePoint(encoded);
  } on Object {
    return null;
  }
  final x = q?.x, y = q?.y;
  if (q == null || q.isInfinity || x == null || y == null) return null;
  if (y * y != x * x * x + domain.curve.a! * x + domain.curve.b!) return null;
  return q;
}

pc.ECDSASigner _ecdsaSigner(EcCurve curve, {required bool deterministic}) {
  // HMAC's block length is the hash's: 64 bytes for SHA-256, 128 for SHA-384.
  final (digest, mac) = switch (curve) {
    EcCurve.p256 => (pc.SHA256Digest() as pc.Digest, pc.HMac(pc.SHA256Digest(), 64)),
    EcCurve.p384 => (pc.SHA384Digest() as pc.Digest, pc.HMac(pc.SHA384Digest(), 128)),
  };
  return pc.ECDSASigner(digest, deterministic ? mac : null);
}

const oidSha256 = '2.16.840.1.101.3.4.2.1';
const oidSha512 = '2.16.840.1.101.3.4.2.3';

/// EMSA-PKCS1-v1_5 (RFC 8017 section 9.2) of a [digest] made with the hash
/// [hashOid] names, [length] bytes long: 00 01 ff ... ff 00, then the
/// DigestInfo. Throws [KeyProblem.damaged] when it does not fit [length].
Uint8List emsaPkcs1(String hashOid, List<int> digest, int length) {
  final info = derSequence([
    derSequence([derOid(hashOid), derNull()]),
    derOctetString(digest),
  ]);
  check(length >= info.length + 11, 'RSA: key too small');
  return Uint8List(length)
    ..[1] = 1
    ..fillRange(2, length - info.length - 1, 0xff)
    ..setAll(length - info.length, info);
}

/// An RSA PKCS#1 v1.5 signature by [key] of a [digest] made with the hash
/// [hashOid] names, worked out with the key's CRT values.
BigInt rsaSignPkcs1(RsaMaterial key, String hashOid, List<int> digest) {
  final m = bytesToBigInt(emsaPkcs1(hashOid, digest, (key.n.bitLength + 7) >> 3));
  final s1 = m.modPow(key.dp, key.p);
  final s2 = m.modPow(key.dq, key.q);
  final h = (key.qinv * (s1 - s2)) % key.p;
  return s2 + h * key.q;
}

/// Whether [signature] is [key]'s RSA PKCS#1 v1.5 signature of a [digest]
/// made with the hash [hashOid] names. False for a modulus over
/// [maxRsaBits], an exponent no real key has, or a signature not below
/// the modulus: such numbers would only make the check slow.
bool rsaVerifyPkcs1(RsaPublicHalf key, String hashOid, List<int> digest, BigInt signature) {
  final n = key.n, e = key.e;
  if (n.bitLength > maxRsaBits || e.bitLength > 64 || e < BigInt.two || signature < BigInt.zero || signature >= n) return false;
  final Uint8List expected;
  try {
    expected = emsaPkcs1(hashOid, digest, (n.bitLength + 7) >> 3);
  } on KeyFormatException {
    return false;
  }
  return _equal(bigIntToBytes(signature.modPow(e, n), expected.length), expected);
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// An RSA key of [bits] with e = 65537, from pointycastle's generator fed
/// by a Fortuna generator seeded from the platform's random source.
RsaMaterial generateRsa(int bits) {
  final random = pc.FortunaRandom()..seed(pc.KeyParameter(randomBytes(32)));
  final generator = pc.RSAKeyGenerator()..init(pc.ParametersWithRandom(pc.RSAKeyGeneratorParameters(BigInt.from(65537), bits, 64), random));
  final pair = generator.generateKeyPair();
  final key = pair.privateKey;
  return RsaMaterial.fromPrimes(n: key.n!, e: key.publicExponent!, d: key.privateExponent!, p: key.p!, q: key.q!);
}
