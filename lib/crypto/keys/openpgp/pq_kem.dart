// The two post-quantum key agreements of OpenPGP: the key that wraps a
// message's session key, from an ML-KEM shared secret and an ECDH one.
//
// - RFC 9980 section 4.2, ML-KEM-768+X25519 (algorithm 35): X25519 and
//   ML-KEM-768 each give a key share, and the key-wrapping key is
//   SHA3-256(mlkemKeyShare || ecdhKeyShare || ecdhCipherText ||
//   ecdhPublicKey || algId || "OpenPGPCompositeKDFv1" || 21).
// - LibrePGP's Kyber (algorithm 8), as GnuPG 2.5 does it (g10/pkglue.c and
//   common/kem.c): the ECDH share is first hashed with SHA3-256 (SHA3-512
//   for brainpoolP384r1) over the raw ECDH result, the ephemeral key and
//   the recipient's key, and the key-wrapping key is
//   KMAC256("OpenPGPCompositeKeyDerivationFunction", 00000001 ||
//   eccKeyShare || eccCipherText || mlkemKeyShare || mlkemCipherText ||
//   cipher || fingerprint, 256, "KDF"). X25519 is used as is; the two
//   brainpool curves give their uncompressed shared point.
//
// Decapsulation runs both halves whatever happens and gives a key; a
// wrong half only shows when the AES key wrap's check fails, and every
// failure is the same [PgpProblem.damaged] (design decision 4).

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../../bytes.dart';
import '../../keccak.dart';
import '../../ml_kem.dart';
import '../algorithms.dart' show pointOnCurve;
import '../der.dart';
import 'ecdh.dart';
import 'key_info.dart';
import 'pgp_error.dart';
import 'stream.dart';

const _failed = PgpException(PgpProblem.damaged, detail: 'session key');

/// What an encapsulation gives: the key that wraps the session key, and
/// the two ciphertexts the recipient needs to make it again.
typedef PqEncapsulation = ({Uint8List kek, Uint8List eccCipherText, Uint8List mlKemCipherText});

// ─── RFC 9980: ML-KEM-768+X25519 ──────────────────────────────────────────────

/// The domain separation of RFC 9980's combiner, then its length.
final _compositeDomain = [...'OpenPGPCompositeKDFv1'.codeUnits, 21];

/// RFC 9980's multiKeyCombine for algorithm [algorithm] (35).
Uint8List mlKemX25519Combine({
  required Uint8List mlKemKeyShare,
  required Uint8List ecdhKeyShare,
  required Uint8List ecdhCipherText,
  required Uint8List ecdhPublicKey,
  int algorithm = 35,
}) => sha3_256([...mlKemKeyShare, ...ecdhKeyShare, ...ecdhCipherText, ...ecdhPublicKey, algorithm, ..._compositeDomain]);

/// Encapsulates to the ML-KEM-768+X25519 public key [public] (32 bytes of
/// X25519, then 1184 of ML-KEM-768). [ephemeralSecret] (32 bytes) and
/// [mlKemMessage] (32) stand in for fresh random bytes, for known answers.
Future<PqEncapsulation> mlKemX25519Encapsulate(Uint8List public, {Uint8List? ephemeralSecret, Uint8List? mlKemMessage}) async {
  pgpCheck(public.length == 32 + MlKem768.publicKeyLength, 'ML-KEM-768+X25519: public key length');
  final x25519 = Uint8List.sublistView(public, 0, 32);
  final secret = ephemeralSecret ?? randomBytes(32);
  final ephemeral = await x25519Public(secret);
  final ecdh = await x25519Shared(secret, x25519);
  final mlKem = asPgpError(() => MlKem768.encapsulate(Uint8List.sublistView(public, 32), mlKemMessage));
  final kek = mlKemX25519Combine(mlKemKeyShare: mlKem.sharedSecret, ecdhKeyShare: ecdh, ecdhCipherText: ephemeral, ecdhPublicKey: x25519);
  return (kek: kek, eccCipherText: ephemeral, mlKemCipherText: mlKem.cipherText);
}

/// The key-wrapping key for the ciphertexts [ephemeral] (32 bytes) and
/// [mlKemCipherText] (1088) sent to the ML-KEM-768+X25519 key whose public
/// key is [public] and whose secrets are [x25519Secret] and the expanded
/// [mlKemSecretKey]. Both halves always run; a ciphertext of the wrong
/// size or a point of small order throws the same [PgpProblem.damaged] a
/// wrong key gives when the key wrap is checked.
Future<Uint8List> mlKemX25519Decapsulate({
  required Uint8List public,
  required Uint8List x25519Secret,
  required Uint8List mlKemSecretKey,
  required Uint8List ephemeral,
  required Uint8List mlKemCipherText,
}) async {
  if (public.length != 32 + MlKem768.publicKeyLength || ephemeral.length != 32 || mlKemCipherText.length != MlKem768.cipherTextLength) {
    throw _failed;
  }
  final mlKem = MlKem768.decapsulate(mlKemCipherText, mlKemSecretKey);
  final Uint8List ecdh;
  try {
    ecdh = await x25519Shared(x25519Secret, ephemeral);
  } on PgpException {
    throw _failed;
  }
  return mlKemX25519Combine(
    mlKemKeyShare: mlKem,
    ecdhKeyShare: ecdh,
    ecdhCipherText: ephemeral,
    ecdhPublicKey: Uint8List.sublistView(public, 0, 32),
  );
}

// ─── LibrePGP: Kyber ──────────────────────────────────────────────────────────

/// The curves of the Kyber keys used here, by the name `key_info.dart`
/// gives the key.
enum KyberCurve {
  x25519(32),
  brainpoolP256r1(65),
  brainpoolP384r1(97);

  const KyberCurve(this.pointLength);

  /// The length of a point: 32 for X25519 (without its 0x40), 65 and 97
  /// for the brainpool curves, uncompressed.
  final int pointLength;

  /// The curve of a Kyber key named [name], or null for one not used.
  static KyberCurve? ofKey(String name) => switch (name) {
    'ky768_cv25519' => x25519,
    'ky768_bp256' => brainpoolP256r1,
    'ky1024_bp384' => brainpoolP384r1,
    _ => null,
  };

  pc.ECDomainParameters get _domain => pc.ECDomainParameters(this == brainpoolP256r1 ? 'brainpoolp256r1' : 'brainpoolp384r1');
}

/// The public parts of a Kyber subkey: its curve, its ECC point (without
/// X25519's 0x40) and its ML-KEM key.
class KyberPublic {
  const KyberPublic._(this.curve, this.point, this.mlKem);

  /// Reads the public material of the Kyber key packet [key]. Throws
  /// [PgpProblem.unsupported] naming the key for a pairing not used.
  factory KyberPublic.of(KeyPacket key) {
    final curve = KyberCurve.ofKey(key.name);
    if (key.algorithm != 8 || curve == null) throw PgpException(PgpProblem.unsupported, detail: key.name);
    final r = PgpReader.bytes(key.publicMaterial);
    r.bytes(r.byte()); // the curve's OID
    var point = r.bytes((r.uint16() + 7) >> 3);
    if (curve == KyberCurve.x25519) {
      pgpCheck(point.length == 33 && point[0] == 0x40, 'Kyber: X25519 point');
      point = Uint8List.sublistView(point, 1);
    }
    pgpCheck(point.length == curve.pointLength, 'Kyber: point length');
    return KyberPublic._(curve, point, r.bytes(r.uint32()));
  }

  final KyberCurve curve;
  final Uint8List point;
  final Uint8List mlKem;
}

/// LibrePGP's KMAC key combiner: the key that wraps the session key of
/// [cipher] for the Kyber subkey with [fingerprint] (its 32-byte version 5
/// fingerprint).
Uint8List kyberCombine({
  required Uint8List eccKeyShare,
  required Uint8List eccCipherText,
  required Uint8List mlKemKeyShare,
  required Uint8List mlKemCipherText,
  required int cipher,
  required Uint8List fingerprint,
}) => kmac256(
  'OpenPGPCompositeKeyDerivationFunction'.codeUnits,
  [0, 0, 0, 1, ...eccKeyShare, ...eccCipherText, ...mlKemKeyShare, ...mlKemCipherText, cipher, ...fingerprint],
  32,
  customization: 'KDF'.codeUnits,
);

/// GnuPG's ECC key share: a SHA-3 hash of the raw ECDH result, the
/// ephemeral key and the recipient's key.
Uint8List _eccKeyShare(KyberCurve curve, Uint8List ecdh, Uint8List ephemeral, Uint8List recipient) {
  final input = [...ecdh, ...ephemeral, ...recipient];
  return curve == KyberCurve.brainpoolP384r1 ? sha3_512(input) : sha3_256(input);
}

/// The ECDH of [curve]: the shared secret of the [secret] scalar and the
/// [point], as GnuPG's raw KEM gives it.
Future<Uint8List> _ecdh(KyberCurve curve, Uint8List secret, Uint8List point) async {
  if (curve == KyberCurve.x25519) {
    try {
      return await x25519Shared(secret, point);
    } on PgpException {
      throw _failed;
    }
  }
  // A sender's point that is not on the curve must not meet the key's scalar
  final q = pointOnCurve(curve._domain, point);
  final shared = q == null ? null : q * bytesToBigInt(secret);
  if (shared == null || shared.isInfinity) throw _failed;
  return shared.getEncoded(false);
}

/// Encapsulates to a Kyber subkey of [curve]: [eccPublic] its ECC point
/// (32 bytes of X25519 without the 0x40, or an uncompressed brainpool
/// point), [mlKemPublic] its ML-KEM key, for a session key of [cipher]
/// under [fingerprint]. [ephemeralSecret] and [mlKemMessage] stand in for
/// fresh random bytes.
Future<PqEncapsulation> kyberEncapsulate({
  required KyberCurve curve,
  required Uint8List eccPublic,
  required Uint8List mlKemPublic,
  required int cipher,
  required Uint8List fingerprint,
  Uint8List? ephemeralSecret,
  Uint8List? mlKemMessage,
}) async {
  pgpCheck(eccPublic.length == curve.pointLength, 'Kyber: point length');
  final Uint8List ephemeral;
  final Uint8List ecdh;
  if (curve == KyberCurve.x25519) {
    final secret = ephemeralSecret ?? randomBytes(32);
    ephemeral = await x25519Public(secret);
    ecdh = await _ecdh(curve, secret, eccPublic);
  } else {
    final domain = curve._domain;
    var k = ephemeralSecret == null ? BigInt.zero : bytesToBigInt(ephemeralSecret);
    while (k <= BigInt.zero || k >= domain.n) {
      k = bytesToBigInt(randomBytes((domain.n.bitLength + 7) ~/ 8));
    }
    ephemeral = (domain.G * k)!.getEncoded(false);
    ecdh = await _ecdh(curve, bigIntToBytes(k), eccPublic);
  }
  final ({Uint8List cipherText, Uint8List sharedSecret}) mlKem;
  switch (mlKemPublic.length) {
    case MlKem768.publicKeyLength:
      mlKem = asPgpError(() => MlKem768.encapsulate(mlKemPublic, mlKemMessage));
    case MlKem1024.publicKeyLength:
      mlKem = asPgpError(() => MlKem1024.encapsulate(mlKemPublic, mlKemMessage));
    default:
      throw const PgpException(PgpProblem.damaged, detail: 'Kyber: ML-KEM key length');
  }
  final kek = kyberCombine(
    eccKeyShare: _eccKeyShare(curve, ecdh, ephemeral, eccPublic),
    eccCipherText: ephemeral,
    mlKemKeyShare: mlKem.sharedSecret,
    mlKemCipherText: mlKem.cipherText,
    cipher: cipher,
    fingerprint: fingerprint,
  );
  return (kek: kek, eccCipherText: ephemeral, mlKemCipherText: mlKem.cipherText);
}

/// The key-wrapping key for [ephemeral] and [mlKemCipherText] sent to the
/// Kyber subkey of [curve] with [fingerprint], whose ECC point is
/// [eccPublic] and whose secrets are [eccSecret] (X25519's in its own byte
/// order, a brainpool scalar big-endian) and the expanded [mlKemSecretKey],
/// for a session key of [cipher]. Fails as [mlKemX25519Decapsulate] does.
Future<Uint8List> kyberDecapsulate({
  required KyberCurve curve,
  required Uint8List eccPublic,
  required Uint8List eccSecret,
  required Uint8List mlKemSecretKey,
  required Uint8List ephemeral,
  required Uint8List mlKemCipherText,
  required int cipher,
  required Uint8List fingerprint,
}) async {
  if (ephemeral.length != curve.pointLength) throw _failed;
  final Uint8List mlKem;
  switch (mlKemSecretKey.length) {
    case MlKem768.secretKeyLength when mlKemCipherText.length == MlKem768.cipherTextLength:
      mlKem = MlKem768.decapsulate(mlKemCipherText, mlKemSecretKey);
    case MlKem1024.secretKeyLength when mlKemCipherText.length == MlKem1024.cipherTextLength:
      mlKem = MlKem1024.decapsulate(mlKemCipherText, mlKemSecretKey);
    default:
      throw _failed;
  }
  final ecdh = await _ecdh(curve, eccSecret, ephemeral);
  return kyberCombine(
    eccKeyShare: _eccKeyShare(curve, ecdh, ephemeral, eccPublic),
    eccCipherText: ephemeral,
    mlKemKeyShare: mlKem,
    mlKemCipherText: mlKemCipherText,
    cipher: cipher,
    fingerprint: fingerprint,
  );
}
