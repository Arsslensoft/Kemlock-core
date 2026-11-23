/// The P-256 key pairs passkeys and the passkey inbox use: making one,
/// reading and writing it as PKCS#8, key agreement, and ES256 signatures.
/// The iOS extension and the Android provider do the same with their
/// platforms' own P-256, and the fixtures in test/fixtures/passkeys hold
/// all three to the same bytes.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'keys/algorithms.dart';
import 'keys/der.dart';
import 'keys/pkcs8.dart';

/// A P-256 key pair: the 32-byte private scalar [d] and the public [point],
/// 65 bytes uncompressed (X9.63: 0x04, x, y).
class P256KeyPair {
  const P256KeyPair(this.d, this.point);

  /// The pair with scalar [d], its point worked out.
  factory P256KeyPair.fromScalar(Uint8List d) {
    final material = ecMaterial(EcCurve.p256, d);
    return P256KeyPair(material.d, material.point);
  }

  final Uint8List d;
  final Uint8List point;

  /// The public point's x and y, 32 bytes each, as COSE keys hold them.
  Uint8List get x => Uint8List.sublistView(point, 1, 33);
  Uint8List get y => Uint8List.sublistView(point, 33, 65);

  /// PKCS#8 DER, as `openssl pkey` writes it, with the public point.
  Uint8List toPkcs8() => writePkcs8(EcMaterial(EcCurve.p256, d, point));

  /// The pair a PKCS#8 file holds; throws `KeyFormatException` for anything
  /// but a P-256 key.
  static Future<P256KeyPair> fromPkcs8(Uint8List der) async {
    final material = await readPkcs8(der);
    if (material is! EcMaterial || material.curve != EcCurve.p256) throw ArgumentError('not a P-256 key');
    return P256KeyPair(material.d, material.point);
  }
}

final _random = Random.secure();

/// A new P-256 key pair, from the platform's secure random source.
P256KeyPair newP256KeyPair() {
  final n = EcCurve.p256.domain.n;
  while (true) {
    final d = Uint8List.fromList([for (var i = 0; i < 32; i++) _random.nextInt(256)]);
    final scalar = bytesToBigInt(d);
    if (scalar > BigInt.zero && scalar < n) return P256KeyPair.fromScalar(d);
  }
}

/// [point] as a point of P-256, uncompressed. Anything else throws: the
/// passkey inbox's files come from outside the vault, and their point is
/// multiplied with the inbox's long-lived private key ([pointOnCurve]).
pc.ECPoint _point(Uint8List point) => pointOnCurve(EcCurve.p256.domain, point) ?? (throw ArgumentError('not a P-256 point'));

/// The ECDH shared secret of [d] and [peerPoint]: the x coordinate, 32
/// bytes, as CryptoKit and Java's `KeyAgreement` give it.
Uint8List p256SharedSecret(Uint8List d, Uint8List peerPoint) {
  final shared = (_point(peerPoint) * bytesToBigInt(d))!;
  if (shared.isInfinity) throw ArgumentError('no shared secret');
  return bigIntToBytes(shared.x!.toBigInteger()!, 32);
}

/// An ES256 signature of [message] by [key]: ECDSA over SHA-256, DER
/// encoded as WebAuthn wants it, and deterministic (RFC 6979), so the
/// fixtures can hold one.
Uint8List es256Sign(P256KeyPair key, Uint8List message) {
  final domain = EcCurve.p256.domain;
  final signer = pc.Signer('SHA-256/DET-ECDSA')
    ..init(true, pc.PrivateKeyParameter<pc.ECPrivateKey>(pc.ECPrivateKey(bytesToBigInt(key.d), domain)));
  final signature = signer.generateSignature(message) as pc.ECSignature;
  // Low-s, as the platforms' verifiers prefer
  final s = signature.s > domain.n >> 1 ? domain.n - signature.s : signature.s;
  return derSequence([derInteger(signature.r), derInteger(s)]);
}

/// Whether [signature], DER, is an ES256 signature of [message] by the key at [point].
bool es256Verify(Uint8List point, Uint8List message, Uint8List signature) {
  try {
    final r = readSequence(signature);
    final sr = r.integer();
    final ss = r.integer();
    r.done();
    final domain = EcCurve.p256.domain;
    final verifier = pc.Signer('SHA-256/ECDSA')..init(false, pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(_point(point), domain)));
    return verifier.verifySignature(message, pc.ECSignature(sr, ss));
  } catch (_) {
    return false;
  }
}
