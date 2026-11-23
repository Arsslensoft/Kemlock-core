@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:test/test.dart';

/// `m' = "kemlock/v1/sig1" || lp(context) || lp(message)`, built here from
/// crypto.md rather than by the code under test.
Uint8List _signed(String context, List<int> message) => Uint8List.fromList([
  ...utf8.encode('kemlock/v1/sig1'),
  ...u32be(context.length),
  ...utf8.encode(context),
  ...u32be(message.length),
  ...message,
]);

void main() {
  final privateKey = Uint8List.fromList(List.generate(64, (i) => (i * 5 + 1) & 0xff));
  final message = utf8.encode('the bundle');
  final randomness = Uint8List(32);
  late Uint8List publicKey;
  late Uint8List signature;

  setUpAll(() async {
    publicKey = await Sig1.publicKeyOf(privateKey);
    signature = await Sig1.sign(privateKey, message, context: SignContext.bundle, randomness: randomness);
  });

  test('has the sizes crypto.md gives', () {
    expect(publicKey, hasLength(1984));
    expect(signature, hasLength(3373));
  });

  test('the public key is the ML-DSA-65 key of the seed, then the Ed25519 public key', () async {
    expect(publicKey.sublist(0, 1952), MlDsa65.keygen(privateKey.sublist(0, 32)).publicKey);
    final pair = await c.Ed25519().newKeyPairFromSeed(privateKey.sublist(32));
    expect(publicKey.sublist(1952), (await pair.extractPublicKey()).bytes);
  });

  test('each half signs m-prime: ML-DSA with an empty context, then Ed25519', () async {
    final signed = _signed('bundle', message);
    final mlDsa = MlDsa65.keygen(privateKey.sublist(0, 32));
    expect(signature.sublist(0, 3309), MlDsa65.sign(mlDsa.secretKey, signed, randomness: randomness));
    expect(MlDsa65.verify(mlDsa.publicKey, signed, signature.sublist(0, 3309)), isTrue);
    final ed = c.Ed25519();
    final pair = await ed.newKeyPairFromSeed(privateKey.sublist(32));
    expect(signature.sublist(3309), (await ed.sign(signed, keyPair: pair)).bytes);
  });

  test('verifies, and verifies a hedged signature too', () async {
    expect(await Sig1.verify(publicKey, message, signature, context: SignContext.bundle), isTrue);
    final hedged = await Sig1.sign(privateKey, message, context: SignContext.bundle);
    expect(hedged, isNot(signature));
    expect(await Sig1.verify(publicKey, message, hedged, context: SignContext.bundle), isTrue);
  });

  test('a signature made under "manifest" does not verify as "bundle"', () async {
    final manifest = await Sig1.sign(privateKey, message, context: SignContext.manifest, randomness: randomness);
    expect(await Sig1.verify(publicKey, message, manifest, context: SignContext.manifest), isTrue);
    expect(await Sig1.verify(publicKey, message, manifest, context: SignContext.bundle), isFalse);
    expect(await Sig1.verify(publicKey, message, signature, context: SignContext.manifest), isFalse);
  });

  test('another message, or another key, does not verify', () async {
    expect(await Sig1.verify(publicKey, utf8.encode('another bundle'), signature, context: SignContext.bundle), isFalse);
    final otherKey = Uint8List.fromList(privateKey)..[0] ^= 1;
    expect(await Sig1.verify(await Sig1.publicKeyOf(otherKey), message, signature, context: SignContext.bundle), isFalse);
  });

  test('a signature with only one valid half does not verify', () async {
    final other = await Sig1.sign(privateKey, utf8.encode('another message'), context: SignContext.bundle, randomness: randomness);
    // ML-DSA half of this signature with the Ed25519 half of another
    final mlDsaOnly = Uint8List.fromList([...signature.sublist(0, 3309), ...other.sublist(3309)]);
    // Ed25519 half of this signature with the ML-DSA half of another
    final edOnly = Uint8List.fromList([...other.sublist(0, 3309), ...signature.sublist(3309)]);
    expect(await Sig1.verify(publicKey, message, mlDsaOnly, context: SignContext.bundle), isFalse);
    expect(await Sig1.verify(publicKey, message, edOnly, context: SignContext.bundle), isFalse);
    // One flipped byte in either half
    for (final index in [0, 1500, 3308, 3309, 3372]) {
      final changed = Uint8List.fromList(signature)..[index] ^= 1;
      expect(await Sig1.verify(publicKey, message, changed, context: SignContext.bundle), isFalse, reason: 'byte $index');
    }
  });

  test('refuses keys and signatures of the wrong length', () async {
    await expectLater(Sig1.verify(Uint8List(1983), message, signature, context: 'bundle'), throwsA(isA<MalformedException>()));
    await expectLater(Sig1.verify(publicKey, message, Uint8List(3372), context: 'bundle'), throwsA(isA<MalformedException>()));
    await expectLater(Sig1.sign(Uint8List(63), message, context: 'bundle'), throwsA(isA<MalformedException>()));
    await expectLater(Sig1.generate(Uint8List(32)), throwsA(isA<MalformedException>()));
  });
}
