@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keccak.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  final vectors = readVectors('ml_kem_1024.json')! as Map<String, Object?>;
  final keygenVectors = objects(vectors['keygen']);
  final keys = [for (final v in keygenVectors) MlKem1024.keygen(fromHex(v['seed']! as String))];

  group("matches noble's ml_kem1024", () {
    test('keygen from fixed seeds', () {
      for (final (i, v) in keygenVectors.indexed) {
        final (:publicKey, :secretKey) = keys[i];
        expect(publicKey, hasLength(1568));
        expect(secretKey, hasLength(3168));
        if (v.containsKey('publicKey')) {
          expect(b64(publicKey), v['publicKey'], reason: 'seed $i');
          expect(b64(secretKey), v['secretKey'], reason: 'seed $i');
        } else {
          expect(toHex(sha3_256(publicKey)), v['publicKeySha3'], reason: 'seed $i');
          expect(toHex(sha3_256(secretKey)), v['secretKeySha3'], reason: 'seed $i');
        }
      }
    });

    test('encapsulate with fixed messages, and decapsulate back', () {
      for (final v in objects(vectors['encapsulate'])) {
        final key = keys[v['key']! as int];
        final (:cipherText, :sharedSecret) = MlKem1024.encapsulate(key.publicKey, fromHex(v['message']! as String));

        expect(b64(cipherText), v['cipherText']);
        expect(toHex(sharedSecret), v['sharedSecret']);
        expect(toHex(MlKem1024.decapsulate(cipherText, key.secretKey)), v['sharedSecret']);
      }
    });

    test('decapsulate a tampered or foreign ciphertext to the implicit rejection secret', () {
      final encapsulations = objects(vectors['encapsulate']);
      for (final v in objects(vectors['reject'])) {
        final cipherText = unb64(encapsulations[v['encapsulation']! as int]['cipherText']! as String);
        final index = v['index'] as int?;
        if (index != null) cipherText[index] ^= v['mask']! as int;

        final sharedSecret = MlKem1024.decapsulate(cipherText, keys[v['key']! as int].secretKey);

        expect(toHex(sharedSecret), v['sharedSecret'], reason: '$v');
      }
    });

    test('use a key pair from its random keygen', () {
      final v = vectors['randomKey']! as Map<String, Object?>;
      final publicKey = unb64(v['publicKey']! as String);
      final secretKey = unb64(v['secretKey']! as String);

      final (:cipherText, :sharedSecret) = MlKem1024.encapsulate(publicKey, fromHex(v['message']! as String));
      expect(b64(cipherText), v['cipherText']);
      expect(toHex(sharedSecret), v['sharedSecret']);
      expect(toHex(MlKem1024.decapsulate(cipherText, secretKey)), v['sharedSecret']);
      expect(toHex(MlKem1024.decapsulate(unb64(v['randomCipherText']! as String), secretKey)), v['randomSharedSecret']);
    });

    test("reads the public key back out of a secret key, noble's included", () {
      final v = vectors['randomKey']! as Map<String, Object?>;
      expect(b64(MlKem1024.publicKeyOf(unb64(v['secretKey']! as String))), v['publicKey']);
      final (:publicKey, :secretKey) = MlKem1024.keygen();
      expect(MlKem1024.publicKeyOf(secretKey), publicKey);
    });
  });

  test('round-trips with random keys and messages', () {
    final a = MlKem1024.keygen();
    final b = MlKem1024.keygen();
    expect(a.publicKey, isNot(b.publicKey));

    final first = MlKem1024.encapsulate(a.publicKey);
    final second = MlKem1024.encapsulate(a.publicKey);
    expect(first.sharedSecret, hasLength(32));
    expect(first.cipherText, hasLength(1568));
    expect(first.sharedSecret, isNot(second.sharedSecret));
    expect(MlKem1024.decapsulate(first.cipherText, a.secretKey), first.sharedSecret);
    expect(MlKem1024.decapsulate(second.cipherText, a.secretKey), second.sharedSecret);
    // Another key's secret key gets an unrelated secret, not an error.
    expect(MlKem1024.decapsulate(first.cipherText, b.secretKey), isNot(first.sharedSecret));
  });

  group('decapsulateWithMessage', () {
    test("gives the message a ciphertext was made from, noble's vectors included", () {
      for (final v in objects(vectors['encapsulate'])) {
        final key = keys[v['key']! as int];
        final opened = MlKem1024.decapsulateWithMessage(unb64(v['cipherText']! as String), key.secretKey);

        expect(toHex(opened.sharedSecret), v['sharedSecret']);
        expect(toHex(opened.message!), v['message']);
      }
      final (:publicKey, :secretKey) = MlKem1024.keygen();
      final message = randomBytes(32);
      final opened = MlKem1024.decapsulateWithMessage(MlKem1024.encapsulate(publicKey, message).cipherText, secretKey);
      expect(opened.message, message);
    });

    test('gives no message, and the implicit rejection secret, for a ciphertext the key did not make', () {
      final encapsulations = objects(vectors['encapsulate']);
      for (final v in objects(vectors['reject'])) {
        final cipherText = unb64(encapsulations[v['encapsulation']! as int]['cipherText']! as String);
        final index = v['index'] as int?;
        if (index != null) cipherText[index] ^= v['mask']! as int;

        final opened = MlKem1024.decapsulateWithMessage(cipherText, keys[v['key']! as int].secretKey);

        expect(opened.message, isNull, reason: '$v');
        expect(toHex(opened.sharedSecret), v['sharedSecret'], reason: '$v');
      }
    });
  });

  test('leaves the seed, message and keys it is given as they were', () {
    final seed = fromHex(keygenVectors.first['seed']! as String);
    final seedCopy = Uint8List.fromList(seed);
    final (:publicKey, :secretKey) = MlKem1024.keygen(seed);
    final message = Uint8List(32)..fillRange(0, 32, 7);
    final publicKeyCopy = Uint8List.fromList(publicKey);
    final secretKeyCopy = Uint8List.fromList(secretKey);

    final (:cipherText, sharedSecret: _) = MlKem1024.encapsulate(publicKey, message);
    final cipherTextCopy = Uint8List.fromList(cipherText);
    MlKem1024.decapsulate(cipherText, secretKey);

    expect(seed, seedCopy);
    expect(message, List.filled(32, 7));
    expect(publicKey, publicKeyCopy);
    expect(secretKey, secretKeyCopy);
    expect(cipherText, cipherTextCopy);
  });

  group('throws an ArgumentError where noble throws', () {
    final (:publicKey, :secretKey) = keys.first;
    final cipherText = MlKem1024.encapsulate(publicKey).cipherText;

    test('on inputs of the wrong length', () {
      expect(() => MlKem1024.keygen(Uint8List(63)), throwsArgumentError);
      expect(() => MlKem1024.keygen(Uint8List(65)), throwsArgumentError);
      expect(() => MlKem1024.encapsulate(publicKey.sublist(1)), throwsArgumentError);
      expect(() => MlKem1024.encapsulate(publicKey, Uint8List(31)), throwsArgumentError);
      expect(() => MlKem1024.decapsulate(cipherText.sublist(1), secretKey), throwsArgumentError);
      expect(() => MlKem1024.decapsulate(cipherText, secretKey.sublist(1)), throwsArgumentError);
      expect(() => MlKem1024.decapsulate(concatBytes([cipherText, Uint8List(1)]), secretKey), throwsArgumentError);
    });

    test('on a public key with a coefficient of q or more (the modulus check)', () {
      // The first 12-bit coefficient becomes 4095.
      final bad = Uint8List.fromList(publicKey)
        ..[0] = 0xff
        ..[1] |= 0x0f;
      expect(() => MlKem1024.encapsulate(bad), throwsArgumentError);
    });

    test("on a secret key whose public key doesn't match its hash", () {
      final bad = Uint8List.fromList(secretKey)..[2000] ^= 1;
      expect(() => MlKem1024.decapsulate(cipherText, bad), throwsArgumentError);
      expect(() => MlKem1024.publicKeyOf(bad), throwsArgumentError);
      expect(() => MlKem1024.publicKeyOf(secretKey.sublist(1)), throwsArgumentError);
    });
  });
}
