@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sealed_box.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/hkdf.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's sealed-box.json (crypto.md "Sealed box"): a box, the key pair
// it was sealed to, its context and aad, and the other contexts it must not
// open under. The cases don't carry the randomness of the kx1 encapsulation,
// only the nonce inside the box, so the box is opened and its AES-GCM part is
// then sealed again with its own nonce under the key that crypto.md's key
// schedule gives from the decapsulated secret.
void main() {
  group("the server's sealed-box vectors", () {
    for (final c in readServerCases('sealed-box.json')) {
      final name = c['name']! as String;
      final context = c['context']! as String;
      final aad = fromHex(c['aad']! as String);
      final privateKey = fromHex(c['private_key']! as String);
      final publicKey = fromHex(c['public_key']! as String);
      final box = fromHex(c['sealed_box']! as String);
      final secret = fromHex(c['secret']! as String);
      final wrongContexts = (c['wrong_contexts']! as List<Object?>).cast<String>();

      test('$name: opens to the secret under its context and aad', () async {
        expect(box[0], sealedBoxVersion);
        expect(box, hasLength(1 + Kx1.ciphertextLength + 12 + secret.length + 16));
        expect(toHex(await openBox(box, privateKey, context: context, aad: aad)), c['secret']);
      });

      test('$name: the key pair of the case is a kx1 pair', () async {
        expect(toHex(await Kx1.publicKeyOf(privateKey)), c['public_key']);
      });

      test('$name: its sealed value is the AES-GCM seal under the key crypto.md derives', () async {
        final kx1Ciphertext = box.sublist(1, 1 + Kx1.ciphertextLength);
        final nonce = box.sublist(1 + Kx1.ciphertextLength, 1 + Kx1.ciphertextLength + 12);
        final sealedValue = box.sublist(1 + Kx1.ciphertextLength + 12);

        final sharedSecret = await Kx1.decapsulate(kx1Ciphertext, privateKey);
        final contextBytes = label(context);
        final key = hkdfSha256(sharedSecret, salt: const [], info: [...label('kemlock/v1/seal'), ...lp(contextBytes)]);
        final again = await aesGcmEncrypt(key, secret, nonce: nonce, aad: [...lp(contextBytes), ...lp(aad)]);
        expect(toHex(again.ct), toHex(sealedValue));
      });

      for (final wrong in wrongContexts) {
        test('$name: does not open under the context "$wrong"', () async {
          expect(wrong, isNot(context));
          await expectLater(openBox(box, privateKey, context: wrong, aad: aad), throwsA(isA<CorruptedException>()));
        });
      }

      test('$name: does not open under another aad', () async {
        final longer = [...aad, 0];
        await expectLater(openBox(box, privateKey, context: context, aad: longer), throwsA(isA<CorruptedException>()));
        if (aad.isNotEmpty) {
          final flipped = List<int>.of(aad)..[0] ^= 1;
          await expectLater(openBox(box, privateKey, context: context, aad: flipped), throwsA(isA<CorruptedException>()));
        }
      });

      test('$name: a box sealed now to the public key opens under the same context and aad only', () async {
        final fresh = await sealBox(publicKey, secret, context: context, aad: aad);
        expect(fresh, hasLength(box.length));
        expect(toHex(await openBox(fresh, privateKey, context: context, aad: aad)), c['secret']);
        await expectLater(openBox(fresh, privateKey, context: wrongContexts.first, aad: aad), throwsA(isA<CorruptedException>()));
      });
    }
  });
}
