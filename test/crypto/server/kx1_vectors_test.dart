@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's kx1.json (crypto.md "kx1"): the key pair expanded from the
// 96-byte private key, a ciphertext and its shared secret, and two changed
// ciphertexts that pin the outputs of ML-KEM's implicit rejection and of a
// changed X25519 half. The cases don't carry the randomness of encapsulation
// (ML-KEM's m, the ephemeral X25519 key), so the ciphertext is opened, not
// sealed again; a fresh encapsulation is checked by its own round trip.
void main() {
  group("the server's kx1 vectors", () {
    for (final c in readServerCases('kx1.json')) {
      final name = c['name']! as String;
      final privateKey = fromHex(c['private_key']! as String);
      final publicKey = fromHex(c['public_key']! as String);
      final ciphertext = fromHex(c['ciphertext']! as String);

      test('$name: the private key is the ML-KEM seed then the X25519 secret', () {
        expect(privateKey, hasLength(Kx1.privateKeyLength));
        expect(toHex(privateKey.sublist(0, 64)), c['mlkem_seed']);
        expect(toHex(privateKey.sublist(64)), c['x25519_secret']);
      });

      test('$name: expands to the public key', () async {
        final pair = await Kx1.generate(privateKey);
        expect(pair.publicKey, hasLength(Kx1.publicKeyLength));
        expect(toHex(pair.publicKey), c['public_key']);
        expect(toHex(pair.privateKey), c['private_key']);
        expect(toHex(await Kx1.publicKeyOf(privateKey)), c['public_key']);
      });

      test('$name: decapsulates the ciphertext to the shared secret', () async {
        expect(ciphertext, hasLength(Kx1.ciphertextLength));
        final secret = await Kx1.decapsulate(ciphertext, privateKey);
        expect(toHex(secret), c['shared_secret']);
      });

      for (final changed in (c['changed_ciphertexts']! as List<Object?>).cast<Map<String, Object?>>()) {
        test('$name: ${changed['description']} gives the pinned secret', () async {
          final changedCiphertext = fromHex(changed['ciphertext']! as String);
          expect(changedCiphertext, hasLength(Kx1.ciphertextLength));
          // Exactly one byte differs from the good ciphertext.
          var differing = 0;
          for (var i = 0; i < ciphertext.length; i++) {
            if (ciphertext[i] != changedCiphertext[i]) differing++;
          }
          expect(differing, 1);

          final secret = await Kx1.decapsulate(changedCiphertext, privateKey);
          expect(toHex(secret), changed['shared_secret']);
          expect(toHex(secret), isNot(c['shared_secret']));
        });
      }

      test('$name: a fresh encapsulation to the public key opens with the private key', () async {
        final fresh = await Kx1.encapsulate(publicKey);
        expect(fresh.ciphertext, hasLength(Kx1.ciphertextLength));
        expect(await Kx1.decapsulate(fresh.ciphertext, privateKey), Uint8List.fromList(fresh.sharedSecret));
      });
    }
  });
}
