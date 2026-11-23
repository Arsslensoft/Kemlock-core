@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's sig1.json (crypto.md "sig1"): the key pair from the ML-DSA
// seed and the Ed25519 seed, and a signature over
// "kemlock/v1/sig1" || lp(context) || lp(message). The ML-DSA half is the
// deterministic variant (32 zero bytes of randomness), so each signature is
// made again and compared byte for byte; verifiers accept either.
void main() {
  final cases = readServerCases('sig1.json');
  final deterministic = Uint8List(32);

  group("the server's sig1 vectors", () {
    for (final c in cases) {
      final name = c['name']! as String;
      final context = c['context']! as String;
      final privateKey = fromHex(c['private_key']! as String);
      final publicKey = fromHex(c['public_key']! as String);
      final message = fromHex(c['message']! as String);
      final signature = fromHex(c['signature']! as String);

      test('$name: the private key is the ML-DSA seed then the Ed25519 seed', () {
        expect(privateKey, hasLength(Sig1.privateKeyLength));
        expect(toHex(privateKey.sublist(0, 32)), c['mldsa_seed']);
        expect(toHex(privateKey.sublist(32)), c['ed25519_seed']);
      });

      test('$name: expands to the public key', () async {
        expect(publicKey, hasLength(Sig1.publicKeyLength));
        expect(toHex(await Sig1.publicKeyOf(privateKey)), c['public_key']);
      });

      test('$name: signing again with fixed randomness gives the signature', () async {
        expect(signature, hasLength(Sig1.signatureLength));
        final again = await Sig1.sign(privateKey, message, context: context, randomness: deterministic);
        expect(toHex(again), c['signature']);
      });

      test('$name: verifies under its context', () async {
        expect(await Sig1.verify(publicKey, message, signature, context: context), isTrue);
      });

      test('$name: does not verify under another context or message', () async {
        for (final other in ['bundle', 'manifest', 'other']) {
          if (other == context) continue;
          expect(await Sig1.verify(publicKey, message, signature, context: other), isFalse, reason: other);
        }
        final changed = Uint8List.fromList([...message, 0]);
        expect(await Sig1.verify(publicKey, changed, signature, context: context), isFalse);
      });

      test('$name: needs both halves: a changed ML-DSA half or Ed25519 half fails', () async {
        final mlDsaBad = Uint8List.fromList(signature)..[0] ^= 1;
        expect(await Sig1.verify(publicKey, message, mlDsaBad, context: context), isFalse);
        final edBad = Uint8List.fromList(signature)..[3309] ^= 1;
        expect(await Sig1.verify(publicKey, message, edBad, context: context), isFalse);
        // Each half alone, with the other replaced by another case's half.
        for (final other in cases) {
          if (other['name'] == name) continue;
          final otherSignature = fromHex(other['signature']! as String);
          final mlDsaOnly = Uint8List.fromList([...signature.sublist(0, 3309), ...otherSignature.sublist(3309)]);
          final edOnly = Uint8List.fromList([...otherSignature.sublist(0, 3309), ...signature.sublist(3309)]);
          expect(await Sig1.verify(publicKey, message, mlDsaOnly, context: context), isFalse, reason: 'ML-DSA half only, ${other['name']}');
          expect(await Sig1.verify(publicKey, message, edOnly, context: context), isFalse, reason: 'Ed25519 half only, ${other['name']}');
        }
      });

      test('$name: a signature or key of the wrong length is malformed', () async {
        await expectLater(
          Sig1.verify(publicKey, message, Uint8List.fromList(signature.sublist(1)), context: context),
          throwsA(isA<MalformedException>()),
        );
        await expectLater(
          Sig1.verify(Uint8List.fromList(publicKey.sublist(1)), message, signature, context: context),
          throwsA(isA<MalformedException>()),
        );
      });
    }
  });
}
