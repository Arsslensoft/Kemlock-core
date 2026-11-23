@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/confirm.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's confirm.json (crypto.md "Member confirmation"): the 134-byte
// statement, the member's bundle and the fingerprint behind it, the confirmer's
// sig1 signature under the context "confirm", the contexts it must not verify
// under and the statements it must not cover. The file is copied by
// tool/server/copy_vectors.sh; until it is, these tests skip.
void main() {
  final skip = serverVectorSkip('confirm.json');
  if (skip != null) {
    test("the server's confirm vectors", () {}, skip: skip);
    return;
  }

  group("the server's confirm vectors", () {
    for (final c in readServerCases('confirm.json')) {
      final name = c['name']! as String;
      final bundle = KeyBundle.parse(fromHex(c['member_bundle']! as String));
      final statement = fromHex(c['statement']! as String);
      final signature = fromHex(c['signature']! as String);
      final confirmerPublic = fromHex(c['confirmer_public_key']! as String);

      test('$name: the statement is rebuilt from the space, the member, the key version, the fingerprint and the confirmer', () {
        expect(toHex(bundle.fingerprint), c['fingerprint']);
        expect(bundle.keyVersion, c['member_key_version']);
        expect(toHex(bundle.accountId), c['member']);
        final rebuilt = ConfirmStatement.forBundle(
          space: fromHex(c['space']! as String),
          bundle: bundle,
          confirmer: fromHex(c['confirmer']! as String),
        );
        expect(toHex(rebuilt.bytes), c['statement']);
        expect(statement, hasLength(ConfirmStatement.length));
        expect(rebuilt.covers(bundle), isTrue);
      });

      test('$name: the signature verifies under the confirmer’s key', () async {
        expect(signature, hasLength(Sig1.signatureLength));
        final verified = await verifyConfirmation(statement, signature, confirmerPublic);
        expect(toHex(verified.confirmer), c['confirmer']);
      });

      for (final wrong in (c['wrong_contexts']! as List<Object?>).cast<String>()) {
        test('$name: does not verify under the context "$wrong"', () async {
          expect(await Sig1.verify(confirmerPublic, statement, signature, context: wrong), isFalse);
        });
      }

      for (final changed in (c['changed_statements']! as List<Object?>).cast<Map<String, Object?>>()) {
        test('$name: does not cover the statement "${changed['name']}"', () async {
          final other = fromHex(changed['statement']! as String);
          expect(other, isNot(statement));
          await expectLater(verifyConfirmation(other, signature, confirmerPublic), throwsA(isA<CorruptedException>()));
        });
      }

      test('$name: a flipped byte of the statement or the signature does not verify', () async {
        for (final index in [0, 17, 18, 40, 100, 133]) {
          final flipped = Uint8List.fromList(statement)..[index] ^= 1;
          await expectLater(
            verifyConfirmation(flipped, signature, confirmerPublic),
            throwsA(anyOf(isA<CorruptedException>(), isA<MalformedException>())),
            reason: 'statement byte $index',
          );
        }
        for (final index in [0, 1000, 3308, 3309, 3372]) {
          final flipped = Uint8List.fromList(signature)..[index] ^= 1;
          await expectLater(
            verifyConfirmation(statement, flipped, confirmerPublic),
            throwsA(isA<CorruptedException>()),
            reason: 'signature byte $index',
          );
        }
      });
    }
  });
}
