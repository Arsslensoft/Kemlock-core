@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/opaque/hash_to_group.dart';
import 'package:kemlock_core/crypto/opaque/oprf.dart';
import 'package:kemlock_core/crypto/opaque/ristretto255.dart';
import 'package:kemlock_core/crypto/opaque/scalar25519.dart';
import 'package:test/test.dart';

import '../vectors.dart';

Object? _fixture(String name) => jsonDecode(File('test/fixtures/account/rfc/$name').readAsStringSync());

// RFC 9380 appendix K.3 (expand_message_xmd with SHA-512) and RFC 9497
// appendix A.1.1 (the ristretto255-SHA512 OPRF in mode 0), copied by script
// from the RFCs' text into test/fixtures/account/rfc/.
void main() {
  group('expand_message_xmd with SHA-512 (RFC 9380 appendix K.3)', () {
    final vectors = _fixture('expand_message_xmd_rfc9380.json')! as Map<String, Object?>;
    final dst = utf8.encode(vectors['dst']! as String);

    test('gives the uniform bytes of every test', () {
      final tests = objects(vectors['tests']);
      expect(tests, hasLength(10));
      for (final t in tests) {
        final msg = utf8.encode(t['msg']! as String);
        final length = t['len']! as int;
        expect(
          toHex(expandMessageXmdSha512(msg, dst, length)),
          t['uniformBytes'],
          reason: 'msg ${(t['msg']! as String).length} bytes, $length out',
        );
      }
    });

    test('refuses a DST or length out of range', () {
      expect(() => expandMessageXmdSha512([1], Uint8List(256), 32), throwsArgumentError);
      expect(() => expandMessageXmdSha512([1], const [], 32), throwsArgumentError);
      expect(() => expandMessageXmdSha512([1], dst, 0), throwsArgumentError);
      expect(() => expandMessageXmdSha512([1], dst, 64 * 255 + 1), throwsArgumentError);
    });
  });

  group('the OPRF (RFC 9497 appendix A.1.1)', () {
    final vectors = _fixture('oprf_rfc9497.json')! as Map<String, Object?>;
    final tests = objects(vectors['tests']);
    final seed = fromHex(vectors['seed']! as String);
    final keyInfo = fromHex(vectors['keyInfo']! as String);

    test('derives the server key from the seed and key info', () {
      final pair = Oprf.deriveKeyPair(seed, keyInfo);
      expect(toHex(pair.privateKey), vectors['skSm']);
      expect(pair.publicKey, hasLength(32));
      expect(RistrettoPoint.decode(pair.publicKey), isNotNull);
    });

    test('the context string is "OPRFV1-" 0x00 "-ristretto255-SHA512"', () {
      expect(toHex(oprfContextString), '4f50524656312d002d72697374726574746f3235352d534841353132');
    });

    for (final (i, t) in tests.indexed) {
      test('test vector ${i + 1}: blind, evaluate, finalize', () {
        final input = fromHex(t['input']! as String);
        final sk = fromHex(vectors['skSm']! as String);
        final blinded = Oprf.blind(input, blind: fromHex(t['blind']! as String));
        expect(toHex(blinded.blindedElement), t['blindedElement']);
        final evaluated = Oprf.blindEvaluate(sk, blinded.blindedElement);
        expect(toHex(evaluated), t['evaluationElement']);
        expect(toHex(Oprf.finalize(input, blinded.blind, evaluated)), t['output']);
      });
    }

    test('a random blind gives the same output as a fixed one, whatever it is', () {
      final input = fromHex(tests.first['input']! as String);
      final sk = fromHex(vectors['skSm']! as String);
      final first = Oprf.blind(input);
      final second = Oprf.blind(input);
      expect(first.blindedElement, isNot(second.blindedElement), reason: 'the blinded element hides the input');
      final outputs = [
        for (final b in [first, second]) toHex(Oprf.finalize(input, b.blind, Oprf.blindEvaluate(sk, b.blindedElement))),
      ];
      expect(outputs[0], outputs[1]);
      expect(outputs[0], tests.first['output']);
    });

    test('another input, or another server key, gives another output', () {
      final sk = fromHex(vectors['skSm']! as String);
      final blinded = Oprf.blind(fromHex(tests.first['input']! as String));
      final evaluated = Oprf.blindEvaluate(sk, blinded.blindedElement);
      final right = Oprf.finalize(fromHex(tests.first['input']! as String), blinded.blind, evaluated);
      expect(Oprf.finalize([1, 2, 3], blinded.blind, evaluated), isNot(right));
      final otherKey = Oprf.deriveKeyPair(seed, [1, 2, 3]).privateKey;
      expect(
        Oprf.finalize(fromHex(tests.first['input']! as String), blinded.blind, Oprf.blindEvaluate(otherKey, blinded.blindedElement)),
        isNot(right),
      );
    });

    test('refuses an invalid element, the identity, and a bad blind', () {
      final identity = RistrettoPoint.identity.encode();
      expect(() => Oprf.blindEvaluate(Scalar25519.randomNonZero(), identity), throwsA(isA<OprfException>()));
      expect(() => Oprf.blindEvaluate(Scalar25519.randomNonZero(), Uint8List(32)..[0] = 1), throwsA(isA<OprfException>()));
      expect(() => Oprf.finalize([1], Scalar25519.randomNonZero(), identity), throwsA(isA<OprfException>()));
      expect(() => Oprf.blind([1], blind: Uint8List(32)), throwsA(isA<OprfException>()));
      expect(() => Oprf.blind([1], blind: Uint8List(32)..fillRange(0, 32, 0xff)), throwsA(isA<OprfException>()));
    });
  });
}
