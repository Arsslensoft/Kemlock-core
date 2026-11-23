@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// acvp/ml-dsa-65.json holds ML-DSA-65 key generation cases of NIST's ACVP
// vectors for FIPS 204, and acvp/ml-dsa-65-sigGen.json and -sigVer.json
// signing and verification cases of the external, pure interface.
// openssl/ml-dsa-65.* is a key OpenSSL 3.6.1 made with
// `openssl genpkey -algorithm ML-DSA-65 -pkeyopt hexseed:<seed>`, the seed
// in ml-dsa-65.seed.hex.

/// The test groups of an ACVP signing file, each case with its group.
List<(Map<String, Object?>, Map<String, Object?>)> _signingCases(String name) => [
  for (final group in objects((jsonDecode(keyFixtureText('acvp/$name')) as Map<String, Object?>)['testGroups']))
    for (final v in objects(group['tests'])) (group, v),
];

Uint8List _hex(Map<String, Object?> v, String field) => fromHex(v[field]! as String);

void main() {
  final vectors = objects((jsonDecode(keyFixtureText('acvp/ml-dsa-65.json')) as Map<String, Object?>)['keyGen']);

  test("gives NIST's known answers for key generation", () {
    for (final v in vectors) {
      final (:publicKey, :secretKey) = MlDsa65.keygen(fromHex(v['seed']! as String));
      expect(publicKey, fromHex(v['pk']! as String), reason: 'tcId ${v['tcId']}');
      expect(secretKey, fromHex(v['sk']! as String), reason: 'tcId ${v['tcId']}');
    }
  });

  test('works out the public key from a secret key alone', () {
    for (final v in vectors) {
      expect(MlDsa65.publicKeyOf(fromHex(v['sk']! as String)), fromHex(v['pk']! as String), reason: 'tcId ${v['tcId']}');
    }
  });

  test('gives the key OpenSSL made from the same seed', () {
    final seed = fromHex(keyFixtureText('openssl/ml-dsa-65.seed.hex').trim());
    final (:publicKey, :secretKey) = MlDsa65.keygen(seed);

    final spki = readSequence(keyFixture('openssl/ml-dsa-65.spki.der'));
    expect(spki.sequence().oid(), '2.16.840.1.101.3.4.3.18');
    expect(publicKey, spki.bitString(), reason: 'the public key OpenSSL derived');

    final pkcs8 = readSequence(readPemBlocks(keyFixtureText('openssl/ml-dsa-65.expanded.pem')).single.decode())
      ..smallInteger()
      ..sequence();
    expect(secretKey, DerReader(pkcs8.octetString()).octetString(), reason: "OpenSSL's expanded secret key");
  });

  test('refuses a secret key whose parts do not belong together', () {
    final sk = fromHex(vectors.first['sk']! as String);
    expect(() => MlDsa65.publicKeyOf(sk.sublist(1)), throwsArgumentError);
    // A changed tr, s1 coefficient, and t0 coefficient.
    for (final index in [64, 128, MlDsa65.secretKeyLength - 1]) {
      final broken = Uint8List.fromList(sk)..[index] ^= 0x01;
      expect(() => MlDsa65.publicKeyOf(broken), throwsArgumentError, reason: 'byte $index');
    }
    // An s1 word of 15, above 2 * eta.
    final outOfRange = Uint8List.fromList(sk)..[128] |= 0x0f;
    expect(() => MlDsa65.publicKeyOf(outOfRange), throwsArgumentError);
    expect(() => MlDsa65.keygen(Uint8List(31)), throwsArgumentError);
  });

  test('random keys have their sizes, and differ', () {
    final a = MlDsa65.keygen();
    final b = MlDsa65.keygen();
    expect(a.publicKey, hasLength(1952));
    expect(a.secretKey, hasLength(4032));
    expect(a.publicKey, isNot(b.publicKey));
    expect(MlDsa65.publicKeyOf(a.secretKey), a.publicKey);
  });

  group('signing', () {
    final sigGen = _signingCases('ml-dsa-65-sigGen.json');
    final sigVer = _signingCases('ml-dsa-65-sigVer.json');

    test("NIST's signing and verification cases load", () {
      for (final (group, _) in [...sigGen, ...sigVer]) {
        expect(group['parameterSet'], 'ML-DSA-65');
        expect(group['signatureInterface'], 'external');
        expect(group['preHash'], 'pure');
      }
      expect(sigGen.where((c) => c.$1['deterministic'] == true), hasLength(6));
      expect(sigGen.where((c) => c.$1['deterministic'] == false), hasLength(6));
      expect(sigVer.where((c) => c.$2['testPassed'] == true), hasLength(3));
      expect(sigVer.where((c) => c.$2['testPassed'] == false), hasLength(8));
    });

    test("gives NIST's known signatures", () {
      for (final (group, v) in sigGen) {
        // The deterministic variant signs with 32 zero bytes of randomness.
        final rnd = group['deterministic']! as bool ? Uint8List(32) : _hex(v, 'rnd');
        final signature = MlDsa65.sign(_hex(v, 'sk'), _hex(v, 'message'), context: _hex(v, 'context'), randomness: rnd);
        expect(signature, _hex(v, 'signature'), reason: 'tcId ${v['tcId']}');
        expect(
          MlDsa65.verify(_hex(v, 'pk'), _hex(v, 'message'), signature, context: _hex(v, 'context')),
          isTrue,
          reason: 'tcId ${v['tcId']}',
        );
      }
    });

    test("gives NIST's verdicts", () {
      for (final (_, v) in sigVer) {
        expect(
          MlDsa65.verify(_hex(v, 'pk'), _hex(v, 'message'), _hex(v, 'signature'), context: _hex(v, 'context')),
          v['testPassed'],
          reason: 'tcId ${v['tcId']}: ${v['reason']}',
        );
      }
    });

    test('hedged signatures verify, and differ from one run to the next', () {
      final (:publicKey, :secretKey) = MlDsa65.keygen();
      final message = utf8.encode('a message');
      final a = MlDsa65.sign(secretKey, message);
      final b = MlDsa65.sign(secretKey, message);
      expect(a, hasLength(MlDsa65.signatureLength));
      expect(a, isNot(b));
      expect(MlDsa65.verify(publicKey, message, a), isTrue);
      expect(MlDsa65.verify(publicKey, message, b), isTrue);
    });

    test('does not verify a signature of another message or context, or one with a byte changed', () {
      final (_, v) = sigGen.first;
      final pk = _hex(v, 'pk');
      final message = _hex(v, 'message');
      final context = _hex(v, 'context');
      final signature = _hex(v, 'signature');
      expect(MlDsa65.verify(pk, message, signature, context: context), isTrue);

      expect(MlDsa65.verify(pk, Uint8List.fromList(message)..[0] ^= 0x01, signature, context: context), isFalse);
      expect(MlDsa65.verify(pk, [...message, 0], signature, context: context), isFalse);
      expect(MlDsa65.verify(pk, message, signature), isFalse, reason: 'without the context');
      // A byte of c~, of z, of the hint positions, and the last hint end.
      for (final index in [0, 48, 1000, MlDsa65.signatureLength - 61, MlDsa65.signatureLength - 1]) {
        final changed = Uint8List.fromList(signature)..[index] ^= 0x01;
        expect(MlDsa65.verify(pk, message, changed, context: context), isFalse, reason: 'byte $index');
      }
      final otherKey = MlDsa65.keygen().publicKey;
      expect(MlDsa65.verify(otherKey, message, signature, context: context), isFalse, reason: 'another key');
    });

    test('refuses a key, signature, randomness or context of the wrong length', () {
      final (_, v) = sigGen.first;
      final sk = _hex(v, 'sk');
      final pk = _hex(v, 'pk');
      final signature = _hex(v, 'signature');
      final message = [1, 2, 3];
      final longContext = Uint8List(256);

      expect(() => MlDsa65.sign(sk.sublist(1), message), throwsArgumentError);
      expect(() => MlDsa65.sign(sk, message, randomness: Uint8List(31)), throwsArgumentError);
      expect(() => MlDsa65.sign(sk, message, context: longContext), throwsArgumentError);
      expect(() => MlDsa65.verify(pk.sublist(1), message, signature), throwsArgumentError);
      expect(() => MlDsa65.verify(pk, message, signature.sublist(1)), throwsArgumentError);
      expect(() => MlDsa65.verify(pk, message, Uint8List.fromList([...signature, 0])), throwsArgumentError);
      expect(() => MlDsa65.verify(pk, message, signature, context: longContext), throwsArgumentError);
      // A context of 255 bytes is the longest allowed.
      final context = Uint8List(255);
      expect(MlDsa65.verify(pk, message, MlDsa65.sign(sk, message, context: context), context: context), isTrue);
    });
  });
}
