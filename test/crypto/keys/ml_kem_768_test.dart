@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// test/fixtures/keys/acvp/ml-kem-768.json holds ML-KEM-768 cases of NIST's
// ACVP vectors for FIPS 203 (its "source" says which file), kept with
// NIST's field names and test case ids.

void main() {
  final vectors = jsonDecode(keyFixtureText('acvp/ml-kem-768.json')) as Map<String, Object?>;
  Uint8List hex(Map<String, Object?> v, String field) => fromHex(v[field]! as String);

  test('key generation from d and z', () {
    for (final v in objects(vectors['keyGen'])) {
      final (:publicKey, :secretKey) = MlKem768.keygen(Uint8List.fromList([...hex(v, 'd'), ...hex(v, 'z')]));
      expect(publicKey, hex(v, 'ek'), reason: 'tcId ${v['tcId']}');
      expect(secretKey, hex(v, 'dk'), reason: 'tcId ${v['tcId']}');
    }
  });

  test('encapsulation with a fixed message', () {
    for (final v in objects(vectors['encapsulation'])) {
      final (:cipherText, :sharedSecret) = MlKem768.encapsulate(hex(v, 'ek'), hex(v, 'm'));
      expect(cipherText, hex(v, 'c'), reason: 'tcId ${v['tcId']}');
      expect(sharedSecret, hex(v, 'k'), reason: 'tcId ${v['tcId']}');
    }
  });

  test('decapsulation, of good ciphertexts and of modified ones (implicit rejection)', () {
    final reasons = <Object?>{};
    for (final v in objects(vectors['decapsulation'])) {
      expect(MlKem768.decapsulate(hex(v, 'c'), hex(v, 'dk')), hex(v, 'k'), reason: 'tcId ${v['tcId']}: ${v['reason']}');
      reasons.add(v['reason']);
    }
    expect(reasons, {'valid decapsulation', 'modified ciphertext'});
  });

  test('the key checks: a decapsulation key whose hash was changed, an encapsulation key out of range', () {
    for (final v in objects(vectors['decapsulationKeyCheck'])) {
      final dk = hex(v, 'dk');
      final cipherText = Uint8List(MlKem768.cipherTextLength);
      if (v['testPassed']! as bool) {
        expect(MlKem768.decapsulate(cipherText, dk), hasLength(32), reason: 'tcId ${v['tcId']}');
      } else {
        expect(() => MlKem768.decapsulate(cipherText, dk), throwsArgumentError, reason: 'tcId ${v['tcId']}: ${v['reason']}');
      }
    }
    for (final v in objects(vectors['encapsulationKeyCheck'])) {
      final ek = hex(v, 'ek');
      if (v['testPassed']! as bool) {
        expect(MlKem768.encapsulate(ek).sharedSecret, hasLength(32), reason: 'tcId ${v['tcId']}');
      } else {
        expect(() => MlKem768.encapsulate(ek), throwsArgumentError, reason: 'tcId ${v['tcId']}: ${v['reason']}');
      }
    }
  });

  test('round-trips with random keys, at its own sizes', () {
    final (:publicKey, :secretKey) = MlKem768.keygen();
    expect(publicKey, hasLength(1184));
    expect(secretKey, hasLength(2400));
    final (:cipherText, :sharedSecret) = MlKem768.encapsulate(publicKey);
    expect(cipherText, hasLength(1088));
    expect(MlKem768.decapsulate(cipherText, secretKey), sharedSecret);
    expect(() => MlKem768.encapsulate(MlKem1024.keygen().publicKey), throwsArgumentError);
  });
}
