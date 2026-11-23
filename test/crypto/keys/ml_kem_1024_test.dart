@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// test/fixtures/keys/acvp/ml-kem-1024.json holds ML-KEM-1024 cases of NIST's
// ACVP vectors for FIPS 203 (its "source" says which file), kept with NIST's
// field names and test case ids. ml_kem_test.dart holds ML-KEM-1024 to
// noble's vectors; these are NIST's own, for the exchange key's ML-KEM half.

void main() {
  final vectors = jsonDecode(keyFixtureText('acvp/ml-kem-1024.json')) as Map<String, Object?>;
  Uint8List hex(Map<String, Object?> v, String field) => fromHex(v[field]! as String);

  test('key generation from d and z', () {
    for (final v in objects(vectors['keyGen'])) {
      final (:publicKey, :secretKey) = MlKem1024.keygen(Uint8List.fromList([...hex(v, 'd'), ...hex(v, 'z')]));
      expect(publicKey, hex(v, 'ek'), reason: 'tcId ${v['tcId']}');
      expect(secretKey, hex(v, 'dk'), reason: 'tcId ${v['tcId']}');
    }
  });

  test('encapsulation with a fixed message', () {
    for (final v in objects(vectors['encapsulation'])) {
      final (:cipherText, :sharedSecret) = MlKem1024.encapsulate(hex(v, 'ek'), hex(v, 'm'));
      expect(cipherText, hex(v, 'c'), reason: 'tcId ${v['tcId']}');
      expect(sharedSecret, hex(v, 'k'), reason: 'tcId ${v['tcId']}');
    }
  });

  test('decapsulation, of good ciphertexts and of a modified one (implicit rejection)', () {
    final reasons = <Object?>{};
    for (final v in objects(vectors['decapsulation'])) {
      expect(MlKem1024.decapsulate(hex(v, 'c'), hex(v, 'dk')), hex(v, 'k'), reason: 'tcId ${v['tcId']}: ${v['reason']}');
      reasons.add(v['reason']);
    }
    expect(reasons, hasLength(2));
  });
}
