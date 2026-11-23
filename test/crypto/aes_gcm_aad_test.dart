@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

import 'vectors.dart';

// test/fixtures/account/aes-gcm-aad-wycheproof.json holds AES-256-GCM cases
// with additional data from Project Wycheproof (its "source" says which file),
// kept with its test case ids and field names.
void main() {
  final cases = objects(
    (jsonDecode(File('test/fixtures/account/aes-gcm-aad-wycheproof.json').readAsStringSync()) as Map<String, Object?>)['tests'],
  );
  final key = Uint8List.fromList(List.generate(32, (i) => i));
  final nonce = Uint8List.fromList(List.generate(12, (i) => 100 + i));

  test("matches Wycheproof's AES-256-GCM cases with additional data", () async {
    expect(cases, isNotEmpty);
    for (final v in cases) {
      final reason = 'tcId ${v['tcId']}';
      final k = fromHex(v['key']! as String);
      final iv = fromHex(v['iv']! as String);
      final aad = fromHex(v['aad']! as String);
      final msg = fromHex(v['msg']! as String);
      final sealed = (v['ct']! as String) + (v['tag']! as String);
      if (v['kind'] == 'valid') {
        final encrypted = await aesGcmEncrypt(k, msg, nonce: iv, aad: aad);
        expect(toHex(encrypted.ct), sealed, reason: reason);
        expect(await aesGcmDecrypt(k, iv, fromHex(sealed), aad: aad), msg, reason: reason);
      } else {
        await expectLater(aesGcmDecrypt(k, iv, fromHex(sealed), aad: aad), throwsA(isA<AesGcmAuthError>()), reason: reason);
      }
    }
  });

  test('the tag covers the additional data: another aad, or none, does not open the seal', () async {
    final sealed = await aesGcmEncrypt(key, utf8.encode('secret'), nonce: nonce, aad: utf8.encode('place A'));
    expect(await aesGcmDecrypt(key, nonce, sealed.ct, aad: utf8.encode('place A')), utf8.encode('secret'));
    await expectLater(aesGcmDecrypt(key, nonce, sealed.ct, aad: utf8.encode('place B')), throwsA(isA<AesGcmAuthError>()));
    await expectLater(aesGcmDecrypt(key, nonce, sealed.ct), throwsA(isA<AesGcmAuthError>()));
  });

  test('without additional data the bytes are the ones it always made', () async {
    final plain = await aesGcmEncrypt(key, utf8.encode('secret'), nonce: nonce);
    final empty = await aesGcmEncrypt(key, utf8.encode('secret'), nonce: nonce, aad: const []);
    expect(plain.ct, empty.ct);
    expect(await aesGcmDecrypt(key, nonce, plain.ct, aad: const []), utf8.encode('secret'));
  });
}
