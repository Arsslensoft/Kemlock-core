@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  final key = Uint8List.fromList(List.generate(32, (i) => i));

  test("matches WebCrypto's AES-GCM with the same key and nonce", () async {
    for (final v in objects(readVectors('aes_gcm.json'))) {
      final key = fromHex(v['key']! as String);
      final nonce = fromHex(v['nonce']! as String);
      final plaintext = fromHex(v['plaintext']! as String);

      final encrypted = await aesGcmEncrypt(key, plaintext, nonce: nonce);
      expect(toHex(encrypted.nonce), v['nonce']);
      expect(toHex(encrypted.ct), v['ct'], reason: '${plaintext.length} bytes, ${nonce.length}-byte nonce');
      expect(toHex(await aesGcmDecrypt(key, nonce, fromHex(v['ct']! as String))), v['plaintext']);
    }
  });

  test('draws a fresh 12-byte nonce when none is given, and the tag follows the ciphertext', () async {
    final data = utf8.encode('{"accounts":[]}');
    final first = await aesGcmEncrypt(key, data);
    final second = await aesGcmEncrypt(key, data);

    expect(first.nonce, hasLength(12));
    expect(first.nonce, isNot(second.nonce));
    expect(first.ct, hasLength(data.length + 16));
    expect(await aesGcmDecrypt(key, first.nonce, first.ct), data);
  });

  group('throws AesGcmAuthError', () {
    late Uint8List nonce;
    late Uint8List ct;
    setUpAll(() async {
      (:nonce, :ct) = await aesGcmEncrypt(key, utf8.encode('secret'));
    });

    test('for the wrong key', () async {
      final other = Uint8List.fromList(key)..[0] ^= 1;
      await expectLater(aesGcmDecrypt(other, nonce, ct), throwsA(isA<AesGcmAuthError>()));
    });

    test('for a changed nonce, ciphertext or tag', () async {
      await expectLater(aesGcmDecrypt(key, Uint8List.fromList(nonce)..[11] ^= 1, ct), throwsA(isA<AesGcmAuthError>()));
      await expectLater(aesGcmDecrypt(key, nonce, Uint8List.fromList(ct)..[0] ^= 1), throwsA(isA<AesGcmAuthError>()));
      await expectLater(aesGcmDecrypt(key, nonce, Uint8List.fromList(ct)..[ct.length - 1] ^= 0x80), throwsA(isA<AesGcmAuthError>()));
    });

    test('for data cut short, even below the length of a tag', () async {
      await expectLater(aesGcmDecrypt(key, nonce, ct.sublist(0, ct.length - 1)), throwsA(isA<AesGcmAuthError>()));
      await expectLater(aesGcmDecrypt(key, nonce, ct.sublist(0, 15)), throwsA(isA<AesGcmAuthError>()));
      await expectLater(aesGcmDecrypt(key, nonce, []), throwsA(isA<AesGcmAuthError>()));
    });
  });

  test('takes only 256-bit keys and a nonce', () async {
    await expectLater(aesGcmEncrypt(Uint8List(16), [1]), throwsArgumentError);
    await expectLater(aesGcmEncrypt(key, [1], nonce: []), throwsArgumentError);
    await expectLater(aesGcmDecrypt(Uint8List(31), Uint8List(12), Uint8List(16)), throwsArgumentError);
    await expectLater(aesGcmDecrypt(key, [], Uint8List(16)), throwsArgumentError);
  });
}
