@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:test/test.dart';

import 'vectors.dart';

/// An account made on Vaultwarden 1.37.5, holding items the official
/// Bitwarden CLI made (see test/vaultwarden_server/make_fixtures_test.dart).
Map<String, Object?> _account(String kdf) =>
    jsonDecode(File('test/fixtures/vaultwarden/account-$kdf.json').readAsStringSync()) as Map<String, Object?>;

Future<String?> _open(Object? value, BwKey key) async => value is String ? bwDecryptString(value, key) : null;

void main() {
  test('expands keys as RFC 5869 does (test case 1, from its PRK)', () {
    final okm = hkdfExpandSha256(
      fromHex('077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'),
      fromHex('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    expect(toHex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });

  group('encrypted strings', () {
    final key = BwKey.fromBytes(List.generate(64, (i) => i));

    test('round-trip, with a fresh IV each time', () async {
      final first = await bwEncryptString('hunter2 ✓', key);
      final second = await bwEncryptString('hunter2 ✓', key);
      expect(first, startsWith('2.'));
      expect(first.split('|'), hasLength(3));
      expect(first, isNot(second));
      expect(await bwDecryptString(first, key), 'hunter2 ✓');
      expect(EncString.parse(first).toString(), first);
    });

    test('refuse a changed value or another key', () async {
      final value = EncString.parse(await bwEncryptString('secret', key));
      final changed = Uint8List.fromList(value.data)..[0] ^= 1;
      await expectLater(bwDecrypt(EncString(type: 2, iv: value.iv, data: changed, mac: value.mac), key), throwsA(isA<BwCryptoError>()));
      await expectLater(bwDecrypt(value, BwKey.fromBytes(List.filled(64, 7))), throwsA(isA<BwCryptoError>()));
      // A type 2 value needs a MAC key
      await expectLater(bwDecrypt(value, BwKey(key.enc)), throwsA(isA<BwCryptoError>()));
    });

    test('read type 0 values, which have no MAC', () async {
      final legacy = BwKey(key.enc);
      final value = await bwEncrypt(utf8.encode('old'), legacy);
      expect(value.type, 0);
      expect(value.toString().split('|'), hasLength(2));
      expect(utf8.decode(await bwDecrypt(EncString.parse(value.toString()), legacy)), 'old');
    });

    test('refuse a value without a MAC under a key that has a MAC key', () async {
      // What a server would send to get past the MAC: the same bytes, as type 0
      final value = EncString.parse(await bwEncryptString('secret', key));
      final stripped = EncString(type: 0, iv: value.iv, data: value.data);
      await expectLater(bwDecrypt(stripped, key), throwsA(isA<BwCryptoError>()));
      await expectLater(bwDecryptString(stripped.toString(), key), throwsA(isA<BwCryptoError>()));
      await expectLater(bwOpenCipherKey(stripped.toString(), key), throwsA(isA<BwCryptoError>()));
    });

    test('refuse what is not one, or a type not supported', () {
      for (final text in ['', 'plain text', '2.abc', '2.a|b', '2.!!|AA==|AA==', '4.AAAA', '7.AAAA|AAAA|AAAA']) {
        expect(() => EncString.parse(text), throwsA(isA<BwCryptoError>()), reason: text);
        expect(isEncString(text), isFalse, reason: text);
      }
    });
  });

  test('salts with the email trimmed and lower-cased', () async {
    const kdf = BwKdf(type: BwKdfType.pbkdf2, iterations: 1000);
    expect(await bwMasterKey('pw', ' Me@Example.COM ', kdf), await bwMasterKey('pw', 'me@example.com', kdf));
  });

  test('reads the KDF from prelogin, and refuses one it does not know', () {
    expect(
      BwKdf.fromJson({'kdf': 1, 'kdfIterations': 3, 'kdfMemory': 64, 'kdfParallelism': 4}),
      const BwKdf(type: BwKdfType.argon2id, iterations: 3, memory: 64, parallelism: 4),
    );
    expect(BwKdf.fromJson({'Kdf': 0, 'KdfIterations': 600000}), const BwKdf(type: BwKdfType.pbkdf2, iterations: 600000));
    expect(() => BwKdf.fromJson({'kdf': 2, 'kdfIterations': 1}), throwsFormatException);
    expect(() => BwKdf.fromJson({'kdf': 1, 'kdfIterations': 3}), throwsFormatException);
  });

  test('refuses a KDF cost a server made too cheap to protect the password, or too dear to run', () {
    Map<String, Object?> pbkdf2(Object? iterations) => {'kdf': 0, 'kdfIterations': iterations};
    Map<String, Object?> argon2({int iterations = 3, int memory = 64, int parallelism = 4}) => {
      'kdf': 1,
      'kdfIterations': iterations,
      'kdfMemory': memory,
      'kdfParallelism': parallelism,
    };
    expect(BwKdf.fromJson(pbkdf2(5000)).iterations, 5000);
    expect(BwKdf.fromJson(pbkdf2(2000000)).iterations, 2000000);
    expect(BwKdf.fromJson(argon2(iterations: 2, memory: 16, parallelism: 1)).memory, 16);
    expect(BwKdf.fromJson(argon2(iterations: 10, memory: 1024, parallelism: 16)).memory, 1024);
    for (final json in [
      pbkdf2(1),
      pbkdf2(4999),
      pbkdf2(2000001),
      pbkdf2(0),
      pbkdf2(-1),
      pbkdf2('600000'),
      pbkdf2(600000.5),
      argon2(iterations: 1),
      argon2(iterations: 11),
      argon2(memory: 15),
      argon2(memory: 1025),
      argon2(memory: 1 << 40),
      argon2(parallelism: 0),
      argon2(parallelism: 17),
    ]) {
      expect(() => BwKdf.fromJson(json), throwsFormatException, reason: '$json');
    }
  });

  for (final name in ['pbkdf2', 'argon2id']) {
    test('opens every value of the $name account the Bitwarden CLI filled', () async {
      final account = _account(name);
      final kdf = BwKdf.fromJson(account['prelogin']! as Map<String, Object?>);
      final masterKey = await bwMasterKey(account['password']! as String, account['email']! as String, kdf);
      final token = account['token']! as Map<String, Object?>;
      final userKey = await bwOpenUserKey(token['Key']! as String, masterKey);

      final sync = account['sync']! as Map<String, Object?>;
      final folder = (sync['folders']! as List<Object?>).single! as Map<String, Object?>;
      expect(await _open(folder['name'], userKey), 'Kemlock');

      final ciphers = {for (final cipher in (sync['ciphers']! as List<Object?>).cast<Map<String, Object?>>()) cipher['id']: cipher};
      final expected = (account['expected']! as Map<String, Object?>)['items']! as List<Object?>;
      for (final item in expected.cast<Map<String, Object?>>()) {
        final cipher = ciphers[item['id']]!;
        final key = cipher['key'] is String ? await bwOpenCipherKey(cipher['key']! as String, userKey) : userKey;
        expect(cipher['type'], item['type']);
        expect(cipher['folderId'], folder['id']);
        expect(await _open(cipher['name'], key), item['name']);
        expect(await _open(cipher['notes'], key), item['notes']);
        expect(cipher['favorite'], item['favorite']);
        expect(cipher['reprompt'], item['reprompt']);
        final fields = [
          for (final field in (cipher['fields'] as List<Object?>? ?? const []).cast<Map<String, Object?>>())
            {'name': await _open(field['name'], key), 'value': await _open(field['value'], key), 'type': field['type']},
        ];
        expect(fields, item['fields'] ?? isEmpty);
        if (item['login'] case final Map<String, Object?> login) {
          final theirs = cipher['login']! as Map<String, Object?>;
          for (final field in ['username', 'password', 'totp']) {
            final want = login[field] == '' ? null : login[field];
            expect(await _open(theirs[field], key), want, reason: '${item['name']} $field');
          }
          final uris = [
            for (final uri in (theirs['uris'] as List<Object?>? ?? const []).cast<Map<String, Object?>>()) await _open(uri['uri'], key),
          ];
          expect(uris, [for (final uri in (login['uris']! as List<Object?>).cast<Map<String, Object?>>()) uri['uri']]);
        }
      }
    }, timeout: const Timeout(Duration(minutes: 2)));
  }

  test('a wrong password does not open the user key', () async {
    final account = _account('pbkdf2');
    final kdf = BwKdf.fromJson(account['prelogin']! as Map<String, Object?>);
    final masterKey = await bwMasterKey('not the password', account['email']! as String, kdf);
    await expectLater(
      bwOpenUserKey((account['token']! as Map<String, Object?>)['Key']! as String, masterKey),
      throwsA(isA<BwCryptoError>()),
    );
  });

  test('derives the hash the server checks from the master key and the password', () async {
    // The fixtures' sign-ins went through with this hash; here it's pinned
    final masterKey = await bwMasterKey(
      'correct horse battery',
      'kemlock@example.com',
      const BwKdf(type: BwKdfType.pbkdf2, iterations: 5000),
    );
    final hash = await bwMasterPasswordHash(masterKey, 'correct horse battery');
    expect(unb64(hash), hasLength(32));
    expect(hash, await bwMasterPasswordHash(masterKey, 'correct horse battery'));
    expect(hash, isNot(await bwMasterPasswordHash(masterKey, 'another password')));
  });
}
