@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:test/test.dart';

/// HKDF-SHA256 with one output block, worked out straight from RFC 5869 with
/// `package:crypto`, apart from `hkdf.dart`: PRK = HMAC(zeros(32), ikm) and
/// OKM = HMAC(PRK, info || 0x01).
Uint8List _hkdfOneBlock(List<int> ikm, String info) {
  final prk = hash.Hmac(hash.sha256, Uint8List(32)).convert(ikm).bytes;
  return Uint8List.fromList(hash.Hmac(hash.sha256, prk).convert([...utf8.encode(info), 1]).bytes);
}

void main() {
  final root = Uint8List.fromList(List.generate(64, (i) => i * 3 + 1));

  test('the user key is HKDF of the root under "kemlock/v1/user"', () {
    expect(deriveUserKey(root), _hkdfOneBlock(root, 'kemlock/v1/user'));
    expect(deriveUserKey(root), hasLength(32));
  });

  test('each child is HKDF of the user key under its own label', () {
    final user = deriveUserKey(root);
    expect(deriveChildKey(user, KeyLabel.itemWrap), _hkdfOneBlock(user, 'kemlock/v1/item-wrap'));
    expect(deriveChildKey(user, KeyLabel.privateKeys), _hkdfOneBlock(user, 'kemlock/v1/private-keys'));
    expect(deriveChildKey(user, KeyLabel.manifest), _hkdfOneBlock(user, 'kemlock/v1/manifest'));
  });

  test('every key of the tree is different', () {
    final keys = AccountKeys.fromRoot(root);
    final all = {root, keys.userKey, keys.itemWrapKey, keys.privateKeysKey, keys.manifestKey}.map(base64.encode).toSet();
    expect(all, hasLength(5));
  });

  test('a root or parent of the wrong length is refused', () {
    expect(() => deriveUserKey(Uint8List(32)), throwsA(isA<MalformedException>()));
    expect(() => deriveChildKey(Uint8List(64), KeyLabel.itemWrap), throwsA(isA<MalformedException>()));
    expect(newRootKey(), hasLength(64));
  });

  test('the root of a Compatible account is its Bitwarden user key, 64 bytes', () async {
    // The account the Bitwarden CLI filled on Vaultwarden (see bitwarden_test.dart).
    final account = jsonDecode(File('test/fixtures/vaultwarden/account-pbkdf2.json').readAsStringSync()) as Map<String, Object?>;
    final kdf = BwKdf.fromJson(account['prelogin']! as Map<String, Object?>);
    final masterKey = await bwMasterKey(account['password']! as String, account['email']! as String, kdf);
    final token = account['token']! as Map<String, Object?>;
    final userKey = await bwOpenUserKey(token['Key']! as String, masterKey);
    expect(userKey.bytes, hasLength(rootKeyLength));
    final keys = AccountKeys.fromRoot(userKey.bytes);
    expect(keys.userKey, deriveUserKey(userKey.bytes));
    expect(keys.root, userKey.bytes);
  });

  test('disposing zeroes the root, the user key and the children', () {
    final keys = AccountKeys.fromRoot(root);
    final buffers = [keys.root, keys.userKey, keys.itemWrapKey, keys.privateKeysKey, keys.manifestKey];
    expect(buffers.every((b) => b.any((byte) => byte != 0)), isTrue);
    keys.dispose();
    expect(keys.isDisposed, isTrue);
    for (final buffer in buffers) {
      expect(buffer.every((byte) => byte == 0), isTrue);
    }
    expect(() => keys.userKey, throwsStateError);
  });
}
