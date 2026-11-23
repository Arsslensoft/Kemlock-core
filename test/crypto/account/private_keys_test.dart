@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/private_keys.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

void main() {
  final key = Uint8List.fromList(List.generate(32, (i) => 0x40 + i));
  final kx1Private = Uint8List.fromList(List.generate(96, (i) => i));
  final sig1Private = Uint8List.fromList(List.generate(64, (i) => 0xc0 + i));
  final accountId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ab');
  final nonce = Uint8List.fromList(List.generate(12, (i) => 0x20 + i));

  Future<Uint8List> seal({Uint8List? sealKey, List<int>? id, int keyVersion = 1}) => sealPrivateKeys(
    privateKeysKey: sealKey ?? key,
    accountId: id ?? accountId,
    keyVersion: keyVersion,
    kx1PrivateKey: kx1Private,
    sig1PrivateKey: sig1Private,
  );

  Future<PrivateKeys> open(Uint8List sealed, {Uint8List? sealKey, List<int>? id, int keyVersion = 1}) =>
      openPrivateKeys(privateKeysKey: sealKey ?? key, accountId: id ?? accountId, keyVersion: keyVersion, sealed: sealed);

  test('the sizes are 161 bytes of plaintext and 189 sealed', () {
    expect(privateKeysPlaintextLength, 161);
    expect(sealedPrivateKeysLength, 189);
  });

  test('seals u8(1), the kx1 private key and the sig1 private key under the aad crypto.md gives', () async {
    final sealed = await sealPrivateKeys(
      privateKeysKey: key,
      accountId: accountId,
      keyVersion: 7,
      kx1PrivateKey: kx1Private,
      sig1PrivateKey: sig1Private,
      nonce: nonce,
    );
    // plaintext and aad written out by hand
    final plaintext = [1, ...kx1Private, ...sig1Private];
    final aad = [...utf8.encode('kemlock/v1/private-keys'), ...accountId, 0, 0, 0, 7];
    expect(plaintext, hasLength(161));
    final expected = await aesGcmEncrypt(key, plaintext, nonce: nonce, aad: aad);
    expect(sealed, [...nonce, ...expected.ct]);
    expect(sealed, hasLength(189));
  });

  test('opens with the same key, account id and key version', () async {
    final keys = await open(await seal(keyVersion: 4), keyVersion: 4);
    expect(keys.kx1PrivateKey, kx1Private);
    expect(keys.sig1PrivateKey, sig1Private);
  });

  test('opens under the private-keys child of an account', () async {
    final keys = AccountKeys.fromRoot(Uint8List.fromList(List.generate(64, (i) => i)));
    final sealed = await seal(sealKey: keys.privateKeysKey);
    expect((await open(sealed, sealKey: keys.privateKeysKey)).sig1PrivateKey, sig1Private);
    await expectLater(open(sealed, sealKey: keys.itemWrapKey), throwsA(isA<CorruptedException>()));
    keys.dispose();
  });

  test('sealing twice gives different bytes', () async {
    expect(await seal(), isNot(await seal()));
  });

  test('another key, account id or key version fails as corrupted', () async {
    final sealed = await seal();
    await expectLater(open(sealed, sealKey: Uint8List.fromList(key)..[0] ^= 1), throwsA(isA<CorruptedException>()));
    await expectLater(open(sealed, id: uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ac')), throwsA(isA<CorruptedException>()));
    await expectLater(open(sealed, keyVersion: 2), throwsA(isA<CorruptedException>()));
  });

  test('a changed byte fails as corrupted', () async {
    final sealed = await seal();
    for (final index in [0, 11, 12, 100, 172, 173, 188]) {
      await expectLater(open(Uint8List.fromList(sealed)..[index] ^= 1), throwsA(isA<CorruptedException>()), reason: 'byte $index');
    }
  });

  test('a sealed value of the wrong length is malformed', () async {
    final sealed = await seal();
    await expectLater(open(sealed.sublist(0, 188)), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List.fromList([...sealed, 0])), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List(0)), throwsA(isA<MalformedException>()));
  });

  test('a version byte other than 1 is malformed, though the tag verifies', () async {
    final aad = [...utf8.encode('kemlock/v1/private-keys'), ...accountId, 0, 0, 0, 1];
    for (final version in [0, 2, 255]) {
      final forged = await aesGcmEncrypt(key, [version, ...kx1Private, ...sig1Private], nonce: nonce, aad: aad);
      await expectLater(open(Uint8List.fromList([...nonce, ...forged.ct])), throwsA(isA<MalformedException>()), reason: 'version $version');
    }
  });

  test('keys of the wrong length or a wrong id are refused before sealing', () async {
    await expectLater(
      sealPrivateKeys(privateKeysKey: key, accountId: accountId, keyVersion: 1, kx1PrivateKey: Uint8List(95), sig1PrivateKey: sig1Private),
      throwsA(isA<MalformedException>()),
    );
    await expectLater(
      sealPrivateKeys(privateKeysKey: key, accountId: accountId, keyVersion: 1, kx1PrivateKey: kx1Private, sig1PrivateKey: Uint8List(65)),
      throwsA(isA<MalformedException>()),
    );
    await expectLater(seal(sealKey: Uint8List(31)), throwsA(isA<MalformedException>()));
    await expectLater(seal(id: Uint8List(15)), throwsA(isA<MalformedException>()));
  });
}
