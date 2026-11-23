@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:kemlock_core/vault/key_unlock.dart';
import 'package:test/test.dart';

/// One file of test/fixtures/vault/key-unlock.
class KeyUnlockFixture {
  KeyUnlockFixture(String name)
    : json = jsonDecode(File('test/fixtures/vault/key-unlock/$name.json').readAsStringSync()) as Map<String, Object?>;

  final Map<String, Object?> json;

  String get password => json['password']! as String;
  Uint8List get keySecret => unb64(json['keySecret']! as String);
  Map<String, Object?> get config => json['config']! as Map<String, Object?>;
  String get rawConfig => jsonEncode(config);
  KeyUnlock get keyUnlock => KeyUnlock.of(config)!;

  /// Each enrolled key's output, in the order the config lists the keys.
  List<Uint8List> get outputs => [for (final output in (json['outputs']! as Map<String, Object?>).values) unb64(output! as String)];

  /// The private key under [wrapKey], or [AesGcmAuthError].
  Future<Uint8List> open(Uint8List wrapKey) =>
      aesGcmDecrypt(wrapKey, unb64(config['skNonce']! as String), unb64(config['skEnc']! as String));

  /// Whether [secretKey] is the private key the fixture was made with.
  bool isTheKey(Uint8List secretKey) => sha256.convert(secretKey).toString() == json['secretKeySha256'];
}

/// The fixtures by mode, as task 2.3 lists them.
const keyUnlockFixtures = ['password-with-key', 'key', 'both', 'both-two-keys'];

/// The password's key with the real parameters, which every fixture shares.
Uint8List fixturePasswordKey(KeyUnlockFixture fixture, [String? password]) =>
    scrypt(utf8.encode(password ?? fixture.password), unb64(fixture.config['salt']! as String), n: 131072, r: 8, p: 1);

Uint8List _flipped(Uint8List bytes) => Uint8List.fromList(bytes)..[7] ^= 0x10;

// openspec: add-security-key-unlock, task 2.3
void main() {
  late Uint8List passwordKey;
  late Uint8List wrongPasswordKey;

  setUpAll(() {
    final any = KeyUnlockFixture('both');
    passwordKey = fixturePasswordKey(any);
    wrongPasswordKey = fixturePasswordKey(any, 'another password');
  });

  Matcher refused() => throwsA(isA<AesGcmAuthError>());

  test('every fixture reads as the mode it was written in', () {
    final modes = {for (final name in keyUnlockFixtures) name: KeyUnlockFixture(name).keyUnlock.mode};
    expect(modes, {
      'password-with-key': UnlockMode.password,
      'key': UnlockMode.key,
      'both': UnlockMode.both,
      'both-two-keys': UnlockMode.both,
    });
    expect(KeyUnlockFixture('both-two-keys').keyUnlock.keys, hasLength(2));
  });

  test('every enrolled key’s output unwraps the stated key secret, and no other output does', () async {
    for (final name in keyUnlockFixtures) {
      final fixture = KeyUnlockFixture(name);
      final unlock = fixture.keyUnlock;
      expect(fixture.outputs, hasLength(unlock.keys.length));
      for (final (index, key) in unlock.keys.indexed) {
        expect(await unwrapKeySecret(key, fixture.outputs[index], unlock.salt), fixture.keySecret, reason: name);
        await expectLater(unwrapKeySecret(key, _flipped(fixture.outputs[index]), unlock.salt), refused(), reason: name);
        // Nor does the key secret itself
        await expectLater(unwrapKeySecret(key, fixture.keySecret, unlock.salt), refused(), reason: name);
      }
    }
  });

  test('"password" with a key enrolled opens with the password alone', () async {
    final fixture = KeyUnlockFixture('password-with-key');
    expect(fixture.isTheKey(await fixture.open(passwordKey)), isTrue);
    await expectLater(fixture.open(wrongPasswordKey), refused());
    await expectLater(fixture.open(keyModeWrapKey(fixture.keySecret, fixture.keyUnlock.salt)), refused());
  });

  test('"key" opens with the key secret, and with no password', () async {
    final fixture = KeyUnlockFixture('key');
    final salt = fixture.keyUnlock.salt;
    expect(fixture.isTheKey(await fixture.open(keyModeWrapKey(fixture.keySecret, salt))), isTrue);
    await expectLater(fixture.open(keyModeWrapKey(_flipped(fixture.keySecret), salt)), refused());
    await expectLater(fixture.open(passwordKey), refused());
    await expectLater(fixture.open(bothModeWrapKey(passwordKey, fixture.keySecret, salt)), refused());
    expect(fixture.keyUnlock.check, isNull);
  });

  for (final name in ['both', 'both-two-keys']) {
    test('"$name" opens with the password and the key secret together, and with neither alone', () async {
      final fixture = KeyUnlockFixture(name);
      final unlock = fixture.keyUnlock;
      expect(fixture.isTheKey(await fixture.open(bothModeWrapKey(passwordKey, fixture.keySecret, unlock.salt))), isTrue);
      // The password alone, the key alone, and each with the other wrong
      await expectLater(fixture.open(passwordKey), refused());
      await expectLater(fixture.open(keyModeWrapKey(fixture.keySecret, unlock.salt)), refused());
      await expectLater(fixture.open(bothModeWrapKey(wrongPasswordKey, fixture.keySecret, unlock.salt)), refused());
      await expectLater(fixture.open(bothModeWrapKey(passwordKey, _flipped(fixture.keySecret), unlock.salt)), refused());
      // The check tells the right password, and opens nothing
      expect(sameBytes(passwordCheck(passwordKey, unlock.salt), unlock.check!), isTrue);
      expect(sameBytes(passwordCheck(wrongPasswordKey, unlock.salt), unlock.check!), isFalse);
      await expectLater(fixture.open(unlock.check!), refused());
    });
  }

  test('each of two keys opens the vault on its own', () async {
    final fixture = KeyUnlockFixture('both-two-keys');
    final unlock = fixture.keyUnlock;
    for (final (index, key) in unlock.keys.indexed) {
      final keySecret = await unwrapKeySecret(key, fixture.outputs[index], unlock.salt);
      expect(fixture.isTheKey(await fixture.open(bothModeWrapKey(passwordKey, keySecret, unlock.salt))), isTrue);
    }
    await expectLater(unwrapKeySecret(unlock.keys[0], fixture.outputs[1], unlock.salt), refused());
    await expectLater(unwrapKeySecret(unlock.keys[1], fixture.outputs[0], unlock.salt), refused());
  });

  test('the fixtures are the bytes that were written', () {
    final digests = {
      for (final name in keyUnlockFixtures)
        name: sha256.convert(File('test/fixtures/vault/key-unlock/$name.json').readAsBytesSync()).toString(),
    };
    expect(digests, _digests);
  });
}

/// SHA-256 of each fixture file as it was written.
const _digests = <String, String>{
  'password-with-key': 'de7d8e06454f5d6a2f3ae422c635d37283f2f8045f23fe3f161aa18e02c2bf42',
  'key': 'ebd995d27aef44d347864003cbabd8fe620f78a708e34a09214326683a235e9c',
  'both': 'c419ec832b6f95509c888b33aea222a73442bbaec28e9be6787cfc58adf3a7d1',
  'both-two-keys': '6df11a93340ded868d5a59299aae3ee56fc510810275239e589253c4d06ff267',
};
