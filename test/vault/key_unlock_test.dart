@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/vault/key_unlock.dart';
import 'package:test/test.dart';

Uint8List _filled(int byte) => Uint8List.fromList(List.filled(32, byte));

/// [bytes] with one bit changed.
Uint8List _flipped(Uint8List bytes, [int at = 0]) => Uint8List.fromList(bytes)..[at] ^= 1;

// openspec: add-security-key-unlock, task 2.2
void main() {
  final salt = _filled(0x5a);
  final passwordKey = _filled(0x11);
  final keySecret = _filled(0x22);
  final output = _filled(0x33);

  group('the derivations', () {
    test('each gives a different key for the same inputs', () {
      final keys = {
        b64(keyWrapKey(keySecret, salt)),
        b64(keyModeWrapKey(keySecret, salt)),
        b64(passwordCheck(keySecret, salt)),
        b64(bothModeWrapKey(keySecret, keySecret, salt)),
        // The same 64 bytes as "both" takes, under the other labels
        b64(keyModeWrapKey(Uint8List.fromList([...keySecret, ...keySecret]), salt)),
      };
      expect(keys, hasLength(5));
      for (final key in keys) {
        expect(unb64(key), hasLength(32));
      }
    });

    test('each is the same for the same inputs, and another under another salt', () {
      expect(keyModeWrapKey(keySecret, salt), keyModeWrapKey(keySecret, salt));
      expect(bothModeWrapKey(passwordKey, keySecret, salt), bothModeWrapKey(passwordKey, keySecret, salt));
      expect(keyModeWrapKey(keySecret, salt), isNot(keyModeWrapKey(keySecret, _flipped(salt))));
      expect(passwordCheck(passwordKey, salt), isNot(passwordCheck(passwordKey, _flipped(salt))));
    });

    test('"both" changes when either the password’s key or the key secret changes by one bit', () {
      final both = bothModeWrapKey(passwordKey, keySecret, salt);
      for (final at in [0, 15, 31]) {
        expect(bothModeWrapKey(_flipped(passwordKey, at), keySecret, salt), isNot(both));
        expect(bothModeWrapKey(passwordKey, _flipped(keySecret, at), salt), isNot(both));
      }
    });

    test('the password check is not the key that wraps anything', () {
      final check = passwordCheck(passwordKey, salt);
      expect(check, isNot(passwordKey));
      expect(check, isNot(bothModeWrapKey(passwordKey, keySecret, salt)));
    });

    test('sameBytes tells equal lists from different ones', () {
      expect(sameBytes(output, _filled(0x33)), isTrue);
      expect(sameBytes(output, _flipped(output, 31)), isFalse);
      expect(sameBytes(output, output.sublist(1)), isFalse);
    });
  });

  group('wrapping the key secret', () {
    Future<EnrolledKey> entry() async {
      final wrap = await wrapKeySecret(keySecret, output, salt);
      return EnrolledKey(
        id: '0011223344556677',
        credential: _filled(0xc0),
        nonce: wrap.nonce,
        ct: wrap.ct,
        name: 'Example Key',
        addedAt: 1794000000000,
        pinBound: true,
      );
    }

    test('opens with the output that made it', () async {
      expect(await unwrapKeySecret(await entry(), output, salt), keySecret);
    });

    test('opens with no other output, and under no other salt', () async {
      final key = await entry();
      await expectLater(unwrapKeySecret(key, _flipped(output), salt), throwsA(isA<AesGcmAuthError>()));
      await expectLater(unwrapKeySecret(key, keySecret, salt), throwsA(isA<AesGcmAuthError>()));
      await expectLater(unwrapKeySecret(key, output, _flipped(salt)), throwsA(isA<AesGcmAuthError>()));
    });
  });

  group('keyUnlock', () {
    Map<String, Object?> json({String mode = 'both'}) => {
      'v': 1,
      'mode': mode,
      'salt': b64(salt),
      if (mode == 'both') 'check': b64(passwordCheck(passwordKey, salt)),
      'keys': [
        {
          'id': '0011223344556677',
          'credential': b64(_filled(0xc0)),
          'nonce': b64(Uint8List(12)),
          'ct': b64(Uint8List(48)),
          'name': 'YubiKey 5C NFC',
          'addedAt': 1794000000000,
          'pinBound': true,
        },
      ],
    };

    test('reads what it writes', () {
      final parsed = KeyUnlock.parse(json())!;
      expect(parsed.mode, UnlockMode.both);
      expect(parsed.salt, salt);
      expect(parsed.check, passwordCheck(passwordKey, salt));
      expect(parsed.keys.single.name, 'YubiKey 5C NFC');
      expect(parsed.keys.single.pinBound, isTrue);
      expect(parsed.keyFor(_filled(0xc0)), same(parsed.keys.single));
      expect(parsed.keyFor(_filled(0xc1)), isNull);
      expect(jsonEncode(parsed.toJson()), jsonEncode(json()));
    });

    test('reads each mode, and keeps a check only with both', () {
      for (final mode in UnlockMode.values) {
        final parsed = KeyUnlock.parse({...json(mode: mode.name), 'check': b64(_filled(1))})!;
        expect(parsed.mode, mode);
        expect(parsed.check == null, mode != UnlockMode.both);
        expect(parsed.toJson().containsKey('check'), mode == UnlockMode.both);
      }
    });

    test('keeps the members it does not know through parse and toJson', () {
      final future = json();
      future['later'] = {
        'a': [1, 2, 3],
      };
      (future['keys']! as List<Object?>).single as Map<String, Object?>
        ..['transport'] = 'nfc'
        ..['counter'] = 7;
      final written = KeyUnlock.parse(jsonDecode(jsonEncode(future)))!.toJson();
      expect(written['later'], {
        'a': [1, 2, 3],
      });
      final key = (written['keys']! as List<Object?>).single! as Map<String, Object?>;
      expect(key['transport'], 'nfc');
      expect(key['counter'], 7);
      // And again through a rename and a change of mode
      final changed = KeyUnlock.parse(written)!;
      final renamed = changed.copyWith(mode: UnlockMode.key, keys: [changed.keys.single.renamed('Spare')]).toJson();
      expect(renamed['later'], isNotNull);
      expect(((renamed['keys']! as List<Object?>).single! as Map<String, Object?>)['transport'], 'nfc');
      expect(renamed.containsKey('check'), isFalse);
    });

    test('a malformed one reads as absent', () {
      Map<String, Object?> without(String member) => json()..remove(member);
      Map<String, Object?> withKey(Map<String, Object?> change) => json()
        ..['keys'] = [
          {...(json()['keys']! as List<Object?>).single! as Map<String, Object?>, ...change},
        ];
      final malformed = <Object?>[
        null,
        'both',
        <Object?>[],
        {...json(), 'v': 2},
        {...json(), 'v': '1'},
        {...json(), 'mode': 'later'},
        {...json(), 'salt': b64(Uint8List(16))},
        {...json(), 'salt': 'not base64 !'},
        {...json(), 'check': b64(Uint8List(8))},
        {...json(), 'keys': <Object?>[]},
        {...json(), 'keys': 'none'},
        without('mode'),
        without('salt'),
        without('keys'),
        without('check'),
        withKey({'id': ''}),
        withKey({'credential': 7}),
        withKey({'credential': ''}),
        withKey({'nonce': null}),
        withKey({'ct': '***'}),
      ];
      for (final value in malformed) {
        expect(KeyUnlock.parse(value), isNull, reason: '$value');
      }
      expect(KeyUnlock.of(null), isNull);
      expect(KeyUnlock.of({'salt': 'x'}), isNull);
      expect(KeyUnlock.of({'keyUnlock': json()}), isNotNull);
    });
  });

  test('the modes say what they need', () {
    expect(UnlockMode.password.needsKey, isFalse);
    expect(UnlockMode.key.needsKey, isTrue);
    expect(UnlockMode.both.needsKey, isTrue);
    expect(UnlockMode.key.hasPassword, isFalse);
    expect(UnlockMode.both.hasPassword, isTrue);
    expect(UnlockMode.fromName('nothing'), isNull);
  });
}
