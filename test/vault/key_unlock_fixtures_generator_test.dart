@TestOn('vm')
library;

// Writes test/fixtures/vault/key-unlock/, and runs only when asked:
//
//   OUT=test/fixtures/vault/key-unlock flutter test test/vault/key_unlock_fixtures_generator_test.dart
//
// It ran once, when add-security-key-unlock was built (its task 2.3), and
// the files it wrote are frozen: never run it again over them. It builds
// each config by hand in the format the store reads, from fixed seeds and
// with the real scrypt parameters, rather than through VaultStore, so the
// fixtures also check that format and the derivations of key_unlock.dart.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:kemlock_core/vault/key_unlock.dart';
import 'package:test/test.dart';

/// [n] bytes for [label], always the same.
Uint8List _seeded(String label, int n) {
  final out = BytesBuilder();
  for (var i = 0; out.length < n; i++) {
    out.add(sha256.convert(utf8.encode('kemlock key unlock fixture/$label/$i')).bytes);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, n));
}

const _password = 'fixture password';

void main() {
  final out = Platform.environment['OUT'];

  test('writes the key unlock fixtures to OUT', () async {
    final scryptSalt = _seeded('scrypt salt', 32);
    final passwordKey = scrypt(utf8.encode(_password), scryptSalt, n: 131072, r: 8, p: 1);
    final pair = MlKem1024.keygen(_seeded('pair', 64));
    final keySecret = _seeded('key secret', 32);
    final salt = _seeded('key unlock salt', 32);
    final outputs = {'first': _seeded('output/first', 32), 'second': _seeded('output/second', 32)};
    final credentials = {'first': _seeded('credential/first', 64), 'second': _seeded('credential/second', 48)};

    Future<Map<String, Object?>> entry(String key, {required bool pinBound}) async {
      final wrap = await aesGcmEncrypt(keyWrapKey(outputs[key]!, salt), keySecret, nonce: _seeded('wrap nonce/$key', 12));
      return {
        'id': _seeded('id/$key', 8).map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(),
        'credential': b64(credentials[key]!),
        'nonce': b64(wrap.nonce),
        'ct': b64(wrap.ct),
        'name': key == 'first' ? 'YubiKey 5C NFC' : 'Spare key',
        'addedAt': key == 'first' ? 1794000000000 : 1794000600000,
        'pinBound': pinBound,
      };
    }

    Future<Map<String, Object?>> config(String name, UnlockMode mode, List<String> keys) async {
      final wrapKey = switch (mode) {
        UnlockMode.password => passwordKey,
        UnlockMode.key => keyModeWrapKey(keySecret, salt),
        UnlockMode.both => bothModeWrapKey(passwordKey, keySecret, salt),
      };
      final wrapped = await aesGcmEncrypt(wrapKey, pair.secretKey, nonce: _seeded('sk nonce/$name', 12));
      return {
        'salt': b64(scryptSalt),
        'skNonce': b64(wrapped.nonce),
        'skEnc': b64(wrapped.ct),
        'publicKey': b64(pair.publicKey),
        'scrypt': {'N': 131072, 'r': 8, 'p': 1},
        'keyUnlock': {
          'v': 1,
          'mode': mode.name,
          'salt': b64(salt),
          if (mode == UnlockMode.both) 'check': b64(passwordCheck(passwordKey, salt)),
          'keys': [for (final key in keys) await entry(key, pinBound: true)],
        },
      };
    }

    const encoder = JsonEncoder.withIndent('  ');
    const frozen =
        'Written once by test/vault/key_unlock_fixtures_generator_test.dart, from fixed seeds and with the real scrypt '
        'parameters, when add-security-key-unlock was built, and never regenerated.';
    final dir = Directory(out!)..createSync(recursive: true);
    final files = <String, (String, UnlockMode, List<String>)>{
      'password-with-key.json': (
        'A vault that still opens with its password, with one key enrolled: the state between enrolling a key and turning a mode on.',
        UnlockMode.password,
        ['first'],
      ),
      'key.json': ('A vault that opens with a security key alone.', UnlockMode.key, ['first']),
      'both.json': ('A vault that needs its password and a security key.', UnlockMode.both, ['first']),
      'both-two-keys.json': (
        'A vault that needs its password and one of two security keys, each of which opens it on its own.',
        UnlockMode.both,
        ['first', 'second'],
      ),
    };
    for (final MapEntry(key: file, value: (about, mode, keys)) in files.entries) {
      File('${dir.path}/$file').writeAsStringSync(
        '${encoder.convert({
          'about': '$frozen $about key_unlock_fixtures_test.dart opens it with the secrets below and refuses it without each.',
          'password': _password,
          'keySecret': b64(keySecret),
          'outputs': {for (final key in keys) key: b64(outputs[key]!)},
          'secretKeySha256': sha256.convert(pair.secretKey).toString(),
          'config': await config(file, mode, keys),
        })}\n',
      );
    }
    File('${dir.path}/README.md').writeAsStringSync(
      [
        '# Key unlock fixtures',
        '',
        frozen,
        '',
        'Each file holds one vault config (`config`), as `backmycodes_vault_config` stores it, in one way of',
        'opening of add-security-key-unlock, and the secrets that open it. The four configs hold the same',
        'ML-KEM-1024 key pair, whose private key has the SHA-256 `${sha256.convert(pair.secretKey)}`.',
        '',
        '| File | Mode | Keys enrolled |',
        '|---|---|---|',
        for (final MapEntry(key: file, value: (_, mode, keys)) in files.entries) '| `$file` | `${mode.name}` | ${keys.join(', ')} |',
        '',
        'The secrets, the same in every file:',
        '',
        '- the password: `$_password` (scrypt N=131072, r=8, p=1, with the config\'s `salt`);',
        '- the key secret, base64: `${b64(keySecret)}`;',
        '- the `hmac-secret` output of the first key, base64: `${b64(outputs['first']!)}`;',
        '- the `hmac-secret` output of the second key, base64: `${b64(outputs['second']!)}`.',
        '',
        'These are test values made from fixed seeds. No real key gave them.',
        '',
      ].join('\n'),
    );
  }, skip: out == null ? 'Set OUT to the fixture folder to write the fixtures.' : false);
}
