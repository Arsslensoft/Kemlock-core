@TestOn('vm')
library;

// Writes test/fixtures/vault/rotation/before.json and after-commit.json, and
// runs only when asked:
//
//   OUT=test/fixtures/vault/rotation flutter test test/vault/rotation_fixtures_generator_test.dart
//
// It ran once, when replace-vault-key-pair was built (its task 7.1), and the
// files it wrote are frozen: never run it again over them. It builds the
// storage by hand in the formats the store reads, from fixed seeds, rather
// than through VaultStore, so the fixtures also check those formats.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:test/test.dart';

/// [n] bytes for [label], always the same.
Uint8List _seeded(String label, int n) {
  final out = BytesBuilder();
  for (var i = 0; out.length < n; i++) {
    out.add(sha256.convert(utf8.encode('kemlock rotation fixture/$label/$i')).bytes);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, n));
}

/// [plain] sealed to [publicKey] as the store seals a value, from seeds named [label].
Future<String> _seal(List<int> plain, Uint8List publicKey, String label) async {
  final kem = MlKem1024.encapsulate(publicKey, _seeded('$label/m', 32));
  final sealed = await aesGcmEncrypt(kem.sharedSecret, plain, nonce: _seeded('$label/nonce', 12));
  return jsonEncode({'kemCT': b64(kem.cipherText), 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)});
}

Future<Map<String, Object?>> _wrapForKit(
  String kitId,
  Uint8List key,
  int threshold,
  int shares,
  String createdAt,
  Uint8List secret,
  String label,
) async {
  final sealed = await aesGcmEncrypt(key, secret, nonce: _seeded('$label/nonce', 12));
  return {
    'kitId': kitId,
    'threshold': threshold,
    'shares': shares,
    'createdAt': createdAt,
    'nonce': b64(sealed.nonce),
    'ct': b64(sealed.ct),
  };
}

const _password = 'fixture password';

/// What the vault holds, by base key, as each value's JSON.
final _values = <String, Object?>{
  'backmycodes_vault_data': [
    {'id': 'a1', 'type': 'totp', 'issuer': 'ACME', 'label': 'me', 'secret': 'JBSWY3DPEHPK3PXP', 'addedAt': 1763200000000},
  ],
  'backmycodes_backup_data': [
    {
      'id': 's1',
      'serviceName': 'GitHub',
      'codes': [
        {'code': 'abcd-1234', 'used': false},
      ],
      'addedAt': 1763200000000,
    },
  ],
  'backmycodes_note_data': [
    {'id': 'n1', 'title': 'Passport', 'text': 'In the drawer', 'addedAt': 1763200000000},
  ],
  'backmycodes_key_data': [
    {
      'id': 'k1',
      'name': 'laptop',
      'kind': 'ssh',
      'algorithm': 'ed25519',
      'privateKey': 'MC4CAQAwBQYDK2VwBCIEIA==',
      'publicKey': 'MCowBQYDK2VwAyEA',
      'origin': 'generated',
      'addedAt': 1763200000000,
    },
  ],
  'backmycodes_passkey_data': [
    {
      'id': 'p1',
      'credentialId': 'AAECAwQFBgcICQoLDA0ODw',
      'rpId': 'github.com',
      'userHandle': 'dXNlcg',
      'userName': 'octocat',
      'privateKey': 'MIGHAgEAMBMGByqGSM49AgEG',
      'addedAt': 1763200000000,
    },
  ],
  'backmycodes_sync': {'enabled': true, 'passphraseKey': 'c2VjcmV0'},
  'backmycodes_vaultwarden': {'server': 'https://vw.example', 'refreshToken': 'r'},
};

/// A value a newer version might add, whose plaintext re-encoding JSON would change.
const _futureKey = 'backmycodes_future_thing';
const _futurePlain = r'{"name":"café","n":1.0}';

void main() {
  final out = Platform.environment['OUT'];

  test('writes the key replacement fixtures to OUT', () async {
    final salt = _seeded('salt', 32);
    final kek = scrypt(utf8.encode(_password), salt, n: 131072, r: 8, p: 1);
    final old = MlKem1024.keygen(_seeded('old pair', 64));
    final next = MlKem1024.keygen(_seeded('new pair', 64));
    final oldKitKey = _seeded('old kit', 32);
    final newKitKey = _seeded('new kit', 32);
    const oldKit = (kitId: 'OLDKT', threshold: 2, shares: 3, createdAt: '2026-11-01T00:00:00.000Z');
    const newKit = (kitId: 'NEWKT', threshold: 2, shares: 3, createdAt: '2026-11-16T00:00:00.000Z');
    Map<String, Object?> kitRecord(({String kitId, int threshold, int shares, String createdAt}) kit, Uint8List key) => {
      'kitId': kit.kitId,
      'key': b64(key),
      'threshold': kit.threshold,
      'shares': kit.shares,
      'createdAt': kit.createdAt,
    };

    Future<Map<String, Object?>> config(
      ({Uint8List publicKey, Uint8List secretKey}) pair,
      String label,
      Map<String, Object?> recovery,
    ) async {
      final wrapped = await aesGcmEncrypt(kek, pair.secretKey, nonce: _seeded('$label/config', 12));
      return {
        'salt': b64(salt),
        'skNonce': b64(wrapped.nonce),
        'skEnc': b64(wrapped.ct),
        'publicKey': b64(pair.publicKey),
        'scrypt': {'N': 131072, 'r': 8, 'p': 1},
        'recovery': recovery,
      };
    }

    // Before: every kind, a 2-of-3 kit, a key of a newer version, and the biometric entry versions
    // before the hardware key wrote, which kept the seal key beside the private key it seals
    final sealKey = _seeded('seal key', 32);
    final native = await aesGcmEncrypt(sealKey, old.secretKey, nonce: _seeded('native', 12));
    final before = <String, String>{
      'backmycodes_vault_config': jsonEncode(
        await config(old, 'old', await _wrapForKit(oldKit.kitId, oldKitKey, 2, 3, oldKit.createdAt, old.secretKey, 'old kit wrap')),
      ),
      for (final MapEntry(:key, :value) in _values.entries) key: await _seal(utf8.encode(jsonEncode(value)), old.publicKey, 'old $key'),
      'backmycodes_recovery': await _seal(utf8.encode(jsonEncode(kitRecord(oldKit, oldKitKey))), old.publicKey, 'old recovery'),
      _futureKey: await _seal(utf8.encode(_futurePlain), old.publicKey, 'old future'),
      'backmycodes_native_bio': jsonEncode({'sealKey': b64(sealKey), 'nativeSkNonce': b64(native.nonce), 'nativeSkEnc': b64(native.ct)}),
    };

    // After the commit: the biometric entry gone, the old key under the new pair, the config on the
    // new pair with the new kit, the new kit's key written, and half the values sealed again
    const resealed = {'backmycodes_vault_data', 'backmycodes_backup_data', 'backmycodes_note_data'};
    final rotation = {'v': 1, 'previous': b64(old.secretKey), 'recovery': kitRecord(newKit, newKitKey), 'startedAt': 1763251200000};
    final afterCommit = <String, String>{
      'backmycodes_vault_config': jsonEncode(
        await config(next, 'new', await _wrapForKit(newKit.kitId, newKitKey, 2, 3, newKit.createdAt, next.secretKey, 'new kit wrap')),
      ),
      for (final MapEntry(:key, :value) in _values.entries)
        key: resealed.contains(key) ? await _seal(utf8.encode(jsonEncode(value)), next.publicKey, 'new $key') : before[key]!,
      'backmycodes_recovery': await _seal(utf8.encode(jsonEncode(kitRecord(newKit, newKitKey))), next.publicKey, 'new recovery'),
      _futureKey: before[_futureKey]!,
      'backmycodes_key_rotation': await _seal(utf8.encode(jsonEncode(rotation)), next.publicKey, 'rotation'),
    };

    const encoder = JsonEncoder.withIndent('  ');
    const frozen =
        'Written once by test/vault/rotation_fixtures_generator_test.dart, from fixed seeds, when '
        'replace-vault-key-pair was built, and never regenerated.';
    Map<String, Object?> kitOf(({String kitId, int threshold, int shares, String createdAt}) kit, Uint8List key) => {
      'kitId': kit.kitId,
      'key': b64(key),
      'threshold': kit.threshold,
      'shares': kit.shares,
    };
    final dir = Directory(out!)..createSync(recursive: true);
    File('${dir.path}/before.json').writeAsStringSync(
      '${encoder.convert({
        'about': '$frozen The storage of a vault from before this version: one of every kind, a 2-of-3 Recovery Kit, a sealed '
            'value under a key no version knows yet, and the biometric entry that kept its seal key beside the private key, '
            'with the real scrypt parameters. rotation_fixtures_test.dart opens it with the password and the kit, and '
            'replaces its key.',
        'password': _password,
        'kit': kitOf(oldKit, oldKitKey),
        'values': _values,
        'future': {'key': _futureKey, 'plain': _futurePlain},
        'storage': before,
      })}\n',
    );
    File('${dir.path}/after-commit.json').writeAsStringSync(
      '${encoder.convert({
        'about': '$frozen The vault of before.json with its key replaced and the app killed after the commit: the old key '
            'under the new pair, the config on the new pair and a new 2-of-3 kit, the new kit’s key written, and '
            'three of the nine sealed values sealed to the new pair. rotation_fixtures_test.dart opens it with the '
            'password and with the new kit, which finish the replacement.',
        'password': _password,
        'kit': kitOf(newKit, newKitKey),
        'oldKit': kitOf(oldKit, oldKitKey),
        'values': _values,
        'future': {'key': _futureKey, 'plain': _futurePlain},
        'storage': afterCommit,
      })}\n',
    );
  }, skip: out == null ? 'Writes the frozen fixtures; set OUT to run' : false);
}
