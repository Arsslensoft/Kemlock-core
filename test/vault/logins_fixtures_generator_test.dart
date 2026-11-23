@TestOn('vm')
library;

// Writes the fixtures of test/fixtures/logins, and runs only when asked:
//
//   OUT=test/fixtures/logins flutter test test/vault/logins_fixtures_generator_test.dart
//
// It ran once, when add-passwords was built (its task 7.7), and the files it
// wrote are frozen: never run it again over them. The exports go through
// exportVault and exportVaultPlaintext with the real scrypt parameters, the
// sync files through encryptSyncFile with fixed nonces, and the vault's
// storage is built by hand from fixed seeds in the formats the store reads,
// as card_key_fixture_generator_test.dart builds its own, so the fixture
// checks those formats too.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

import 'logins_fixture_inputs.dart';

/// [n] bytes for [label], always the same.
Uint8List _seeded(String label, int n) {
  final out = BytesBuilder();
  for (var i = 0; out.length < n; i++) {
    out.add(sha256.convert(utf8.encode('kemlock logins fixture/$label/$i')).bytes);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, n));
}

/// [plain] sealed to [publicKey] as the store seals a value, from seeds named [label].
Future<String> _seal(List<int> plain, Uint8List publicKey, String label) async {
  final kem = MlKem1024.encapsulate(publicKey, _seeded('$label/m', 32));
  final sealed = await aesGcmEncrypt(kem.sharedSecret, plain, nonce: _seeded('$label/nonce', 12));
  return jsonEncode({'kemCT': b64(kem.cipherText), 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)});
}

const _indent = JsonEncoder.withIndent('  ');

void main() {
  final out = Platform.environment['OUT'];
  final skip = out == null ? 'Writes the frozen fixtures; set OUT to run' : null;
  final logins = [loginsFixtureMail, loginsFixtureApp, loginsFixtureShared];

  test('writes the exports holding logins', () async {
    File('$out/export-with-logins.json').writeAsStringSync(
      await exportVault(const [loginsFixtureAccount], const [], loginsFixturePassword, logins: logins, now: loginsFixtureWrittenAt),
    );
    File('$out/export-with-logins-plain.json')
        .writeAsStringSync(exportVaultPlaintext(const [loginsFixtureAccount], const [], logins: logins, now: loginsFixtureWrittenAt));
  }, skip: skip);

  test('writes the sync files of the vault and of its space', () async {
    Future<Map<String, Object?>> file(String label, SyncDoc doc) async {
      final key = _seeded('$label/key', 32);
      return {'key': b64(key), 'file': await encryptSyncFile(doc, key, random: (n) => _seeded('$label/nonce', n))};
    }

    final own = SyncDoc(
      accounts: const [loginsFixtureAccount],
      logins: [loginsFixtureMail, loginsFixtureApp],
      deleted: [Tombstone.fromJson(loginsFixtureDeleted)],
    );
    final space = SyncDoc(logins: [loginsFixtureShared]);
    final fixture = {
      'about':
          'Written once by test/vault/logins_fixtures_generator_test.dart when logins joined sync (openspec: add-passwords), '
          'and never regenerated. Two sync files, each with its 32-byte key: the vault\'s own and its space fam\'s.',
      'own': await file('own', own),
      'space': await file('space', space),
    };
    File('$out/sync-with-logins.json').writeAsStringSync('${_indent.convert(fixture)}\n');
  }, skip: skip);

  test('writes the storage of a vault holding logins and a generated password', () async {
    final salt = _seeded('salt', 32);
    final kek = scrypt(utf8.encode(loginsFixturePassword), salt, n: 131072, r: 8, p: 1);
    final pair = MlKem1024.keygen(_seeded('pair', 64));
    final wrapped = await aesGcmEncrypt(kek, pair.secretKey, nonce: _seeded('config', 12));
    final storage = {
      'backmycodes_vault_config': jsonEncode({
        'salt': b64(salt),
        'skNonce': b64(wrapped.nonce),
        'skEnc': b64(wrapped.ct),
        'publicKey': b64(pair.publicKey),
        'scrypt': {'N': 131072, 'r': 8, 'p': 1},
      }),
      'backmycodes_login_data': await _seal(
        utf8.encode(jsonEncode([for (final login in logins) login.toJson()])),
        pair.publicKey,
        'logins',
      ),
      'backmycodes_generated_data': await _seal(utf8.encode(jsonEncode([loginsFixtureGenerated.toJson()])), pair.publicKey, 'generated'),
    };
    final fixture = {
      'about':
          'Written once by test/vault/logins_fixtures_generator_test.dart, from fixed seeds, when add-passwords was built, '
          'and never regenerated. The storage of a vault holding three logins and a password AutoFill generated, with the '
          'real scrypt parameters. logins_fixtures_test.dart opens it with the password, and replaces its key.',
      'password': loginsFixturePassword,
      'storage': storage,
    };
    File('$out/vault-with-logins.json').writeAsStringSync('${_indent.convert(fixture)}\n');
  }, skip: skip);
}
