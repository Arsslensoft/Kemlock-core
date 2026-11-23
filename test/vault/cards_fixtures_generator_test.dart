@TestOn('vm')
library;

// Writes the fixtures of test/fixtures/cards, and runs only when asked:
//
//   OUT=test/fixtures/cards flutter test test/vault/cards_fixtures_generator_test.dart
//
// Sealed and encrypted files can't be written by hand, so they come from this
// generator, run once in the single build-and-test pass after the
// add-cards-identities-and-websites plan is merged. They are frozen from then
// on: never run it again over them. The storage is built by hand from fixed
// seeds in the formats the store reads, as logins_fixtures_generator_test.dart
// builds its own.
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

import 'cards_fixture_inputs.dart';

/// [n] bytes for [label], always the same.
Uint8List _seeded(String label, int n) {
  final out = BytesBuilder();
  for (var i = 0; out.length < n; i++) {
    out.add(sha256.convert(utf8.encode('kemlock cards fixture/$label/$i')).bytes);
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
  final cards = [cardsFixtureVisa, cardsFixtureMinimal, cardsFixtureShared];
  final identities = [cardsFixtureMe, cardsFixtureWork, cardsFixtureFamily];

  test('writes the exports holding cards and identities', () async {
    File('$out/export-with-cards.json').writeAsStringSync(
      await exportVault(
        const [cardsFixtureAccount],
        const [],
        cardsFixturePassword,
        cards: cards,
        identities: identities,
        now: cardsFixtureWrittenAt,
      ),
    );
    File('$out/export-with-cards-plain.json').writeAsStringSync(
      exportVaultPlaintext(const [cardsFixtureAccount], const [], cards: cards, identities: identities, now: cardsFixtureWrittenAt),
    );
  }, skip: skip);

  test('writes the sync files of the vault and of its space', () async {
    Future<Map<String, Object?>> file(String label, SyncDoc doc) async {
      final key = _seeded('$label/key', 32);
      return {'key': b64(key), 'file': await encryptSyncFile(doc, key, random: (n) => _seeded('$label/nonce', n))};
    }

    final own = SyncDoc(
      accounts: const [cardsFixtureAccount],
      cards: [cardsFixtureVisa, cardsFixtureMinimal],
      identities: [cardsFixtureMe, cardsFixtureWork],
      deleted: [Tombstone.fromJson(cardsFixtureDeleted)],
    );
    final space = SyncDoc(cards: [cardsFixtureShared], identities: [cardsFixtureFamily]);
    final fixture = {
      'about':
          'Written once by test/vault/cards_fixtures_generator_test.dart when cards and identities joined sync (the '
          'add-cards-identities-and-websites plan), and never regenerated. Two sync files, each with its 32-byte key: '
          'the vault own and its space fam.',
      'own': await file('own', own),
      'space': await file('space', space),
    };
    File('$out/sync-with-cards.json').writeAsStringSync('${_indent.convert(fixture)}\n');
  }, skip: skip);

  test('writes the storage of a vault holding cards and identities', () async {
    final salt = _seeded('salt', 32);
    final kek = scrypt(utf8.encode(cardsFixturePassword), salt, n: 131072, r: 8, p: 1);
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
      'backmycodes_card_data': await _seal(utf8.encode(jsonEncode([for (final card in cards) card.toJson()])), pair.publicKey, 'cards'),
      'backmycodes_identity_data': await _seal(
        utf8.encode(jsonEncode([for (final identity in identities) identity.toJson()])),
        pair.publicKey,
        'identities',
      ),
    };
    final fixture = {
      'about':
          'Written once by test/vault/cards_fixtures_generator_test.dart, from fixed seeds, for the '
          'add-cards-identities-and-websites plan, and never regenerated. The storage of a vault holding three cards '
          'and three identities, with the real scrypt parameters. cards_fixtures_test.dart opens it with the password, '
          'and replaces its key.',
      'password': cardsFixturePassword,
      'storage': storage,
    };
    File('$out/vault-with-cards.json').writeAsStringSync('${_indent.convert(fixture)}\n');
  }, skip: skip);
}
