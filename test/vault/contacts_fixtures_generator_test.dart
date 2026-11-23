@TestOn('vm')
library;

// Writes the fixtures of add-pgp-contacts under test/fixtures/vault-items, and
// runs only when asked:
//
//   OUT=test/fixtures/vault-items WRITE=before flutter test test/vault/contacts_fixtures_generator_test.dart
//
// Each ran once, when add-pgp-contacts was built, and the files are frozen:
// never run it again over them.
//
// - WRITE=before wrote export-plain-before-contacts.json with the code from
//   before vault_export.dart knew contacts (the commit before its task 6.1):
//   what a vault without contacts exported then, which it must still export
//   byte for byte.
// - WRITE=export wrote export-with-contacts.json (task 6.4): a plain export
//   of a vault holding a checked and an unchecked contact.
// - WRITE=sync wrote sync-with-contacts.json (task 7.3): the sync file of
//   the same vault, decrypted.
import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

import 'contacts_fixture_inputs.dart';

void main() {
  final out = Platform.environment['OUT'];
  final write = Platform.environment['WRITE'];
  String? skip(String what) => out == null || write != what ? 'Writes a frozen fixture; set OUT and WRITE=$what to run' : null;

  test('writes what a vault without contacts exported before contacts', () {
    File('$out/export-plain-before-contacts.json').writeAsStringSync(
      exportVaultPlaintext(
        fixtureAccounts,
        fixtureServices,
        keys: fixtureKeys,
        notes: fixtureNotes,
        passkeys: fixturePasskeys,
        now: fixtureWrittenAt,
      ),
    );
  }, skip: skip('before'));

  test('writes a plain export holding contacts', () {
    File('$out/export-with-contacts.json').writeAsStringSync(
      exportVaultPlaintext(
        fixtureAccounts,
        fixtureServices,
        keys: fixtureKeys,
        notes: fixtureNotes,
        passkeys: fixturePasskeys,
        contacts: fixtureContacts(),
        now: fixtureWrittenAt,
      ),
    );
  }, skip: skip('export'));

  test('writes the sync file of a vault holding contacts, decrypted', () {
    File('$out/sync-with-contacts.json').writeAsStringSync(const JsonEncoder.withIndent('  ').convert(fixtureSyncDoc().toJson()));
  }, skip: skip('sync'));
}
