@TestOn('vm')
library;

// Writes test/fixtures/vault-items/export-with-key-accounts.json and
// export-with-key-accounts-plain.json, and runs only when asked:
//
//   OUT=test/fixtures/vault-items flutter test test/vault/key_accounts_fixtures_generator_test.dart
//
// It ran once, when add-security-key-codes was built (its task 8.2), and the
// files it wrote are frozen: never run it again over them. It writes them
// through exportVault and exportVaultPlaintext, with the real scrypt
// parameters, as the app does.
import 'dart:io';

import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

/// The password of the encrypted fixture, also in the fixtures' README.
const keyAccountsFixturePassword = 'fixture password';

const _account = OtpAccount(
  id: 'f3c1a9e2-5b7d-4e0a-9c1f-2d8b6a4e7c10',
  issuer: 'GitHub',
  label: 'adalovelace',
  secret: 'JBSWY3DPEHPK3PXP',
  addedAt: 1763251200000,
);

const _onKey = [
  KeyAccount(
    id: '7a2e4c91-0d3b-4f6a-8e5c-1b9d2f7a3c40',
    device: '0102030405060708',
    keyName: 'YubiKey 5C NFC',
    name: 'Bank:ada@example.org',
    issuer: 'Bank',
    label: 'ada@example.org',
    tags: ['money'],
    note: 'Backup codes in the safe',
    addedAt: 1763251200000,
    updatedAt: 1763254800000,
  ),
  KeyAccount(
    id: 'c5d8e1f2-3a4b-4c6d-9e0f-a1b2c3d4e5f6',
    device: '0102030405060708',
    keyName: 'YubiKey 5C NFC',
    name: '60/Mail server:root',
    issuer: 'Mail server',
    label: 'root',
    period: 60,
    algorithm: 'SHA256',
    touch: true,
    addedAt: 1763251200000,
  ),
  KeyAccount(
    id: '1e2f3a4b-5c6d-4e7f-8a9b-0c1d2e3f4a5b',
    device: '0102030405060708',
    keyName: 'YubiKey 5C NFC',
    name: 'Example:counter',
    issuer: 'Example',
    label: 'counter',
    type: KeyAccountType.hotp,
    addedAt: 1763251200000,
  ),
];

void main() {
  final out = Platform.environment['OUT'];

  test('writes the export fixtures with accounts on a security key to OUT', () async {
    final now = DateTime.utc(2026, 11, 16, 12);
    final dir = Directory(out!)..createSync(recursive: true);
    final encrypted = await exportVault(const [_account], const [], keyAccountsFixturePassword, keyAccounts: _onKey, now: now);
    File('${dir.path}/export-with-key-accounts.json').writeAsStringSync(encrypted);
    File('${dir.path}/export-with-key-accounts-plain.json')
        .writeAsStringSync(exportVaultPlaintext(const [_account], const [], keyAccounts: _onKey, now: now));
  }, skip: out == null ? 'Writes the frozen fixtures; set OUT to run' : false);
}
