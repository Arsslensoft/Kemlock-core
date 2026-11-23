import 'dart:io';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';

// What the fixtures of add-pgp-contacts under test/fixtures/vault-items were written from, once, by
// contacts_fixtures_generator_test.dart, and what the tests that open them expect to find.

/// When the fixtures say they were written.
final fixtureWrittenAt = DateTime.utc(2026, 11, 17, 12);

const fixtureAccounts = [OtpAccount(id: 'a1', issuer: 'ACME', label: 'me', secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', addedAt: 1)];
const fixtureServices = [
  BackupService(
    id: 's1',
    serviceName: 'GitHub',
    codes: [BackupCode(code: 'abcd-1234')],
    addedAt: 2,
  ),
];
const fixtureKeys = [
  VaultKey(
    id: 'k1',
    name: 'laptop',
    kind: KeyKind.ssh,
    algorithm: 'ed25519',
    privateKey: 'MC4CAQAwBQYDK2VwBCIEIA==',
    publicKey: 'MCowBQYDK2VwAyEA',
    origin: KeyOrigin.generated,
    addedAt: 3,
  ),
];
const fixtureNotes = [SecureNote(id: 'n1', title: 'Passport', text: 'In the drawer', addedAt: 4)];
const fixturePasskeys = [
  Passkey(
    id: 'p1',
    credentialId: 'AAECAwQFBgcICQoLDA0ODw',
    rpId: 'github.com',
    userHandle: 'dXNlcg',
    userName: 'octocat',
    privateKey: 'MIGHAgEAMBMGByqGSM49AgEG',
    addedAt: 5,
  ),
];

String _key(String file) => b64(readArmor(readPemBlocks(File('test/fixtures/keys/contacts/$file').readAsStringSync()).single));

/// Grace Hopper's key, checked on 3 November 2026 at 09:00 UTC, with a note, and Alan Turing's, never checked.
List<Contact> fixtureContacts() => [
  Contact(
    id: 'c1',
    name: 'Grace Hopper',
    publicKey: _key('grace-1.public.asc'),
    source: ContactSource.qr,
    checkedAt: 1793696400000,
    checkedFingerprint: '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495',
    note: 'Compared on a call',
    addedAt: 6,
    updatedAt: 1793696400000,
  ),
  Contact(id: 'c2', name: 'Alan Turing', publicKey: _key('alan.public.asc'), source: ContactSource.file, addedAt: 7),
];

/// The sync file of that vault's own scope: every kind, the two contacts, and the deletions of an account
/// and of a contact.
SyncDoc fixtureSyncDoc() => SyncDoc(
  accounts: fixtureAccounts,
  backupServices: fixtureServices,
  keys: fixtureKeys,
  notes: fixtureNotes,
  passkeys: fixturePasskeys,
  contacts: fixtureContacts(),
  deleted: const [
    Tombstone(id: 'a-gone', at: 1793600000000),
    Tombstone(id: 'c-gone', at: 1793650000000),
  ],
);
