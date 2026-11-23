@TestOn('vm')
library;

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../../compat/before_key_accounts/sync_merge.dart' as before_key_accounts;

const now = 1_800_000_000_000;

void main() {
  const given = OtpAccount(
    id: 'n1',
    issuer: 'Nextcloud',
    label: 'alice',
    secret: 'JBSWY3DPEHPK3PXP',
    addedAt: 1,
    updatedAt: 10,
    websites: ['cloud.example.org'],
  );

  test('an older phone that renames an account keeps its websites through sync', () {
    // A phone before websites holds the key with the others it doesn't know, and its edits keep them
    final older = OtpAccount.fromJson(given.toJson()..remove('websites')).copyWith(updatedAt: 10);
    final asOlderReadsIt = OtpAccount(
      id: older.id,
      issuer: older.issuer,
      label: older.label,
      secret: older.secret,
      addedAt: older.addedAt,
      updatedAt: older.updatedAt,
      extra: const {
        'websites': ['cloud.example.org'],
      },
    );
    final renamed = asOlderReadsIt.copyWith(issuer: 'Nextcloud (work)', updatedAt: 20);

    final remote = before_key_accounts.SyncDoc.fromJson({
      'accounts': [given.toJson()],
      'backupServices': <Object?>[],
    });
    final merged = before_key_accounts.mergeScope(before_key_accounts.Lists(accounts: [renamed]), ['n1'], remote, now: now);

    // What this version reads from the file the older phone wrote
    final read = SyncDoc.fromJson(merged.doc.toJson()).accounts.single;
    expect(read.issuer, 'Nextcloud (work)');
    expect(read.websites, ['cloud.example.org']);
    expect(read.extra, isEmpty);
  });

  test('this version merges an account’s websites like its other fields', () {
    final local = given.copyWith(websites: ['cloud.example.org', 'files.example.org'], updatedAt: 30);
    final remote = SyncDoc.fromJson({
      'accounts': [given.toJson()],
      'backupServices': <Object?>[],
    });
    final merged = mergeScope(Lists(accounts: [local]), ['n1'], remote, now: now);
    expect(merged.doc.accounts.single.websites, ['cloud.example.org', 'files.example.org']);
  });
}
