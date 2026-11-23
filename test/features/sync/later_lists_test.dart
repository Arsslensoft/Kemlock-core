@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../../compat/before_key_accounts/sync_merge.dart' as before_key_accounts;
import '../../compat/before_vault_items/sync_merge.dart' as old;

/// What a sync file holds once a later version adds keys, notes and passkeys
/// to it: three lists of its own, and their deletions among the tombstones.
/// A phone on this version must write all of it back as it was, so the
/// phones that read them lose nothing when it syncs in between.
const _later = <String, Object?>{
  'keys': [
    {
      'id': 'k1',
      'name': 'laptop',
      'kind': 'ssh',
      'algorithm': 'ed25519',
      'private': 'MC4CAQAwBQYDK2VwBCIEIA==',
      'public': 'MCowBQYDK2VwAyEA',
      'origin': 'generated',
      'addedAt': 5,
    },
  ],
  'notes': [
    {
      'id': 'n1',
      'title': 'Passport',
      'text': 'In the drawer',
      'addedAt': 6,
      'attachments': [
        {'id': 'f1', 'name': 'scan.pdf', 'size': 3, 'key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'addedAt': 6},
      ],
    },
  ],
  'passkeys': [
    {
      'id': 'p1',
      'credentialId': 'AAECAwQFBgcICQoLDA0ODw',
      'rpId': 'example.com',
      'userHandle': 'dXNlcg',
      'userName': 'me@example.com',
      'privateKey': 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQ==',
      'algorithm': -7,
      'addedAt': 7,
    },
  ],
};

/// What a later version adds once more: the accounts kept on a security
/// key, by name and with no secret (openspec: add-security-key-codes).
const _keyAccounts = [
  {
    'id': 'ka1',
    'device': '0102030405060708',
    'keyName': 'YubiKey 5C NFC',
    'name': 'Example:alice@example.org',
    'issuer': 'Example',
    'label': 'alice@example.org',
    'period': 30,
    'type': 'totp',
    'algorithm': 'SHA1',
    'tags': ['work'],
    'addedAt': 8,
  },
];

const _tombstoneOfAKeyAccount = {'id': 'ka-gone', 'at': 1_799_999_500_000};

const _tombstoneOfANote = {'id': 'n-gone', 'at': 1_799_999_000_000};

const now = 1_800_000_000_000;

OtpAccount _account(String id, {int addedAt = 100, int? updatedAt}) =>
    OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: addedAt, updatedAt: updatedAt);

Map<String, Object?> _file(List<OtpAccount> accounts, {List<Map<String, Object?>> deleted = const []}) => {
  'accounts': [for (final account in accounts) account.toJson()],
  'backupServices': <Object?>[],
  'deleted': [...deleted],
  ..._later,
};

/// Round-trips [json] through `jsonEncode` so maps compare as plain JSON.
Object? _plain(Object? json) => jsonDecode(jsonEncode(json));

void main() {
  // What a phone that stays on the version from before these items does,
  // with that version's own merge code
  group('a phone from before keys, notes and passkeys', () {
    test('keeps their lists in SyncDoc as they were', () {
      final file = _file([_account('a1')], deleted: [_tombstoneOfANote]);

      final doc = old.SyncDoc.fromJson(_plain(file)! as Map<String, Object?>);

      expect(old.canonical(doc.toJson()), old.canonical(file));
    });

    test('writes them back with their deletions when it merges', () {
      final remote = old.SyncDoc.fromJson(_plain(_file([_account('a1')], deleted: [_tombstoneOfANote]))! as Map<String, Object?>);

      final merged = old.mergeScope(old.Lists(accounts: [_account('a1'), _account('a2')]), ['a1'], remote, now: now);

      final written = _plain(merged.doc.toJson())! as Map<String, Object?>;
      for (final key in ['keys', 'notes', 'passkeys']) {
        expect(written[key], _plain(_later[key]), reason: key);
      }
      expect(written['deleted'], [_tombstoneOfANote]);
      expect([for (final account in written['accounts']! as List<Object?>) (account! as Map)['id']], ['a1', 'a2']);
    });

    test('never counts them as entries it deleted, nor as entries it holds', () {
      final remote = old.SyncDoc.fromJson(_plain(_file([_account('a1')]))! as Map<String, Object?>);

      final merged = old.mergeScope(old.Lists(accounts: [_account('a1')]), ['a1'], remote, now: now);

      expect(merged.known, ['a1']);
      expect(merged.doc.deleted, isEmpty);
    });

    test('keeps them when it deletes an account in the same run', () {
      final remote = old.SyncDoc.fromJson(_plain(_file([_account('a1'), _account('a2')]))! as Map<String, Object?>);

      final merged = old.mergeScope(old.Lists(accounts: [_account('a1')]), ['a1', 'a2'], remote, now: now);

      final written = _plain(merged.doc.toJson())! as Map<String, Object?>;
      expect(written['notes'], _plain(_later['notes']));
      expect([for (final tomb in merged.doc.deleted) tomb.id], ['a2']);
    });
  });

  // What a phone that stays on the version from before accounts on a
  // security key does, with that version's own merge code
  group('a phone from before accounts on a security key', () {
    Map<String, Object?> file() =>
        _plain({
              ..._file([_account('a1')], deleted: [_tombstoneOfAKeyAccount]),
              'keyAccounts': _keyAccounts,
            })!
            as Map<String, Object?>;

    test('keeps the keyAccounts list in the extra keys of SyncDoc, and writes the file back as it was', () {
      final doc = before_key_accounts.SyncDoc.fromJson(file());

      expect(doc.extra['keyAccounts'], _plain(_keyAccounts));
      expect(before_key_accounts.canonical(doc.toJson()), before_key_accounts.canonical(file()));
    });

    test('writes it back unchanged, with its deletions, when it merges', () {
      final remote = before_key_accounts.SyncDoc.fromJson(file());

      final merged = before_key_accounts.mergeScope(
        before_key_accounts.Lists(accounts: [_account('a1'), _account('a2')]),
        ['a1'],
        remote,
        now: now,
      );

      final written = _plain(merged.doc.toJson())! as Map<String, Object?>;
      expect(written['keyAccounts'], _plain(_keyAccounts));
      expect(written['deleted'], [_tombstoneOfAKeyAccount]);
      expect(merged.known, isNot(contains('ka1')), reason: 'it never counts them as entries it holds, so never as ones it deleted');
    });

    test('this version writes the same file back', () {
      final doc = SyncDoc.fromJson(file());

      expect(canonical(doc.toJson()), canonical(file()));
    });
  });

  // This version reads them, and writes them back the same way
  group('this version', () {
    test('reads the three lists, and writes the file back as it was', () {
      final file = _file([_account('a1')], deleted: [_tombstoneOfANote]);

      final doc = SyncDoc.fromJson(_plain(file)! as Map<String, Object?>);

      expect((doc.keys.single.name, doc.notes.single.title, doc.passkeys.single.rpId), ('laptop', 'Passport', 'example.com'));
      expect(doc.extra, isEmpty);
      expect(canonical(doc.toJson()), canonical(file));
    });

    test('takes them as entries it holds once merged', () {
      final remote = SyncDoc.fromJson(_plain(_file([_account('a1')]))! as Map<String, Object?>);

      final merged = mergeScope(Lists(accounts: [_account('a1')]), ['a1'], remote, now: now);

      expect(merged.known..sort(), ['a1', 'k1', 'n1', 'p1']);
      expect(merged.doc.deleted, isEmpty);
      for (final key in ['keys', 'notes', 'passkeys']) {
        expect((_plain(merged.doc.toJson())! as Map<String, Object?>)[key], _plain(_later[key]), reason: key);
      }
    });

    test('writes a file of codes alone without the three lists', () {
      final doc = SyncDoc(accounts: [_account('a1')]);

      expect(doc.toJson().keys, ['accounts', 'backupServices', 'deleted']);
    });
  });
}
