@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

/// What a sync file holds once a version keeps other people's public keys:
/// a `contacts` list of its own, and their deletions among the tombstones.
/// A phone on a version from before contacts must write all of it back as it
/// was, so the phones that read them lose nothing when it syncs in between.
///
/// This was written against the code from before contacts (the commit before
/// `sync_merge.dart` learned the list), where `contacts` is a key the
/// document does not know: it pins that such a key is kept and written back.
/// The made-up list below keeps that pinned for the lists that come later.
const _contacts = [
  {
    'id': 'c1',
    'name': 'Grace Hopper',
    'public': 'mDMEavvBvhYJKwYBBAHaRw8BAQdA5u9VJy0bk117b67pa3OynrS90v96RwuEYCascWUiiLk=',
    'source': 'qr',
    'checkedAt': 1_799_000_000_000,
    'checkedFingerprint': '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495',
    'addedAt': 8,
  },
];

const _madeUp = [
  {'id': 'h1', 'shape': 'cube', 'addedAt': 9},
];

const _tombstoneOfAContact = {'id': 'c-gone', 'at': 1_799_999_000_000};

const now = 1_800_000_000_000;

OtpAccount _account(String id, {int addedAt = 100, int? updatedAt}) =>
    OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: addedAt, updatedAt: updatedAt);

Map<String, Object?> _file(List<OtpAccount> accounts) => {
  'accounts': [for (final account in accounts) account.toJson()],
  'backupServices': <Object?>[],
  'deleted': [_tombstoneOfAContact],
  'contacts': _contacts,
  'holograms': _madeUp,
};

/// Round-trips [json] through `jsonEncode` so maps compare as plain JSON.
Object? _plain(Object? json) => jsonDecode(jsonEncode(json));

SyncDoc _read(Map<String, Object?> file) => SyncDoc.fromJson(_plain(file)! as Map<String, Object?>);

void main() {
  test('a file with a contacts list reads, and is written back as it was', () {
    final file = _file([_account('a1')]);

    expect(canonical(_read(file).toJson()), canonical(file));
  });

  test('merging a changed account writes the contacts and their deletion back as they were', () {
    final remote = _read(_file([_account('a1')]));

    final merged = mergeScope(
      Lists(
        accounts: [_account('a1', updatedAt: now - 5).copyWith(label: 'work')],
      ),
      ['a1'],
      remote,
      now: now,
    );

    final written = _plain(merged.doc.toJson())! as Map<String, Object?>;
    expect(written['contacts'], _plain(_contacts));
    expect(written['holograms'], _plain(_madeUp));
    expect(written['deleted'], [_tombstoneOfAContact]);
    expect((written['accounts']! as List<Object?>).single, containsPair('label', 'work'));
  });

  test('a list no version knows is never counted among the entries deleted here', () {
    final remote = _read(_file([_account('a1')]));

    final merged = mergeScope(Lists(accounts: [_account('a1')]), ['a1'], remote, now: now);

    expect(merged.known, contains('a1'));
    expect(merged.known, isNot(contains('h1')));
    expect([for (final tomb in merged.doc.deleted) tomb.id], ['c-gone']);
  });
}
