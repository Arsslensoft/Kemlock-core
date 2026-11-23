@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../../compat/before_cards/sync_merge.dart' as before_cards;

const now = 1_800_000_000_000;

const _card = {'id': 'c1', 'name': 'Everyday Visa', 'number': '4111111111111111', 'addedAt': 9};
const _identity = {
  'id': 'i1',
  'name': 'Me',
  'email': 'ada@example.org',
  'documents': [
    {'id': 'd1', 'type': 'passport', 'number': '123456789'},
  ],
  'addedAt': 9,
};
const _tombstoneOfACard = {'id': 'c-gone', 'at': 1_799_999_800_000};

OtpAccount _account(String id) => OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: 100);

/// A sync file a version with cards and identities wrote.
Map<String, Object?> _file() => jsonDecode(
  jsonEncode({
    'accounts': [_account('a1').toJson()],
    'backupServices': <Object?>[],
    'deleted': [_tombstoneOfACard],
    'cards': [_card],
    'identities': [_identity],
  }),
) as Map<String, Object?>;

// The frozen merge is what a phone that stays on the previous version runs,
// so these hold for it as they will for every later list it doesn't know.
void main() {
  group('the frozen merge of the version before cards', () {
    test('keeps both lists in the extra keys of SyncDoc and writes the file back as it was', () {
      final doc = before_cards.SyncDoc.fromJson(_file());

      expect(doc.extra['cards'], [_card]);
      expect(doc.extra['identities'], [_identity]);
      expect(before_cards.canonical(doc.toJson()), before_cards.canonical(_file()));
    });

    test('writes them back unchanged, with their deletion, when it merges', () {
      final remote = before_cards.SyncDoc.fromJson(_file());

      final merged = before_cards.mergeScope(before_cards.Lists(accounts: [_account('a1'), _account('a2')]), ['a1'], remote, now: now);

      final written = jsonDecode(jsonEncode(merged.doc.toJson())) as Map<String, Object?>;
      expect(written['cards'], [_card]);
      expect(written['identities'], [_identity]);
      expect(written['deleted'], [_tombstoneOfACard]);
      expect(merged.known, isNot(contains('c1')), reason: 'it never counts them as entries it holds, so never as ones it deleted');
    });
  });
}
