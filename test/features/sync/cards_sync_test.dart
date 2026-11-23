@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:test/test.dart';

import '../../compat/before_cards/sync_merge.dart' as before_cards;

const now = 1_800_000_000_000;

const _visa = PaymentCard(id: 'c1', name: 'Everyday Visa', number: '4111111111111111', expMonth: 5, expYear: 2029, code: '123', addedAt: 9);
const _me = Identity(
  id: 'i1',
  name: 'Me',
  email: 'ada@example.org',
  documents: [IdentityDocument(id: 'd1', type: 'passport', number: '123456789')],
  addedAt: 9,
);
const _login = Login(id: 'l1', name: 'Larkspur Mail', username: 'ada@example.org', password: 'hunter2', addedAt: 9);

OtpAccount _account(String id) => OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: 100);

Map<String, Object?> _json(Object? value) => jsonDecode(jsonEncode(value)) as Map<String, Object?>;

// the add-cards-identities-and-websites plan, task 3.2
void main() {
  group('a file', () {
    test('without cards or identities is written as the frozen merge writes it', () {
      final doc = SyncDoc(
        accounts: [_account('a1')],
        logins: const [_login],
        deleted: [Tombstone(id: 'x', at: 5)],
      );
      final frozen = before_cards.SyncDoc(
        accounts: [_account('a1')],
        logins: const [_login],
        deleted: [before_cards.Tombstone(id: 'x', at: 5)],
      );

      expect(canonical(doc.toJson()), before_cards.canonical(frozen.toJson()));
      expect(doc.toJson().keys, isNot(contains('cards')));
      expect(doc.toJson().keys, isNot(contains('identities')));
    });

    test('writes both lists after logins, only when they hold something, and reads them back', () {
      final doc = SyncDoc(logins: const [_login], cards: const [_visa], identities: const [_me]);

      // The tombstones are written last, as they always were, so cards and identities sit after logins and before them
      expect(doc.toJson().keys, ['accounts', 'backupServices', 'logins', 'cards', 'identities', 'deleted']);
      expect(SyncDoc(cards: const [_visa]).toJson().keys, ['accounts', 'backupServices', 'cards', 'deleted']);
      final read = SyncDoc.fromJson(_json(doc.toJson()));
      expect(read.cards, [_visa]);
      expect(read.identities, [_me]);
      expect(read.extra, isEmpty);
      expect(read.ids, containsAll(['l1', 'c1', 'i1']));
      expect(read, doc);
    });
  });

  group('merging', () {
    test('takes both kinds as entries it holds, the later copy winning', () {
      final remote = SyncDoc(cards: const [_visa], identities: const [_me]);
      final edited = _visa.copyWith(name: 'Travel Visa', updatedAt: 50);
      final renamed = _me.copyWith(name: 'Ada', updatedAt: 50);

      final merged = mergeScope(
        Lists(cards: [edited], identities: [renamed]),
        ['c1', 'i1'],
        remote,
        now: now,
      );

      expect(merged.known..sort(), ['c1', 'i1']);
      expect(merged.doc.cards.single.name, 'Travel Visa');
      expect(merged.doc.identities.single.name, 'Ada');
      // The other phone's newer copy wins in turn
      final theirs = SyncDoc(cards: [edited.copyWith(code: '999', updatedAt: 60)]);
      expect(mergeScope(Lists(cards: [edited]), ['c1'], theirs, now: now).doc.cards.single.code, '999');
    });

    test('adds a card the other phone added, drops one deleted there, and writes down one deleted here', () {
      expect(mergeScope(const Lists(), const [], SyncDoc(cards: const [_visa]), now: now).doc.cards, [_visa]);

      final deletedThere = SyncDoc(
        deleted: [Tombstone(id: 'c1', at: now - 1000)],
      );
      expect(mergeScope(const Lists(cards: [_visa]), ['c1'], deletedThere, now: now).doc.cards, isEmpty);

      final deletedHere = mergeScope(const Lists(), ['i1'], SyncDoc(identities: const [_me]), now: now);
      expect(deletedHere.doc.identities, isEmpty);
      expect([for (final tomb in deletedHere.doc.deleted) tomb.id], ['i1']);
    });

    test('follows a card into a space, in the space document', () {
      final shared = _visa.copyWith(id: 'c2', spaceId: 's1');
      final family = _me.copyWith(id: 'i2', spaceId: 's1');
      final lists = Lists(accounts: [_account('a1')], cards: [_visa, shared], identities: [_me, family]);

      expect(scopeLists(lists, null).cards.map((card) => card.id), ['c1']);
      expect(scopeLists(lists, 's1').cards.map((card) => card.id), ['c2']);
      expect(scopeLists(lists, 's1').identities.map((identity) => identity.id), ['i2']);

      final fromSpace = SyncDoc(
        cards: [shared.copyWith(name: 'Changed', updatedAt: 70)],
        identities: [family],
      );
      final applied = applyScope(lists, 's1', fromSpace);
      expect(applied.cards.map((card) => (card.id, card.name)), [('c1', 'Everyday Visa'), ('c2', 'Changed')]);
      expect(applied.identities.map((identity) => identity.id), ['i1', 'i2']);
      expect(sameDoc(SyncDoc(cards: [_visa, shared]), SyncDoc(cards: [shared, _visa])), isTrue);
      expect(sameDoc(SyncDoc(cards: const [_visa]), SyncDoc(cards: [_visa.copyWith(name: 'x')])), isFalse);
    });

    test('keeps a card of another scope out when the id belongs to something else', () {
      final lists = Lists(cards: [_visa.copyWith(updatedAt: 10)]);
      final other = SyncDoc(
        cards: [_visa.copyWith(name: 'Other', spaceId: 's1', updatedAt: 99)],
      );

      expect(heldElsewhere(lists, 's1', other), {'c1'});
      expect(applyScope(lists, 's1', other).cards.single.name, 'Everyday Visa');
    });

    test('combining key copies keeps both lists', () async {
      final lists = Lists(cards: const [_visa], identities: const [_me]);

      expect(await combineKeyCopies(lists, null), lists);
    });
  });

  group('a phone from before cards', () {
    test('keeps both lists through a merge of a file that holds them, and they come back as written', () {
      final file = SyncDoc(
        accounts: [_account('a1')],
        cards: const [_visa],
        identities: const [_me],
        deleted: [Tombstone(id: 'c-gone', at: now - 1000)],
      );
      final plain = _json(file.toJson());

      final remote = before_cards.SyncDoc.fromJson(plain);
      final merged = before_cards.mergeScope(before_cards.Lists(accounts: [_account('a1'), _account('a2')]), ['a1'], remote, now: now);
      final written = _json(merged.doc.toJson());

      expect(written['cards'], plain['cards']);
      expect(written['identities'], plain['identities']);
      final back = SyncDoc.fromJson(written);
      expect(back.cards, [_visa]);
      expect(back.identities, [_me]);
      expect(back.deleted.map((tomb) => tomb.id), ['c-gone']);
    });

    test('keeps the cards of a space file the same way', () {
      final space = SyncDoc(cards: [_visa.copyWith(spaceId: 's1')]);
      final plain = _json(space.toJson());

      final merged = before_cards.mergeScope(const before_cards.Lists(), const [], before_cards.SyncDoc.fromJson(plain), now: now);

      expect(_json(merged.doc.toJson())['cards'], plain['cards']);
    });
  });
}
