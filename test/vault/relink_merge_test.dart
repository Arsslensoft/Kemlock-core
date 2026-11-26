@TestOn('vm')
library;

// What a merge does to the links and custom fields of the entries around it (the web vault's relink.ts), what Undo puts back, and what
// deleting an entry does to the links that named it.
import 'dart:convert';

import 'package:kemlock_core/features/duplicates/dedup_cache.dart' show vaultSlot;
import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_merge.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/custom_field.dart';
import 'package:kemlock_core/models/item_link.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/vault/item_links.dart';
import 'package:test/test.dart';

const _l1 = 'aaaaaaaa-0000-4000-8000-000000000001';
const _l2 = 'aaaaaaaa-0000-4000-8000-000000000002';
const _note = 'aaaaaaaa-0000-4000-8000-000000000003';
const _card = 'aaaaaaaa-0000-4000-8000-000000000004';
const _code = 'aaaaaaaa-0000-4000-8000-000000000005';
const _c1 = 'aaaaaaaa-0000-4000-8000-0000000000c1';
const _c2 = 'aaaaaaaa-0000-4000-8000-0000000000c2';

const _kept = Login(id: _l1, name: 'Mail', addedAt: 1);
const _gone = Login(id: _l2, name: 'Mail copy', addedAt: 1);
const _n = SecureNote(id: _note, title: 'Note', addedAt: 1);
const _c = PaymentCard(id: _card, name: 'Card', addedAt: 1);

List<String> _ids(VaultEntry<Object?> entry) => [for (final link in entry.links) link.id];

VaultEntry<Object?> _byId(List<VaultEntry<Object?>> entries, String id) => entries.firstWhere((entry) => entry.id == id);

void main() {
  group('relinkForMerge', () {
    final gone = _gone.withLinks([const ItemLink(_note), const ItemLink(_card)]);
    final note = _n.withLinks([const ItemLink(_l2)]);
    final card = _c.withLinks([const ItemLink(_l2)]);
    const code = OtpAccount(id: _code, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', linkedLoginId: _l2, addedAt: 1);
    final lists = Lists(logins: [_kept, gone], notes: [note], cards: [card], accounts: const [code]);

    test('folds the removed ids into every entry that named them, and links the kept item to what they linked to, both ends', () {
      final made = relinkForMerge(lists, kept: _kept, removed: [gone], now: 50);

      expect(_ids(made.kept), [_note, _card]);
      expect(made.kept.changedAt, 50);
      expect(made.others.map((entry) => entry.id), unorderedEquals([_note, _card, _code]));
      expect(_ids(_byId(made.others, _note)), [_l1]);
      expect(_ids(_byId(made.others, _card)), [_l1]);
      expect((_byId(made.others, _code) as OtpAccount).linkedLoginId, _l1);
      expect(made.others.every((entry) => entry.changedAt == 50), isTrue);
      expect(made.undo.map((step) => step.id), unorderedEquals([_note, _card, _code]));
    });

    test('never links the kept item to itself or to a removed one', () {
      final kept = _kept.withLinks([const ItemLink(_l2)]);
      final both = _gone.withLinks([const ItemLink(_l1)]);

      final made = relinkForMerge(
        Lists(logins: [kept, both]),
        kept: kept,
        removed: [both],
        now: 5,
      );

      expect(made.kept.links, isEmpty);
      expect(made.others, isEmpty);
    });

    test('links the kept item back from an entry it is linked to that did not name it', () {
      final kept = _kept.withLinks([const ItemLink(_note)]);

      final made = relinkForMerge(
        Lists(logins: [kept, _gone], notes: const [_n]),
        kept: kept,
        removed: [_gone],
        now: 5,
      );

      expect(identical(made.kept, kept), isTrue, reason: 'nothing to add to it');
      expect(_ids(_byId(made.others, _note)), [_l1]);
    });

    test('changes nothing for an entry the merge does not touch, and for a merge with nothing to relink', () {
      final made = relinkForMerge(
        Lists(logins: const [_kept, _gone], notes: const [_n], cards: const [_c]),
        kept: _kept,
        removed: [_gone],
        now: 5,
      );

      expect(identical(made.kept, _kept), isTrue);
      expect(made.others, isEmpty);
      expect(made.undo, isEmpty);
    });

    test('writes nothing to the kept item when it is not writable, and still points the entries at it', () {
      final made = relinkForMerge(lists, kept: _kept, removed: [gone], now: 50, keptWritable: false);

      expect(identical(made.kept, _kept), isTrue);
      expect(_ids(_byId(made.others, _note)), [_l1]);
      expect(_ids(_byId(made.others, _card)), [_l1]);
    });

    test('carries over the custom fields the kept item lacks, by name, kind and value, and an admin field once', () {
      const a = CustomField(name: 'Employee ID', value: 'E-1', kind: CustomFieldKind.text);
      const b = CustomField(name: 'Badge', value: 'B-2', kind: CustomFieldKind.hidden);
      const other = CustomField(name: 'Employee ID', value: 'E-9', kind: CustomFieldKind.text);
      const keptAdmin = CustomField(name: 'Region', value: 'EU', kind: CustomFieldKind.text, adminField: 'def-1');
      const goneAdmin = CustomField(name: 'Region', value: 'US', kind: CustomFieldKind.text, adminField: 'def-1');
      final kept = _kept.copyWith(fields: [a, keptAdmin]);
      final removed = _gone.copyWith(fields: [a, b, other, goneAdmin]);

      final made = relinkForMerge(
        Lists(logins: [kept, removed]),
        kept: kept,
        removed: [removed],
        now: 7,
      );

      final fields = (made.kept as Login).fields;
      expect(fields.map((field) => '${field.name}=${field.value}'), ['Employee ID=E-1', 'Region=EU', 'Badge=B-2', 'Employee ID=E-9']);
      expect(made.kept.changedAt, 7);
    });

    test('points a login that named a removed code at the code that stays', () {
      const kept = OtpAccount(id: _c1, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
      const removed = OtpAccount(id: _c2, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
      const holder = Login(id: _l1, name: 'Mail', accountId: _c2, addedAt: 1);

      final made = relinkForMerge(
        Lists(logins: const [holder], accounts: const [kept, removed]),
        kept: kept,
        removed: [removed],
        now: 9,
      );

      expect((made.others.single as Login).accountId, _c1);
      expect(made.undo.single.before, {'accountId': _c2});
      expect(made.undo.single.after, {'accountId': _c1});
    });
  });

  group('undoRelink', () {
    final gone = _gone.withLinks([const ItemLink(_note)]);
    final note = _n.withLinks([const ItemLink(_l2)]);
    const code = OtpAccount(id: _code, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', linkedLoginId: _l2, addedAt: 1);

    test('puts back what the merge changed, and only where the entry still holds what the merge wrote', () {
      final made = relinkForMerge(
        Lists(logins: [_kept, gone], notes: [note], accounts: const [code]),
        kept: _kept,
        removed: [gone],
        now: 50,
      );
      final after = Lists(logins: [made.kept as Login], notes: [made.others.firstWhere((e) => e.id == _note) as SecureNote]);
      final edited = (made.others.firstWhere((e) => e.id == _code) as OtpAccount).copyWith(linkedLoginId: _card);

      final undone = undoRelink(Lists(logins: after.logins, notes: after.notes, accounts: [edited]), made.undo, now: 99);

      expect(undone.map((entry) => entry.id), [_note], reason: 'the code was tied to another login since, and keeps what it holds');
      expect(_ids(undone.single), [_l2]);
      expect(undone.single.changedAt, 99);
    });

    test('takes back a member the entry did not hold before, and skips a step for an entry the vault lost', () {
      final kept = _kept.withLinks([const ItemLink(_note)]);
      final made = relinkForMerge(
        Lists(logins: [kept, _gone], notes: const [_n]),
        kept: kept,
        removed: [_gone],
        now: 9,
      );
      expect(made.undo.single.before, {'links': null});

      final undone = undoRelink(Lists(logins: [kept], notes: made.others.whereType<SecureNote>().toList()), [
        ...made.undo,
        const RelinkUndo(id: 'gone', before: {'links': null}, after: {'links': null}),
      ], now: 10);

      expect(undone.single.id, _note);
      expect(undone.single.toJson().containsKey('links'), isFalse);
    });

    test('a step is plain JSON and reads back as it was written', () {
      final made = relinkForMerge(
        Lists(logins: [_kept, gone], notes: [note]),
        kept: _kept,
        removed: [gone],
        now: 50,
      );
      final written = jsonDecode(jsonEncode([for (final step in made.undo) step.toJson()])) as List<Object?>;

      final read = [for (final step in written) RelinkUndo.fromJson(step)];

      expect(read, made.undo);
      expect(RelinkUndo.tryFromJson('x'), isNull);
      expect(RelinkUndo.tryFromJson({'id': 'a', 'before': 1, 'after': {}}), isNull);
    });
  });

  group('droppedLinksTo', () {
    test('gives every entry that named the deleted one without that link, and the code and login that were tied to it', () {
      final login = _kept.withLinks([const ItemLink(_note)]);
      final note = _n.withLinks([const ItemLink(_l1), const ItemLink(_card)]);
      const code = OtpAccount(id: _code, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', linkedLoginId: _l1, addedAt: 1);

      final dropped = droppedLinksTo(Lists(logins: [login], notes: [note], accounts: const [code], cards: const [_c]), login, now: 30);

      expect(dropped.map((entry) => entry.id), unorderedEquals([_note, _code]));
      expect(_ids(_byId(dropped, _note)), [_card]);
      expect((_byId(dropped, _code) as OtpAccount).linkedLoginId, isNull);
      expect(dropped.every((entry) => entry.changedAt == 30), isTrue);
    });

    test('has nothing for an entry nothing names', () {
      expect(droppedLinksTo(Lists(logins: const [_kept], notes: const [_n]), _kept, now: 3), isEmpty);
    });
  });

  group('the duplicate merge', () {
    DedupItem item(Login login) => DedupItem(login, id: login.id, changedAt: login.changedAt, spaceId: login.spaceId);

    test('relinks through MergeChoices, and a merge record keeps what Undo needs', () {
      final gone = _gone.copyWith(updatedAt: 5).withLinks([const ItemLink(_note)]);
      final note = _n.withLinks([const ItemLink(_l2)]);
      final choices = MergeChoices([item(_kept), item(gone)]).withKept(_l1);

      final made = choices.relink(Lists(logins: [_kept, gone], notes: [note]), now: 60);

      expect(_ids(made.kept), [_note]);
      expect(_ids(_byId(made.others, _note)), [_l1]);
      final record = MergeRecord(
        id: 'm1',
        at: 60,
        kind: mergeKindOf(_kept),
        kept: mergeJsonOf(_kept),
        removed: [mergeJsonOf(gone)],
        relinkUndo: made.undo,
      );
      final read = MergeRecord.fromJson(jsonDecode(jsonEncode(record.toJson())))!;
      expect(read.relinkUndo, made.undo);
      expect(planUndo(read, find: (_) => null)!.relinkUndo, made.undo);
      expect(MergeRecord(id: 'm2', at: 1, kind: 'login', kept: const {}, removed: const []).toJson().containsKey('relinkUndo'), isFalse);
    });

    test('a kept item that cannot be changed gets no link written, and the other entries still point at it', () {
      final gone = _gone.withLinks([const ItemLink(_note)]);
      final note = _n.withLinks([const ItemLink(_l2)]);
      final readOnly = MergeChoices([item(_kept), item(gone)], readOnlySlots: const {vaultSlot}).withKept(_l1);

      final made = readOnly.relink(Lists(logins: [_kept, gone], notes: [note]), now: 60);

      expect(made.kept.links, isEmpty);
      expect(_ids(_byId(made.others, _note)), [_l1]);
    });
  });
}
