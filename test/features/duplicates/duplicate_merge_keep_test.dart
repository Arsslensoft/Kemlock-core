@TestOn('vm')
library;

import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

// What a merge keeps of the copies that go, and what Undo merge puts back without overwriting what the person did since
Login login(String id, {String? accountId, int at = 1000, List<String>? tags, String password = 'hunter2', int? updatedAt}) => Login(
  id: id,
  name: 'Orbit',
  username: 'sam',
  password: password,
  websites: const ['orbit.example'],
  accountId: accountId,
  tags: tags,
  addedAt: at,
  updatedAt: updatedAt,
);

OtpAccount code(String id, {List<String>? tags, List<String>? websites, int at = 1000, int? order}) => OtpAccount(
  id: id,
  type: OtpType.totp,
  issuer: 'Orbit',
  label: 'sam',
  secret: 'JBSWY3DPEHPK3PXP',
  tags: tags,
  websites: websites,
  order: order,
  addedAt: at,
);

List<DedupItem> entries(List<Object> items, {required String Function(Object) idOf, required int Function(Object) atOf}) => [
  for (final item in items) DedupItem(item, id: idOf(item), changedAt: atOf(item)),
];

List<DedupItem> logins(List<Login> items) => entries(items, idOf: (item) => (item as Login).id, atOf: (item) => (item as Login).changedAt);

List<DedupItem> codes(List<OtpAccount> items) =>
    entries(items, idOf: (item) => (item as OtpAccount).id, atOf: (item) => (item as OtpAccount).changedAt);

void main() {
  group('a login merge', () {
    test('keeps the code link of the copy that goes when the one that stays has none', () {
      final kept = login('a', at: 1000);
      final gone = login('b', accountId: 'code-1', at: 2000);
      final merged = MergeChoices(logins([kept, gone])).withKept('a').merged(3000) as Login;
      expect(merged.accountId, 'code-1');
    });

    test('keeps its own link when it has one, and takes no link when neither has', () {
      final kept = login('a', accountId: 'code-1');
      final gone = login('b', accountId: 'code-2', at: 2000);
      expect((MergeChoices(logins([kept, gone])).withKept('a').merged(3000) as Login).accountId, 'code-1');
      expect((MergeChoices(logins([login('a'), login('b', at: 2000)])).withKept('a').merged(3000) as Login).accountId, isNull);
    });
  });

  group('a code merge', () {
    test('keeps the union of the tags and of the websites of the copies, the first spelling first', () {
      final kept = code('a', tags: ['Work'], websites: ['orbit.example']);
      final gone = code('b', tags: ['Home', 'Work'], websites: ['orbit.example', 'orbit.test'], at: 2000);
      final merged = MergeChoices(codes([kept, gone])).withKept('a').merged(3000) as OtpAccount;
      expect(merged.tags, ['Work', 'Home']);
      expect(merged.websites, ['orbit.example', 'orbit.test']);
    });

    test('leaves tags and websites off when no copy has any', () {
      final merged = MergeChoices(codes([code('a'), code('b', at: 2000)])).withKept('a').merged(3000) as OtpAccount;
      expect(merged.tags, isNull);
      expect(merged.websites, isNull);
    });
  });

  group('Undo merge', () {
    MergeRecord recordOf(List<Object> before, {required String keptId, required int at, List<Login> relinked = const []}) => MergeRecord(
      id: 'm1',
      at: at,
      kind: mergeKindOf(before.first),
      kept: mergeJsonOf(before.firstWhere((item) => (item is OtpAccount ? item.id : (item as Login).id) == keptId)),
      removed: [
        for (final item in before)
          if ((item is OtpAccount ? item.id : (item as Login).id) != keptId) mergeJsonOf(item),
      ],
      relinked: [for (final login in relinked) mergeJsonOf(login)],
    );

    test('brings the removed items back as they were, and the kept one as it was', () {
      final kept = code('a', tags: ['Work']);
      final gone = code('b', at: 2000);
      final record = recordOf([kept, gone], keptId: 'a', at: 5000);
      final now = kept.copyWith(tags: ['Work', 'Home'], updatedAt: 5000);
      final plan = planUndo(record, find: (id) => id == 'a' ? now : null)!;
      expect(plan.removed, [gone]);
      expect(plan.kept, kept);
      expect(plan.keptEdited, isFalse);
      expect(plan.keptGone, isFalse);
    });

    test('says the kept item was edited after the merge, so the caller asks before it is overwritten', () {
      final kept = code('a');
      final record = recordOf([kept, code('b', at: 2000)], keptId: 'a', at: 5000);
      final edited = kept.copyWith(note: 'mine', updatedAt: 5001);
      expect(planUndo(record, find: (id) => id == 'a' ? edited : null)!.keptEdited, isTrue);
      // The merge stamped it at the record's own time: not an edit
      final stamped = kept.copyWith(updatedAt: 5000);
      expect(planUndo(record, find: (id) => id == 'a' ? stamped : null)!.keptEdited, isFalse);
    });

    test('says the kept item is gone, and does not bring back a removed item the vault holds again', () {
      final kept = code('a');
      final gone = code('b', at: 2000);
      final record = recordOf([kept, gone], keptId: 'a', at: 5000);
      final plan = planUndo(record, find: (id) => id == 'b' ? gone.copyWith(order: 3, updatedAt: 6000) : null)!;
      expect(plan.keptGone, isTrue);
      expect(plan.removed, isEmpty);
    });

    test('gives a relinked login back only its link, and only while it points at the code that stayed', () {
      final kept = code('a');
      final record = recordOf(
        [kept, code('b', at: 2000)],
        keptId: 'a',
        at: 5000,
        relinked: [login('l1', accountId: 'b'), login('l2', accountId: 'b'), login('l3', accountId: 'b')],
      );
      final held = {
        // Relinked by the merge, and edited since: its password stays what it is now
        'l1': login('l1', accountId: 'a', password: 'newer', updatedAt: 6000),
        // Linked to another code since
        'l2': login('l2', accountId: 'c'),
        // Gone
      };
      final plan = planUndo(record, find: (id) => id == 'a' ? kept : held[id])!;
      expect(plan.relinks, {'l1': 'b'});
    });

    test('cannot read a record of a kind it does not know', () {
      final record = MergeRecord(id: 'm', at: 1, kind: 'spaceship', kept: const {}, removed: const []);
      expect(planUndo(record, find: (_) => null), isNull);
    });
  });
}
