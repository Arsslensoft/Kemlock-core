@TestOn('vm')
library;

// The copy step of a move (move-off-vaultwarden-sync, task 3.2): items created only when absent, an equal
// one skipped, a different one merged and written over the revision read, a batch refused as stale decided
// again, and progress recorded per batch, against the fake Kemlock Server.
import 'dart:typed_data';

import 'package:kemlock_core/features/sync/kemlock/km_move_copy.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_plan.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_record.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_server.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'km_move_kit.dart';

class _Killed implements Exception {}

Future<KmCopyResult> _copy(MoveRig rig, KmMovePlan plan, KmMoveRecord record, {List<KmMoveRecord>? saved}) =>
    KmMoveCopy(server: rig.moveServer).run(plan, record, now: moveNow, save: (next) async => saved?.add(next));

void main() {
  test('creates each item once at revision 1, and records the hash it sent', () async {
    final rig = MoveRig();
    final lists = Lists(accounts: [account(uuidN(1)), account(uuidN(2))]);
    final plan = rig.plan(lists);

    final result = await _copy(rig, plan, newRecord());

    expect(rig.server.items.keys, unorderedEquals([for (final item in plan.items) item.itemId]));
    expect(rig.server.items.values.map((item) => item.revision), [1, 1]);
    expect(result.record.sent.keys, unorderedEquals([uuidN(1), uuidN(2)]));
    expect(result.record.sent[uuidN(1)], plan.items.first.hash);
    expect(result.skipped, isEmpty);
  });

  test('a batch sent twice leaves one item per id, and the second run writes nothing', () async {
    final rig = MoveRig();
    final plan = rig.plan(Lists(accounts: [account(uuidN(1)), account(uuidN(2))]));
    await _copy(rig, plan, newRecord());
    final batches = rig.batches;

    // A phone that lost its record resends the same batch
    final again = await _copy(rig, plan, newRecord());

    expect(rig.server.items, hasLength(2));
    expect(rig.server.items.values.map((item) => item.revision), [1, 1]);
    expect(rig.batches, batches, reason: 'equal items are skipped, so nothing is sent');
    expect(again.record.sent, hasLength(2));
  });

  test('an equal item another phone moved first is skipped', () async {
    final rig = MoveRig();
    await rig.another().put(account(uuidN(1)));
    final plan = rig.plan(Lists(accounts: [account(uuidN(1))]));

    final result = await _copy(rig, plan, newRecord());

    expect(rig.batches, 1, reason: 'only the other phone wrote');
    expect(rig.server.items.values.single.revision, 1);
    expect(result.record.sent[uuidN(1)], plan.items.single.hash);
  });

  test('a newer field here is merged into the item and written over the revision read', () async {
    final rig = MoveRig();
    await rig.another().put(account(uuidN(1), issuer: 'Old', updatedAt: 5));
    final mine = account(uuidN(1), issuer: 'New', updatedAt: 20);

    final result = await _copy(rig, rig.plan(Lists(accounts: [mine])), newRecord());

    final stored = (await rig.read()).items[rig.itemUuidOf(uuidN(1))]!;
    expect(stored.revision, 2);
    expect(stored.entry!['issuer'], 'New');
    expect(result.record.sent[uuidN(1)], kmEntryHash(mine.toJson()));
    expect(rig.server.requests.where((r) => r.method == 'POST' && r.url.path.endsWith('items:batch')), hasLength(2));
  });

  test('an older field here never overwrites the server’s newer one', () async {
    final rig = MoveRig();
    final theirs = account(uuidN(1), issuer: 'Theirs', updatedAt: 30);
    await rig.another().put(theirs);

    final result = await _copy(rig, rig.plan(Lists(accounts: [account(uuidN(1), issuer: 'Mine', updatedAt: 10)])), newRecord());

    final stored = (await rig.read()).items[rig.itemUuidOf(uuidN(1))]!;
    expect(stored.revision, 1);
    expect(stored.entry!['issuer'], 'Theirs');
    expect(result.record.sent[uuidN(1)], kmEntryHash(theirs.toJson()), reason: 'the hash is of what the server holds');
  });

  test('a batch refused as stale stores nothing, and is decided again from what the other device wrote', () async {
    final rig = MoveRig();
    final other = rig.another();
    var fired = false;
    rig.server.respond = (request) async {
      if (!fired && request.method == 'POST' && request.url.path.endsWith('items:batch')) {
        fired = true;
        await other.put(account(uuidN(2), issuer: 'Remote', updatedAt: 5));
      }
      return rig.server.handle(request);
    };
    final plan = rig.plan(
      Lists(
        accounts: [
          account(uuidN(1)),
          account(uuidN(2), issuer: 'Local', updatedAt: 10),
        ],
      ),
    );

    final result = await _copy(rig, plan, newRecord());

    expect(rig.server.staleBatches, 1);
    final items = (await rig.read()).items;
    expect(items.keys, unorderedEquals([for (final item in plan.items) item.itemId]));
    expect(items[rig.itemUuidOf(uuidN(2))]!.entry!['issuer'], 'Local');
    expect(items[rig.itemUuidOf(uuidN(2))]!.revision, 2);
    expect(result.record.sent.keys, unorderedEquals([uuidN(1), uuidN(2)]));
  });

  test('records each batch once the server confirmed it, so a move cut short sends only the rest', () async {
    final rig = MoveRig();
    final plan = rig.plan(Lists(accounts: [for (var i = 1; i <= 5; i++) account(uuidN(i))]), batchSize: 2);
    final saved = <KmMoveRecord>[];

    await expectLater(
      KmMoveCopy(server: rig.moveServer).run(
        plan,
        newRecord(),
        now: moveNow,
        save: (next) async {
          saved.add(next);
          throw _Killed();
        },
      ),
      throwsA(isA<_Killed>()),
    );
    expect(saved.single.sent, hasLength(2));
    expect(rig.server.items, hasLength(2));
    final batches = rig.batches;

    final result = await _copy(rig, plan, saved.single);

    expect(rig.server.items, hasLength(5));
    expect(rig.server.items.values.map((item) => item.revision), everyElement(1));
    expect(rig.batches - batches, 2, reason: 'the first batch is not sent again');
    expect(result.record.sent, hasLength(5));
  });

  test('leaves an entry whose item the server holds deleted, and never brings it back', () async {
    final rig = MoveRig();
    final id = rig.itemUuidOf(uuidN(1));
    await rig.another().put(account(uuidN(1)));
    rig.server.write(id: id, kind: 'otp', revision: 2);

    final result = await _copy(rig, rig.plan(Lists(accounts: [account(uuidN(1)), account(uuidN(2))])), newRecord());

    expect(result.skipped, [uuidN(1)]);
    expect(result.record.sent.keys, [uuidN(2)]);
    expect(rig.server.items[id]!.deleted, isTrue);
  });

  test('stops at an item it cannot open, unless an earlier check named it to send again', () async {
    final rig = MoveRig();
    final id = rig.itemUuidOf(uuidN(1));
    rig.server.write(id: id, kind: 'otp', revision: 1, ciphertext: Uint8List.fromList([1, 2, 3]), itemKey: Uint8List.fromList([4, 5]));
    final plan = rig.plan(Lists(accounts: [account(uuidN(1))]));

    await expectLater(_copy(rig, plan, newRecord()), throwsA(isA<KmMoveError>().having((e) => e.issue, 'issue', KmMoveIssue.unreadable)));

    final result = await _copy(rig, plan, newRecord().copyWith(redo: [uuidN(1)]));

    expect(rig.server.items[id]!.revision, 2);
    expect(result.record.redo, isEmpty);
    expect((await rig.read()).items[id]!.applied, isTrue);
  });
}
