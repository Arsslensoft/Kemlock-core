@TestOn('vm')
library;

// A deletion is dated by the server's own `deletedAt` when it gives one, and by the last sync before this phone
// saw it only as the fallback (the server's app contract; add-kemlock-server-sync, design 2).
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

const _a = '3f2c9a71-e4b0-4856-8a00-0000000000a1';

/// Two phones holding [_a], both synced; the first then deletes it at [deletedAfter] after the second's sync, and
/// the second edits it [editedAfter] after that same sync. Returns the second phone after it syncs the deletion.
Future<KmPhone> _scenario({required Duration deletedAfter, required Duration editedAfter, required bool dated}) async {
  final server = FakeKemlockServer()..checkTokens = false;
  final clock = KmClock();
  final one = KmPhone(
    server,
    clock: clock,
    lists: Lists(accounts: [acct(_a, updatedAt: 5)]),
  );
  await one.run();
  final two = one.another();
  await two.run();
  final synced = clock.ms;
  two.lists = Lists(
    accounts: [acct(_a, label: 'edited', updatedAt: synced + editedAfter.inMilliseconds)],
  );
  one.lists = const Lists();
  if (dated) server.deletionTime = synced + deletedAfter.inMilliseconds;
  await one.run();
  clock.tick();
  await two.run();
  return two;
}

void main() {
  test('the server\'s date wins: an edit made before the deletion, after this phone\'s last sync, is deleted', () async {
    final two = await _scenario(deletedAfter: const Duration(seconds: 45), editedAfter: const Duration(seconds: 30), dated: true);
    expect(two.ids, isEmpty);
  });

  test('an edit made after the server\'s date outlives the deletion', () async {
    final two = await _scenario(deletedAfter: const Duration(seconds: 20), editedAfter: const Duration(seconds: 30), dated: true);
    expect(two.lists.accounts.single.label, 'edited');
  });

  test('with no server date, the last sync before the phone saw it stands in, so the same edit stays', () async {
    final two = await _scenario(deletedAfter: const Duration(seconds: 45), editedAfter: const Duration(seconds: 30), dated: false);
    expect(two.lists.accounts.single.label, 'edited');
  });

  test('a date in the future counts as now', () async {
    final server = FakeKemlockServer()..checkTokens = false;
    final clock = KmClock();
    final one = KmPhone(
      server,
      clock: clock,
      lists: Lists(accounts: [acct(_a, updatedAt: 5)]),
    );
    await one.run();
    final two = one.another();
    await two.run();
    one.lists = const Lists();
    server.deletionTime = clock.ms + const Duration(days: 365).inMilliseconds;
    await one.run();
    clock.tick();
    // The run takes place a minute from now; an edit a half minute after that is newer than "now", which a date
    // of next year must not outrun
    two.lists = Lists(
      accounts: [acct(_a, label: 'edited', updatedAt: clock.ms + 90000)],
    );
    await two.run();
    expect(two.lists.accounts.single.label, 'edited', reason: 'the date is clamped to now, so an entry newer than now wins');
  });
}
