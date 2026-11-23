@TestOn('vm')
library;

// The removal guard Vaultwarden and Kemlock Server sync share: the same cases pin both.
import 'package:kemlock_core/features/sync/removal_guard.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart' as vw;
import 'package:test/test.dart';

const _now = 1000 * 60 * 60 * 24 * 30;

RemovalCheck _check(int removals, int scope, {int? removedHere, List<LostRun> recent = const [], RemovalChoice? choice}) =>
    checkRemovals(removals: removals, removedHere: removedHere ?? 0, scope: scope, recent: recent, now: _now, choice: choice);

void main() {
  group('one run', () {
    test('stops for more than three removals that are more than a quarter of the scope', () {
      expect(_check(4, 10).stop, isTrue);
      expect(_check(12, 40).stop, isTrue);
      expect(_check(11, 40).stop, isTrue, reason: '44 is over 40');
    });

    test('goes on for three or fewer, however large their share, and for a quarter or less', () {
      expect(_check(3, 4).stop, isFalse);
      expect(_check(1, 1).stop, isFalse);
      expect(_check(10, 40).stop, isFalse, reason: 'exactly a quarter');
      expect(_check(5, 100).stop, isFalse);
    });

    test('goes on once the user chose, either way', () {
      expect(_check(12, 40, choice: RemovalChoice.keep).stop, isFalse);
      expect(_check(12, 40, choice: RemovalChoice.remove).stop, isFalse);
    });
  });

  group('the runs of the last day', () {
    test('five of 40 removed at each of four runs in an afternoon: the run that crosses a quarter stops and asks', () {
      var state = <String, Object?>{};
      final stops = <bool>[];
      for (var run = 0; run < 4; run++) {
        final at = _now + run * 60 * 60 * 1000;
        final check = checkRemovals(removals: 5, removedHere: 5, scope: 40, recent: lostLately(state, at), now: at);
        stops.add(check.stop);
        if (check.stop) break;
        state = {lostKey: check.lostJson};
      }

      expect(stops, [false, false, true]);
    });

    test('a run that removes nothing here adds nothing to the count', () {
      final check = checkRemovals(removals: 5, removedHere: 0, scope: 100, recent: const [(at: _now - 1000, count: 2)], now: _now);

      expect(check.stop, isFalse);
      expect(check.lostNow, [(at: _now - 1000, count: 2)]);
    });

    test('the user saying to remove them starts the count again, and keeping them leaves it', () {
      const recent = [(at: _now - 1000, count: 6)];

      expect(_check(2, 40, removedHere: 2, recent: recent, choice: RemovalChoice.remove).lostNow, isEmpty);
      expect(_check(2, 40, removedHere: 2, recent: recent, choice: RemovalChoice.keep).lostNow, hasLength(2));
    });

    test('only the runs inside the window count, and only those with something removed', () {
      final state = {
        lostKey: [
          [_now - removalWindow.inMilliseconds - 1, 9],
          [_now - 1000, 3],
          [_now - 2000, 0],
          'not a pair',
        ],
      };

      expect(lostLately(state, _now), [(at: _now - 1000, count: 3)]);
      expect(lostLately(const {}, _now), isEmpty);
    });

    test('is kept in the scope state as pairs, and read back as it was written', () {
      final check = _check(1, 40, removedHere: 1, recent: const [(at: _now - 5000, count: 2)]);

      expect(check.lostJson, [
        [_now - 5000, 2],
        [_now, 1],
      ]);
      expect(lostLately({lostKey: check.lostJson}, _now), check.lostNow);
    });
  });

  test('Vaultwarden sync still exports the names its callers and tests use, and the same state key', () {
    expect(vw.removalWindow, removalWindow);
    expect(vw.vwLostKey, lostKey);
    expect(vw.RemovalChoice.keep, RemovalChoice.keep);
    expect(vw.lostLately({lostKey: <Object?>[]}, _now), isEmpty);
  });
}
