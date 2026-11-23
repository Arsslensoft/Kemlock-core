/// The removal guard both servers' syncs use (Vaultwarden and Kemlock Server):
/// a run that would remove many entries stops and asks. Two rules:
///
/// - more than three removals and more than a quarter of the scope;
/// - the entries this run takes off this phone, counted together with the
///   runs of the last day ([removalWindow]), are more than three and more than
///   a quarter of the scope: a server that withholds three items at a time
///   would otherwise empty the vault run by run.
///
/// A stopped run raises a problem with its count, and the sheet's Keep and
/// Remove answer with a [RemovalChoice]. The scope state keeps the recent
/// runs under [lostKey].
///
/// Pure Dart, no Flutter.
library;

/// What the user decided about a run the removal guard stopped.
enum RemovalChoice {
  /// Go ahead and remove them.
  remove,

  /// Keep everything: no deletion either way this run, so what's missing on
  /// one side comes back from the other.
  keep,
}

/// The scope state's key for the entries recent runs took off this phone,
/// as `[when, how many]` pairs, for the removal guard to count over
/// [removalWindow].
const lostKey = 'lost';

/// How far back the removal guard counts the entries this phone lost.
const removalWindow = Duration(days: 1);

/// A run that took [count] entries off this phone at [at] (epoch ms).
typedef LostRun = ({int at, int count});

/// The runs in [state] that took entries off this phone within
/// [removalWindow] before [now] (epoch ms), and how many each took.
List<LostRun> lostLately(Map<String, Object?> state, int now) => [
  for (final pair in (state[lostKey] as List<Object?>? ?? const []).whereType<List<Object?>>())
    if (pair case [final int at, final int count] when count > 0 && at > now - removalWindow.inMilliseconds) (at: at, count: count),
];

/// What the guard decided about a run.
class RemovalCheck {
  const RemovalCheck({required this.stop, required this.lostNow});

  /// Whether the run must stop and ask.
  final bool stop;

  /// The runs to keep in the scope state for the next run's count: [lostLately] and this run's, or none
  /// once the user said to remove them, when the count starts again.
  final List<LostRun> lostNow;

  /// [lostNow] as the scope state keeps it, `[[at, count], …]`.
  List<List<int>> get lostJson => [
    for (final run in lostNow) [run.at, run.count],
  ];
}

/// Checks a run before it writes. [removals] is how many entries the run removes, here and on the
/// server, and [scope] how many the scope holds on the larger side; [removedHere] is how many of
/// them are taken off this phone, and [recent] the runs [lostLately] found. With a [choice] the user
/// already decided, the run goes on.
RemovalCheck checkRemovals({
  required int removals,
  required int removedHere,
  required int scope,
  required List<LostRun> recent,
  required int now,
  RemovalChoice? choice,
}) {
  final lately = recent.fold(0, (sum, run) => sum + run.count);
  final many = removals > 3 && removals * 4 > scope;
  final manyLately = removedHere > 0 && lately > 0 && removedHere + lately > 3 && (removedHere + lately) * 4 > scope + lately;
  // Once the user said to remove them, the count starts again
  final lostNow = choice == RemovalChoice.remove ? const <LostRun>[] : [...recent, if (removedHere > 0) (at: now, count: removedHere)];
  return RemovalCheck(stop: choice == null && (many || manyLately), lostNow: lostNow);
}
