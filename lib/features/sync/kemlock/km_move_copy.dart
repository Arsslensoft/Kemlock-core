/// The copy step of a move (move-off-vaultwarden-sync, design 3, task 3.2): each entry of the plan is
/// written as a `kem1` item, and only what is absent is created.
///
/// The step reads the vault through the Kemlock API and decides each item before it sends:
///
/// - **absent:** created, with no expected revision, so a second phone moving the same vault, or a batch
///   resent after a lost answer, can't make a second item;
/// - **there and equal:** done, nothing is written;
/// - **there and different:** another device moved first, or wrote since. The phone merges the single
///   entry with `mergeScope`, as a sync does, and writes the merge with the revision it read as the
///   expected one (`If-Match`). An entry the server already holds as the merge is done, and never
///   overwritten by an older copy;
/// - **a tombstone:** the entry was deleted elsewhere. It isn't written, and the first Kemlock sync
///   decides it as any sync does;
/// - **an item this phone can't open:** the move stops, unless an earlier check named the entry as one to
///   send again, which overwrites a damaged item of its own.
///
/// A batch is all or none, so a 409 (another device wrote an item meanwhile) stores nothing: the step
/// reads again and decides again, three times. The hash of each entry is recorded once the server
/// confirmed it, per batch, so a move cut short sends only what it hadn't, and none twice.
///
/// Pure Dart, no Flutter.
library;

import '../sync_merge.dart';
import 'km_api.dart';
import 'km_cache.dart';
import 'km_kinds.dart';
import 'km_move_plan.dart';
import 'km_move_record.dart';
import 'km_move_server.dart';

/// How many times a batch is decided again when items keep changing under it.
const _attempts = 3;

/// What the copy step did: the record as it stands, and the entries it left because the server holds
/// their item deleted.
typedef KmCopyResult = ({KmMoveRecord record, List<String> skipped});

/// [local] and [remote], two copies of one entry, as one: `mergeScope`'s, with the key copies combined
/// first, as a sync joins two copies. When the merge can't give exactly one entry, [remote] is kept: the
/// server's copy is never overwritten by a guess.
Future<Map<String, Object?>> kmMergeEntry(KmEntry local, KmEntry remote, int now) async {
  final remoteDoc = kmDocOf([remote]);
  final merged = mergeScope(await combineKeyCopies(kmDocOf([local]), remoteDoc), const [], remoteDoc, now: now);
  final entries = kmEntriesOf(merged.doc);
  return entries.length == 1 ? entries.single.json : remote.json;
}

/// Writes a plan's items to the server.
class KmMoveCopy {
  KmMoveCopy({required this.server});

  final KmMoveServer server;

  /// Runs the step for [plan] from where [record] stands. [save] stores the record after each batch.
  /// Throws a [KmMoveError] for an item it can't read, and what the API throws.
  Future<KmCopyResult> run(
    KmMovePlan plan,
    KmMoveRecord record, {
    required int now,
    required Future<void> Function(KmMoveRecord next) save,
    void Function(int done, int total)? onProgress,
  }) async {
    var current = record;
    var view = await _readIfNeeded(plan, record);
    final skipped = <String>[];
    var done = 0;
    for (final batch in plan.batches) {
      final todo = [
        for (final item in batch)
          if (!current.sent.containsKey(item.entryId) || current.redo.contains(item.entryId)) item,
      ];
      if (todo.isNotEmpty) {
        final redo = current.redo.toSet();
        for (var attempt = 1; ; attempt++) {
          final read = view ??= await server.read();
          final writes = <KmMoveWrite>[];
          final settled = <String, String>{};
          final gone = <String>[];
          for (final item in todo) {
            final cached = read.items[item.itemId];
            if (cached == null) {
              writes.add(_write(item, item.json, revision: 1));
            } else if (cached.deleted) {
              gone.add(item.entryId);
            } else if (!cached.applied) {
              // A damaged item of this move's own, named by an earlier check, is sent again over itself
              if (!redo.contains(item.entryId)) {
                throw KmMoveError(KmMoveIssue.unreadable, detail: item.itemId);
              }
              writes.add(_write(item, item.json, revision: cached.revision + 1, kind: cached.kind, expected: cached.revision));
            } else {
              final remote = cached.entry!;
              if (canonical(remote) == canonical(item.json)) {
                settled[item.entryId] = item.hash;
                continue;
              }
              final merged = await kmMergeEntry(item.entry, (kind: cached.kind, json: remote), now);
              if (canonical(merged) == canonical(remote)) {
                settled[item.entryId] = kmEntryHash(remote);
              } else {
                writes.add(_write(item, merged, revision: cached.revision + 1, kind: cached.kind, expected: cached.revision));
              }
            }
          }
          try {
            if (writes.isNotEmpty) {
              await server.send(writes);
            }
          } on KmError catch (e) {
            // Another device wrote an item meanwhile: nothing was stored, so read it and decide again
            if (e.problem == KmProblem.stale && attempt < _attempts) {
              view = null;
              continue;
            }
            rethrow;
          }
          for (final write in writes) {
            settled[write.entryId] = kmEntryHash(write.json);
          }
          skipped.addAll(gone);
          final handled = {for (final item in todo) item.entryId};
          current = current.copyWith(
            sent: {...current.sent, ...settled},
            redo: [
              for (final id in current.redo)
                if (!handled.contains(id)) id,
            ],
          );
          await save(current);
          break;
        }
      }
      done += batch.length;
      onProgress?.call(done, plan.count);
    }
    return (record: current, skipped: skipped);
  }

  /// The vault as the server holds it, read once when some entry still has to be decided.
  Future<KmCache?> _readIfNeeded(KmMovePlan plan, KmMoveRecord record) async {
    final pending = plan.items.any((item) => !record.sent.containsKey(item.entryId) || record.redo.contains(item.entryId));
    return pending ? server.read() : null;
  }

  KmMoveWrite _write(KmMoveItem item, Map<String, Object?> json, {required int revision, String? kind, int? expected}) =>
      KmMoveWrite(itemId: item.itemId, entryId: item.entryId, kind: kind ?? item.kind, revision: revision, expected: expected, json: json);
}
