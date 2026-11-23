/// The move off Vaultwarden or WebDAV sync, step by step (move-off-vaultwarden-sync, designs 1 to 6): the
/// old store's ordinary run, the copy, the files, the check, and the old store, each restarted from the
/// step the sealed record names, so a move that is killed, offline or refused picks up where it stopped.
///
/// The runner only orchestrates; each step is its own class and is idempotent:
///
/// 1. `sync`: [KmMoveSource] runs the old engine once, with files, and [applySynced] stores the merge in
///    the vault before anything is copied;
/// 2. `copy`: [KmMoveCopy] writes each entry of the plan as a `kem1` item, creating only what is absent;
/// 3. `files`: [KmMoveFilesStep] uploads each moved note's `KMA1` file and writes the note again;
/// 4. `check`: [KmMoveCheck] signs one manifest and reads the vault back;
/// 5. `oldStore`: [KmMoveOldStore] closes a sealed home, or leaves a plain home or a WebDAV file.
///
/// Nothing is written to the Kemlock API before the first request of step 2, and nothing changes in the
/// old store before step 5. A failed check returns the record to step 2 with what to send again. While a
/// move is unfinished ([kmMoveUnfinished]) the scheduler runs no sync of the vault's own entries; spaces
/// keep syncing, and edits on the phone wait for the first Kemlock sync.
///
/// Pure Dart, no Flutter.
library;

import '../removal_guard.dart';
import '../sync.dart';
import '../sync_merge.dart';
import 'km_cache.dart';
import 'km_files.dart';
import 'km_move_check.dart';
import 'km_move_copy.dart';
import 'km_move_files.dart';
import 'km_move_old_store.dart';
import 'km_move_plan.dart';
import 'km_move_record.dart';
import 'km_move_server.dart';
import 'km_move_source.dart';

/// Whether [record] is a move that has begun and isn't finished: the vault's own entries don't sync
/// until it is.
bool kmMoveUnfinished(KmMoveRecord? record) => record != null && !record.isDone;

/// What a run of the move leaves for the screens and the wiring.
class KmMoveOutcome {
  const KmMoveOutcome({required this.record, this.cache, this.oldStore, this.skipped = const []});

  /// The record as it stands: `done` when the move finished.
  final KmMoveRecord record;

  /// The read-back's cache, for the first Kemlock sync to start from; null when this run began after the
  /// check (a resumed move), which the first sync reads again.
  final KmCache? cache;

  /// What happened to the old store, when this run reached it.
  final KmOldStoreResult? oldStore;

  /// Entries left because the server holds their item deleted: the first Kemlock sync decides them.
  final List<String> skipped;
}

/// Runs a move.
class KmMoveRunner {
  KmMoveRunner({
    required this.store,
    required this.source,
    required this.server,
    required this.files,
    required this.oldStore,
    required this.lists,
    required this.oldState,
    required this.applySynced,
    this.onOldStore,
    this.onProgress,
    this.clock = DateTime.now,
  });

  final KmMoveStore store;
  final KmMoveSource source;
  final KmMoveServer server;

  /// The phone's attached files, as `KMA1`.
  final KmFileStore files;
  final KmMoveOldStore oldStore;

  /// The vault's own entries now: read afresh by each step, so edits made meanwhile are seen.
  final Lists Function() lists;

  /// What the old scope's last run kept.
  final Future<ScopeState> Function() oldState;

  /// Takes the old store's run into the vault: its merged lists and the old scope's state.
  final Future<void> Function(KmMoveSynced synced) applySynced;

  /// Told once the old store was dealt with, before the record says `done`: the wiring marks a plain home's
  /// scope as a copy and stops syncing a WebDAV file here.
  final Future<void> Function(KmOldStoreResult result)? onOldStore;

  /// Told as a step goes: the step and how many of its items are done out of how many.
  final void Function(KmMoveStep step, int done, int total)? onProgress;
  final DateTime Function() clock;

  int get _now => clock().millisecondsSinceEpoch;

  /// Runs the move from where its record stands, or from the start. Throws what a step throws: the old
  /// engine's own errors from the first step, a `KmError` or `KmSyncError` from the Kemlock API, and a
  /// [KmMoveError] for a file that is missing, an item that can't be read or a check that failed. The record
  /// says where the next run resumes.
  Future<KmMoveOutcome> run({RemovalChoice? choice}) async {
    if (await store.loadsNewer()) {
      throw const KmMoveError(KmMoveIssue.newer);
    }
    final stored = await store.load();
    var record = stored ?? KmMoveRecord(source: source.name, server: source.server, home: source.home, mode: source.mode, startedAt: _now);
    if (stored == null) {
      await store.save(record);
    }
    KmCache? cache;
    KmOldStoreResult? finished;
    final skipped = <String>[];
    while (!record.isDone) {
      switch (record.step) {
        case KmMoveStep.sync:
          onProgress?.call(KmMoveStep.sync, 0, 1);
          final synced = await source.sync(lists(), await oldState(), now: _now, choice: choice);
          await applySynced(synced);
          record = await _advance(record, KmMoveStep.copy);
          onProgress?.call(KmMoveStep.sync, 1, 1);
        case KmMoveStep.copy:
          final copyPlan = planKmMove(lists(), server.crypto.owner);
          final copied = await KmMoveCopy(
            server: server,
          ).run(copyPlan, record, now: _now, save: store.save, onProgress: (done, total) => onProgress?.call(KmMoveStep.copy, done, total));
          skipped.addAll(copied.skipped);
          record = await _advance(copied.record, KmMoveStep.files);
        case KmMoveStep.files:
          final filesPlan = planKmMove(lists(), server.crypto.owner);
          final uploaded = await KmMoveFilesStep(server: server, store: files).run(
            filesPlan,
            record,
            now: _now,
            save: store.save,
            onProgress: (done, total) => onProgress?.call(KmMoveStep.files, done, total),
          );
          skipped.addAll(uploaded.skipped);
          record = await _advance(uploaded.record, KmMoveStep.check);
        case KmMoveStep.check:
          onProgress?.call(KmMoveStep.check, 0, record.sent.length);
          final checked = await KmMoveCheck(server: server).run(record, now: _now, save: store.save);
          cache = checked.cache;
          record = await _advance(checked.record, KmMoveStep.oldStore);
          onProgress?.call(KmMoveStep.check, record.sent.length, record.sent.length);
        case KmMoveStep.oldStore:
          onProgress?.call(KmMoveStep.oldStore, 0, 1);
          final dealt = await oldStore.finish(record.sent.keys.toSet());
          await onOldStore?.call(dealt);
          finished = dealt;
          record = record.copyWith(
            step: KmMoveStep.done,
            closed: dealt.outcome == KmOldStore.closed || dealt.outcome == KmOldStore.gone,
            finishedAt: _now,
            result: _result(record, dealt, skipped),
          );
          await store.save(record);
          onProgress?.call(KmMoveStep.oldStore, 1, 1);
        case KmMoveStep.done:
          break;
      }
    }
    return KmMoveOutcome(record: record, cache: cache, oldStore: finished, skipped: skipped);
  }

  Future<KmMoveRecord> _advance(KmMoveRecord record, KmMoveStep step) async {
    final next = record.copyWith(step: step);
    await store.save(next);
    return next;
  }

  /// What the result screen says: what moved by kind, how many files, and what happened to the old store.
  Map<String, Object?> _result(KmMoveRecord record, KmOldStoreResult result, List<String> skipped) {
    final plan = planKmMove(lists(), server.crypto.owner);
    final moved = <String, int>{};
    for (final item in plan.items) {
      if (record.sent.containsKey(item.entryId)) {
        moved.update(item.kind, (n) => n + 1, ifAbsent: () => 1);
      }
    }
    return {
      'moved': moved,
      'files': plan.files.length,
      'oldStore': result.outcome.name,
      if (result.changed > 0) 'changed': result.changed,
      if (result.unreadable > 0) 'unreadable': result.unreadable,
      if (result.unconfirmed > 0) 'unconfirmed': result.unconfirmed,
      if (skipped.isNotEmpty) 'skipped': skipped.length,
    };
  }
}
