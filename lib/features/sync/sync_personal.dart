/// One ordinary run of a WebDAV scope, with the files attached to its notes: the scheduler runs it for
/// the vault's own file and for each space, and the move off WebDAV sync runs it once for the vault's
/// own file before it copies the vault (move-off-vaultwarden-sync, task 3.1), so both run the same code.
///
/// The files go before the document, so it never names one the folder lacks (`attachment_sync.dart`).
/// The files the merged notes name that this phone lacks go to [fetchFiles], outside the run, and are
/// returned as `missing` for a caller that fetches them itself.
library;

import '../../models/secure_note.dart';
import 'attachment_sync.dart';
import 'sync.dart';
import 'sync_merge.dart';
import 'webdav.dart';

/// What a WebDAV scope's run returns: the merged document, the ids it holds, the state to keep, and the
/// files the notes name that this phone lacks.
typedef PersonalRun = ({SyncDoc doc, List<String> known, Map<String, Object?> state, List<NoteAttachment> missing});

/// Syncs [target] once. [local] is this phone's entries in the scope and [state] what the last run kept.
/// [anchors] is this phone's anchors of the account's server spaces, for the vault's own file only (see [syncScope]).
/// Without [files], notes sync without their files. Throws what [syncScope] and [AttachmentSync] throw.
Future<PersonalRun> runWebDavScope({
  required WebDav webDav,
  required SyncTarget target,
  required Lists local,
  required ScopeState state,
  required int now,
  AttachmentSync? files,
  void Function(DavAccount dav, List<NoteAttachment> files)? fetchFiles,
  Object? anchors,
}) async {
  // The count of the newest file seen, so an older one handed back is refused
  final seen = seenSeq(state.extra);
  if (files == null) {
    final result = await syncScope(webDav, target, local, state.known, now: now, seen: seen, anchors: anchors);
    return (doc: result.doc, known: result.known, state: withSeenSeq(state.extra, result.seq), missing: const <NoteAttachment>[]);
  }
  final removed = removedFiles(state.extra, local);
  // Before the document, so it never names a file the folder lacks
  await files.upload(target.dav, local);
  final result = await syncScope(webDav, target, local, state.known, now: now, seen: seen, anchors: anchors);
  final failed = removed.isEmpty ? const <String>[] : await files.deleteRemoved(target.dav, removed, result.doc);
  final wanted = await files.missing(result.doc);
  if (wanted.isNotEmpty) fetchFiles?.call(target.dav, wanted);
  final named = [for (final file in attachmentsOf(result.doc)) file.id];
  final next = {...state.extra}
    ..remove(fileIdsKey)
    ..remove(removedFilesKey);
  if (named.isNotEmpty) next[fileIdsKey] = named;
  if (failed.isNotEmpty) next[removedFilesKey] = failed;
  return (doc: result.doc, known: result.known, state: withSeenSeq(next, result.seq), missing: wanted);
}
