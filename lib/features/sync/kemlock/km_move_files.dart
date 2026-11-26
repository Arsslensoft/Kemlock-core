/// The files step of a move (move-off-vaultwarden-sync, design 2, task 3.3): every moved note's file
/// goes up as the `KMA1` bytes the phone holds, byte for byte, and the note is written again naming the
/// server's file id in its attachment, so another phone can fetch it (`km_files.dart`).
///
/// A plain home keeps a note's file as the plain file under Bitwarden's attachment key, and a sealed one
/// as the sealed bytes; the phone's attachment store holds `KMA1` either way (the old store's run fetched
/// what the phone lacked), so a file the Kemlock API holds is always the phone's own `KMA1` bytes.
///
/// For each note, in the order of the plan:
///
/// 1. the note is read as the server holds it after the copy, which is the entry the vault merged to;
/// 2. an attachment that already names a server file (an earlier try wrote it before the move stopped, or
///    another phone moved first) is kept: a resume uploads nothing twice, except the files a check named
///    in `redoFiles`, which are uploaded again under a new id; the hash recorded for that note is then
///    the one of the note as the server holds it;
/// 3. each other attachment is uploaded from the attachment store, with `KmFiles.upload`. One the phone
///    lacks, or the server refused, stops the move with "A file is missing", naming the note, and nothing
///    in the old store changes;
/// 4. the note is written over the revision read, with the ids stamped, and the hash of what was sent
///    replaces the one the copy recorded. The SHA-256 of each file's bytes is recorded for the check.
///
/// The record is saved after each note, so the step resumes per note.
///
/// Pure Dart, no Flutter.
library;

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../models/secure_note.dart';
import 'km_api.dart';
import 'km_cache.dart';
import 'km_files.dart';
import 'km_kinds.dart';
import 'km_move_plan.dart';
import 'km_move_record.dart';
import 'km_move_server.dart';

/// How many times a note is decided again when it changes under the step.
const _attempts = 3;

/// What the files step did: the record as it stands, and the notes it left because the server holds
/// their item deleted.
typedef KmFilesResult = ({KmMoveRecord record, List<String> skipped});

/// Uploads a plan's files.
class KmMoveFilesStep {
  KmMoveFilesStep({required this.server, required this.store})
    : _files = KmFiles(store: store, connection: server.connection, server: server.server);

  final KmMoveServer server;

  /// The phone's attached files, as `KMA1`.
  final KmFileStore store;
  final KmFiles _files;

  /// Runs the step for [plan] from where [record] stands. [save] stores the record after each note.
  Future<KmFilesResult> run(
    KmMovePlan plan,
    KmMoveRecord record, {
    required int now,
    required Future<void> Function(KmMoveRecord next) save,
    void Function(int done, int total)? onProgress,
  }) async {
    final notes = <String, String>{};
    for (final file in plan.files) {
      notes.putIfAbsent(file.noteId, () => file.itemId);
    }
    var current = record;
    var view = notes.isEmpty ? null : await server.read();
    final skipped = <String>[];
    var done = 0;
    for (final MapEntry(key: noteId, value: itemId) in notes.entries) {
      for (var attempt = 1; ; attempt++) {
        final read = view ??= await server.read();
        final cached = read.items[itemId];
        if (cached == null || (!cached.deleted && (!cached.applied || cached.kind != KmKind.note))) {
          throw KmMoveError(KmMoveIssue.unreadable, detail: itemId);
        }
        if (cached.deleted) {
          skipped.add(noteId);
          break;
        }
        final again = current.redoFiles.toSet();
        final note = _stripped(_noteOf(cached), again);
        final unstamped = [
          for (final file in note.files)
            if (kmServerFileId(file) == null) file,
        ];
        for (final file in unstamped) {
          if (!await store.exists(file.id)) {
            throw KmMoveError(KmMoveIssue.fileMissing, detail: '$noteId/${file.id}');
          }
        }
        var sent = current.sent;
        if (unstamped.isNotEmpty) {
          final stamped = await _files.upload(
            kmDocOf([(kind: KmKind.note, json: note.toJson())]),
            now: now,
            itemIdOf: (_) => itemId,
            onServer: (_) => true,
          );
          final next = stamped?.notes.singleOrNull;
          final unnamed = next == null
              ? unstamped
              : [
                  for (final file in next.files)
                    if (kmServerFileId(file) == null) file,
                ];
          if (next == null || unnamed.isNotEmpty) {
            // Too large for the server, or sized differently than the note says
            throw KmMoveError(KmMoveIssue.fileMissing, detail: '$noteId/${(unnamed.isEmpty ? unstamped : unnamed).first.id}');
          }
          final json = next.toJson();
          try {
            await server.send([
              KmMoveWrite(
                itemId: itemId,
                entryId: noteId,
                kind: cached.kind,
                revision: cached.revision + 1,
                expected: cached.revision,
                json: json,
              ),
            ]);
          } on KmError catch (e) {
            // Another device wrote the note meanwhile: nothing was stored, so read it and decide again
            if (e.problem == KmProblem.stale && attempt < _attempts) {
              view = null;
              continue;
            }
            rethrow;
          }
          sent = {...sent, noteId: kmEntryHash(json)};
        } else {
          // The note already names its files: an earlier try wrote it before the record was saved, or
          // another phone moved first. The copy recorded the note without them, so record what the
          // server holds now, which is what the check reads back
          sent = {...sent, noteId: kmEntryHash(cached.entry!)};
        }
        // What the phone holds of each file, for the check to compare the download with
        final files = {...current.files};
        for (final file in note.files) {
          final bytes = await store.readSealed(file.id);
          if (bytes != null) {
            files[file.id] = b64urlEncode(hash.sha256.convert(bytes).bytes);
          }
        }
        current = current.copyWith(
          sent: sent,
          files: files,
          redoFiles: [
            for (final id in current.redoFiles)
              if (!note.files.any((file) => file.id == id)) id,
          ],
        );
        await save(current);
        break;
      }
      done++;
      onProgress?.call(done, notes.length);
    }
    return (record: current, skipped: skipped);
  }

  /// The note [cached] holds.
  SecureNote _noteOf(KmCachedItem cached) => kmDocOf([(kind: cached.kind, json: cached.entry!)]).notes.single;

  /// [note] without the server's file id on the attachments of [ids]: their files go up again.
  SecureNote _stripped(SecureNote note, Set<String> ids) {
    if (ids.isEmpty || !note.files.any((file) => ids.contains(file.id))) {
      return note;
    }
    return note.copyWith(
      attachments: [
        for (final file in note.files)
          if (ids.contains(file.id))
            NoteAttachment(
              id: file.id,
              name: file.name,
              size: file.size,
              type: file.type,
              key: file.key,
              addedAt: file.addedAt,
              sha256: file.sha256,
              extra: {...file.extra}..remove(kmFileKey),
            )
          else
            file,
      ],
    );
  }
}
