/// How the files attached to notes travel with Kemlock Server sync: each is the
/// `KMA1` file exactly as the phone keeps it, so the server only ever holds
/// ciphertext (`attachment_sync.dart` does the same for WebDAV).
///
/// The server numbers files itself, and needs the note's item to exist before
/// it takes one (`POST /kem/v1/items/{id}/files`), so a run:
///
/// 1. writes the notes as items first, without a server file for the new
///    attachments;
/// 2. uploads each file a note names that this phone has and the server lacks,
///    the exact `KMA1` bytes, with the size announced and the server's limit
///    checked;
/// 3. writes the note again, its attachment now naming the server's file id in
///    its own keys ([kmFileKey], kept as an unknown key by every version), so
///    another phone can fetch it. A note never names a file the server lacks;
/// 4. deletes from the server the files of attachments a note no longer names;
/// 5. fetches the files the merged notes name and this phone lacks. A download
///    stops at the size its note names, and is stored only when it opens with
///    its attachment's key: a file that doesn't is thrown away.
///
/// A file is written once and never changed. The id the phone's notes use for
/// an attachment stays the file's name on the phone; the server's is only the
/// address.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/attachment_format.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';
import '../sync_merge.dart';
import 'km_api.dart';

/// The key of an attachment's JSON that holds the server's file id.
const kmFileKey = 'kemlockFile';

/// The phone's attached files, sealed as `KMA1` (`AttachmentStore`'s side of it).
abstract interface class KmFileStore {
  /// Whether this phone has the file of the attachment [id].
  Future<bool> exists(String id);

  /// The file's `KMA1` bytes, or null when this phone lacks it.
  Future<Uint8List?> readSealed(String id);

  /// Keeps the `KMA1` bytes of the attachment [id].
  Future<void> writeSealed(String id, Uint8List sealed);
}

/// The server's file id an attachment names, or null.
String? kmServerFileId(NoteAttachment file) {
  final id = file.extra[kmFileKey];
  return id is String && id.isNotEmpty ? id : null;
}

/// The files of one vault, uploaded and fetched.
class KmFiles {
  KmFiles({required this.store, required this.connection, required this.server});

  final KmFileStore store;
  final KmConnection connection;
  final Uri server;

  KmApi get _api => connection.api;

  /// Uploads each file a note of [doc] names that has no server file and this phone holds, for the
  /// notes whose item [onServer] says is there. Returns [doc] with those notes stamped [now] and naming
  /// the server's ids, or null when nothing went up. A file the server won't take (too large) is
  /// skipped, and sync goes on without it.
  Future<SyncDoc?> upload(
    SyncDoc doc, {
    required int now,
    required String Function(String noteId) itemIdOf,
    required bool Function(String itemId) onServer,
  }) async {
    final notes = <SecureNote>[];
    var any = false;
    for (final note in doc.notes) {
      final itemId = itemIdOf(note.id);
      if (note.files.isEmpty || !onServer(itemId)) {
        notes.add(note);
        continue;
      }
      final files = <NoteAttachment>[];
      var changed = false;
      for (final file in note.files) {
        final fileId = kmServerFileId(file) == null ? await _uploadOne(itemId, file) : null;
        if (fileId == null) {
          files.add(file);
          continue;
        }
        changed = true;
        files.add(
          NoteAttachment(
            id: file.id,
            name: file.name,
            size: file.size,
            type: file.type,
            key: file.key,
            addedAt: file.addedAt,
            sha256: file.sha256,
            extra: {...file.extra, kmFileKey: fileId},
          ),
        );
      }
      any |= changed;
      notes.add(changed ? note.copyWith(attachments: files, updatedAt: now) : note);
    }
    if (!any) return null;
    return SyncDoc(
      accounts: doc.accounts,
      backupServices: doc.backupServices,
      keys: doc.keys,
      notes: notes,
      passkeys: doc.passkeys,
      keyAccounts: doc.keyAccounts,
      contacts: doc.contacts,
      logins: doc.logins,
      cards: doc.cards,
      identities: doc.identities,
      deleted: doc.deleted,
      seq: doc.seq,
      extra: doc.extra,
    );
  }

  /// The server's id of [file]'s upload, or null when this phone doesn't have the file, it isn't the size
  /// its note says, or the server won't take it.
  Future<String?> _uploadOne(String itemId, NoteAttachment file) async {
    final bytes = await store.readSealed(file.id);
    if (bytes == null || file.size > attachmentSizeLimit || bytes.length != kma1Length(file.size)) return null;
    try {
      final start = await connection.call((token) => _api.startFile(server, token, itemId, bytes.length));
      if (start.size != bytes.length || bytes.length > start.maxSize) return null;
      await connection.call((token) => _api.uploadFile(server, token, itemId, start, bytes));
      return start.fileId;
    } on KmError catch (e) {
      if (e.problem == KmProblem.tooLarge) return null;
      rethrow;
    }
  }

  /// Deletes from the server the files [before] named that [after] doesn't, for notes that are still
  /// there: a note a run held out of the merge never loses its files. Best effort: a file left behind is
  /// only a copy of bytes the server already held.
  Future<void> deleteRemoved(Map<String, Set<String>> before, Map<String, Set<String>> after) async {
    for (final MapEntry(key: itemId, value: ids) in before.entries) {
      final now = after[itemId];
      if (now == null) continue;
      for (final fileId in ids.difference(now)) {
        try {
          await connection.call((token) => _api.deleteFile(server, token, itemId, fileId));
        } on KmError {
          continue;
        }
      }
    }
  }

  /// Fetches the files the notes of [doc] name that this phone lacks, the smallest first. A file that
  /// can't be fetched now, is larger than its note says, or doesn't open with its key is skipped and
  /// tried again at the next run. Returns how many were stored.
  Future<int> download(SyncDoc doc, {required String Function(String noteId) itemIdOf}) async {
    final wanted = <({String itemId, NoteAttachment file, String fileId})>[];
    for (final note in doc.notes) {
      for (final file in note.files) {
        final fileId = kmServerFileId(file);
        if (fileId == null || file.size > attachmentSizeLimit || await store.exists(file.id)) continue;
        wanted.add((itemId: itemIdOf(note.id), file: file, fileId: fileId));
      }
    }
    wanted.sort((a, b) => a.file.size.compareTo(b.file.size));
    var stored = 0;
    for (final (:itemId, :file, :fileId) in wanted) {
      final expected = kma1Length(file.size);
      try {
        final bytes = await connection.call((token) => _api.downloadFile(server, token, itemId, fileId, maxBytes: expected));
        if (bytes.length != expected) continue;
        // Checked by opening it with its own key before it is kept
        await kma1Decrypt(bytes, unb64(file.key));
        await store.writeSealed(file.id, bytes);
        stored++;
      } on KmError {
        continue;
      } on AttachmentDamagedError {
        continue;
      } on FormatException {
        continue;
      }
    }
    return stored;
  }
}
