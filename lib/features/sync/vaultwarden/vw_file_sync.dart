/// Syncing the files attached to notes with the attachments of the notes'
/// items, after a run has written the items (an attachment belongs to an
/// item, so the item comes first):
///
/// 1. upload every file of a note that its item lacks and this phone has:
///    new attachments, and files the server lost. A file this phone lacks
///    too is another phone's to upload; this one waits for it;
/// 2. delete the attachments of files this phone removed from a note, once
///    the note's item no longer names them. A phone never deletes one it
///    didn't remove: it may belong to a note another phone is writing;
/// 3. download, smallest first, every file a note names that its item has
///    and this phone lacks, and keep it only once it opens with its key.
///
/// A server that takes no files, or keeps them on another host, gets none:
/// the items sync without their files, which stay on the phone, and the run
/// says so.
library;

import 'dart:typed_data';

import '../../../crypto/attachment_format.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';
import '../../../vault/attachment_store_interface.dart';
import 'vw_api.dart';
import 'vw_attachments.dart';
import 'vw_codec.dart';
import 'vw_models.dart';
import 'vw_sync.dart' show VwConnection;

/// The scope state's key for the files its notes named after the last run:
/// one gone from the notes since was removed on this phone.
const vwFileIdsKey = 'files';

/// The scope state's key for attachments this phone removed whose deletion
/// didn't go through, as `[item id, attachment id]`, to try again.
const vwPendingDeletesKey = 'removeFiles';

/// The scope state's key for why files didn't go to the server: a
/// [VwFilesRefusal]'s name.
const vwNoFilesKey = 'noFiles';

/// The scope state's key set when a file the server has couldn't be
/// fetched, so the next run reads the vault again rather than stop at the
/// revision date.
const vwFetchKey = 'fetch';

/// What syncing the files did.
class VwFileRun {
  const VwFileRun({
    this.refused,
    this.pendingDeletes = const [],
    this.fetchLater = false,
    this.uploaded = 0,
    this.deleted = 0,
    this.downloaded = 0,
  });

  /// Why files didn't go to the server, or null when they did.
  final VwFilesRefusal? refused;

  /// Deletions that didn't go through, as `[item id, attachment id]`.
  final List<List<String>> pendingDeletes;

  /// A file the server has wasn't fetched: the next run tries again.
  final bool fetchLater;

  final int uploaded;
  final int deleted;
  final int downloaded;

  @override
  String toString() =>
      'VwFileRun(up $uploaded, deleted $deleted, down $downloaded${refused != null ? ', refused: ${refused!.name}' : ''}${fetchLater ? ', later' : ''})';
}

/// The ids of files this phone removed since its last run: named in
/// [state] then, and by none of [notes] now.
Set<String> removedFileIds(Map<String, Object?> state, Iterable<SecureNote> notes) {
  final before = {...?(state[vwFileIdsKey] as List<Object?>?)?.whereType<String>()};
  return before.difference({
    for (final note in notes)
      for (final file in note.files) file.id,
  });
}

/// The deletions [state] still has to try.
List<List<String>> pendingDeletes(Map<String, Object?> state) => [
  for (final pair in (state[vwPendingDeletesKey] as List<Object?>? ?? const []).whereType<List<Object?>>())
    if (pair.length == 2 && pair[0] is String && pair[1] is String) [pair[0]! as String, pair[1]! as String],
];

/// A vault's attached files on the phone, synced with the attachments of
/// its notes' items.
class VwFiles {
  VwFiles({required this.store, required this.vaultId});

  final AttachmentStore store;
  final String vaultId;

  /// Runs the three steps for [notes], whose items, as the run wrote or
  /// found them, are [items] by note id. [before] is each note as its item
  /// held it before the run, whose files' keys find what was removed;
  /// [removed] the files this phone removed; [pending] the deletions left
  /// from before. [mode] says what an attachment holds: sealed, the `KMA1`
  /// file; plain, the file itself. Throws a [VwError] when an upload can't
  /// reach the server, after the others are done.
  Future<VwFileRun> sync({
    required VwConnection connection,
    required BwKey userKey,
    required VaultwardenMode mode,
    required List<SecureNote> notes,
    required Map<String, VwCipher> items,
    required Map<String, SecureNote> before,
    required Set<String> removed,
    required List<List<String>> pending,
  }) async {
    final api = connection.api;
    final server = connection.server;
    VwFilesRefusal? refused;
    VwError? failed;
    var uploaded = 0;
    var deleted = 0;
    var downloaded = 0;
    var fetchLater = false;
    final stillPending = <List<String>>[];
    final downloads = <({VwCipher item, VwAttachment attachment, NoteAttachment file})>[];

    for (final note in notes) {
      final item = items[note.id];
      if (item == null) continue;
      final itemKey = await cipherKey(item, userKey);
      final gone = [
        for (final file in before[note.id]?.files ?? const <NoteAttachment>[])
          if (removed.contains(file.id) && !note.files.any((kept) => kept.id == file.id)) file,
      ];
      final found = await matchAttachments(itemAttachments(item.json), [...note.files, ...gone], itemKey);

      // 1. What the item lacks and this phone has
      for (final file in note.files) {
        if (found.containsKey(file.id)) continue;
        if (refused != null || failed != null) break;
        final sealed = await store.readSealed(vaultId, file.id);
        if (sealed == null) continue;
        try {
          await _upload(connection, item, itemKey, file, sealed, mode);
          uploaded++;
        } on VwFilesRefused catch (e) {
          refused = e.reason;
        } on VwError catch (e) {
          failed = e;
        } on AttachmentDamagedError {
          // A plain file that doesn't open here isn't sent: another phone may have a good copy
          continue;
        }
      }

      // 2. What this phone removed
      for (final file in gone) {
        final attachment = found[file.id];
        if (attachment == null) continue;
        try {
          await connection.call((token) => api.deleteAttachment(server, token, item.id, attachment.id));
          deleted++;
        } on VwError {
          stillPending.add([item.id, attachment.id]);
        }
      }

      // 3. What this phone lacks
      for (final file in note.files) {
        final attachment = found[file.id];
        if (attachment != null && !await store.exists(vaultId, file.id)) downloads.add((item: item, attachment: attachment, file: file));
      }
    }

    for (final [itemId, attachmentId] in pending) {
      try {
        await connection.call((token) => api.deleteAttachment(server, token, itemId, attachmentId));
        deleted++;
      } on VwError catch (e) {
        // Gone already, with its item or by another phone
        if (e.status != 400 && e.status != 404) stillPending.add([itemId, attachmentId]);
      }
    }

    downloads.sort((a, b) => a.file.size.compareTo(b.file.size));
    for (final (:item, :attachment, :file) in downloads) {
      try {
        await _download(connection, item, attachment, file, mode);
        downloaded++;
      } on VwFilesRefused catch (e) {
        refused ??= e.reason;
        break;
      } on VwError {
        fetchLater = true;
      } on BwCryptoError {
        // Damaged, or not the file it says: dropped, and fetched again next time
        fetchLater = true;
      } on AttachmentDamagedError {
        fetchLater = true;
      }
    }

    if (failed != null) throw failed;
    return VwFileRun(
      refused: refused,
      pendingDeletes: stillPending,
      fetchLater: fetchLater,
      uploaded: uploaded,
      deleted: deleted,
      downloaded: downloaded,
    );
  }

  Future<void> _upload(
    VwConnection connection,
    VwCipher item,
    BwKey itemKey,
    NoteAttachment file,
    Uint8List sealed,
    VaultwardenMode mode,
  ) async {
    final fileKey = unb64(file.key);
    final content = mode == VaultwardenMode.sealed ? sealed : await kma1Decrypt(sealed, fileKey);
    final key = attachmentKey(file);
    final data = await bwEncryptAttachment(content, key);
    final name = await bwEncryptString(mode == VaultwardenMode.sealed ? file.id : file.name, itemKey);
    final api = connection.api;
    final server = connection.server;
    final upload = await connection.call(
      (token) async => api.startAttachmentUpload(
        server,
        token,
        item.id,
        key: (await bwEncrypt(key.bytes, itemKey)).toString(),
        fileName: name,
        fileSize: data.length,
      ),
    );
    try {
      await connection.call((token) => api.uploadAttachment(server, token, item.id, upload, data, fileName: name));
    } on VwFilesRefused {
      // Nothing was sent; the record the first step made goes again
      await connection.call((token) => api.deleteAttachment(server, token, item.id, upload.attachmentId)).catchError((Object _) {});
      rethrow;
    }
  }

  Future<void> _download(VwConnection connection, VwCipher item, VwAttachment attachment, NoteAttachment file, VaultwardenMode mode) async {
    final api = connection.api;
    final server = connection.server;
    final address = await connection.call((token) => api.attachmentAddress(server, token, item.id, attachment.id));
    final most = encryptedAttachmentLength(mode == VaultwardenMode.sealed ? kma1Length(file.size) : file.size);
    final data = await api.downloadAttachment(server, address, maxBytes: most);
    final content = await bwDecryptAttachment(data, attachmentKey(file));
    final fileKey = unb64(file.key);
    if (mode == VaultwardenMode.sealed) {
      // Checked by decrypting it before it is kept
      final plain = await kma1Decrypt(content, fileKey);
      if (plain.length != file.size) throw const AttachmentDamagedError('Not the file the note names');
      await store.writeSealed(vaultId, file.id, content);
    } else {
      if (content.length != file.size) throw const BwCryptoError('Not the file the note names');
      await store.write(vaultId, file.id, content, fileKey);
    }
  }
}
