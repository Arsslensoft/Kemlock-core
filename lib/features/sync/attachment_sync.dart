/// How files attached to notes travel with WebDAV sync: each is a file of
/// its own in the scope's folder, `backmycodes-file-<attachment id>`, the
/// `KMA1` file exactly as the phone keeps it, so the server only ever holds
/// ciphertext under a name that says nothing of the file. A file is written
/// once and never changed.
///
/// A scope's run, around the sync of its document:
///
/// 1. List the folder once.
/// 2. Upload every file this phone has that the folder lacks: new
///    attachments, and files the server lost. If one fails, the run stops
///    before the document is written, so it never names a file that isn't
///    there.
/// 3. Read, merge and write the document as before.
/// 4. Delete from the folder the files of attachments this phone removed,
///    once the written document no longer names them. A phone never
///    deletes a file it didn't remove: one nothing names yet may belong to
///    a document another phone is about to write.
/// 5. Hand the files the merged notes name and the phone lacks to the
///    downloads, outside the run.
library;

import 'dart:typed_data';

import '../../models/secure_note.dart';
import '../../vault/attachment_store_interface.dart';
import 'sync_merge.dart';
import 'webdav.dart';

/// The name of an attached file in a sync folder.
String syncedFileName(String attachmentId) => 'backmycodes-file-$attachmentId';

/// The scope state's key for the files its notes named after this phone's
/// last sync: one gone from the notes since was removed here.
const fileIdsKey = 'files';

/// The scope state's key for files this phone removed whose deletion from
/// the folder hasn't gone through yet.
const removedFilesKey = 'removedFiles';

/// The attachments [lists]' notes name.
Iterable<NoteAttachment> attachmentsOf(Lists lists) => [for (final note in lists.notes) ...note.files];

/// Steps 1, 2 and 4 of a scope's run, for one vault's files.
class AttachmentSync {
  AttachmentSync({required this.webDav, required this.store, required this.vaultId});

  final WebDav webDav;
  final AttachmentStore store;
  final String vaultId;

  /// Steps 1 and 2: lists the folder and uploads each of [local]'s files
  /// this phone has and the folder lacks. Throws, before the document is
  /// written, when an upload fails. Returns the names the folder holds now.
  Future<Set<String>> upload(DavAccount dav, Lists local) async {
    final files = attachmentsOf(local).toList();
    if (files.isEmpty) return const {};
    final names = {for (final entry in await webDav.listFolder(dav)) entry.name};
    for (final file in files) {
      final name = syncedFileName(file.id);
      if (names.contains(name)) continue;
      final Uint8List? sealed = await store.readSealed(vaultId, file.id);
      // Not on this phone either: another phone has it to upload
      if (sealed == null) continue;
      await webDav.writeBytesIfAbsent(dav, name, sealed);
      names.add(name);
    }
    return names;
  }

  /// Step 4: deletes from the folder each of [removed] that [doc] doesn't
  /// name. Returns the ones whose deletion didn't go through, to try again.
  Future<List<String>> deleteRemoved(DavAccount dav, Iterable<String> removed, SyncDoc doc) async {
    final named = {for (final file in attachmentsOf(doc)) file.id};
    final failed = <String>[];
    for (final id in removed) {
      if (named.contains(id)) continue;
      try {
        await webDav.deleteFile(dav, syncedFileName(id));
      } on DavError {
        failed.add(id);
      }
    }
    return failed;
  }

  /// Step 5: the files [doc]'s notes name that this phone lacks.
  Future<List<NoteAttachment>> missing(SyncDoc doc) async => [
    for (final file in attachmentsOf(doc))
      if (!await store.exists(vaultId, file.id)) file,
  ];
}

/// The ids this phone removed since its last sync of a scope, and those
/// still waiting from before: named in [state] last time, and named by no
/// note of [local] now.
Set<String> removedFiles(Map<String, Object?> state, Lists local) {
  final before = {...?(state[fileIdsKey] as List<Object?>?)?.whereType<String>()};
  final now = {for (final file in attachmentsOf(local)) file.id};
  return {...before.difference(now), ...?(state[removedFilesKey] as List<Object?>?)?.whereType<String>()};
}
