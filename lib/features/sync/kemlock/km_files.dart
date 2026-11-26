/// How the files attached to notes, and the file of a File item, travel with Kemlock Server sync: each is the
/// `KMA1` file exactly as the phone keeps it, so the server only ever holds
/// ciphertext (`attachment_sync.dart` does the same for WebDAV).
///
/// The server numbers files itself, and needs the item to exist before
/// it takes one (`POST /kem/v1/items/{id}/files`), so a run:
///
/// 1. writes the notes and File items as items first, without a server file for the new
///    attachments;
/// 2. uploads each file an item names that this phone has and the server lacks,
///    the exact `KMA1` bytes, with the size announced and the server's limit
///    checked;
/// 3. writes the item again, its attachment now naming the server's file id in
///    its own keys ([kmFileKey], kept as an unknown key by every version) and the file's
///    `sha256`, so another phone can fetch it. An item never names a file the server lacks,
///    and a file its body already names is never sent again;
/// 4. deletes from the server the files of attachments no item names any more, last, once no body names them;
/// 5. fetches the files the merged items name and this phone lacks (unless [KmFiles.fetchMissing] is off).
///    A download stops at the size its item names, and is stored only when it opens with
///    its attachment's key: a file that doesn't is thrown away.
///
/// A file is written once and never changed. The id the phone's items use for
/// an attachment stays the file's name on the phone; the server's is only the
/// address.
///
/// A note holds any number of attachments (`attachments`); a File item holds one (`file`). Both are
/// the same [NoteAttachment] entry.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/encoding.dart' show Owner;
import '../../../crypto/attachment_core.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_file.dart';
import '../../../vault/attachment_seal.dart' show sha256Hex;
import '../sync_merge.dart';
import 'km_api.dart';
import 'km_kinds.dart';

/// The key of an attachment's JSON that holds the server's file id.
const kmFileKey = 'kemlockFile';

/// The phone's attached files, sealed as `KMA1` (`AttachmentStore`'s side of it).
///
/// What a run asks of it: [readSealed] is called only for the attachments the run must upload, which are those whose item is on
/// the server and whose body names no server file yet. A host that keeps no files (the browser) can therefore hold just the
/// sealed bytes of a file still waiting to go up, in memory, and answer null for every other id. [exists] and [writeSealed] are
/// used only by the step that fetches files this phone lacks, which a host that keeps none turns off with
/// [KmFiles.fetchMissing].
abstract interface class KmFileStore {
  /// Whether this phone has the file of the attachment [id].
  Future<bool> exists(String id);

  /// The file's `KMA1` bytes, or null when this phone lacks it. Asked only for an attachment a run must upload.
  Future<Uint8List?> readSealed(String id);

  /// Keeps the `KMA1` bytes of the attachment [id].
  Future<void> writeSealed(String id, Uint8List sealed);
}

/// The server's file id an attachment names, or null.
String? kmServerFileId(NoteAttachment file) {
  final id = file.extra[kmFileKey];
  return id is String && id.isNotEmpty ? id : null;
}

/// [file] naming the server's file [fileId] and holding the SHA-256 [sha256] of its bytes (its own, when [sha256] is null).
/// Every other member stays as it was.
NoteAttachment kmNamedFile(NoteAttachment file, String fileId, {String? sha256}) => NoteAttachment(
  id: file.id,
  name: file.name,
  size: file.size,
  type: file.type,
  key: file.key,
  addedAt: file.addedAt,
  sha256: sha256 ?? file.sha256,
  extra: {...file.extra, kmFileKey: fileId},
);

/// [file] naming no server file: what a new item made from an old one starts with, until its bytes are sent again.
NoteAttachment kmUnnamedFile(NoteAttachment file) => !file.extra.containsKey(kmFileKey)
    ? file
    : NoteAttachment(
        id: file.id,
        name: file.name,
        size: file.size,
        type: file.type,
        key: file.key,
        addedAt: file.addedAt,
        sha256: file.sha256,
        extra: {...file.extra}..remove(kmFileKey),
      );

/// The files [entry] holds: a note's attachments, a File item's file, none for any other kind.
List<NoteAttachment> kmAttachmentsOf(KmEntry entry) => switch (entry.kind) {
  KmKind.note => SecureNote.fromJson(entry.json).files,
  KmKind.file => [VaultFile.fromJson(entry.json).file],
  _ => const [],
};

/// [entry] with its files replaced by [files], which are as many as it held, in the same order. An entry of a kind with no
/// files comes back as it was. [at] (epoch ms) stamps the entry as changed.
KmEntry kmWithAttachments(KmEntry entry, List<NoteAttachment> files, {int? at}) {
  switch (entry.kind) {
    case KmKind.note:
      final note = SecureNote.fromJson(entry.json).copyWith(attachments: files);
      return (kind: entry.kind, json: (at == null ? note : note.stamped(at)).toJson());
    case KmKind.file:
      final item = VaultFile.fromJson(entry.json).copyWith(file: files.single);
      return (kind: entry.kind, json: (at == null ? item : item.stamped(at)).toJson());
    default:
      return entry;
  }
}

/// [entry] naming none of the server files it named: what the copy of an item is saved as first.
KmEntry kmWithoutServerFiles(KmEntry entry) {
  final files = kmAttachmentsOf(entry);
  if (files.every((file) => !file.extra.containsKey(kmFileKey))) {
    return entry;
  }
  return kmWithAttachments(entry, [for (final file in files) kmUnnamedFile(file)]);
}

/// [entry] naming only the server files [previous] names, which is all a write from a caller is trusted to say: each attachment of
/// [entry] loses the server file it names, then takes the one [previous] names for the attachment with the same `id` and `key`, with
/// that file's `sha256` when it holds one. With no [previous] (a new item) none is named, so the files are uploaded again. An entry
/// whose attachments already say exactly that comes back as it was.
KmEntry kmTrustedFiles(KmEntry entry, KmEntry? previous) {
  final files = kmAttachmentsOf(entry);
  if (files.isEmpty) {
    return entry;
  }
  final held = {for (final file in previous == null ? const <NoteAttachment>[] : kmAttachmentsOf(previous)) file.id: file};
  var changed = false;
  final out = <NoteAttachment>[];
  for (final file in files) {
    final unnamed = kmUnnamedFile(file);
    final old = held[file.id];
    final oldId = old == null || old.key != file.key ? null : kmServerFileId(old);
    final next = old == null || oldId == null ? unnamed : kmNamedFile(unnamed, oldId, sha256: old.sha256);
    changed = changed || next != file;
    out.add(next);
  }
  return changed ? kmWithAttachments(entry, out) : entry;
}

/// Why a file couldn't be fetched on demand.
enum KmFileProblem {
  /// The entry names no file on the server (never uploaded, or from a phone that hasn't sent it yet).
  notOnServer,

  /// The file is larger than the entry says, or than a file may be.
  tooLarge,

  /// The bytes aren't the file the entry names: wrong length, not opened by its key, or a size that differs.
  damaged,

  /// The file opened, and its SHA-256 isn't the one the entry holds.
  hashMismatch,
}

/// A file that [kmFetchFile] could not give.
class KmFileError implements Exception {
  const KmFileError(this.problem);

  final KmFileProblem problem;

  @override
  String toString() => 'KmFileError(${problem.name})';
}

/// The plain bytes of [entry], an attachment of the item [itemId] (a note's, or a File item's `file`), fetched on demand over
/// [connection] to [server]: `GET /kem/v1/items/{id}/files/{fileId}` capped at the size the entry names, opened with its key, and
/// checked against its `sha256` when it has one. Nothing is stored; a host that keeps no files calls this each time the person
/// opens the file. [kmItemId] gives the item id of an entry's id and its owner.
///
/// Throws a [KmFileError] for a file the entry doesn't name on the server ([KmFileProblem.notOnServer]), one larger than the entry
/// says (`tooLarge`), one that doesn't open or isn't its size (`damaged`) and one whose hash differs (`hashMismatch`), and a
/// [KmError] when the server can't be reached or refuses.
Future<Uint8List> kmFetchFile({
  required KmConnection connection,
  required Uri server,
  required String itemId,
  required NoteAttachment entry,
}) async {
  final fileId = kmServerFileId(entry);
  if (fileId == null) {
    throw const KmFileError(KmFileProblem.notOnServer);
  }
  if (entry.size < 0 || entry.size > attachmentSizeLimit) {
    throw const KmFileError(KmFileProblem.tooLarge);
  }
  final expected = kma1Length(entry.size);
  final Uint8List sealed;
  try {
    sealed = await connection.call((token) => connection.api.downloadFile(server, token, itemId, fileId, maxBytes: expected));
  } on KmError catch (e) {
    if (e.problem == KmProblem.tooLarge) {
      throw const KmFileError(KmFileProblem.tooLarge);
    }
    rethrow;
  }
  if (sealed.length != expected) {
    throw const KmFileError(KmFileProblem.damaged);
  }
  final Uint8List plain;
  try {
    plain = await kma1Decrypt(sealed, unb64(entry.key));
  } on AttachmentDamagedError {
    throw const KmFileError(KmFileProblem.damaged);
  } on FormatException {
    throw const KmFileError(KmFileProblem.damaged);
  }
  if (plain.length != entry.size) {
    throw const KmFileError(KmFileProblem.damaged);
  }
  final hash = entry.sha256;
  if (hash != null && hash.toLowerCase() != sha256Hex(plain)) {
    throw const KmFileError(KmFileProblem.hashMismatch);
  }
  return plain;
}

/// A server file a run just made, under its item.
typedef _Created = ({String itemId, String fileId});

/// The key of the scope state that holds [KmFiles.refused].
const kmRefusedFilesKey = 'refusedFiles';

/// The most attachments a scope state remembers as refused: the latest.
const _refusedLimit = 500;

/// The attachment ids [extra], a scope state's `extra`, holds as refused; none for a member of another shape.
Set<String> kmRefusedFilesOf(Map<String, Object?> extra) => {
  if (extra[kmRefusedFilesKey] case final List<Object?> ids) ...ids.whereType<String>(),
};

/// [extra] holding [refused] (the latest few hundred) and every other key as it was; without the member when there are none.
Map<String, Object?> kmWithRefusedFiles(Map<String, Object?> extra, Set<String> refused) {
  if (refused.isEmpty) {
    return extra.containsKey(kmRefusedFilesKey) ? ({...extra}..remove(kmRefusedFilesKey)) : extra;
  }
  final ids = refused.toList();
  return {...extra, kmRefusedFilesKey: ids.length > _refusedLimit ? ids.sublist(ids.length - _refusedLimit) : ids};
}

/// The server's file ids each note and File item of [doc] names, by the item id [itemIdOf] gives its id.
Map<String, Set<String>> kmFileIdsOf(SyncDoc doc, {required String Function(String entryId) itemIdOf}) => {
  for (final note in doc.notes)
    if (note.files.isNotEmpty) itemIdOf(note.id): {for (final file in note.files) ?kmServerFileId(file)},
  for (final item in doc.files) itemIdOf(item.id): {?kmServerFileId(item.file)},
};

/// The ids in [after] that [before] doesn't hold, by item: the files a step uploaded. Items with none are left out.
Map<String, Set<String>> kmNewFileIds(Map<String, Set<String>> before, Map<String, Set<String>> after) => {
  for (final MapEntry(key: itemId, value: ids) in after.entries)
    if (ids.difference(before[itemId] ?? const {}).isNotEmpty) itemId: ids.difference(before[itemId] ?? const {}),
};

/// The files of one vault, uploaded and fetched.
class KmFiles {
  KmFiles({required this.store, required this.connection, required this.server, this.fetchMissing = true, Set<String>? refused})
    : refused = refused ?? <String>{};

  final KmFileStore store;
  final KmConnection connection;
  final Uri server;

  /// Whether a run fetches the files the merged items name and the [store] lacks (step 5). A host that keeps no file bytes (the
  /// browser extension) turns it off, so a sync never downloads every file; it opens one when asked ([fetchPlain]).
  final bool fetchMissing;

  /// The ids of the attachments with no `sha256` that a run couldn't send, because they don't open with their key or the server refused
  /// them: a later run leaves them alone instead of reading and decrypting them again to find their hash. A sync run keeps the set
  /// in its scope state ([kmRefusedFilesOf], [kmWithRefusedFiles]); an attachment that holds its hash is never listed.
  final Set<String> refused;

  KmApi get _api => connection.api;

  /// Uploads each file a note or File item of [doc] names that has no server file and this phone holds, for the
  /// items whose item [onServer] says is there. [itemIdOf] gives the item id of an entry's id. Returns [doc] with those items
  /// stamped [now] and naming the server's ids (and each file's `sha256`), or null when nothing went up. A file the server won't
  /// take (too large) is skipped, and sync goes on without it.
  Future<SyncDoc?> upload(
    SyncDoc doc, {
    required int now,
    required String Function(String entryId) itemIdOf,
    required bool Function(String itemId) onServer,
  }) async {
    final notes = <SecureNote>[];
    final items = <VaultFile>[];
    final created = <_Created>[];
    var any = false;
    try {
      for (final note in doc.notes) {
        final itemId = itemIdOf(note.id);
        final sent = note.files.isEmpty || !onServer(itemId) ? null : await _uploadAll(itemId, note.files, created);
        any |= sent != null;
        notes.add(sent == null ? note : note.copyWith(attachments: sent, updatedAt: now));
      }
      for (final item in doc.files) {
        final itemId = itemIdOf(item.id);
        final sent = onServer(itemId) ? await _uploadAll(itemId, [item.file], created) : null;
        any |= sent != null;
        items.add(sent == null ? item : item.copyWith(file: sent.single).stamped(now));
      }
    } catch (_) {
      // No body names what went up before this stopped, so it is of no use to anyone
      await _discard(created);
      rethrow;
    }
    if (!any) {
      return null;
    }
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
      files: items,
      deleted: doc.deleted,
      seq: doc.seq,
      extra: doc.extra,
    );
  }

  /// [files] with each one that has no server file uploaded and named; null when none went up. Each file that went up is added to
  /// [created], also when a later one throws.
  Future<List<NoteAttachment>?> _uploadAll(String itemId, List<NoteAttachment> files, List<_Created> created) async {
    final out = <NoteAttachment>[];
    var changed = false;
    for (final file in files) {
      // Never sends again a file the body already names
      final sent = kmServerFileId(file) == null ? await _uploadOne(itemId, file) : null;
      if (sent == null) {
        out.add(file);
      } else {
        changed = true;
        created.add((itemId: itemId, fileId: kmServerFileId(sent)!));
        out.add(sent);
      }
    }
    return changed ? out : null;
  }

  /// Deletes the files just [created], best effort: a file left behind is only a copy of bytes the server already held.
  Future<void> _discard(List<_Created> created) async {
    for (final (:itemId, :fileId) in created) {
      try {
        await connection.call((token) => _api.deleteFile(server, token, itemId, fileId));
      } on KmError {
        continue;
      }
    }
  }

  /// Deletes from the server the files [ids] names (the server's file ids by item id): what a caller does when the write that was to
  /// name the files it has just uploaded failed, so none stays that no body names. Best effort; call it with the ids that went up
  /// during this attempt only, never with a file a body of the item already names.
  Future<void> discard(Map<String, Set<String>> ids) => _discard([
    for (final MapEntry(key: itemId, value: files) in ids.entries)
      for (final fileId in files) (itemId: itemId, fileId: fileId),
  ]);

  /// Uploads each file [entry], a note or a File item whose item [itemId] is on the server, names that has no server file and
  /// [store] holds, as [upload] does for a whole document. Returns the entry naming the server's ids and each file's `sha256`,
  /// stamped [now], or null when nothing went up.
  Future<KmEntry?> uploadEntryFiles(KmEntry entry, {required String itemId, required int now}) async {
    final files = kmAttachmentsOf(entry);
    if (files.isEmpty) {
      return null;
    }
    final created = <_Created>[];
    try {
      final sent = await _uploadAll(itemId, files, created);
      return sent == null ? null : kmWithAttachments(entry, sent, at: now);
    } catch (_) {
      await _discard(created);
      rethrow;
    }
  }

  /// [file] naming its upload, or null when this phone doesn't have the file, it isn't the size its item says, it doesn't open
  /// with its key (only checked for a file whose item holds no `sha256`, to write it), or the server won't take it.
  Future<NoteAttachment?> _uploadOne(String itemId, NoteAttachment file) async {
    if (file.size < 0 || file.size > attachmentSizeLimit || (file.sha256 == null && refused.contains(file.id))) {
      return null;
    }
    final bytes = await store.readSealed(file.id);
    if (bytes == null || bytes.length != kma1Length(file.size)) {
      return null;
    }
    var hash = file.sha256;
    if (hash == null) {
      // An older attachment: the hash is of the plain bytes, and a file that doesn't open with its key isn't worth sending
      try {
        hash = sha256Hex(await kma1Decrypt(bytes, unb64(file.key)));
      } on AttachmentDamagedError {
        refused.add(file.id);
        return null;
      } on FormatException {
        refused.add(file.id);
        return null;
      }
    }
    final fileId = await _send(itemId, bytes);
    if (fileId == null && file.sha256 == null) {
      refused.add(file.id);
    }
    return fileId == null ? null : kmNamedFile(file, fileId, sha256: hash);
  }

  /// Sends [bytes], a `KMA1` file, as a new file of the item [itemId] and returns the server's id for it, or null when the server
  /// won't take it (too large).
  Future<String?> _send(String itemId, Uint8List bytes) async {
    try {
      final start = await connection.call((token) => _api.startFile(server, token, itemId, bytes.length));
      if (start.size != bytes.length || bytes.length > start.maxSize) {
        return null;
      }
      await connection.call((token) => _api.uploadFile(server, token, itemId, start, bytes));
      return start.fileId;
    } on KmError catch (e) {
      if (e.problem == KmProblem.tooLarge) {
        return null;
      }
      rethrow;
    }
  }

  /// Deletes from the server the files [before] named that [after] doesn't, for items that are still
  /// there: an item a run held out of the merge never loses its files. Best effort: a file left behind is
  /// only a copy of bytes the server already held. Called last, once no body names them.
  Future<void> deleteRemoved(Map<String, Set<String>> before, Map<String, Set<String>> after) async {
    for (final MapEntry(key: itemId, value: ids) in before.entries) {
      final now = after[itemId];
      if (now == null) {
        continue;
      }
      for (final fileId in ids.difference(now)) {
        try {
          await connection.call((token) => _api.deleteFile(server, token, itemId, fileId));
        } on KmError {
          continue;
        }
      }
    }
  }

  /// Fetches the files the notes and File items of [doc] name that this phone lacks, the smallest first. A file that
  /// can't be fetched now, is larger than its item says, or doesn't open with its key is skipped and
  /// tried again at the next run. Returns how many were stored; none, and nothing asked of the [store], when [fetchMissing] is off.
  Future<int> download(SyncDoc doc, {required String Function(String entryId) itemIdOf}) async {
    if (!fetchMissing) {
      return 0;
    }
    final wanted = <({String itemId, NoteAttachment file, String fileId})>[];
    Future<void> want(String itemId, NoteAttachment file) async {
      final fileId = kmServerFileId(file);
      if (fileId == null || file.size > attachmentSizeLimit || await store.exists(file.id)) {
        return;
      }
      wanted.add((itemId: itemId, file: file, fileId: fileId));
    }

    for (final note in doc.notes) {
      for (final file in note.files) {
        await want(itemIdOf(note.id), file);
      }
    }
    for (final item in doc.files) {
      await want(itemIdOf(item.id), item.file);
    }
    wanted.sort((a, b) => a.file.size.compareTo(b.file.size));
    var stored = 0;
    for (final (:itemId, :file, :fileId) in wanted) {
      final expected = kma1Length(file.size);
      try {
        final bytes = await connection.call((token) => _api.downloadFile(server, token, itemId, fileId, maxBytes: expected));
        if (bytes.length != expected) {
          continue;
        }
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

  /// [kmFetchFile] over this vault's connection.
  Future<Uint8List> fetchPlain(String itemId, NoteAttachment entry) =>
      kmFetchFile(connection: connection, server: server, itemId: itemId, entry: entry);

  /// [fetchPlain] for the entry with the app's id [entryId] in [owner]'s items.
  Future<Uint8List> fetchPlainOf(String entryId, Owner owner, NoteAttachment entry) => fetchPlain(kmItemId(entryId, owner), entry);

  /// Sends each file [entry] names under the item [fromItemId] again under the item [toItemId], which must exist: what a new item
  /// made from an old one (a copy, a move to another owner, a merge) needs, since the server keeps a file under one item's id.
  /// Each file's sealed bytes are read (`GET …/files/{fileId}`) and sent as they are: the chunks of a `KMA1` file aren't bound to the
  /// item, so they open with the same key and nothing is decrypted. The new entry keeps every member (`id`, `name`, `size`, `type`,
  /// `key`, `addedAt`, `sha256`) and names the file the server made for it in `kemlockFile`.
  ///
  /// The caller saves [toItemId] first with [kmWithoutServerFiles] of the entry, so a body never names a file the server lacks,
  /// then saves the returned entry. A file that can't be read or sent (gone from the old item, too large, the wrong length)
  /// stays unnamed in the result and is listed in `failed` by its attachment id; the phone's own copy uploads it at a later
  /// run when it has one. A [KmError] that isn't about the file itself (no network, the session) is thrown.
  Future<({KmEntry entry, List<String> failed})> resendFiles(KmEntry entry, {required String fromItemId, required String toItemId}) async {
    final files = kmAttachmentsOf(entry);
    final out = <NoteAttachment>[];
    final failed = <String>[];
    var changed = false;
    for (final file in files) {
      final oldId = kmServerFileId(file);
      if (oldId == null) {
        out.add(file);
        continue;
      }
      final next = await _resend(file, oldId, fromItemId, toItemId);
      changed = true;
      if (next == null) {
        failed.add(file.id);
        out.add(kmUnnamedFile(file));
      } else {
        out.add(next);
      }
    }
    return (entry: changed ? kmWithAttachments(entry, out) : entry, failed: failed);
  }

  Future<NoteAttachment?> _resend(NoteAttachment file, String oldId, String fromItemId, String toItemId) async {
    if (file.size < 0 || file.size > attachmentSizeLimit) {
      return null;
    }
    final expected = kma1Length(file.size);
    final Uint8List sealed;
    try {
      sealed = await connection.call((token) => _api.downloadFile(server, token, fromItemId, oldId, maxBytes: expected));
    } on KmError catch (e) {
      // The file is gone from the old item, or larger than it should be
      if (e.problem == KmProblem.tooLarge || e.status == 404) {
        return null;
      }
      rethrow;
    }
    if (sealed.length != expected) {
      return null;
    }
    final fileId = await _send(toItemId, sealed);
    return fileId == null ? null : kmNamedFile(file, fileId);
  }
}
