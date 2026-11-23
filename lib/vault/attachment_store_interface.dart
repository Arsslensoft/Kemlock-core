// Pure Dart: where the files attached to notes are kept, as the engines and the vault see it. `attachment_store.dart`
// has the one on the phone's file system.
import 'dart:typed_data';

import '../crypto/bytes.dart';

/// No stored file for an attachment: removed, not synced yet, or left out of an import.
class AttachmentMissingError implements Exception {
  const AttachmentMissingError(this.id);

  final String id;

  @override
  String toString() => 'AttachmentMissingError: $id';
}

/// A stored file, as listing a vault's folder finds it.
typedef StoredAttachment = ({String id, int size, DateTime modified});

/// Where the files attached to notes are kept: one folder per vault, one
/// `KMA1` file per attachment, named by its id, so the name says nothing of
/// the file. Nothing is ever stored in the clear, and a file is never
/// rewritten: a new attachment is a new file.
abstract interface class AttachmentStore {
  /// Encrypts [plain] under [key] and stores it as [vaultId]'s file [id].
  /// It is written under a temporary name and renamed once complete, so a
  /// failed write leaves nothing.
  Future<void> write(String vaultId, String id, Uint8List plain, Uint8List key);

  /// Stores [sealed], a `KMA1` file made elsewhere (an import, a download),
  /// as it is, the same way [write] does.
  Future<void> writeSealed(String vaultId, String id, Uint8List sealed);

  /// The plaintext of [vaultId]'s file [id]. Throws [AttachmentMissingError]
  /// without one and [AttachmentDamagedError] when it doesn't open.
  Future<Uint8List> read(String vaultId, String id, Uint8List key);

  /// The stored `KMA1` file as it is, for exports and sync; null without one.
  Future<Uint8List?> readSealed(String vaultId, String id);

  /// Decrypts [vaultId]'s file [id] to [path], leaving nothing there if it
  /// doesn't open.
  Future<void> decryptTo(String vaultId, String id, Uint8List key, String path);

  Future<bool> exists(String vaultId, String id);

  /// Deletes the file, if there is one.
  Future<void> delete(String vaultId, String id);

  /// The files in [vaultId]'s folder.
  Future<List<StoredAttachment>> list(String vaultId);

  /// Deletes [vaultId]'s folder and everything in it.
  Future<void> deleteVault(String vaultId);

  /// Deletes every vault's files.
  Future<void> deleteAll();
}

/// A new attachment's id: 16 random bytes in base64url.
String newAttachmentId() => b64url(randomBytes(16));
