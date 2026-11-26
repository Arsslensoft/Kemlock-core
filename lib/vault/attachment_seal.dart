// Pure Dart: makes a new attached file, for a note's attachment or a File item's file. The bytes are sealed as `KMA1` under a fresh
// random key, and the entry that names them is returned beside them, with the file's SHA-256 (what the duplicate finder reads).
// Nothing is stored: the caller keeps the sealed bytes where it keeps files (`AttachmentStore.writeSealed`, a browser's memory
// until the upload), and saves the entry in the note or File item.
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../crypto/attachment_core.dart';
import '../crypto/bytes.dart';
import '../models/secure_note.dart';
import 'attachment_store_interface.dart' show newAttachmentId;

/// A file sealed as `KMA1`, and the entry that names it. [sealed] is exactly the bytes to store and upload; the entry holds the file's
/// own key, so nothing else is needed to open it.
typedef SealedAttachment = ({Uint8List sealed, NoteAttachment entry});

/// The SHA-256 of [bytes] as 64 lower-case hex digits: how a file's `sha256` is written.
String sha256Hex(List<int> bytes) => hash.sha256.convert(bytes).toString();

/// Seals [plain] as a `KMA1` file under a new random 256-bit key and names it: a new `id`, [name], the size, [type] when
/// the picker knew it, the key, the time ([now], epoch ms) and the SHA-256 of [plain].
///
/// Throws an [ArgumentError] for a file over [attachmentSizeLimit] or with no [name].
Future<SealedAttachment> sealAttachment(Uint8List plain, {required String name, String? type, required int now}) async {
  if (name.isEmpty) {
    throw ArgumentError.value(name, 'name', 'a file has a name');
  }
  if (plain.length > attachmentSizeLimit) {
    throw ArgumentError.value(plain.length, 'plain', 'a file is at most $attachmentSizeLimit bytes');
  }
  final key = randomBytes(32);
  final sealed = await kma1Encrypt(plain, key);
  return (
    sealed: sealed,
    entry: NoteAttachment(
      id: newAttachmentId(),
      name: name,
      size: plain.length,
      type: type == null || type.isEmpty ? null : type,
      key: b64(key),
      addedAt: now,
      sha256: sha256Hex(plain),
    ),
  );
}
