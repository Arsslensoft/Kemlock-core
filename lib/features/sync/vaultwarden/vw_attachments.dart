/// Files attached to notes, as attachments of their Vaultwarden items.
///
/// Bitwarden encrypts an attachment's data with a 64-byte key of its own
/// (AES-256-CBC and HMAC-SHA256), into a buffer `2 | iv (16) | mac (32) |
/// data`, and keeps that key, and the file's name, encrypted with the item's
/// key. Kemlock gives a note's file the key [attachmentKey] derives from the
/// file's own key, so any phone holding the note finds which attachment is
/// which file without another record, and never sends a file twice:
///
/// - sealed, the data is the `KMA1` file as the phone keeps it, under the
///   attachment's id as its name, so the server and Bitwarden's apps only
///   see ciphertext under a name that says nothing;
/// - plain, the data is the file itself, under its real name, so Bitwarden's
///   apps download and open it.
///
/// An attachment is never replaced: a file is written once, and one removed
/// from a note is deleted.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import '../../../crypto/background.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';

/// What [attachmentKey] derives with.
const _keyInfo = 'Kemlock attachment in Bitwarden';

/// The Bitwarden key of [file]'s attachment: HKDF-Expand-SHA256 of the
/// file's own key with "Kemlock attachment in Bitwarden", 64 bytes. Other
/// phones derive the same, which is how they tell the file's attachment.
BwKey attachmentKey(NoteAttachment file) => BwKey.fromBytes(hkdfExpandSha256(unb64(file.key), utf8.encode(_keyInfo), 64));

/// Whether [a] and [b] are the same key.
bool sameKey(BwKey a, BwKey b) {
  final x = a.bytes;
  final y = b.bytes;
  if (x.length != y.length) return false;
  var diff = 0;
  for (var i = 0; i < x.length; i++) {
    diff |= x[i] ^ y[i];
  }
  return diff == 0;
}

/// An encrypted buffer's type: AES-256-CBC with HMAC-SHA256.
const _bufferType = 2;
const _ivLength = 16;
const _macLength = 32;
const _headerLength = 1 + _ivLength + _macLength;

/// Above this, encryption runs in a background isolate.
const _inlineLimit = 1024 * 1024;

final _aesCbc = DartAesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);

/// [data] encrypted as Bitwarden encrypts an attachment, with [key].
Future<Uint8List> bwEncryptAttachment(Uint8List data, BwKey key) async {
  if (key.mac == null) throw ArgumentError('An attachment key has a MAC key');
  if (data.length <= _inlineLimit) return _encrypt(data, key.enc, key.mac!);
  final enc = key.enc;
  final mac = key.mac!;
  return runInBackground(() => _encrypt(data, enc, mac), debugName: 'bitwarden attachment');
}

/// The data of [buffer], a Bitwarden attachment, opened with [key]. Throws a
/// [BwCryptoError] when it isn't one, or [key] doesn't open it.
Future<Uint8List> bwDecryptAttachment(Uint8List buffer, BwKey key) async {
  if (key.mac == null) throw ArgumentError('An attachment key has a MAC key');
  if (buffer.length <= _inlineLimit) return _decrypt(buffer, key.enc, key.mac!);
  final enc = key.enc;
  final mac = key.mac!;
  return runInBackground(() => _decrypt(buffer, enc, mac), debugName: 'bitwarden attachment');
}

Uint8List _mac(Uint8List key, Uint8List iv, Uint8List data) =>
    Uint8List.fromList(hash.Hmac(hash.sha256, key).convert(concatBytes([iv, data])).bytes);

Future<Uint8List> _encrypt(Uint8List data, Uint8List enc, Uint8List mac) async {
  final iv = randomBytes(_ivLength);
  final box = await _aesCbc.encrypt(data, secretKey: SecretKeyData(List<int>.of(enc)), nonce: iv);
  final cipherText = Uint8List.fromList(box.cipherText);
  return concatBytes([
    Uint8List.fromList(const [_bufferType]),
    iv,
    _mac(mac, iv, cipherText),
    cipherText,
  ]);
}

Future<Uint8List> _decrypt(Uint8List buffer, Uint8List enc, Uint8List mac) async {
  if (buffer.length < _headerLength + 16 || buffer[0] != _bufferType) {
    throw const BwCryptoError('Not an encrypted attachment');
  }
  final iv = Uint8List.sublistView(buffer, 1, 1 + _ivLength);
  final tag = Uint8List.sublistView(buffer, 1 + _ivLength, _headerLength);
  final cipherText = Uint8List.sublistView(buffer, _headerLength);
  final expected = _mac(mac, iv, cipherText);
  var diff = 0;
  for (var i = 0; i < _macLength; i++) {
    diff |= expected[i] ^ tag[i];
  }
  if (diff != 0) throw const BwCryptoError('Wrong key or changed data');
  try {
    final plain = await _aesCbc.decrypt(
      SecretBox(cipherText, nonce: iv, mac: Mac.empty),
      secretKey: SecretKeyData(List<int>.of(enc)),
    );
    return Uint8List.fromList(plain);
  } catch (_) {
    throw const BwCryptoError('Wrong key or changed data');
  }
}

/// How long [length] bytes are once encrypted as an attachment, which is
/// the size an upload announces.
int encryptedAttachmentLength(int length) => _headerLength + (length ~/ 16 + 1) * 16;

/// One attachment of an item, as `/api/sync` lists it: its name and key
/// still encrypted with the item's key.
class VwAttachment {
  const VwAttachment({required this.id, required this.fileName, required this.key, required this.size, this.url});

  /// Reads one of an item's `attachments`; null when it lacks an id.
  static VwAttachment? fromJson(Map<String, Object?> json) {
    final id = json['id'];
    if (id is! String || id.isEmpty) return null;
    final size = json['size'];
    return VwAttachment(
      id: id,
      fileName: json['fileName'] as String?,
      key: json['key'] as String?,
      size: size is num ? size.toInt() : int.tryParse('${size ?? ''}') ?? 0,
      url: json['url'] as String?,
    );
  }

  final String id;
  final String? fileName;

  /// The attachment's key, encrypted with the item's; null on attachments
  /// from before Bitwarden gave each one its own.
  final String? key;

  /// The encrypted data's size.
  final int size;
  final String? url;

  @override
  String toString() => 'VwAttachment($id, $size)';
}

/// The attachments of an item as `/api/sync` gives it.
List<VwAttachment> itemAttachments(Map<String, Object?> cipher) => [
  for (final json in (cipher['attachments'] as List<Object?>? ?? const []).whereType<Map<String, Object?>>()) ?VwAttachment.fromJson(json),
];

/// Which of [attachments] holds each of [files], by file id: the one whose
/// key, opened with [itemKey], is the key [attachmentKey] derives for it.
/// Attachments that hold none of them (added in Bitwarden, or keyless) are
/// left out.
Future<Map<String, VwAttachment>> matchAttachments(List<VwAttachment> attachments, Iterable<NoteAttachment> files, BwKey itemKey) async {
  final wanted = {for (final file in files) file.id: attachmentKey(file)};
  final found = <String, VwAttachment>{};
  for (final attachment in attachments) {
    final encrypted = attachment.key;
    if (encrypted == null) continue;
    final BwKey key;
    try {
      key = BwKey.fromBytes(await bwDecrypt(EncString.parse(encrypted), itemKey));
    } on BwCryptoError {
      continue;
    } on ArgumentError {
      continue;
    }
    for (final MapEntry(key: id, value: derived) in wanted.entries) {
      if (sameKey(key, derived)) {
        found.putIfAbsent(id, () => attachment);
        break;
      }
    }
  }
  return found;
}
