// Sends, from `docs/crypto.md` "Sends" in the Kemlock server repository. A
// Send shares a note or a file through a link whose key `K` is only ever in
// the link's fragment, so the server holds ciphertext and can't open it.
//
//   link key K  = 32 random bytes
//   send id     = a UUID version 4 the client chooses
//   access id   = base64url(send id (16)), 22 characters
//
//   payload key = HKDF(K, salt = absent, info = "kemlock/v1/send-payload", L = 32)
//   proof salt  = HKDF(K, salt = absent, info = "kemlock/v1/send-proof" || send id, L = 16)
//   meta key    = HKDF(owner's "kemlock/v1/item-wrap" child key, salt = absent,
//                      info = "kemlock/v1/send-meta" || send id || u32be(key version), L = 32)
//
//   aad       = label || send id (16) || lp(kind)
//   payload   = AES-256-GCM(payload key, nonce, payload JSON, aad, label "kemlock/v1/send-payload")
//   meta      = AES-256-GCM(meta key, nonce, meta JSON, aad, label "kemlock/v1/send-meta")
//   sealedKey = u32be(key version) || AES-256-GCM(item-wrap key, nonce, K,
//               aad = "kemlock/v1/send-key" || send id || u32be(key version))     64 bytes
//
//   proof = Argon2id(NFC password, proof salt, m = 19456 KiB, t = 2, p = 1, L = 32)
//
// A file Send's bytes are one `KMA1` file under the payload key. The meta
// key comes from the owner's item-wrap key and never from `K`, so a link
// holder can't read the owner's notes. Every keyed value here is a fresh
// buffer the caller wipes after use.
//
// Pure Dart, no Flutter, beside `kem1.dart`.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../aes_gcm.dart';
import '../attachment_core.dart';
import '../bytes.dart';
import '../hkdf.dart';
import 'argon2id.dart';
import 'encoding.dart';

/// The kind of a Send that holds text.
const sendKindText = 'text';

/// The kind of a Send that holds a file.
const sendKindFile = 'file';

/// The length of the link key `K`.
const sendLinkKeyLength = 32;

/// The length of `sealedKey`: the key version, a nonce, `K` and a tag.
const sendSealedKeyLength = 4 + 12 + sendLinkKeyLength + 16;

/// The least a sealed payload or meta can be: a nonce and a tag around
/// nothing, which is what the server checks.
const sendMinimumSealedLength = 12 + 16;

/// The server's cap on `payload`, 256 KiB.
const sendMaxPayloadLength = 256 * 1024;

/// The server's cap on `meta`, 16 KiB.
const sendMaxMetaLength = 16 * 1024;

/// The length of the password proof.
const sendProofLength = 32;

/// The largest `size` a payload may name, 2^53, as the web vault reads it.
const sendMaxFileSize = 9007199254740992;

/// The labels of "Sends".
abstract final class SendLabel {
  static const payload = 'kemlock/v1/send-payload';
  static const meta = 'kemlock/v1/send-meta';
  static const proof = 'kemlock/v1/send-proof';
  static const key = 'kemlock/v1/send-key';
}

/// The settings of the password proof, fixed by `crypto.md` so a recipient
/// needs nothing from the server: 19 MiB, 2 passes and 1 lane.
const sendProofSettings = Argon2idSettings(memoryKiB: 19456, iterations: 2, parallelism: 1);

/// A fresh random link key `K`.
Uint8List newSendLinkKey() => randomBytes(sendLinkKeyLength);

/// A fresh random send id: 16 bytes of a version 4 UUID, which the server
/// requires.
Uint8List newSendId() {
  final id = randomBytes(16);
  id[6] = (id[6] & 0x0f) | 0x40;
  id[8] = (id[8] & 0x3f) | 0x80;
  return id;
}

/// The access id of [sendId]: its 16 bytes in base64url, 22 characters.
String sendAccessId(List<int> sendId) => b64urlEncode(requireLength(sendId, 16, 'a send id'));

/// The send id an [accessId] names. Anything but 22 canonical base64url
/// characters of 16 bytes is a [MalformedException].
Uint8List sendIdFromAccessId(String accessId) {
  if (accessId.length != 22) throw const MalformedException('an access id is 22 characters');
  return requireLength(b64urlDecode(accessId), 16, 'a send id');
}

/// The payload key of the Send whose link key is [linkKey].
Uint8List sendPayloadKey(List<int> linkKey) {
  requireLength(linkKey, sendLinkKeyLength, 'the link key');
  return hkdfSha256(linkKey, salt: const [], info: label(SendLabel.payload), length: 32);
}

/// The 16-byte salt of the password proof, bound to the Send.
Uint8List sendProofSalt(List<int> linkKey, List<int> sendId) {
  requireLength(linkKey, sendLinkKeyLength, 'the link key');
  requireLength(sendId, 16, 'a send id');
  return hkdfSha256(linkKey, salt: const [], info: concatBytes([label(SendLabel.proof), sendId]), length: 16);
}

/// The meta key, from the owner's item-wrap key, the send id and the key
/// version `sealedKey` names. Never from the link key.
Uint8List sendMetaKey(List<int> itemWrapKey, List<int> sendId, int keyVersion) {
  requireLength(itemWrapKey, 32, 'the item-wrap key');
  requireLength(sendId, 16, 'a send id');
  return hkdfSha256(itemWrapKey, salt: const [], info: concatBytes([label(SendLabel.meta), sendId, u32be(keyVersion)]), length: 32);
}

/// The additional data of a payload or a meta: `label || send id || lp(kind)`.
/// The label is raw ASCII with no length before it.
Uint8List sendAad(String sealLabel, List<int> sendId, String kind) {
  requireLength(sendId, 16, 'a send id');
  _checkKind(kind);
  return concatBytes([label(sealLabel), sendId, lp(label(kind))]);
}

/// The additional data of `sealedKey`.
Uint8List sendKeyAad(List<int> sendId, int keyVersion) {
  requireLength(sendId, 16, 'a send id');
  return concatBytes([label(SendLabel.key), sendId, u32be(keyVersion)]);
}

/// Seals [plaintext] as a Send's payload ([sealLabel] is
/// [SendLabel.payload]) or meta ([SendLabel.meta]) under [key], bound to the
/// send id and kind. [nonce] is random unless given, for known-answer tests
/// only. Returns `nonce || ciphertext || tag`.
Future<Uint8List> sealSendPart({
  required String sealLabel,
  required Uint8List key,
  required List<int> sendId,
  required String kind,
  required List<int> plaintext,
  Uint8List? nonce,
}) async {
  requireLength(key, 32, 'a send key');
  final sealed = await aesGcmEncrypt(key, plaintext, nonce: nonce, aad: sendAad(sealLabel, sendId, kind));
  return concatBytes([sealed.nonce, sealed.ct]);
}

/// Opens a sealed payload or meta. One for another send id, another kind or
/// another key, or with a changed byte, is a [CorruptedException]; one
/// shorter than a nonce and a tag is a [MalformedException].
Future<Uint8List> openSendPart({
  required String sealLabel,
  required Uint8List key,
  required List<int> sendId,
  required String kind,
  required List<int> sealed,
}) async {
  requireLength(key, 32, 'a send key');
  if (sealed.length < sendMinimumSealedLength) throw const MalformedException('a sealed Send part is at least 28 bytes');
  return _open(key, sealed, sendAad(sealLabel, sendId, kind));
}

/// Wraps [linkKey] under the owner's item-wrap key: `u32be(key version)`
/// then the seal, [sendSealedKeyLength] bytes.
Future<Uint8List> wrapLinkKey({
  required Uint8List itemWrapKey,
  required List<int> sendId,
  required int keyVersion,
  required Uint8List linkKey,
  Uint8List? nonce,
}) async {
  requireLength(itemWrapKey, 32, 'the item-wrap key');
  requireLength(linkKey, sendLinkKeyLength, 'the link key');
  final sealed = await aesGcmEncrypt(itemWrapKey, linkKey, nonce: nonce, aad: sendKeyAad(sendId, keyVersion));
  return concatBytes([u32be(keyVersion), sealed.nonce, sealed.ct]);
}

/// The key version in the first four bytes of [sealedKey], read before
/// anything is opened, so the meta key derives without `K`.
int sealedKeyVersion(List<int> sealedKey) {
  requireLength(sealedKey, sendSealedKeyLength, 'a sealed key');
  return ByteData.sublistView(Uint8List.fromList(sealedKey.sublist(0, 4))).getUint32(0);
}

/// Opens [sealedKey] to the link key. One under another key version, for
/// another send id or under another wrap key is a [CorruptedException].
Future<Uint8List> unwrapLinkKey({required Uint8List itemWrapKey, required List<int> sendId, required List<int> sealedKey}) async {
  requireLength(itemWrapKey, 32, 'the item-wrap key');
  final keyVersion = sealedKeyVersion(sealedKey);
  final key = await _open(itemWrapKey, sealedKey.sublist(4), sendKeyAad(sendId, keyVersion));
  if (key.length != sendLinkKeyLength) {
    wipe(key);
    throw const CorruptedException();
  }
  return key;
}

/// The password proof: Argon2id of [password] in NFC form with the proof
/// salt of this Send, under [sendProofSettings]. [runner] runs Argon2id,
/// [isolateArgon2id] by default. The caller wipes the proof once it is sent.
Future<Uint8List> sendProof(String password, List<int> linkKey, List<int> sendId, {Argon2idRunner runner = isolateArgon2id}) async {
  final salt = sendProofSalt(linkKey, sendId);
  try {
    return await deriveMasterKey(password, salt, settings: sendProofSettings, runner: runner);
  } finally {
    wipe(salt);
  }
}

/// The `password` field of a request: the [proof] in base64url.
String sendProofText(List<int> proof) => b64urlEncode(requireLength(proof, sendProofLength, 'a password proof'));

/// The plaintext of a file Send as a `KMA1` file under [linkKey]'s payload
/// key, sealed in a background isolate. The payload key is wiped after.
Future<Uint8List> sealSendFile(Uint8List plain, List<int> linkKey) async {
  final key = sendPayloadKey(linkKey);
  try {
    return await kma1Encrypt(plain, key);
  } finally {
    wipe(key);
  }
}

/// The plaintext of the received `KMA1` [file] of a Send whose payload
/// names [size] bytes of plaintext. A file whose length isn't
/// `kma1Length(size)` is refused before anything is decrypted, as is one that
/// doesn't open ([AttachmentDamagedError]); a plaintext of another length
/// than [size] is refused too.
Future<Uint8List> openSendFile(Uint8List file, List<int> linkKey, int size) async {
  if (!sendFileLengthMatches(size, file.length)) throw const MalformedException('the file is not the length its payload names');
  final key = sendPayloadKey(linkKey);
  try {
    final plain = await kma1Decrypt(file, key);
    if (plain.length != size) {
      wipe(plain);
      throw const MalformedException('the file is not the size its payload names');
    }
    return plain;
  } finally {
    wipe(key);
  }
}

/// Whether [fileSize], as the server announces it, is the `KMA1` length of a
/// file of [plainSize] bytes.
bool sendFileLengthMatches(int plainSize, int fileSize) =>
    plainSize >= 0 && plainSize <= sendMaxFileSize && kma1Length(plainSize) == fileSize;

/// The payload of a Send: what a recipient opens. For a text, exactly
/// `{"name","text"}`; for a file, exactly `{"name","mime","size"}` where
/// `size` is the file's plaintext length. A reader refuses any other field.
final class SendPayload {
  const SendPayload.text({required this.name, required String this.text}) : mime = null, size = null;

  const SendPayload.file({required this.name, required String this.mime, required int this.size}) : text = null;

  /// Reads the plaintext of an opened payload of [kind]. An extra or missing
  /// field, a wrong type, a negative `size` or one above 2^53 is a
  /// [MalformedException].
  factory SendPayload.parse(List<int> plaintext, String kind) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(plaintext));
    } on FormatException {
      throw const MalformedException('the payload is not JSON');
    }
    if (kind == sendKindText) {
      final fields = strictObject(json, required: {'name', 'text'});
      return SendPayload.text(name: _string(fields, 'name'), text: _string(fields, 'text'));
    }
    if (kind == sendKindFile) {
      final fields = strictObject(json, required: {'name', 'mime', 'size'});
      final size = fields['size'];
      if (size is! int || size < 0 || size > sendMaxFileSize) throw const MalformedException('size is an integer from 0 to 2^53');
      return SendPayload.file(name: _string(fields, 'name'), mime: _string(fields, 'mime'), size: size);
    }
    throw MalformedException('unknown Send kind: $kind');
  }

  final String name;

  /// The text of a text Send, else null.
  final String? text;

  /// The file's media type, else null.
  final String? mime;

  /// The file's plaintext length, else null.
  final int? size;

  String get kind => text != null ? sendKindText : sendKindFile;

  /// The JSON the payload is sealed as, UTF-8.
  Uint8List encode() =>
      Uint8List.fromList(utf8.encode(jsonEncode(text != null ? {'name': name, 'text': text} : {'name': name, 'mime': mime, 'size': size})));
}

/// The owner's list entry of a Send, exactly `{"name","notes"}`.
final class SendMeta {
  const SendMeta({required this.name, required this.notes});

  /// Reads the plaintext of an opened meta. An extra or missing field or a
  /// wrong type is a [MalformedException].
  factory SendMeta.parse(List<int> plaintext) {
    final Object? json;
    try {
      json = jsonDecode(utf8.decode(plaintext));
    } on FormatException {
      throw const MalformedException('the meta is not JSON');
    }
    final fields = strictObject(json, required: {'name', 'notes'});
    return SendMeta(name: _string(fields, 'name'), notes: _string(fields, 'notes'));
  }

  final String name;
  final String notes;

  /// The JSON the meta is sealed as, UTF-8.
  Uint8List encode() => Uint8List.fromList(utf8.encode(jsonEncode({'name': name, 'notes': notes})));
}

Future<Uint8List> _open(Uint8List key, List<int> sealed, Uint8List aad) async {
  try {
    return await aesGcmDecrypt(key, sealed.sublist(0, 12), sealed.sublist(12), aad: aad);
  } on AesGcmAuthError {
    throw const CorruptedException();
  }
}

void _checkKind(String kind) {
  if (kind != sendKindText && kind != sendKindFile) throw ArgumentError.value(kind, 'kind', 'a Send is a text or a file');
}

String _string(Map<String, Object?> fields, String name) {
  final value = fields[name];
  if (value is! String) throw MalformedException('$name is a string');
  return value;
}
