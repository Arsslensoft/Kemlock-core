// `kem1`, the item envelope of `docs/crypto.md`. Each item has its own random
// 32-byte item key. The revision is part of what is sealed, so the client
// assigns it: a new item is revision 1, and each write is the previous
// revision plus one.
//
//   aad        = "kemlock/v1/item" || item id (16) || u64be(revision) || lp(kind) || owner (17)
//   ciphertext = AES-256-GCM(item key, nonce, item JSON (UTF-8), aad)
//
//   wrap aad   = "kemlock/v1/item-key" || item id (16) || owner (17) || u32be(key version)
//   item_key   = AES-256-GCM(owner's "kemlock/v1/item-wrap" child key, nonce, item key, wrap aad)
//
// A sealed value is nonce (12) || ciphertext || tag (16). The item key wrap is
// not bound to the revision, so an edit may keep the item key. A decoder
// checks every length before it decrypts anything.

library;

import 'dart:typed_data';

import '../aes_gcm.dart';
import '../bytes.dart';
import 'encoding.dart';

/// The wire value of `format` for an item sealed this way.
const kem1Format = 'kem1';

/// The plaintext the server accepts, 2 MiB of item JSON.
const kem1MaxPlaintextLength = 2 * 1024 * 1024;

const _nonceLength = 12;
const _tagLength = 16;

/// The least a sealed value can be: a nonce and a tag around nothing.
const kem1MinimumSealedLength = _nonceLength + _tagLength;

/// The length of a wrapped item key: nonce, 32-byte key and tag.
const kem1WrappedKeyLength = _nonceLength + 32 + _tagLength;

/// An item kind: 1 to 64 bytes of `[a-z0-9_-]`, such as `login`, `otp`,
/// `note`, `backup-codes`, `passkey`, `pgp-key`, `ssh-key`, `certificate`,
/// `card` or `identity`.
bool isValidKind(String kind) => _kind.hasMatch(kind);

final _kind = RegExp(r'^[a-z0-9_-]{1,64}$');

/// Seals and opens items and their keys.
abstract final class Kem1 {
  /// A fresh random 32-byte item key.
  static Uint8List newItemKey() => randomBytes(32);

  /// The additional data an item's ciphertext is bound to.
  static Uint8List itemAad({required List<int> itemId, required int revision, required String kind, required Owner owner}) {
    requireLength(itemId, 16, 'an item id');
    if (revision < 1) throw ArgumentError.value(revision, 'revision', 'a revision starts at 1');
    _checkKind(kind);
    return concatBytes([label('kemlock/v1/item'), itemId, u64be(revision), lp(label(kind)), owner.bytes]);
  }

  /// The additional data an item key's wrap is bound to.
  static Uint8List wrapAad({required List<int> itemId, required Owner owner, required int keyVersion}) {
    requireLength(itemId, 16, 'an item id');
    return concatBytes([label('kemlock/v1/item-key'), itemId, owner.bytes, u32be(keyVersion)]);
  }

  /// Seals [plaintext], the item's JSON as UTF-8, under [itemKey] for this
  /// item, revision, kind and owner. [nonce] is random unless given, which
  /// is for known-answer tests only. Returns `nonce || ciphertext || tag`.
  static Future<Uint8List> sealItem({
    required Uint8List itemKey,
    required List<int> itemId,
    required int revision,
    required String kind,
    required Owner owner,
    required List<int> plaintext,
    Uint8List? nonce,
  }) async {
    requireLength(itemKey, 32, 'an item key');
    if (plaintext.length > kem1MaxPlaintextLength) throw ArgumentError.value(plaintext.length, 'plaintext', 'over 2 MiB');
    final aad = itemAad(itemId: itemId, revision: revision, kind: kind, owner: owner);
    final sealed = await aesGcmEncrypt(itemKey, plaintext, nonce: nonce, aad: aad);
    return concatBytes([sealed.nonce, sealed.ct]);
  }

  /// Opens a sealed item. The ciphertext of another item, another revision,
  /// another kind or another owner, or a changed byte, is a
  /// [CorruptedException]; one shorter than a nonce and a tag is a
  /// [MalformedException].
  static Future<Uint8List> openItem({
    required Uint8List itemKey,
    required List<int> itemId,
    required int revision,
    required String kind,
    required Owner owner,
    required List<int> ciphertext,
  }) async {
    requireLength(itemKey, 32, 'an item key');
    if (ciphertext.length < kem1MinimumSealedLength) throw const MalformedException('a sealed item is at least 28 bytes');
    final aad = itemAad(itemId: itemId, revision: revision, kind: kind, owner: owner);
    return _open(itemKey, ciphertext, aad);
  }

  /// Wraps [itemKey] under the owner's `item-wrap` child key. Returns
  /// `nonce || ciphertext || tag`, 60 bytes.
  static Future<Uint8List> wrapItemKey({
    required Uint8List itemWrapKey,
    required List<int> itemId,
    required Owner owner,
    required int keyVersion,
    required Uint8List itemKey,
    Uint8List? nonce,
  }) async {
    requireLength(itemWrapKey, 32, 'the item-wrap key');
    requireLength(itemKey, 32, 'an item key');
    final sealed = await aesGcmEncrypt(
      itemWrapKey,
      itemKey,
      nonce: nonce,
      aad: wrapAad(itemId: itemId, owner: owner, keyVersion: keyVersion),
    );
    return concatBytes([sealed.nonce, sealed.ct]);
  }

  /// Unwraps an item key. A wrapped key of another length is a
  /// [MalformedException]; one for another item, owner or key version, or
  /// under another wrap key, is a [CorruptedException].
  static Future<Uint8List> unwrapItemKey({
    required Uint8List itemWrapKey,
    required List<int> itemId,
    required Owner owner,
    required int keyVersion,
    required List<int> wrapped,
  }) async {
    requireLength(itemWrapKey, 32, 'the item-wrap key');
    requireLength(wrapped, kem1WrappedKeyLength, 'a wrapped item key');
    return _open(itemWrapKey, wrapped, wrapAad(itemId: itemId, owner: owner, keyVersion: keyVersion));
  }
}

Future<Uint8List> _open(Uint8List key, List<int> sealed, Uint8List aad) async {
  try {
    return await aesGcmDecrypt(key, sealed.sublist(0, _nonceLength), sealed.sublist(_nonceLength), aad: aad);
  } on AesGcmAuthError {
    throw const CorruptedException();
  }
}

void _checkKind(String kind) {
  if (!isValidKind(kind)) throw ArgumentError.value(kind, 'kind', 'must be 1 to 64 bytes of [a-z0-9_-]');
}

/// An item as the Kemlock API carries it, for `format` "kem1":
///
/// ```json
/// { "id": "…uuid…", "owner": "user:…uuid…", "kind": "login", "format": "kem1",
///   "revision": 4, "keyVersion": 1, "ciphertext": "…b64url…", "itemKey": "…b64url…",
///   "deleted": false }
/// ```
///
/// A deleted item is a tombstone: `deleted: true` with `ciphertext` and
/// `itemKey` absent. Its revision still moves on, so a device sees the
/// deletion as a newer write.
final class Kem1Item {
  Kem1Item({
    required this.id,
    required this.owner,
    required this.kind,
    required this.revision,
    required this.keyVersion,
    this.ciphertext,
    this.itemKey,
  }) {
    uuidBytes(id);
    if (revision < 1) throw const MalformedException('a revision starts at 1');
    u32be(keyVersion);
    if (!isValidKind(kind)) throw MalformedException('not an item kind: $kind');
    if ((ciphertext == null) != (itemKey == null)) throw const MalformedException('ciphertext and itemKey come together');
    if (ciphertext != null && ciphertext!.length < kem1MinimumSealedLength) {
      throw const MalformedException('a sealed item is at least 28 bytes');
    }
    if (itemKey != null && itemKey!.length != kem1WrappedKeyLength) throw const MalformedException('a wrapped item key is 60 bytes');
  }

  /// A tombstone: a deletion at [revision].
  Kem1Item.tombstone({required this.id, required this.owner, required this.kind, required this.revision, required this.keyVersion})
    : ciphertext = null,
      itemKey = null {
    uuidBytes(id);
    if (revision < 1) throw const MalformedException('a revision starts at 1');
    u32be(keyVersion);
    if (!isValidKind(kind)) throw MalformedException('not an item kind: $kind');
  }

  /// Reads the JSON object. Unknown fields, an unknown `format`, padded or
  /// standard-alphabet base64, and a tombstone that carries a ciphertext (or
  /// an item without one) are a [MalformedException]. Every length is
  /// checked here, before anything is decrypted.
  factory Kem1Item.fromJson(Object? json) {
    final fields = strictObject(
      json,
      required: {'id', 'owner', 'kind', 'format', 'revision', 'keyVersion', 'deleted'},
      optional: {'ciphertext', 'itemKey'},
    );
    final format = fields['format'];
    if (format != kem1Format) throw MalformedException('unknown item format: $format');
    final id = _string(fields, 'id');
    final owner = Owner.fromWire(_string(fields, 'owner'));
    final kind = _string(fields, 'kind');
    final revision = _int(fields, 'revision');
    final keyVersion = _int(fields, 'keyVersion');
    final deleted = fields['deleted'];
    if (deleted is! bool) throw const MalformedException('deleted is a boolean');
    if (deleted) {
      if (fields.containsKey('ciphertext') || fields.containsKey('itemKey')) {
        throw const MalformedException('a tombstone carries no ciphertext');
      }
      return Kem1Item.tombstone(id: id, owner: owner, kind: kind, revision: revision, keyVersion: keyVersion);
    }
    if (!fields.containsKey('ciphertext') || !fields.containsKey('itemKey')) {
      throw const MalformedException('an item needs ciphertext and itemKey');
    }
    return Kem1Item(
      id: id,
      owner: owner,
      kind: kind,
      revision: revision,
      keyVersion: keyVersion,
      ciphertext: b64urlDecode(_string(fields, 'ciphertext')),
      itemKey: b64urlDecode(_string(fields, 'itemKey')),
    );
  }

  /// The item's id, hyphenated lower-case.
  final String id;
  final Owner owner;
  final String kind;
  final int revision;
  final int keyVersion;

  /// `nonce || ciphertext || tag`, or null for a tombstone.
  final Uint8List? ciphertext;

  /// The wrapped item key, 60 bytes, or null for a tombstone.
  final Uint8List? itemKey;

  bool get deleted => ciphertext == null;

  Map<String, Object?> toJson() => {
    'id': id,
    'owner': owner.toWire(),
    'kind': kind,
    'format': kem1Format,
    'revision': revision,
    'keyVersion': keyVersion,
    if (ciphertext != null) 'ciphertext': b64urlEncode(ciphertext!),
    if (itemKey != null) 'itemKey': b64urlEncode(itemKey!),
    'deleted': deleted,
  };
}

String _string(Map<String, Object?> fields, String name) {
  final value = fields[name];
  if (value is! String) throw MalformedException('$name is a string');
  return value;
}

int _int(Map<String, Object?> fields, String name) {
  final value = fields[name];
  if (value is! int) throw MalformedException('$name is an integer');
  return value;
}
