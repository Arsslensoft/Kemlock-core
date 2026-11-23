// Legacy ids, `docs/crypto.md` "Legacy ids". The server keys items and spaces
// by UUID, but the app holds older ids it can't change, because sync pairs
// copies of an entry across WebDAV, Vaultwarden and the server by them: 0.1.0
// entries such as `acc-1`, 16-hex entry ids such as `3f2c9a71e4b0d856`, and
// space ids of 1 to 64 characters of `[A-Za-z0-9_-]`. An id that isn't a
// hyphenated lower-case UUID maps to a deterministic UUIDv8 (RFC 9562 section
// 5.8), so every client makes the same one:
//
//   space uuid = uuidv8(SHA-256("kemlock/v1/legacy-id" || lp("space") || lp(old space id)))
//   item uuid  = uuidv8(SHA-256("kemlock/v1/legacy-id" || lp("item") || owner (17) || lp(old item id)))
//
// `uuidv8(h)` takes `h[0..16]`, sets the version nibble (`b[6] = b[6] & 0x0f |
// 0x80`) and the variant bits (`b[8] = b[8] & 0x3f | 0x80`). Old ids are their
// UTF-8 bytes, exactly as stored. The item's owner is part of its input,
// because two people's 0.1.0 vaults both hold an `acc-1`; a space owner uses
// its mapped space uuid. The original id stays inside the item's JSON. An id
// that already is a UUID is never mapped.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'encoding.dart';

final _spaceId = RegExp(r'^[A-Za-z0-9_-]{1,64}$');

/// The UUID of the space with the app's id [spaceId], hyphenated lower-case.
/// A [spaceId] that already is a UUID is returned as it is. Any other must be
/// 1 to 64 characters of `[A-Za-z0-9_-]`.
String spaceUuid(String spaceId) {
  if (isUuidText(spaceId)) return spaceId;
  if (!_spaceId.hasMatch(spaceId)) throw MalformedException('not a space id: $spaceId');
  return _uuidv8(concatBytes([label('kemlock/v1/legacy-id'), lp(label('space')), lp(utf8.encode(spaceId))]));
}

/// The UUID of the item with the app's id [itemId] in [owner]'s store,
/// hyphenated lower-case. An [itemId] that already is a UUID is returned as it
/// is. [owner] of a space holds that space's mapped UUID.
String itemUuid(String itemId, Owner owner) {
  if (isUuidText(itemId)) return itemId;
  if (itemId.isEmpty) throw const MalformedException('an item id is not empty');
  return _uuidv8(concatBytes([label('kemlock/v1/legacy-id'), lp(label('item')), owner.bytes, lp(utf8.encode(itemId))]));
}

String _uuidv8(List<int> input) {
  final digest = hash.sha256.convert(input).bytes;
  final b = Uint8List.fromList(digest.sublist(0, 16));
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  return uuidText(b);
}
