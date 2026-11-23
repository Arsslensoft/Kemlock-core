// The conventions of `docs/crypto.md` in the Kemlock server repository,
// "Conventions": big-endian integers, `lp(x)`, UUIDs as 16 raw bytes,
// owners of 17 bytes and base64url without padding. Every Kemlock account
// format is built from these, and every reader here is strict: it checks
// lengths before it decrypts anything and refuses unknown fields and
// trailing bytes.
//
// Pure Dart, no Flutter, so the code moves into a shared package unchanged.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../bytes.dart';

/// Input that is not in the format: a wrong length, an unknown version, an
/// unknown field, a padded base64url value or trailing bytes. Nothing was
/// decrypted.
class MalformedException implements Exception {
  const MalformedException(this.message);

  final String message;

  @override
  String toString() => 'MalformedException: $message';
}

/// Input of the right shape that does not authenticate: a wrong key, or data
/// that was changed. It never says which part failed.
class CorruptedException implements Exception {
  const CorruptedException([this.message = 'corrupted']);

  final String message;

  @override
  String toString() => 'CorruptedException: $message';
}

/// Zeroes [bytes] in place. Dart can't promise that no copy of a secret is
/// left, because the garbage collector may have moved it, but a buffer this
/// code owns is cleared as soon as it is done with.
void wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

/// [bytes] as an owned copy, `Uint8List` whatever list it came in.
Uint8List copyBytes(List<int> bytes) => Uint8List.fromList(bytes);

/// ASCII [text] as bytes, for the labels of `crypto.md`, which are written in
/// double quotes there and used as bytes with no terminator.
Uint8List label(String text) {
  for (var i = 0; i < text.length; i++) {
    if (text.codeUnitAt(i) > 0x7f) throw ArgumentError.value(text, 'text', 'a label is ASCII');
  }
  return Uint8List.fromList(text.codeUnits);
}

/// One byte, `u8(value)`.
Uint8List u8(int value) {
  if (value < 0 || value > 0xff) throw ArgumentError.value(value, 'value', 'does not fit u8');
  return Uint8List(1)..[0] = value;
}

/// Two bytes, `u16be(value)`.
Uint8List u16be(int value) {
  if (value < 0 || value > 0xffff) throw ArgumentError.value(value, 'value', 'does not fit u16');
  return Uint8List(2)..buffer.asByteData().setUint16(0, value);
}

/// Four bytes, `u32be(value)`.
Uint8List u32be(int value) {
  if (value < 0 || value > 0xffffffff) throw ArgumentError.value(value, 'value', 'does not fit u32');
  return Uint8List(4)..buffer.asByteData().setUint32(0, value);
}

/// Eight bytes, `u64be(value)`. A Dart `int` holds 63 bits of it, which is
/// far above any revision or counter.
Uint8List u64be(int value) {
  if (value < 0) throw ArgumentError.value(value, 'value', 'does not fit u64');
  return Uint8List(8)
    ..buffer.asByteData().setUint32(0, value >> 32)
    ..buffer.asByteData().setUint32(4, value & 0xffffffff);
}

/// `lp(x) = u32be(len(x)) || x`, the length-prefixed form of every variable
/// field inside a hashed or authenticated input, so fields can never run into
/// each other.
Uint8List lp(List<int> x) => concatBytes([u32be(x.length), x]);

/// A UUID's 16 raw bytes (RFC 9562 byte order) from its hyphenated lower-case
/// text. Upper case, braces, a missing hyphen and any other form are refused.
Uint8List uuidBytes(String uuid) {
  if (!_uuidText.hasMatch(uuid)) throw MalformedException('not a hyphenated lower-case UUID: $uuid');
  final hex = uuid.replaceAll('-', '');
  return Uint8List.fromList([for (var i = 0; i < 32; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);
}

/// The hyphenated lower-case text of a UUID's 16 [bytes].
String uuidText(List<int> bytes) {
  if (bytes.length != 16) throw MalformedException('a UUID is 16 bytes, not ${bytes.length}');
  final hex = [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// Whether [text] is a hyphenated lower-case UUID. An id that already is one
/// is never mapped by "Legacy ids".
bool isUuidText(String text) => _uuidText.hasMatch(text);

final _uuidText = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

/// What an owner is: `u8(type)` of an owner is 1 for a user's own vault and 2
/// for a space.
enum OwnerType {
  user(0x01, 'user'),
  space(0x02, 'space');

  const OwnerType(this.code, this.wireName);

  final int code;
  final String wireName;
}

/// An owner, 17 bytes on the wire of a hashed input: `u8(type) || uuid`.
final class Owner {
  Owner(this.type, List<int> id) : id = Uint8List.fromList(id) {
    if (id.length != 16) throw MalformedException('an owner id is 16 bytes, not ${id.length}');
  }

  /// A user's own vault, from the user's hyphenated UUID.
  factory Owner.user(String uuid) => Owner(OwnerType.user, uuidBytes(uuid));

  /// A space, from its hyphenated UUID (a mapped one for an older space id).
  factory Owner.space(String uuid) => Owner(OwnerType.space, uuidBytes(uuid));

  /// Reads the 17 bytes. Another length or an unknown type is refused.
  factory Owner.fromBytes(List<int> bytes) {
    if (bytes.length != 17) throw MalformedException('an owner is 17 bytes, not ${bytes.length}');
    final type = OwnerType.values.where((t) => t.code == bytes[0]);
    if (type.isEmpty) throw MalformedException('unknown owner type ${bytes[0]}');
    return Owner(type.first, bytes.sublist(1));
  }

  /// Reads the JSON form, `user:<uuid>` or `space:<uuid>` with the UUID
  /// hyphenated and lower case. Any other prefix, or another form of the
  /// UUID, is refused.
  factory Owner.fromWire(String text) {
    for (final type in OwnerType.values) {
      final prefix = '${type.wireName}:';
      if (text.startsWith(prefix)) return Owner(type, uuidBytes(text.substring(prefix.length)));
    }
    throw MalformedException('unknown owner form: $text');
  }

  final OwnerType type;
  final Uint8List id;

  /// `u8(type) || uuid`, 17 bytes.
  Uint8List get bytes => concatBytes([u8(type.code), id]);

  /// The JSON form, `user:<uuid>` or `space:<uuid>`, hyphenated lower case.
  String toWire() => '${type.wireName}:${uuidText(id)}';

  @override
  bool operator ==(Object other) => other is Owner && other.type == type && constantTimeEquals(other.id, id);

  @override
  int get hashCode => Object.hash(type, Object.hashAll(id));
}

/// Base64url without padding (RFC 4648 section 5), the form of every binary
/// value in Kemlock API JSON.
String b64urlEncode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// Reads base64url without padding. A decoder refuses padding, the standard
/// alphabet, whitespace and any final character whose unused bits are not
/// zero, so a value has one text only.
Uint8List b64urlDecode(String text) {
  if (!_b64urlText.hasMatch(text) || text.length % 4 == 1) throw const MalformedException('not base64url without padding');
  final padded = text.padRight((text.length + 3) ~/ 4 * 4, '=');
  final List<int> bytes;
  try {
    bytes = base64Url.decode(padded);
  } on FormatException {
    throw const MalformedException('not base64url without padding');
  }
  if (b64urlEncode(bytes) != text) throw const MalformedException('base64url is not canonical');
  return Uint8List.fromList(bytes);
}

final _b64urlText = RegExp(r'^[A-Za-z0-9_-]*$');

/// [bytes] when it is exactly [length] long, else a [MalformedException]
/// naming [what]. Check lengths first, decrypt after.
Uint8List requireLength(List<int> bytes, int length, String what) {
  if (bytes.length != length) throw MalformedException('$what is $length bytes, not ${bytes.length}');
  return bytes is Uint8List ? bytes : Uint8List.fromList(bytes);
}

/// A strict reader over a byte string: every read checks that the bytes are
/// there, and [finish] refuses trailing bytes.
final class ByteReader {
  ByteReader(List<int> bytes) : _bytes = bytes is Uint8List ? bytes : Uint8List.fromList(bytes);

  final Uint8List _bytes;
  int _offset = 0;

  int get remaining => _bytes.length - _offset;

  /// The next [n] bytes, as a copy.
  Uint8List read(int n, String what) {
    if (n < 0 || n > remaining) throw MalformedException('$what: $remaining bytes left, $n needed');
    final out = Uint8List.fromList(Uint8List.sublistView(_bytes, _offset, _offset + n));
    _offset += n;
    return out;
  }

  int readU8(String what) => read(1, what)[0];

  int readU16(String what) => ByteData.sublistView(read(2, what)).getUint16(0);

  int readU32(String what) => ByteData.sublistView(read(4, what)).getUint32(0);

  /// Everything left.
  Uint8List readRest() => read(remaining, 'rest');

  /// Throws a [MalformedException] unless every byte was read.
  void finish() {
    if (remaining != 0) throw MalformedException('$remaining trailing bytes');
  }
}

/// The fields of the JSON object [json], when it holds every name in
/// [required], no name outside [required] and [optional], and nothing else.
/// An unknown field is refused, as `crypto.md` says.
Map<String, Object?> strictObject(Object? json, {required Set<String> required, Set<String> optional = const {}}) {
  if (json is! Map<String, Object?>) throw const MalformedException('expected a JSON object');
  for (final name in json.keys) {
    if (!required.contains(name) && !optional.contains(name)) throw MalformedException('unknown field $name');
  }
  for (final name in required) {
    if (!json.containsKey(name)) throw MalformedException('missing field $name');
  }
  return json;
}
