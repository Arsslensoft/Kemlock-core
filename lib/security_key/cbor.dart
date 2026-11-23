/// The CBOR a security key speaks (RFC 8949, in CTAP2's canonical form):
/// integers, byte and text strings, arrays, maps and booleans.
///
/// Values are plain Dart: `int`, `Uint8List`, `String`, `List<Object?>`,
/// `Map<Object, Object?>` and `bool`. Writing puts a map's keys in
/// CTAP2's canonical order, whatever order they were given in. Reading
/// refuses what CTAP forbids (indefinite lengths, duplicate map keys) and
/// anything left over or cut short. It also reads null and floating-point
/// numbers, which a key may put under a member this app does not use.
///
/// `Cbor` in `features/passkeys/passkey_bytes.dart` is another, write-only
/// one, pinned by the passkey fixtures; this one does not replace it.
library;

import 'dart:convert';
import 'dart:typed_data';

/// Bytes that are not the CBOR a key may send.
class CborError extends FormatException {
  const CborError(super.message);
}

/// [value] in CTAP2 canonical CBOR.
Uint8List cborEncode(Object? value) {
  final out = BytesBuilder(copy: false);
  _write(out, value);
  return out.takeBytes();
}

void _head(BytesBuilder out, int major, int value) {
  final top = major << 5;
  if (value < 24) {
    out.addByte(top | value);
  } else if (value < 0x100) {
    out.add([top | 24, value]);
  } else if (value < 0x10000) {
    out.add([top | 25, value >> 8, value & 0xff]);
  } else if (value < 0x100000000) {
    out.add([top | 26, value >> 24 & 0xff, value >> 16 & 0xff, value >> 8 & 0xff, value & 0xff]);
  } else {
    out.addByte(top | 27);
    for (var shift = 56; shift >= 0; shift -= 8) {
      out.addByte(value >> shift & 0xff);
    }
  }
}

void _write(BytesBuilder out, Object? value) {
  switch (value) {
    case final int v:
      v >= 0 ? _head(out, 0, v) : _head(out, 1, -1 - v);
    case final Uint8List v:
      _head(out, 2, v.length);
      out.add(v);
    case final String v:
      final encoded = utf8.encode(v);
      _head(out, 3, encoded.length);
      out.add(encoded);
    case final List<Object?> v:
      _head(out, 4, v.length);
      for (final item in v) {
        _write(out, item);
      }
    case final Map<Object?, Object?> v:
      final entries = [for (final entry in v.entries) (cborEncode(entry.key), entry.value)]..sort((a, b) => _canonical(a.$1, b.$1));
      for (var i = 1; i < entries.length; i++) {
        if (_canonical(entries[i - 1].$1, entries[i].$1) == 0) throw const CborError('A map has the same key twice.');
      }
      _head(out, 5, entries.length);
      for (final (key, item) in entries) {
        out.add(key);
        _write(out, item);
      }
    case final bool v:
      out.addByte(v ? 0xf5 : 0xf4);
    default:
      throw CborError('CTAP2 has no encoding for ${value.runtimeType}.');
  }
}

/// CTAP2's order of two encoded map keys: the lower major type first, then
/// the shorter, then the lower in byte order. On encoded keys that is
/// "shorter first, then byte order", but for the major type, which the
/// first byte decides.
int _canonical(Uint8List a, Uint8List b) {
  final majorA = a[0] >> 5;
  final majorB = b[0] >> 5;
  if (majorA != majorB) return majorA - majorB;
  if (a.length != b.length) return a.length - b.length;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return 0;
}

/// The value [bytes] hold. Throws a [CborError] for anything that is not
/// one whole CBOR item of the kinds a key may send.
Object? cborDecode(List<int> bytes) {
  final reader = _Reader(bytes is Uint8List ? bytes : Uint8List.fromList(bytes));
  final value = reader.item(0);
  if (reader.offset != reader.bytes.length) throw const CborError('There are bytes after the CBOR item.');
  return value;
}

/// The first CBOR item of [bytes] and how many bytes it takes, for an item
/// with others after it, as the parts of a credential's `authData` are.
(Object? value, int length) cborDecodeFirst(List<int> bytes) {
  final reader = _Reader(bytes is Uint8List ? bytes : Uint8List.fromList(bytes));
  final value = reader.item(0);
  return (value, reader.offset);
}

class _Reader {
  _Reader(this.bytes);

  /// Deeper nesting than any CTAP message has; a guard against a hostile answer.
  static const _maxDepth = 16;

  final Uint8List bytes;
  int offset = 0;

  int _byte() {
    if (offset >= bytes.length) throw const CborError('The CBOR item is cut short.');
    return bytes[offset++];
  }

  Uint8List _take(int length) {
    if (length < 0 || bytes.length - offset < length) throw const CborError('The CBOR item is cut short.');
    final taken = Uint8List.sublistView(bytes, offset, offset + length);
    offset += length;
    return taken;
  }

  int _argument(int info) {
    if (info < 24) return info;
    if (info > 27) throw CborError(info == 31 ? 'CTAP2 forbids indefinite lengths.' : 'A CBOR item has a reserved length.');
    final size = 1 << (info - 24);
    var value = 0;
    for (var i = 0; i < size; i++) {
      final byte = _byte();
      if (i == 0 && size == 8 && byte >= 0x80) throw const CborError('A CBOR number is too large.');
      value = value << 8 | byte;
    }
    return value;
  }

  Object? item(int depth) {
    if (depth > _maxDepth) throw const CborError('The CBOR item is nested too deep.');
    final first = _byte();
    final major = first >> 5;
    final info = first & 0x1f;
    switch (major) {
      case 0:
        return _argument(info);
      case 1:
        return -1 - _argument(info);
      case 2:
        return Uint8List.fromList(_take(_argument(info)));
      case 3:
        try {
          return utf8.decode(_take(_argument(info)));
        } on FormatException {
          throw const CborError('A CBOR text string is not UTF-8.');
        }
      case 4:
        final length = _argument(info);
        if (length > bytes.length - offset) throw const CborError('The CBOR item is cut short.');
        return <Object?>[for (var i = 0; i < length; i++) item(depth + 1)];
      case 5:
        final length = _argument(info);
        if (length > bytes.length - offset) throw const CborError('The CBOR item is cut short.');
        final map = <Object, Object?>{};
        for (var i = 0; i < length; i++) {
          final key = item(depth + 1);
          if (key is! int && key is! String) throw const CborError('A CBOR map key is neither a number nor text.');
          if (map.containsKey(key)) throw const CborError('A CBOR map has the same key twice.');
          map[key!] = item(depth + 1);
        }
        return map;
      case 6:
        throw const CborError('CTAP2 has no CBOR tags.');
      default:
        switch (info) {
          case 20:
            return false;
          case 21:
            return true;
          case 22 || 23:
            return null;
          case 25:
            return _half(ByteData.sublistView(_take(2)).getUint16(0));
          case 26:
            return ByteData.sublistView(_take(4)).getFloat32(0);
          case 27:
            return ByteData.sublistView(_take(8)).getFloat64(0);
          case 31:
            throw const CborError('CTAP2 forbids indefinite lengths.');
          default:
            throw const CborError('A CBOR simple value is not one CTAP2 uses.');
        }
    }
  }

  /// An IEEE 754 half-precision number (RFC 8949, appendix D).
  static double _half(int half) {
    final exponent = half >> 10 & 0x1f;
    final mantissa = half & 0x3ff;
    final double value;
    if (exponent == 0) {
      value = mantissa * 5.960464477539063e-8;
    } else if (exponent != 31) {
      value = (mantissa + 1024) * 5.960464477539063e-8 * (1 << (exponent - 1));
    } else {
      value = mantissa == 0 ? double.infinity : double.nan;
    }
    return half & 0x8000 != 0 ? -value : value;
  }
}

/// [value] as a map with number keys, as every CTAP2 request and answer
/// is; members under other keys are dropped. Empty when [value] is no map.
Map<int, Object?> cborIntMap(Object? value) => {
  if (value is Map)
    for (final MapEntry(:key, value: item) in value.entries)
      if (key is int) key: item,
};

/// [value] as a map with text keys, as CTAP2's options and entities are.
Map<String, Object?> cborTextMap(Object? value) => {
  if (value is Map)
    for (final MapEntry(:key, value: item) in value.entries)
      if (key is String) key: item,
};
