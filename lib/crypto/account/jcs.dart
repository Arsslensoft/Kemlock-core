// RFC 8785 (JSON Canonicalization Scheme) for the JSON the app signs or
// hashes, such as an entry of a space's chain (`docs/plans/add-server-spaces.md`,
// design 2): objects without whitespace and with their members sorted by the
// UTF-16 code units of their names, arrays in order, strings written as
// `jcsStringArray` writes them, and integers as plain digits.
//
// Only the JSON a signature covers goes through here, and it holds no
// fractions: a number that isn't a whole number from -(2^53 - 1) to 2^53 - 1,
// the range in which ECMAScript writes an integer as digits alone, is refused,
// so no float is ever written two ways.
//
// Pure Dart, no Flutter.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'dedup.dart' show jcsStringArray;

/// The largest whole number ECMAScript writes as plain digits, 2^53 - 1.
const jcsMaxSafeInteger = 9007199254740991;

/// [value] as RFC 8785 JSON text. [value] is built of `Map<String, Object?>`,
/// `List`, `String`, `int`, `bool` and `null`; anything else, a double and a
/// whole number out of range included, is an [ArgumentError].
String jcs(Object? value) {
  final out = StringBuffer();
  _write(out, value);
  return out.toString();
}

/// The UTF-8 bytes of [jcs] of [value], which is what is signed and hashed.
Uint8List jcsBytes(Object? value) => Uint8List.fromList(utf8.encode(jcs(value)));

void _write(StringBuffer out, Object? value) {
  switch (value) {
    case null:
      out.write('null');
    case bool():
      out.write(value ? 'true' : 'false');
    case int():
      if (value < -jcsMaxSafeInteger || value > jcsMaxSafeInteger) {
        throw ArgumentError.value(value, 'value', 'a number outside the range JCS writes as digits');
      }
      out.write(value.toString());
    case String():
      _writeString(out, value);
    case List<Object?>():
      out.write('[');
      for (var i = 0; i < value.length; i++) {
        if (i > 0) {
          out.write(',');
        }
        _write(out, value[i]);
      }
      out.write(']');
    case Map<String, Object?>():
      // String's comparison is by UTF-16 code unit, which is the order RFC 8785 asks for
      final names = value.keys.toList()..sort();
      out.write('{');
      for (var i = 0; i < names.length; i++) {
        if (i > 0) {
          out.write(',');
        }
        _writeString(out, names[i]);
        out.write(':');
        _write(out, value[names[i]]);
      }
      out.write('}');
    default:
      throw ArgumentError.value(value, 'value', 'not JSON: ${value.runtimeType}');
  }
}

/// A string as `jcsStringArray` writes the one element of an array: the quoted, escaped form.
void _writeString(StringBuffer out, String value) {
  final array = jcsStringArray([value]);
  out.write(array.substring(1, array.length - 1));
}
