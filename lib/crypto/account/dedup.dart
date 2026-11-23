// Duplicate tags, `docs/crypto.md` "Duplicate tags" in the Kemlock server
// repository:
//
//   dedup key = HKDF(ikm = user key or space key, salt = absent,
//                    info = "kemlock dedup v1" || owner (17) || u32be(key version), L = 32)
//   tag       = HMAC-SHA256(dedup key, canonical input)
//
// The canonical input is a JSON array whose first element is the tag's name,
// followed by the normalised values as strings, serialised as RFC 8785 (JCS)
// without whitespace. A tag is the full 32 bytes of the MAC, never cut short.
// The owner and the key version are in the key, not in the array, so one value
// in two owners, or under two versions of a key, gives different tags.
//
// This file is the tag builder other plans call, and the server's vectors in
// `test/fixtures/server/dedup.json` hold it to `kemlock-crypto`'s bytes.
// Pure Dart, no Flutter, so the code moves into a shared package unchanged.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import '../hkdf.dart';
import 'encoding.dart';

/// The length of a dedup key and of a tag, in bytes.
const dedupKeyLength = 32;

/// The length of a tag, in bytes: all of the HMAC-SHA-256 output.
const dedupTagLength = 32;

/// The dedup key of [ownerKey], the 32-byte user key or space key, for the
/// [owner] and its [keyVersion]. The caller wipes it with [wipe] when the tags
/// are made.
Uint8List dedupKey(List<int> ownerKey, Owner owner, int keyVersion) {
  requireLength(ownerKey, dedupKeyLength, 'the owner key');
  return hkdfSha256(
    ownerKey,
    salt: const [],
    info: concatBytes([label('kemlock dedup v1'), owner.bytes, u32be(keyVersion)]),
    length: dedupKeyLength,
  );
}

/// [values] as an RFC 8785 (JCS) JSON array of strings, without whitespace.
///
/// A string is written between double quotes. The quote and the backslash are
/// escaped with a backslash, backspace, form feed, line feed, carriage return
/// and tab as `\b`, `\f`, `\n`, `\r` and `\t`, and every other code point
/// below U+0020 as `\u00xx` with lower-case hex. Everything else, U+007F and
/// U+2028 included, is written as it is. A lone surrogate, which no valid
/// text holds, is written as `\udxxx` the way ECMAScript's `JSON.stringify`
/// does.
String jcsStringArray(List<String> values) {
  final out = StringBuffer('[');
  for (var i = 0; i < values.length; i++) {
    if (i > 0) {
      out.write(',');
    }
    _writeString(out, values[i]);
  }
  out.write(']');
  return out.toString();
}

void _writeString(StringBuffer out, String value) {
  out.write('"');
  final units = value.codeUnits;
  for (var i = 0; i < units.length; i++) {
    final unit = units[i];
    switch (unit) {
      case 0x22:
        out.write(r'\"');
      case 0x5c:
        out.write(r'\\');
      case 0x08:
        out.write(r'\b');
      case 0x0c:
        out.write(r'\f');
      case 0x0a:
        out.write(r'\n');
      case 0x0d:
        out.write(r'\r');
      case 0x09:
        out.write(r'\t');
      default:
        if (unit < 0x20) {
          out.write('\\u${unit.toRadixString(16).padLeft(4, '0')}');
        } else if (unit >= 0xd800 && unit <= 0xdbff && i + 1 < units.length && units[i + 1] >= 0xdc00 && units[i + 1] <= 0xdfff) {
          // A surrogate pair is one code point, written as it is
          out.writeCharCode(unit);
          out.writeCharCode(units[++i]);
        } else if (unit >= 0xd800 && unit <= 0xdfff) {
          out.write('\\u${unit.toRadixString(16).padLeft(4, '0')}');
        } else {
          out.writeCharCode(unit);
        }
    }
  }
  out.write('"');
}

/// The canonical input of a tag: the UTF-8 bytes of [jcsStringArray] of
/// `[name, ...values]`.
Uint8List dedupInput(String name, List<String> values) => Uint8List.fromList(utf8.encode(jcsStringArray([name, ...values])));

/// The tag of `[name, ...values]` under [key], a dedup key: HMAC-SHA-256 of
/// the canonical input, all 32 bytes.
Uint8List dedupTag(List<int> key, String name, List<String> values) {
  requireLength(key, dedupKeyLength, 'the dedup key');
  return Uint8List.fromList(hash.Hmac(hash.sha256, key).convert(dedupInput(name, values)).bytes);
}

/// Whether tags [a] and [b] are the same bytes, in a time that doesn't depend on where they
/// first differ.
bool dedupTagsEqual(List<int> a, List<int> b) => constantTimeEquals(a, b);
