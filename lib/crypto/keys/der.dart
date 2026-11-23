// A small DER reader and writer (X.690), enough for the key structures in
// `pkcs8.dart` and `pbes2.dart` and the certificates of `x509.dart`:
// definite lengths, low tag numbers, and the universal types keys and
// certificates use. Reading is strict about lengths and lenient
// about integers: an INTEGER with a redundant leading zero byte is read as
// its value (some encoders write them) but a negative one is refused, since
// no key field is negative.

import 'dart:convert';
import 'dart:typed_data';

import 'key_error.dart';

const tagBoolean = 0x01;
const tagInteger = 0x02;
const tagBitString = 0x03;
const tagOctetString = 0x04;
const tagNull = 0x05;
const tagOid = 0x06;
const tagUtf8String = 0x0c;
const tagPrintableString = 0x13;
const tagTeletexString = 0x14;
const tagIa5String = 0x16;
const tagUtcTime = 0x17;
const tagGeneralizedTime = 0x18;
const tagBmpString = 0x1e;
const tagSequence = 0x30;
const tagSet = 0x31;

/// The tag of `[n]`: context-specific, constructed when [constructed].
int contextTag(int n, {bool constructed = true}) => 0x80 | (constructed ? 0x20 : 0) | n;

/// One DER element: its [tag], its [content], and [encoded], the whole
/// element as it appeared (tag, length and content).
class DerElement {
  const DerElement(this.tag, this.content, this.encoded);

  final int tag;
  final Uint8List content;
  final Uint8List encoded;
}

/// Reads DER elements one after another from a byte range. Every method
/// throws [KeyFormatException] with [KeyProblem.damaged] when the bytes
/// aren't what it reads, and nothing else.
class DerReader {
  DerReader(Uint8List bytes) : this._(bytes, 0, bytes.length);

  DerReader._(this._bytes, this._pos, this._end);

  final Uint8List _bytes;
  int _pos;
  final int _end;

  bool get isEmpty => _pos >= _end;

  /// The tag of the next element, or null at the end.
  int? get nextTag => isEmpty ? null : _bytes[_pos];

  /// The next element, whatever its tag.
  DerElement read() {
    check(_pos < _end, 'DER: nothing left');
    final start = _pos;
    final tag = _bytes[_pos++];
    check(tag & 0x1f != 0x1f, 'DER: high tag number');
    check(_pos < _end, 'DER: no length');
    var length = _bytes[_pos++];
    if (length & 0x80 != 0) {
      // Long form: 1 to 4 length bytes, the shortest that fit. 0x80 alone
      // (indefinite length) is BER, not DER.
      final count = length & 0x7f;
      check(count >= 1 && count <= 4 && _end - _pos >= count, 'DER: length of length');
      length = 0;
      for (var i = 0; i < count; i++) {
        length = (length << 8) | _bytes[_pos++];
      }
      check(length >= 0x80 && (count == 1 || length >> (8 * (count - 1)) != 0), 'DER: length not minimal');
    }
    check(length <= _end - _pos, 'DER: length past the end');
    final content = Uint8List.sublistView(_bytes, _pos, _pos + length);
    _pos += length;
    return DerElement(tag, content, Uint8List.sublistView(_bytes, start, _pos));
  }

  /// The next element, which must have [tag].
  DerElement expect(int tag) {
    final element = read();
    check(element.tag == tag, 'DER: expected tag 0x${tag.toRadixString(16)}, got 0x${element.tag.toRadixString(16)}');
    return element;
  }

  /// A reader over the contents of the next element, a SEQUENCE.
  DerReader sequence() => DerReader(expect(tagSequence).content);

  /// A reader over the contents of the next element if it has [tag] (a
  /// constructed context tag, mostly), or null when it doesn't.
  DerReader? optional(int tag) => nextTag == tag ? DerReader(read().content) : null;

  /// The next element's content if it has [tag], or null when it doesn't.
  Uint8List? optionalContent(int tag) => nextTag == tag ? read().content : null;

  /// A non-negative INTEGER.
  BigInt integer() => bytesToBigInt(unsignedInteger());

  /// A non-negative INTEGER that fits in an int, such as a version.
  int smallInteger() {
    final magnitude = unsignedInteger();
    check(magnitude.length <= 6, 'DER: integer too large');
    var value = 0;
    for (final b in magnitude) {
      value = (value << 8) | b;
    }
    return value;
  }

  /// A non-negative INTEGER's magnitude, big-endian, without leading zeros
  /// (empty for zero).
  Uint8List unsignedInteger() {
    final content = expect(tagInteger).content;
    check(content.isNotEmpty, 'DER: empty integer');
    check(content[0] & 0x80 == 0, 'DER: negative integer');
    var start = 0;
    while (start < content.length && content[start] == 0) {
      start++;
    }
    return Uint8List.sublistView(content, start);
  }

  /// An OBJECT IDENTIFIER, dotted.
  String oid() => decodeOid(expect(tagOid).content);

  Uint8List octetString() => expect(tagOctetString).content;

  /// A BIT STRING's bytes; it must have no unused bits.
  Uint8List bitString() {
    final content = expect(tagBitString).content;
    check(content.isNotEmpty && content[0] == 0, 'DER: bit string with unused bits');
    return Uint8List.sublistView(content, 1);
  }

  void readNull() => check(expect(tagNull).content.isEmpty, 'DER: NULL with content');

  /// A reader over the contents of the next element, a SET.
  DerReader set() => DerReader(expect(tagSet).content);

  /// A BOOLEAN: one byte, `00` or `ff`.
  bool boolean() {
    final content = expect(tagBoolean).content;
    check(content.length == 1 && (content[0] == 0 || content[0] == 0xff), 'DER: boolean');
    return content[0] != 0;
  }

  /// The content bytes of an INTEGER, two's complement, as they are: for a
  /// certificate's serial number, which runs to 20 bytes and which some
  /// authorities have issued negative.
  Uint8List rawInteger() {
    final content = expect(tagInteger).content;
    check(content.isNotEmpty, 'DER: empty integer');
    return content;
  }

  /// A BIT STRING that may end part way through its last byte, as named
  /// bits do: its bytes, and how many low bits of the last are unused.
  ({Uint8List bytes, int unused}) bitStringWithUnused() {
    final content = expect(tagBitString).content;
    check(content.isNotEmpty && content[0] <= 7 && (content.length > 1 || content[0] == 0), 'DER: bit string');
    return (bytes: Uint8List.sublistView(content, 1), unused: content[0]);
  }

  /// A UTCTime or a GeneralizedTime, to the second and in UTC, as DER
  /// writes both: `YYMMDDHHMMSSZ` (years 1950 to 2049) or `YYYYMMDDHHMMSSZ`.
  DateTime time() {
    final element = read();
    check(element.tag == tagUtcTime || element.tag == tagGeneralizedTime, 'DER: not a time');
    final digits = element.tag == tagUtcTime ? 12 : 14;
    final content = element.content;
    check(content.length == digits + 1 && content.last == 0x5a, 'DER: time form');
    final numbers = <int>[];
    for (var i = 0; i < digits; i += 2) {
      final high = content[i] - 0x30, low = content[i + 1] - 0x30;
      check(high >= 0 && high <= 9 && low >= 0 && low <= 9, 'DER: time digits');
      numbers.add(high * 10 + low);
    }
    final int year;
    if (element.tag == tagUtcTime) {
      year = numbers[0] < 50 ? 2000 + numbers[0] : 1900 + numbers[0];
    } else {
      year = numbers.removeAt(0) * 100 + numbers[0];
    }
    final time = DateTime.utc(year, numbers[1], numbers[2], numbers[3], numbers[4], numbers[5]);
    // DateTime rolls 31 February over into March: a date that is not one is refused.
    check(
      time.month == numbers[1] &&
          time.day == numbers[2] &&
          time.hour == numbers[3] &&
          time.minute == numbers[4] &&
          time.second == numbers[5],
      'DER: no such time',
    );
    return time;
  }

  /// A string of one of the types names use. UTF8String must be UTF-8 and
  /// PrintableString and IA5String ASCII; TeletexString is read as Latin-1
  /// and BMPString as UTF-16 with a trailing odd byte dropped, since both
  /// are only shown.
  String string() {
    final element = read();
    final content = element.content;
    switch (element.tag) {
      case tagUtf8String:
        try {
          return utf8.decode(content);
        } on FormatException {
          throw const KeyFormatException(KeyProblem.damaged, 'DER: not UTF-8');
        }
      case tagPrintableString || tagIa5String:
        check(content.every((byte) => byte < 0x80), 'DER: not ASCII');
        return String.fromCharCodes(content);
      case tagTeletexString:
        return latin1.decode(content);
      case tagBmpString:
        return String.fromCharCodes([for (var i = 0; i + 1 < content.length; i += 2) content[i] << 8 | content[i + 1]]);
      default:
        throw const KeyFormatException(KeyProblem.damaged, 'DER: not a string');
    }
  }

  /// Throws unless everything has been read.
  void done() => check(isEmpty, 'DER: trailing data');
}

/// Reads a whole buffer as one SEQUENCE and nothing after it.
DerReader readSequence(Uint8List bytes) {
  final outer = DerReader(bytes);
  final sequence = outer.sequence();
  outer.done();
  return sequence;
}

/// The dotted form of an OBJECT IDENTIFIER's content.
String decodeOid(Uint8List content) {
  check(content.isNotEmpty, 'DER: empty OID');
  final arcs = <int>[];
  var value = 0;
  var bytes = 0;
  for (final b in content) {
    check(bytes > 0 || b != 0x80, 'DER: OID arc not minimal');
    check(++bytes <= 8, 'DER: OID arc too large');
    value = (value << 7) | (b & 0x7f);
    if (b & 0x80 == 0) {
      arcs.add(value);
      value = 0;
      bytes = 0;
    }
  }
  check(bytes == 0, 'DER: OID cut short');
  final first = arcs.first;
  final head = first < 40 ? [0, first] : (first < 80 ? [1, first - 40] : [2, first - 80]);
  return [...head, ...arcs.skip(1)].join('.');
}

// ─── Writing ──────────────────────────────────────────────────────────────────

/// One element: [tag], the shortest length, and [content].
Uint8List derTlv(int tag, List<int> content) {
  final length = content.length;
  final header = <int>[tag];
  if (length < 0x80) {
    header.add(length);
  } else {
    final lengthBytes = <int>[];
    for (var l = length; l > 0; l >>= 8) {
      lengthBytes.insert(0, l & 0xff);
    }
    header
      ..add(0x80 | lengthBytes.length)
      ..addAll(lengthBytes);
  }
  return Uint8List(header.length + length)
    ..setAll(0, header)
    ..setAll(header.length, content);
}

Uint8List derSequence(List<List<int>> items) => derTlv(tagSequence, [for (final item in items) ...item]);

/// A non-negative INTEGER.
Uint8List derInteger(BigInt value) {
  if (value.isNegative) throw ArgumentError.value(value, 'value', 'must not be negative');
  final magnitude = bigIntToBytes(value);
  // A zero byte in front when the top bit is set, so it doesn't read as
  // negative; zero itself is one zero byte.
  return derTlv(tagInteger, magnitude.isEmpty || magnitude[0] & 0x80 != 0 ? [0, ...magnitude] : magnitude);
}

Uint8List derSmallInteger(int value) => derInteger(BigInt.from(value));

Uint8List derOid(String dotted) {
  final arcs = dotted.split('.').map(int.parse).toList();
  final content = <int>[];
  void arc(int value) {
    final groups = <int>[value & 0x7f];
    for (var v = value >> 7; v > 0; v >>= 7) {
      groups.insert(0, 0x80 | (v & 0x7f));
    }
    content.addAll(groups);
  }

  arc(arcs[0] * 40 + arcs[1]);
  arcs.skip(2).forEach(arc);
  return derTlv(tagOid, content);
}

Uint8List derOctetString(List<int> bytes) => derTlv(tagOctetString, bytes);

/// A BIT STRING of whole bytes.
Uint8List derBitString(List<int> bytes) => derTlv(tagBitString, [0, ...bytes]);

Uint8List derNull() => derTlv(tagNull, const []);

/// A SET OF: [items] in the order of their encodings, as DER asks.
Uint8List derSet(List<List<int>> items) {
  final sorted = [...items]..sort(_compareBytes);
  return derTlv(tagSet, [for (final item in sorted) ...item]);
}

int _compareBytes(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

Uint8List derBoolean(bool value) => derTlv(tagBoolean, [value ? 0xff : 0]);

Uint8List derUtf8String(String text) => derTlv(tagUtf8String, utf8.encode(text));

final _printable = RegExp(r"^[A-Za-z0-9 '()+,\-./:=?]*$");

/// A PrintableString. Throws [ArgumentError] for a character the type
/// does not have, such as `@` or an accent.
Uint8List derPrintableString(String text) {
  if (!_printable.hasMatch(text)) throw ArgumentError.value(text, 'text', 'not a PrintableString');
  return derTlv(tagPrintableString, text.codeUnits);
}

String _two(int value) => value.toString().padLeft(2, '0');

String _clock(DateTime utc) => '${_two(utc.month)}${_two(utc.day)}${_two(utc.hour)}${_two(utc.minute)}${_two(utc.second)}Z';

/// A UTCTime, to the second. Throws [ArgumentError] outside 1950 to 2049,
/// the years its two digits stand for.
Uint8List derUtcTime(DateTime time) {
  final utc = time.toUtc();
  if (utc.year < 1950 || utc.year > 2049) throw ArgumentError.value(time, 'time', 'outside the years a UTCTime holds');
  return derTlv(tagUtcTime, '${_two(utc.year % 100)}${_clock(utc)}'.codeUnits);
}

/// A GeneralizedTime, to the second.
Uint8List derGeneralizedTime(DateTime time) {
  final utc = time.toUtc();
  if (utc.year < 0 || utc.year > 9999) throw ArgumentError.value(time, 'time', 'outside the years a GeneralizedTime holds');
  return derTlv(tagGeneralizedTime, '${utc.year.toString().padLeft(4, '0')}${_clock(utc)}'.codeUnits);
}

/// A time as RFC 5280 writes it in a certificate: a UTCTime through 2049
/// and a GeneralizedTime from 2050.
Uint8List derTime(DateTime time) => time.toUtc().year < 2050 ? derUtcTime(time) : derGeneralizedTime(time);

/// A BIT STRING of named bits: bit 0 is the highest bit of the first
/// byte. The bits after the last one set are left off, as DER asks.
Uint8List derNamedBits(Set<int> bits) {
  if (bits.isEmpty) return derTlv(tagBitString, const [0]);
  final last = bits.reduce((a, b) => a > b ? a : b);
  final bytes = Uint8List(last ~/ 8 + 1);
  for (final bit in bits) {
    bytes[bit ~/ 8] |= 0x80 >> (bit % 8);
  }
  return derTlv(tagBitString, [7 - last % 8, ...bytes]);
}

// ─── Integers as bytes ────────────────────────────────────────────────────────

/// An unsigned big-endian number.
BigInt bytesToBigInt(List<int> bytes) {
  var result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

/// The big-endian bytes of a non-negative [value]: the fewest that hold it
/// (none for zero), or exactly [length], zeros in front.
Uint8List bigIntToBytes(BigInt value, [int? length]) {
  final size = (value.bitLength + 7) >> 3;
  if (length != null && size > length) throw ArgumentError.value(value, 'value', 'does not fit in $length bytes');
  final out = Uint8List(length ?? size);
  var v = value;
  final mask = BigInt.from(0xff);
  for (var i = out.length - 1; i >= 0 && v > BigInt.zero; i--) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}
