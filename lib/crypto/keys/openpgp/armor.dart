// OpenPGP ASCII armor (RFC 9580 section 6): a `-----BEGIN PGP ...-----`
// line, optional `Name: value` headers and a blank line, base64, an
// optional `=XXXX` CRC-24 line, and the end line.

import 'dart:convert';
import 'dart:typed_data';

import '../key_error.dart';
import '../pem.dart';
import 'pgp_error.dart';
import 'stream.dart';

const pgpPrivateKeyBlock = 'PGP PRIVATE KEY BLOCK';
const pgpPublicKeyBlock = 'PGP PUBLIC KEY BLOCK';

final _checksumLine = RegExp(r'(^|\s)=([A-Za-z0-9+/]{4})\s*$');

/// The bytes of an armored block, found by [readPemBlocks]. The CRC-24
/// line is left out and not checked: RFC 9580 says a reader must not
/// reject a block for it, and the packets' own lengths catch a block that
/// was cut. Throws [KeyProblem.damaged] when the base64 is broken.
Uint8List readArmor(PemBlock block) {
  checkSize(block.body.length);
  final match = _checksumLine.firstMatch(block.body);
  return decodeBase64(match == null ? block.body : block.body.substring(0, match.start));
}

/// [data] armored as [type], with 64-character lines and the CRC-24 line
/// GnuPG writes, unless [checksum] is false: RFC 9580 section 6.1 says it
/// must not be written for what holds only version 6 keys and signatures,
/// or ends in a version 2 SEIPD packet.
String writeArmor(String type, List<int> data, {bool checksum = true}) {
  final encoded = base64.encode(data);
  final out = StringBuffer('-----BEGIN $type-----\n\n');
  for (var i = 0; i < encoded.length; i += 64) {
    out.writeln(encoded.substring(i, i + 64 > encoded.length ? encoded.length : i + 64));
  }
  if (checksum) {
    final crc = crc24(data);
    out.writeln('=${base64.encode([crc >> 16, (crc >> 8) & 0xff, crc & 0xff])}');
  }
  out.writeln('-----END $type-----');
  return out.toString();
}

/// The CRC-24 of RFC 9580 section 6.1.1.
int crc24(List<int> data) {
  var crc = 0xb704ce;
  for (final b in data) {
    crc ^= (b & 0xff) << 16;
    for (var i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000 != 0) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

// ─── Messages and signatures ──────────────────────────────────────────────────

const pgpMessageBlock = 'PGP MESSAGE';
const pgpSignatureBlock = 'PGP SIGNATURE';
const pgpSignedMessageBlock = 'PGP SIGNED MESSAGE';

final _beginLine = RegExp(r'^-----BEGIN (PGP [A-Z0-9 ,/]+)-----[ \t\r]*$', multiLine: true);

/// What the start of some input is: binary packets ([type] null), or text
/// holding an armor block of [type] that begins at [offset].
typedef ArmorSniff = ({String? type, int offset});

/// Looks at [head], the first bytes of an input (all of it, or its first
/// 64 KiB), and says whether it is binary OpenPGP data or text with an
/// armor block, which may have other text before it, as a pasted mail
/// does. Throws [PgpProblem.notAMessage] for text without a block, and
/// [PgpProblem.unsupported] for a block that is one part of several.
ArmorSniff sniffArmor(Uint8List head) {
  if (head.isEmpty) throw const PgpException(PgpProblem.notAMessage);
  final text = latin1.decode(head);
  final match = _beginLine.firstMatch(text);
  // Binary data starts with a packet header, whose top bit is set. Text
  // may too (a letter outside ASCII), so a BEGIN line with nothing but
  // text before it wins.
  final textBefore = match != null && !text.substring(0, match.start).contains(RegExp(r'[\x00-\x08\x0e-\x1f]'));
  if (head[0] & 0x80 != 0 && !textBefore) return (type: null, offset: 0);
  if (match == null) throw const PgpException(PgpProblem.notAMessage);
  final type = match.group(1)!;
  if (type.contains(', PART')) throw const PgpException(PgpProblem.unsupported, detail: 'multi-part armor');
  return (type: type, offset: match.start);
}

/// The bytes of the first armor block in a stream of text, decoded line by
/// line as they are asked for: the block may be a file of any size. Text
/// before the block and after it is skipped. The CRC-24 line is not
/// checked, as for keys.
class ArmorReader implements ByteSource {
  ArmorReader._(this._in, this.type, this.headers);

  /// Reads up to the blank line after the block's headers. Throws
  /// [PgpProblem.notAMessage] when [text] holds no block.
  factory ArmorReader.open(PgpReader text) {
    String? type;
    for (var line = _line(text); line != null; line = _line(text)) {
      final match = _beginLine.firstMatch(line);
      if (match == null) continue;
      type = match.group(1)!;
      break;
    }
    if (type == null) throw const PgpException(PgpProblem.notAMessage);
    if (type.contains(', PART')) throw const PgpException(PgpProblem.unsupported, detail: 'multi-part armor');
    final headers = <(String, String)>[];
    // A clear-signed text has its own framing after the headers
    for (var line = _line(text); line != null && line.trim().isNotEmpty; line = _line(text)) {
      final colon = line.indexOf(': ');
      pgpCheck(colon > 0, 'armor header');
      headers.add((line.substring(0, colon), line.substring(colon + 2).trim()));
    }
    return ArmorReader._(text, type, headers);
  }

  final PgpReader _in;

  /// `PGP MESSAGE`, `PGP SIGNATURE`, `PGP PUBLIC KEY BLOCK`, ...
  final String type;

  /// The `Name: value` lines, in order (`Comment`, `Version`, `Hash`).
  final List<(String, String)> headers;

  final _quad = Uint8List(4);
  int _quadFill = 0;
  bool _done = false;

  static String? _line(PgpReader r) {
    if (r.atEnd) return null;
    final out = <int>[];
    for (var b = r.peek(); b != null; b = r.peek()) {
      r.byte();
      if (b == 0x0a) break;
      checkLineLength(out.length);
      out.add(b);
    }
    if (out.isNotEmpty && out.last == 0x0d) out.removeLast();
    return latin1.decode(out);
  }

  @override
  Uint8List? next() {
    while (!_done) {
      final piece = _in.some();
      if (piece == null) throw const PgpException(PgpProblem.damaged, detail: 'armor without an end');
      final out = Uint8List(piece.length * 3 ~/ 4 + 3);
      var n = 0;
      for (final c in piece) {
        final v = _base64Value[c];
        if (v >= 0) {
          _quad[_quadFill++] = v;
          if (_quadFill == 4) {
            out[n++] = (_quad[0] << 2) | (_quad[1] >> 4);
            out[n++] = ((_quad[1] << 4) | (_quad[2] >> 2)) & 0xff;
            out[n++] = ((_quad[2] << 6) | _quad[3]) & 0xff;
            _quadFill = 0;
          }
        } else if (v == -2) {
          continue; // white space
        } else if (c == 0x3d || c == 0x2d) {
          // Padding, the CRC line or the END line: the data is over
          pgpCheck(_quadFill != 1, 'armor: base64');
          if (_quadFill >= 2) out[n++] = (_quad[0] << 2) | (_quad[1] >> 4);
          if (_quadFill == 3) out[n++] = ((_quad[1] << 4) | (_quad[2] >> 2)) & 0xff;
          _done = true;
          break;
        } else {
          throw const PgpException(PgpProblem.damaged, detail: 'armor: not base64');
        }
      }
      if (n > 0) return Uint8List.sublistView(out, 0, n);
    }
    return null;
  }
}

/// A line of armor longer than this is not armor.
void checkLineLength(int length) => pgpCheck(length < 1 << 20, 'armor: line too long');

/// The value of each base64 character; -2 for white space, -1 otherwise.
final _base64Value = () {
  final table = Int8List(256)..fillRange(0, 256, -1);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  for (var i = 0; i < 64; i++) {
    table[alphabet.codeUnitAt(i)] = i;
  }
  for (final c in [0x20, 0x09, 0x0a, 0x0d]) {
    table[c] = -2;
  }
  return table;
}();

/// The bytes of the first armor block of [type] (any type when null) in
/// [text], which is held whole. Throws [PgpProblem.notAMessage] when there
/// is none.
Uint8List readArmorBlock(Uint8List text, {String? type, int max = 64 * 1024 * 1024}) {
  final armor = ArmorReader.open(PgpReader.bytes(text));
  if (type != null && armor.type != type) throw const PgpException(PgpProblem.notAMessage);
  return PgpReader(armor).rest(max: max);
}
