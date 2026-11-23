// The cleartext signature framework (RFC 9580 section 7): text that stays
// readable, with its signature in armor after it.
//
//   -----BEGIN PGP SIGNED MESSAGE-----
//   Hash: SHA512
//
//   the text, a line that starts with a dash written "- -like this"
//   -----BEGIN PGP SIGNATURE-----
//   ...
//
// The signature is of type 0x01 over the text with each line's trailing
// spaces and tabs dropped and its lines joined by CR LF. The line ending
// before the signature's armor is not part of the text.
//
// The text is handled as bytes throughout (one character per byte, as
// Latin-1), so that text in any encoding hashes as it was signed.

import 'dart:convert';
import 'dart:typed_data';

import 'armor.dart';
import 'pgp_error.dart';

/// A clear-signed text taken apart.
class CleartextMessage {
  const CleartextMessage(this.textBytes, this.signatures);

  /// The signed text, its dash-escapes removed and its lines ending in LF.
  /// It has no line ending after its last line unless that was signed.
  final Uint8List textBytes;

  /// The signature packets, binary.
  final Uint8List signatures;

  /// [textBytes] as UTF-8, with a replacement character where it is not.
  String get text => utf8.decode(textBytes, allowMalformed: true);
}

const _begin = '-----BEGIN PGP SIGNED MESSAGE-----';
const _beginSignature = '-----BEGIN PGP SIGNATURE-----';

/// Reads the first clear-signed text in [input]. Throws
/// [PgpProblem.notAMessage] when there is none,
/// [PgpProblem.unsupported] for a `NotDashEscaped` text, and
/// [PgpProblem.damaged] for one whose framing is broken.
CleartextMessage readCleartext(Uint8List input) {
  final lines = latin1.decode(input).replaceAll('\r\n', '\n').split('\n');
  var at = lines.indexWhere((line) => line.trimRight() == _begin);
  if (at < 0) throw const PgpException(PgpProblem.notAMessage);
  at++;
  // Armor headers, of which only Hash is allowed, up to an empty line
  for (; at < lines.length && lines[at].trim().isNotEmpty; at++) {
    final line = lines[at];
    if (line.startsWith('NotDashEscaped:')) throw const PgpException(PgpProblem.unsupported, detail: 'NotDashEscaped');
    pgpCheck(line.startsWith('Hash: '), 'clear-signed text: header');
  }
  pgpCheck(at < lines.length, 'clear-signed text: no text');
  at++;
  final text = <String>[];
  for (; at < lines.length && lines[at].trimRight() != _beginSignature; at++) {
    final line = lines[at];
    if (line.startsWith('- ')) {
      text.add(line.substring(2));
    } else {
      // A line starting with a dash that was not escaped is no text line
      pgpCheck(!line.startsWith('-'), 'clear-signed text: dash');
      text.add(line);
    }
  }
  pgpCheck(at < lines.length, 'clear-signed text: no signature');
  final armor = Uint8List.fromList(latin1.encode(lines.sublist(at).join('\n')));
  return CleartextMessage(Uint8List.fromList(latin1.encode(text.join('\n'))), readArmorBlock(armor, type: pgpSignatureBlock, max: 1 << 20));
}

/// What a clear-text signature hashes for [textBytes]: each line without
/// its trailing spaces and tabs, the lines joined by CR LF. A hasher in
/// text mode leaves these line endings as they are.
///
/// Each line is cut from its end, one pass over the bytes: the text is
/// whatever a sender wrote, and a pattern that looks for spaces up to a
/// line's end takes a time that grows with the square of a long run of
/// spaces that does not end the line.
Uint8List cleartextSignedBytes(Uint8List textBytes) {
  final out = BytesBuilder(copy: true);
  var start = 0;
  for (var i = 0; i <= textBytes.length; i++) {
    if (i < textBytes.length && textBytes[i] != 0x0a) continue;
    // Spaces, tabs, and the CR of a CR LF, which the LF's own CR LF replaces
    var end = i;
    while (end > start && (textBytes[end - 1] == 0x20 || textBytes[end - 1] == 0x09 || textBytes[end - 1] == 0x0d)) {
      end--;
    }
    if (start > 0) out.add(const [0x0d, 0x0a]);
    out.add(Uint8List.sublistView(textBytes, start, end));
    start = i + 1;
  }
  return out.takeBytes();
}

/// [text] clear-signed: [signatures], the signature packets made with
/// SHA-512 over [cleartextSignedBytes] of its UTF-8 bytes, armored after
/// the dash-escaped text. Lines that start with a dash, and with "From "
/// as mail programs would otherwise mangle, are escaped. Version 6
/// signatures ([version6]) go without the legacy "Hash" header and the
/// CRC-24 line, which RFC 9580 sections 6.1 and 6.2.2.3 keep for version
/// 4 ones.
String writeCleartext(String text, Uint8List signatures, {bool version6 = false}) {
  final out = StringBuffer(version6 ? '$_begin\n\n' : '$_begin\nHash: SHA512\n\n');
  for (final line in text.replaceAll('\r\n', '\n').split('\n')) {
    out
      ..write(line.startsWith('-') || line.startsWith('From ') ? '- ' : '')
      ..write(line)
      ..write('\n');
  }
  out.write(writeArmor(pgpSignatureBlock, signatures, checksum: !version6));
  return out.toString();
}
