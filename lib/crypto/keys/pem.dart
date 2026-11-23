// PEM blocks (RFC 7468, and the RFC 1421 headers legacy OpenSSL keys carry):
// `-----BEGIN <label>-----`, base64, `-----END <label>-----`. Text pasted
// from chat or mail often has its line breaks changed, so a block is found
// by its markers, not by lines, and whitespace inside the base64 is ignored.

import 'dart:convert';
import 'dart:typed_data';

import 'key_error.dart';

/// One PEM block: its label, the RFC 1421 headers before its base64 (only
/// legacy encrypted keys have them), and the base64 [body], not yet
/// decoded.
class PemBlock {
  const PemBlock(this.label, this.headers, this.body, this.text);

  /// `PRIVATE KEY`, `OPENSSH PRIVATE KEY`, `PGP PRIVATE KEY BLOCK`, ...
  final String label;

  /// `Proc-Type`, `DEK-Info`, ... in the order they came.
  final Map<String, String> headers;

  /// The base64 between the headers and the end marker.
  final String body;

  /// The whole block, markers included, as it appeared.
  final String text;

  /// [body] decoded. Throws [KeyProblem.damaged] when it isn't base64.
  Uint8List decode() => decodeBase64(body);
}

final _begin = RegExp(r'-----BEGIN ([A-Z0-9 ]+)-----');

/// The PEM blocks in [text], in order. A block whose end marker is missing
/// (text cut short) throws [KeyProblem.damaged].
List<PemBlock> readPemBlocks(String text) {
  checkSize(text.length);
  final blocks = <PemBlock>[];
  var from = 0;
  while (true) {
    final matches = _begin.allMatches(text, from).iterator;
    if (!matches.moveNext()) return blocks;
    final begin = matches.current;
    final label = begin.group(1)!;
    final endMarker = '-----END $label-----';
    final end = text.indexOf(endMarker, begin.end);
    check(end >= 0, 'PEM: no end marker for $label');
    final (headers, body) = _splitHeaders(text.substring(begin.end, end));
    blocks.add(PemBlock(label, headers, body, text.substring(begin.start, end + endMarker.length)));
    from = end + endMarker.length;
  }
}

/// RFC 1421 headers are `Name: value` lines at the top of the body, ended
/// by a blank line; a line starting with whitespace continues the one
/// before.
(Map<String, String>, String) _splitHeaders(String body) {
  final lines = const LineSplitter().convert(body);
  final headers = <String, String>{};
  var i = 0;
  while (i < lines.length && lines[i].trim().isEmpty) {
    i++;
  }
  String? last;
  for (; i < lines.length; i++) {
    final line = lines[i];
    final colon = line.indexOf(':');
    if (last != null && line.isNotEmpty && (line[0] == ' ' || line[0] == '\t') && colon < 0) {
      headers[last] = '${headers[last]}${line.trim()}';
    } else if (colon > 0) {
      last = line.substring(0, colon).trim();
      headers[last] = line.substring(colon + 1).trim();
    } else {
      break;
    }
  }
  return (headers, lines.skip(i).join('\n'));
}

final _base64Text = RegExp(r'^[A-Za-z0-9+/]*={0,2}$');
final _whitespace = RegExp(r'\s');

/// Standard base64 with whitespace anywhere and the padding optional.
/// Throws [KeyProblem.damaged] for anything else.
Uint8List decodeBase64(String text) {
  final compact = text.replaceAll(_whitespace, '');
  check(_base64Text.hasMatch(compact) && compact.replaceAll('=', '').length % 4 != 1, 'PEM: not base64');
  try {
    return base64.decode(base64.normalize(compact));
  } on FormatException {
    throw const KeyFormatException(KeyProblem.damaged, 'PEM: not base64');
  }
}

/// [bytes] as a PEM block with lines of [lineLength] characters (64 as
/// RFC 7468 says; `ssh-keygen` writes 70), ending in a newline.
String writePem(String label, List<int> bytes, {int lineLength = 64}) {
  final encoded = base64.encode(bytes);
  final out = StringBuffer('-----BEGIN $label-----\n');
  for (var i = 0; i < encoded.length; i += lineLength) {
    out.writeln(encoded.substring(i, i + lineLength > encoded.length ? encoded.length : i + lineLength));
  }
  out.writeln('-----END $label-----');
  return out.toString();
}
