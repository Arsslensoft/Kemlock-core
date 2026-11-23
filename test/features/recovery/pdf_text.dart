import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// One page of a PDF, as [PdfText] reads it.
class PdfTextPage {
  const PdfTextPage({required this.width, required this.height, required this.lines, required this.fonts, required this.images});

  /// The page size in points, from its media box.
  final double width;
  final double height;

  /// What each baseline says, top to bottom: the runs drawn on it, joined.
  final List<String> lines;

  /// The fonts the page's text is drawn in.
  final Set<String> fonts;

  /// How many pictures the page draws; the QR code is drawn as shapes, not one.
  final int images;

  String get text => lines.join('\n');
}

/// A PDF the `pdf` package wrote (version 1.4, compressed or not), read
/// back as a PDF reader would: its objects through the xref table, and the
/// text each page draws, decoded through each font's ToUnicode map. After
/// the luggage organizer's `test/helpers/pdf_reader.dart`.
class PdfText {
  PdfText(Uint8List bytes) : source = latin1.decode(bytes);

  final String source;

  late final Map<int, String> objects = _readObjects();

  late final List<PdfTextPage> pages = [
    for (final body in objects.values)
      if (RegExp(r'/Type\s*/Page[/>\s]').hasMatch(body)) _readPage(body),
  ];

  /// Every page's lines, pages apart by a blank line.
  String get text => pages.map((p) => p.text).join('\n\n');

  Map<int, String> _readObjects() {
    final start = int.parse(RegExp(r'startxref\s+(\d+)\s+%%EOF\s*$').firstMatch(source)![1]!);
    final table = RegExp(r'^xref\s+0 (\d+)\s*\n').firstMatch(source.substring(start))!;
    final count = int.parse(table[1]!);
    final entries = source.substring(start + table[0]!.length).split('\n').take(count).toList();
    return {
      for (var n = 1; n < count; n++)
        n: () {
          final offset = int.parse(entries[n].substring(0, 10));
          return source.substring(offset, source.indexOf('endobj', offset));
        }(),
    };
  }

  /// An object's stream, inflated when it is deflated.
  String _stream(String body) {
    final start = body.indexOf('stream') + 'stream'.length;
    final from = body.startsWith('\r\n', start) ? start + 2 : start + 1;
    final length = int.parse(RegExp(r'/Length (\d+)').firstMatch(body)![1]!);
    final raw = body.substring(from, from + length);
    if (!body.contains('/FlateDecode')) return raw;
    return latin1.decode(zlib.decode(latin1.encode(raw)));
  }

  Map<int, int> _toUnicode(int fontObject) {
    final font = objects[fontObject]!;
    final cmap = _stream(objects[int.parse(RegExp(r'/ToUnicode (\d+) 0 R').firstMatch(font)![1]!)]!);
    return {
      for (final m in RegExp(r'<([0-9A-Fa-f]{4})>\s*<([0-9A-Fa-f]{4,})>').allMatches(cmap))
        int.parse(m[1]!, radix: 16): int.parse(m[2]!, radix: 16),
    };
  }

  PdfTextPage _readPage(String body) {
    final box = RegExp(r'/MediaBox\s*\[([-\d. ]+)\]').firstMatch(body)![1]!.trim().split(RegExp(r'\s+')).map(double.parse).toList();
    final fonts = {for (final m in RegExp(r'/(F\d+) (\d+) 0 R').allMatches(body)) m[1]!: int.parse(m[2]!)};
    final contents = RegExp(r'/Contents\s*(?:\[([\d R]+)\]|(\d+) 0 R)').firstMatch(body)!;
    final streams = contents[2] != null
        ? [int.parse(contents[2]!)]
        : RegExp(r'(\d+) 0 R').allMatches(contents[1]!).map((m) => int.parse(m[1]!));
    final maps = <String, Map<int, int>>{};
    final names = <String, String>{};
    final runs = <({String text, double y})>[];
    var images = 0;
    for (final stream in streams) {
      final ops = _stream(objects[stream]!);
      images += RegExp(r'/I\d+ Do').allMatches(ops).length;
      for (final m in RegExp(
        r'BT\s*/(F\d+) ([\d.]+) Tf\s*(?:[-\d.]+ T[cwzLsr]\s*)*([-\d.]+) ([-\d.]+) Td\s*\[?<([0-9a-fA-F]*)>\]?\s*T[Jj]\s*ET',
      ).allMatches(ops)) {
        final font = m[1]!;
        final map = maps.putIfAbsent(font, () => _toUnicode(fonts[font]!));
        names.putIfAbsent(font, () => RegExp(r'/BaseFont\s*/([^/\[<>\s]+)').firstMatch(objects[fonts[font]!]!)![1]!);
        final hex = m[5]!;
        final text = String.fromCharCodes([
          for (var i = 0; i < hex.length; i += 4) map[int.parse(hex.substring(i, i + 4), radix: 16)] ?? 0xFFFD,
        ]);
        runs.add((text: text, y: double.parse(m[4]!)));
      }
    }
    final lines = <String>[];
    double? y;
    for (final run in runs) {
      if (run.y == y) {
        // The pdf package draws each word on its own, and the spaces as gaps between them
        lines.last += ' ${run.text}';
      } else {
        lines.add(run.text);
      }
      y = run.y;
    }
    return PdfTextPage(width: box[2] - box[0], height: box[3] - box[1], lines: lines, fonts: names.values.toSet(), images: images);
  }
}
