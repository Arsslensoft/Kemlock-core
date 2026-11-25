@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/vault/export_archive.dart';
import 'package:test/test.dart';

Uint8List _zip(List<ArchiveFile> entries) {
  final archive = Archive();
  for (final entry in entries) {
    archive.addFile(entry);
  }
  return Uint8List.fromList(ZipEncoder().encodeBytes(archive));
}

ArchiveFile _entry(String name, List<int> bytes) => ArchiveFile.noCompress(name, bytes.length, bytes);

/// [zip] with the central directory's uncompressed size of [name] set to
/// [size], as an archive made to lie about an entry would have it.
Uint8List _claiming(Uint8List zip, String name, int size) {
  final data = ByteData.sublistView(zip);
  final encoded = utf8.encode(name);
  for (var at = 0; at + 46 <= zip.length; at++) {
    if (data.getUint32(at, Endian.little) != 0x02014b50) continue;
    final nameLength = data.getUint16(at + 28, Endian.little);
    if (nameLength == encoded.length && utf8.decode(zip.sublist(at + 46, at + 46 + nameLength)) == name) {
      data.setUint32(at + 24, size, Endian.little);
      return zip;
    }
  }
  throw StateError('No $name in the directory');
}

Matcher _refused(ExportArchiveProblem problem, [String? entry]) =>
    throwsA(isA<ExportArchiveError>().having((e) => e.problem, 'problem', problem).having((e) => e.entry, 'entry', entry ?? anything));

void main() {
  const json = '{"version": 2, "app": "BackMyCodes"}';
  final key = randomBytes(32);
  final sealed = {
    for (final id in ['f1', 'f2', 'f3']) id: kma1EncryptSync(Uint8List.fromList(utf8.encode('file $id')), key),
  };

  test('round-trips an export and three sealed files, stored as they are', () async {
    final missing = <String>[];
    final bytes = await buildExportArchive(
      exportJson: json,
      files: [for (final MapEntry(key: id, value: bytes) in sealed.entries) (id: id, name: null, bytes: () async => bytes)],
      missing: missing,
    );

    expect(missing, isEmpty);
    expect(isExportArchive(bytes), isTrue);
    final read = readExportArchive(bytes);
    expect(read.exportJson, json);
    expect(read.files.keys, ['f1', 'f2', 'f3']);
    for (final MapEntry(key: id, value: file) in read.files.entries) {
      expect(file(), sealed[id], reason: id);
      expect(kma1DecryptSync(file(), key), utf8.encode('file $id'));
    }
    // Stored, not compressed: what was written is what the zip holds
    final names = [for (final entry in ZipDecoder().decodeBytes(bytes)) entry.name];
    expect(names, ['export.json', 'files/f1', 'files/f2', 'files/f3']);
  });

  test("a plain archive's files go under their names, and come back by id", () async {
    final bytes = await buildExportArchive(
      exportJson: json,
      files: [(id: 'f1', name: '../../passport scan.pdf', bytes: () async => Uint8List.fromList(utf8.encode('%PDF')))],
    );

    expect([for (final entry in ZipDecoder().decodeBytes(bytes)) entry.name], ['export.json', 'files/f1/passport scan.pdf']);
    expect(readExportArchive(bytes).files['f1']!(), utf8.encode('%PDF'));
  });

  test('says which files were not there to write', () async {
    final missing = <String>[];
    final bytes = await buildExportArchive(
      exportJson: json,
      files: [(id: 'f1', name: null, bytes: () async => sealed['f1']), (id: 'gone', name: null, bytes: () async => null)],
      missing: missing,
    );

    expect(missing, ['gone']);
    expect(readExportArchive(bytes).files.keys, ['f1']);
  });

  test('reads an archive zipped again with its entries deflated, as a zip tool writes them', () {
    final file = Uint8List(64 * 1024);
    final bytes = _zip([ArchiveFile.bytes(exportArchiveJson, utf8.encode(json)), ArchiveFile.bytes('files/f1', file)]);
    expect(ZipDecoder().decodeBytes(bytes).findFile('files/f1')!.compression, CompressionType.deflate);

    final read = readExportArchive(bytes);

    expect(read.exportJson, json);
    expect(read.files['f1']!(), file);
  });

  test('tells an archive from a JSON export', () {
    expect(isExportArchive(Uint8List.fromList(utf8.encode(json))), isFalse);
    expect(isExportArchive(Uint8List(2)), isFalse);
  });

  group('refuses', () {
    test('an archive with too many entries', () {
      final bytes = _zip([
        _entry('export.json', utf8.encode(json)),
        for (var i = 0; i < archiveEntryLimit; i++) _entry('files/f$i', const [1]),
      ]);

      expect(() => readExportArchive(bytes), _refused(ExportArchiveProblem.tooManyEntries));
    });

    test('an entry over the size limit, before reading it', () {
      final big = _entry('files/f1', Uint8List(16))..size = archiveFileLimit + 1;
      final bytes = _zip([_entry('export.json', utf8.encode(json)), big]);
      // The directory claims more than a file may hold
      final directory = ZipDecoder().decodeBytes(bytes);
      expect(directory.findFile('files/f1')!.size, greaterThan(archiveFileLimit));

      expect(() => readExportArchive(bytes), _refused(ExportArchiveProblem.tooLarge, 'files/f1'));
    });

    test('a deflated entry that inflates past the size its directory gives, stopping there', () {
      // 32 MB of zeros deflate to a few kilobytes; the directory says 16 bytes, under every limit
      final bomb = Uint8List(32 * 1024 * 1024);
      final bytes = _claiming(_zip([_entry(exportArchiveJson, utf8.encode(json)), ArchiveFile.bytes('files/f1', bomb)]), 'files/f1', 16);
      expect(bytes.length, lessThan(1024 * 1024));
      final entry = ZipDecoder().decodeBytes(bytes).findFile('files/f1')!;
      expect((entry.compression, entry.size), (CompressionType.deflate, 16));
      // The archive package inflates no further than the directory's size, which is checked before any content is read
      expect(entry.readBytes, throwsA(isA<ArchiveException>().having((e) => e.message, 'message', contains('larger than the 16 bytes'))));

      expect(() => readExportArchive(bytes).files['f1']!(), _refused(ExportArchiveProblem.damaged, 'files/f1'));
    });

    test('an export.json over its limit', () {
      final big = _entry('export.json', Uint8List(16))..size = archiveJsonLimit + 1;

      expect(() => readExportArchive(_zip([big])), _refused(ExportArchiveProblem.tooLarge, 'export.json'));
    });

    for (final name in ['files/../../etc/passwd', 'notes.txt', 'files/a/b/c', 'files/has space', '/files/f1', 'export.json.bak']) {
      test('an entry named $name', () {
        final bytes = _zip([
          _entry('export.json', utf8.encode(json)),
          _entry(name, const [1]),
        ]);

        expect(() => readExportArchive(bytes), _refused(ExportArchiveProblem.unexpectedEntry, name));
      });
    }

    test('two entries for one file', () {
      final bytes = _zip([
        _entry('export.json', utf8.encode(json)),
        _entry('files/f1', const [1]),
        _entry('files/f1/a.pdf', const [2]),
      ]);

      expect(() => readExportArchive(bytes), _refused(ExportArchiveProblem.unexpectedEntry, 'files/f1/a.pdf'));
    });

    test('an archive without export.json', () {
      expect(
        () => readExportArchive(
          _zip([
            _entry('files/f1', const [1]),
          ]),
        ),
        _refused(ExportArchiveProblem.noExport),
      );
    });

    test('bytes that are no archive', () {
      expect(() => readExportArchive(Uint8List.fromList([0x50, 0x4b, 0x03, 0x04, 1, 2, 3])), _refused(ExportArchiveProblem.damaged));
    });
  });
}
