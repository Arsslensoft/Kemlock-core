/// The `.zip` an export of a vault with attached files is saved as.
///
/// It is stored, not compressed, and holds `export.json`, the ordinary
/// export, then each attached file: in an encrypted export, the `KMA1`
/// file as the phone keeps it, at `files/<attachment id>`, whose key is
/// inside the sealed payload, so nothing is encrypted again and the
/// archive tells only sizes; in a plain export, the decrypted file at
/// `files/<attachment id>/<name>`. Unzipped, `export.json` opens in any
/// version of Kemlock.
///
/// Archives come from anywhere when imported, so reading refuses one with
/// too many entries, an entry too large or of a name it doesn't expect,
/// before any content is read.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:archive/archive.dart';

/// The export inside an archive.
const exportArchiveJson = 'export.json';

/// The most entries an archive to import may hold.
const archiveEntryLimit = 10000;

/// The largest `export.json` an archive to import may hold.
const archiveJsonLimit = 64 * 1024 * 1024;

/// The largest attached file an archive to import may hold: the 50 MB a
/// note takes, and its encryption's overhead.
const archiveFileLimit = 51 * 1024 * 1024;

final _sealedName = RegExp(r'^files/([A-Za-z0-9_-]{1,64})$');
final _plainName = RegExp(r'^files/([A-Za-z0-9_-]{1,64})/([^/]+)$');
final _folderName = RegExp(r'^files/(?:[A-Za-z0-9_-]{1,64}/)?$');

/// Why an archive can't be imported.
enum ExportArchiveProblem { tooManyEntries, tooLarge, unexpectedEntry, noExport, damaged }

/// An archive that can't be imported; nothing of it was used.
class ExportArchiveError implements Exception {
  const ExportArchiveError(this.problem, [this.entry]);

  final ExportArchiveProblem problem;

  /// The entry at fault, when one is.
  final String? entry;

  @override
  String toString() => 'ExportArchiveError(${problem.name}${entry == null ? '' : ', $entry'})';
}

/// One attached file to put in an archive.
typedef ArchiveAttachment = ({String id, String? name, Future<Uint8List?> Function() bytes});

/// Whether [bytes] start like a zip archive rather than a JSON export.
bool isExportArchive(Uint8List bytes) => bytes.length >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4b && bytes[2] == 0x03 && bytes[3] == 0x04;

/// Builds an archive of [exportJson] and [files], in memory. A file is named `files/<id>`, or `files/<id>/<name>` when it has a
/// [ArchiveAttachment.name] (a plain export). The entries are stored, not compressed. [missing] gets the ids of the files that
/// weren't there to write. The app writes its archives to a path, one file at a time (its own `export_archive.dart`); this is the
/// same archive for a host with no file system, such as the browser extension.
Future<Uint8List> buildExportArchive({required String exportJson, required List<ArchiveAttachment> files, List<String>? missing}) async {
  final archive = Archive();
  final json = utf8.encode(exportJson);
  archive.addFile(ArchiveFile.noCompress(exportArchiveJson, json.length, json));
  for (final file in files) {
    final bytes = await file.bytes();
    if (bytes == null) {
      missing?.add(file.id);
      continue;
    }
    final name = file.name == null ? 'files/${file.id}' : 'files/${file.id}/${_safeFileName(file.name!)}';
    archive.addFile(ArchiveFile.noCompress(name, bytes.length, bytes));
  }
  return Uint8List.fromList(ZipEncoder().encodeBytes(archive));
}

/// A file's name as an archive entry: no folders, nothing empty.
String _safeFileName(String name) {
  final base = name.split(RegExp(r'[/\\]')).where((part) => part.isNotEmpty && part != '.' && part != '..').lastOrNull ?? '';
  return base.isEmpty ? 'file' : base;
}

/// What an archive held: the export's text, and its files by attachment id
/// (sealed in an encrypted export, plain in a plain one), each read when
/// asked for, so one is in memory at a time. Reading a file throws
/// [ExportArchiveError] when its content disagrees with the directory.
class ExportArchive {
  const ExportArchive({required this.exportJson, required this.files});

  final String exportJson;
  final Map<String, Uint8List Function()> files;
}

/// Reads an archive made by [writeExportArchive], or by unzipping and
/// zipping one again. Throws [ExportArchiveError] for one over the limits,
/// with an entry of another name, without `export.json`, or damaged.
ExportArchive readExportArchive(Uint8List bytes) {
  final Archive archive;
  try {
    archive = ZipDecoder().decodeBytes(bytes);
  } catch (_) {
    throw const ExportArchiveError(ExportArchiveProblem.damaged);
  }
  // A zip header with nothing readable after it decodes as no entries at all
  if (archive.isEmpty) throw const ExportArchiveError(ExportArchiveProblem.damaged);
  if (archive.length > archiveEntryLimit) throw const ExportArchiveError(ExportArchiveProblem.tooManyEntries);

  // Every name and size first, from the archive's directory, before any content is read
  ArchiveFile? json;
  final files = <String, ArchiveFile>{};
  for (final entry in archive) {
    final name = entry.name;
    if (!entry.isFile) {
      if (_folderName.hasMatch(name)) continue;
      throw ExportArchiveError(ExportArchiveProblem.unexpectedEntry, name);
    }
    if (name == exportArchiveJson) {
      if (entry.size > archiveJsonLimit) throw ExportArchiveError(ExportArchiveProblem.tooLarge, name);
      json = entry;
      continue;
    }
    final id = (_sealedName.firstMatch(name) ?? _plainName.firstMatch(name))?.group(1);
    if (id == null || files.containsKey(id)) throw ExportArchiveError(ExportArchiveProblem.unexpectedEntry, name);
    if (entry.size > archiveFileLimit) throw ExportArchiveError(ExportArchiveProblem.tooLarge, name);
    files[id] = entry;
  }
  if (json == null) throw const ExportArchiveError(ExportArchiveProblem.noExport);

  Uint8List content(ArchiveFile entry, int limit) {
    final Uint8List? data;
    try {
      data = entry.readBytes();
    } catch (_) {
      throw ExportArchiveError(ExportArchiveProblem.damaged, entry.name);
    }
    // The directory said how large it is; content that disagrees was tampered with
    if (data == null || data.length != entry.size || data.length > limit) {
      throw ExportArchiveError(ExportArchiveProblem.damaged, entry.name);
    }
    return data;
  }

  final String text;
  try {
    text = utf8.decode(content(json, archiveJsonLimit));
  } on FormatException {
    throw const ExportArchiveError(ExportArchiveProblem.damaged, exportArchiveJson);
  }
  return ExportArchive(
    exportJson: text,
    files: {for (final MapEntry(key: id, value: entry) in files.entries) id: () => content(entry, archiveFileLimit)},
  );
}
