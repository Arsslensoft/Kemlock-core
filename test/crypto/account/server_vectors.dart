// The Kemlock server's published test vectors (CC0-1.0), copied by
// tool/server/copy_vectors.sh into test/fixtures/server/. Until the server
// publishes them the folder is absent, and a format test that needs one of
// the files passes `skip: serverVectorSkip(name)`, which says what it waits
// for. Nothing of the app's making stands in for these files.

import 'dart:convert';
import 'dart:io';

const serverVectorFolder = 'test/fixtures/server';

/// Why a test that needs the server's [file] is skipped, or null once the
/// file has been copied.
String? serverVectorSkip(String file) {
  if (File('$serverVectorFolder/$file').existsSync()) return null;
  return 'waits for the server vector $file: run tool/server/copy_vectors.sh once test-vectors/ is published';
}

/// The JSON of the server vector [file].
Object? readServerVector(String file) => jsonDecode(File('$serverVectorFolder/$file').readAsStringSync());

/// The `SHA256SUMS` lines as file name to lower-case hex digest, or null when
/// the folder is absent.
Map<String, String>? readServerChecksums() {
  final sums = File('$serverVectorFolder/SHA256SUMS');
  if (!sums.existsSync()) return null;
  final out = <String, String>{};
  for (final line in sums.readAsLinesSync()) {
    final trimmed = line.trim();
    if (trimmed.isEmpty) continue;
    final match = RegExp(r'^([0-9a-fA-F]{64})\s+\*?(.+)$').firstMatch(trimmed);
    if (match == null) throw FormatException('SHA256SUMS line is not "digest  name"', line);
    out[match.group(2)!] = match.group(1)!.toLowerCase();
  }
  return out;
}

/// The `cases` of the server vector [file] (`argon2id.json` and so on), after
/// checking that its `format` is [format], the file's name unless given (the
/// OPAQUE file says `opaque1`), and its `version` is [version]. Each case is a
/// JSON object.
List<Map<String, Object?>> readServerCases(String file, {String? format, int version = 1}) {
  final json = readServerVector(file)! as Map<String, Object?>;
  final expected = format ?? file.replaceFirst(RegExp(r'\.json$'), '');
  if (json['format'] != expected) throw FormatException('$file holds the format ${json['format']}, not $expected');
  if (json['version'] != version) throw FormatException('$file is version ${json['version']}, not $version');
  return (json['cases']! as List<Object?>).cast<Map<String, Object?>>();
}
