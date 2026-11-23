@TestOn('vm')
library;

import 'dart:io';

import 'package:crypto/crypto.dart' as hash;
import 'package:test/test.dart';

import 'server_vectors.dart';

// The server's vectors are copied by tool/server/copy_vectors.sh and never
// edited. SHA256SUMS comes from the server, so a hand-edited file fails
// here and the failure names it.
void main() {
  final sums = readServerChecksums();
  if (sums == null) {
    test(
      'the server vectors are checked once they are copied',
      () {},
      skip: 'test/fixtures/server is absent: the server has not published test-vectors/ yet',
    );
    return;
  }

  group('server vectors', () {
    for (final entry in sums.entries) {
      test('${entry.key} matches SHA256SUMS', () {
        final file = File('$serverVectorFolder/${entry.key}');
        expect(file.existsSync(), isTrue, reason: '${entry.key} is listed in SHA256SUMS but missing');
        final digest = hash.sha256.convert(file.readAsBytesSync()).toString();
        expect(digest, entry.value, reason: '${entry.key} was edited: refresh it with tool/server/copy_vectors.sh');
      });
    }

    test('every vector file is listed in SHA256SUMS', () {
      final names = Directory(serverVectorFolder)
          .listSync()
          .whereType<File>()
          .map((f) => f.uri.pathSegments.last)
          .where((name) => name.endsWith('.json') && name != 'SOURCE.json');
      for (final name in names) {
        expect(sums.containsKey(name), isTrue, reason: '$name is not in SHA256SUMS');
      }
    });

    test('SOURCE.json names the repo, the commit and the date', () {
      final source = readServerVector('SOURCE.json')! as Map<String, Object?>;
      expect(source.keys, containsAll(['repo', 'commit', 'date']));
    });
  });
}
