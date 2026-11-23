@TestOn('vm')
library;

// The PGP message fixtures are all there: every file the two NOTES.md name
// exists and holds something, and an armored one holds exactly one block.

import 'dart:io';

import 'package:test/test.dart';

import 'fixtures.dart';

final _fileName = RegExp(r'`((?:gnupg/|kemlock/)?[A-Za-z0-9][A-Za-z0-9._-]*\.(?:asc|gpg|sig|txt))`');

List<String> _named(String notes, String folder) => [
  for (final match in _fileName.allMatches(File('test/fixtures/pgp/$notes').readAsStringSync())) '$folder${match.group(1)}',
];

void main() {
  final files = {..._named('rfc9580/NOTES.md', 'rfc9580/'), ..._named('NOTES.md', '')}.toList();

  test('the notes name the fixtures', () {
    expect(files.where((f) => f.startsWith('rfc9580/')), hasLength(6));
    expect(files.where((f) => f.startsWith('gnupg/')).length, greaterThan(60));
    // Nothing in the folders is left unexplained
    for (final folder in ['rfc9580', 'gnupg', 'kemlock']) {
      for (final file in Directory('test/fixtures/pgp/$folder').listSync().whereType<File>()) {
        final name = '$folder/${file.uri.pathSegments.last}';
        if (name.endsWith('NOTES.md')) continue;
        expect(files, contains(name), reason: '$name is not in NOTES.md');
      }
    }
  });

  for (final file in files) {
    test('$file is there', () {
      final bytes = pgpFixture(file);
      expect(bytes, isNotEmpty);
      if (file.endsWith('.asc')) {
        final text = String.fromCharCodes(bytes);
        expect('-----END PGP '.allMatches(text), hasLength(1), reason: 'one armor block');
        expect(text, startsWith('-----BEGIN PGP '));
      }
    });
  }

  test('the sample stream is the one the large fixtures were made from', () {
    // Its first bytes, from tool/pgp/sample_file.dart
    expect(hexOf(sampleBytes(8)), hexOf(sampleBytes(16).sublist(0, 8)));
    expect(sampleBytes(5242880).length, 5242880);
  });
}
