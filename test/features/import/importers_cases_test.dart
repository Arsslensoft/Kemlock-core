@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/import/importers.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

// What `importers.ts` calls each source and error.
const sources = {
  'google': ImportSource.google,
  'aegis': ImportSource.aegis,
  '2fas': ImportSource.twoFas,
  'bitwarden': ImportSource.bitwarden,
  'uris': ImportSource.uris,
};
const errors = {
  'unsupported': ImportErrorCode.unsupported,
  'empty': ImportErrorCode.empty,
  'password-required': ImportErrorCode.passwordRequired,
  'bad-password': ImportErrorCode.badPassword,
  'bitwarden-encrypted': ImportErrorCode.bitwardenEncrypted,
};

DetectedFormat? detected(Object? json) => switch (json) {
  {'source': final String source, 'encrypted': final bool encrypted} => (source: sources[source]!, encrypted: encrypted),
  _ => null,
};

/// A result as the TypeScript writes it: accounts without an id or addedAt.
Json? asJson(ForeignImport? result) => result == null
    ? null
    : {
        'source': sources.entries.firstWhere((e) => e.value == result.source).key,
        'accounts': [
          for (final account in result.accounts)
            account.toJson()
              ..remove('id')
              ..remove('addedAt'),
        ],
        'skipped': result.skipped,
      };

void main() {
  // Written by tool/fixtures/importers_cases.mjs from src/lib/importers.ts
  final fixture = jsonDecode(File('test/fixtures/import/cases.json').readAsStringSync()) as Json;

  group('files read as the TypeScript app reads them', () {
    for (final file in (fixture['files']! as List<Object?>).cast<Json>()) {
      test(file['name']! as String, () async {
        final text = file['text']! as String;
        final password = file['password'] as String?;
        expect(detectFormat(text), detected(file['detected']));
        if (file['error'] case final String code) {
          await expectLater(
            parseForeignExport(text, password: password),
            throwsA(isA<ImportError>().having((e) => e.code, 'code', errors[code])),
          );
        } else {
          expect(asJson(await parseForeignExport(text, password: password)), file['result']);
        }
      });
    }
  });

  group('transfer QR codes read as the TypeScript app reads them', () {
    for (final migration in (fixture['migrations']! as List<Object?>).cast<Json>()) {
      test(migration['name']! as String, () {
        expect(asJson(parseGoogleMigration(migration['uri']! as String)), migration['result']);
      });
    }
  });
}
