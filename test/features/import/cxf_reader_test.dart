@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/import/formats/cxf.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

// Cases written by hand from the CXF 1.0 specification; see the README next to them.
final _cases = (jsonDecode(File('test/fixtures/import/cxf/cases.json').readAsStringSync()) as Json)['cases']! as List<Object?>;
final _example = File('test/fixtures/import/cxf/fido-example.json').readAsStringSync();

/// The large part of a case that [name] stands for, built here so the repo holds no 40 MiB file.
String _generate(String name, Json payload) {
  // A case may hold accounts or items that aren't objects; only an object is built on
  final account = switch ((payload['accounts'] as List<Object?>?)?.firstOrNull) {
    final Json json => json,
    _ => null,
  };
  final item = switch ((account?['items'] as List<Object?>?)?.firstOrNull) {
    final Json json => json,
    _ => null,
  };
  switch (name) {
    case 'credentials-40':
      final credentials = item!['credentials']! as List<Object?>;
      final first = credentials.first;
      while (credentials.length < 40) {
        credentials.add(first);
      }
    case 'urls-70':
      (item!['scope']! as Json)['urls'] = [for (var i = 0; i < 70; i++) 'https://example$i.test'];
    case 'items-12000':
      account!['items'] = [
        for (var i = 0; i < 12000; i++) {'id': 'i$i', 'title': 'Item $i', 'credentials': <Object?>[]},
      ];
    case 'long-password':
      final password = ((item!['credentials']! as List<Object?>).first! as Json)['password']! as Json;
      password['value'] = 'a' * 5000;
    case 'deep-500':
      var current = (account!['collections']! as List<Object?>).first! as Json;
      for (var depth = 2; depth <= 500; depth++) {
        final next = <String, Object?>{'id': 'c$depth', 'title': 'c$depth', 'items': <Object?>[]};
        current['subCollections'] = [next];
        current = next;
      }
    case 'pad-40mib':
      return '{${' ' * (40 * 1024 * 1024)}}';
  }
  return jsonEncode(payload);
}

List<CxfCredential> _credentials(CxfDocument document) => document.credentials.toList();

void main() {
  group('the specification\'s example', () {
    test('is read, with one credential of each of the 15 types', () {
      final document = parseCxf(_example);

      expect(document.major, 1);
      expect(document.exporterRpId, 'exporter.example.com');
      expect(document.exporterDisplayName, 'Exporter app');
      expect(document.timestamp, 1705228800);
      expect(document.accounts, hasLength(1));
      expect(document.accounts.single.displayName, 'Jane Smith');
      expect(document.accounts.single.items, hasLength(14));
      expect(
        {for (final credential in _credentials(document)) credential.type},
        {
          'basic-auth',
          'totp',
          'passkey',
          'credit-card',
          'wifi',
          'note',
          'drivers-license',
          'address',
          'ssh-key',
          'file',
          'identity-document',
          'passport',
          'person-name',
          'api-key',
          'generated-password',
        },
      );
      expect(document.cuts.any, isFalse);
    });

    test('reads the fields, scope, tags and collection of its first item', () {
      final account = parseCxf(_example).accounts.single;
      final github = account.items.first;

      expect(github.title, 'GitHub Login');
      expect(github.urls, ['https://github.com']);
      expect(github.androidApps, 0);
      expect(github.tags, ['development', 'git', 'work']);
      expect(github.createdAt, 1705142400);
      final auth = github.credentials.first as CxfBasicAuth;
      expect(auth.valueOf('username'), 'johndoe');
      expect(auth.fields['password']!.concealed, isTrue);
      final totp = github.credentials.last as CxfTotp;
      expect(totp.algorithm, 'sha256');
      expect(account.collections.single.path, ['Work Accounts']);
      expect(account.collections.single.links.map((link) => link.item), contains('9OF-QjVDQo2Wp2xWPw6ZhA'));
    });

    test('reads a passkey\'s extensions and keeps no value of its key in its description', () {
      final passkey = _credentials(parseCxf(_example)).whereType<CxfPasskey>().single;

      expect(passkey.rpId, 'webauthn.io');
      expect(passkey.fido2Extensions!.hmacCredentials, isTrue);
      expect(passkey.fido2Extensions!.credBlob, isTrue);
      expect(passkey.fido2Extensions!.largeBlob, isTrue);
      expect(passkey.toString(), isNot(contains(passkey.key)));
    });

    test('is recognised by its keys', () {
      expect(looksLikeCxf(jsonDecode(_example) as Json), isTrue);
      expect(looksLikeCxf({'version': 1, 'accounts': <Object?>[]}), isFalse);
      expect(looksLikeCxf({'items': <Object?>[], 'encrypted': false}), isFalse);
      expect(cxfExporterName(jsonDecode(_example) as Json), 'Exporter app');
    });
  });

  group('cases written from the specification', () {
    for (final raw in _cases) {
      final testCase = raw! as Json;
      final name = testCase['name']! as String;
      final expected = testCase['expect']! as Json;

      test(name, () {
        final generate = testCase['generate'] as String?;
        final payload = testCase['payload'] as Json?;
        final text = payload != null
            ? _generate(generate ?? '', payload)
            : (generate != null ? _generate(generate, {}) : testCase['text']! as String);

        if (expected['error'] case final Json error) {
          expect(
            () => parseCxf(text),
            throwsA(
              isA<CxfException>()
                  .having((e) => e.problem.name, 'problem', error['problem'])
                  .having((e) => e.version, 'version', error['version'])
                  .having((e) => e.position, 'position', error['position']),
            ),
          );
          return;
        }

        final document = parseCxf(text);
        final account = document.accounts.firstOrNull;
        final items = [for (final account in document.accounts) ...account.items];
        final credentials = _credentials(document);

        if (expected['accounts'] != null) {
          expect(document.accounts, hasLength(expected['accounts']! as int));
        }
        if (expected['itemCount'] != null) {
          expect(items, hasLength(expected['itemCount']! as int));
        }
        if (expected['minor'] != null) {
          expect(document.minor, expected['minor']);
        }
        if (expected['classes'] != null) {
          expect([for (final credential in credentials) credential.runtimeType.toString()], expected['classes']);
        }
        if (expected['types'] != null) {
          expect([for (final credential in credentials) credential.type], expected['types']);
        }
        if (expected['credentialCount'] != null) {
          expect(credentials, hasLength(expected['credentialCount']! as int));
        }
        if (expected['fieldKeys'] != null) {
          expect([
            for (final credential in credentials)
              if (credential is CxfFielded) (credential as CxfFielded).fields.keys.toList()..sort(),
          ], expected['fieldKeys']);
        }
        if (expected['totpAlgorithms'] != null) {
          expect([for (final credential in credentials.whereType<CxfTotp>()) credential.algorithm], expected['totpAlgorithms']);
        }
        if (expected['urlCounts'] != null) {
          expect([for (final item in items) item.urls.length], expected['urlCounts']);
        }
        if (expected['collectionCount'] != null) {
          expect(account!.collections, hasLength(expected['collectionCount']! as int));
          expect(account.collections.last.path, hasLength(expected['collectionCount']! as int));
        }
        if (expected['collectionPaths'] != null) {
          expect([for (final collection in account!.collections) collection.path], expected['collectionPaths']);
        }
        if (expected['collectionLinks'] != null) {
          expect([for (final collection in account!.collections) collection.links.length], expected['collectionLinks']);
        }
        if (expected['accessors'] != null) {
          expect([
            for (final collection in account!.collections)
              [
                for (final accessor in collection.shared!.accessors)
                  {'type': accessor.type, 'accountId': accessor.accountId, 'permissions': accessor.permissions},
              ],
          ], expected['accessors']);
        }
        final cuts = (expected['cuts'] as Json?) ?? const {};
        expect(document.cuts.itemsLeftOut, cuts['itemsLeftOut'] ?? 0);
        expect(document.cuts.credentialsLeftOut, cuts['credentialsLeftOut'] ?? 0);
        expect(document.cuts.urlsLeftOut, cuts['urlsLeftOut'] ?? 0);
        expect(document.cuts.collectionsTooDeep, cuts['collectionsTooDeep'] ?? 0);
        expect(document.cuts.valuesTooLong, cuts['valuesTooLong'] ?? 0);
      });
    }
  });

  group('errors', () {
    test('never hold a value of the payload', () {
      const secret = 'hunter2-should-never-appear';
      for (final text in [
        '{"version":{"major":1},"exporterRpId":"x","accounts":[{"items":["$secret"]}]}',
        '{"version":{"major":2,"minor":0},"password":"$secret"}',
        '{"password":"$secret"',
      ]) {
        try {
          parseCxf(text);
          fail('should have thrown');
        } on CxfException catch (error) {
          expect(error.toString(), isNot(contains(secret)));
          expect(error.message, isNot(contains(secret)));
        }
      }
    });

    test('names the position of a structure that is the wrong shape part-way through', () {
      expect(
        () => parseCxf('{"version":{"major":1},"exporterRpId":"x","accounts":[{"items":[{"title":"a","credentials":[]},7]}]}'),
        throwsA(isA<CxfException>().having((e) => e.position, 'position', 'account 1, item 2')),
      );
    });
  });
}
