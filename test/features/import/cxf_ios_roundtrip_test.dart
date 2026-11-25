@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/import/formats/cxf.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

// What Apple's types carry of the example, item by item: ios/RunnerTests/CredentialExchangeTests.swift
// holds the re-encoded JSON to this list, and this test holds the Dart reader to it too, so that the
// reader and the Swift side agree on what the hand-off keeps.
final _expected = jsonDecode(File('test/fixtures/import/cxf/ios-roundtrip.json').readAsStringSync()) as Json;
final _example = File('test/fixtures/import/cxf/fido-example.json').readAsStringSync();

void main() {
  test('reads from the example the credentials of each item that the iOS round trip expects', () {
    final document = parseCxf(_example);
    final expectedAccounts = _expected['accounts']! as List<Object?>;

    expect(document.accounts, hasLength(expectedAccounts.length));
    for (final (i, account) in document.accounts.indexed) {
      final want = expectedAccounts[i]! as Json;
      expect(account.id, want['id']);
      final wantItems = want['items']! as List<Object?>;
      expect(account.items, hasLength(wantItems.length));
      for (final (j, item) in account.items.indexed) {
        final wantItem = wantItems[j]! as Json;
        expect(item.title, wantItem['title']);
        // Apple's ASImportableCredential has no file case, so a file never comes through
        final types = [
          for (final credential in item.credentials)
            if (credential.type != 'file') credential.type,
        ];
        expect(types, wantItem['types'], reason: item.title);
      }
    }
  });

  test('reads a payload written as Swift writes it: dates with a fraction and the header by the specification names', () {
    final example = jsonDecode(_example) as Json;
    final swift = {...example, 'timestamp': 1705228800.0};

    final document = parseCxf(jsonEncode(swift));

    expect(document.timestamp, 1705228800);
    expect(document.major, 1);
    expect(document.exporterRpId, 'exporter.example.com');
    expect(document.exporterDisplayName, 'Exporter app');
  });
}
