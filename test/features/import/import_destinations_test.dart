@TestOn('vm')
library;

import 'package:kemlock_core/features/import/formats/cxf.dart';
import 'package:kemlock_core/features/import/formats/cxf_map.dart';
import 'package:kemlock_core/features/import/import_destinations.dart';
import 'package:kemlock_core/features/import/import_merge.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

Json _login(String id, String title) => {
  'id': id,
  'title': title,
  'scope': {
    'urls': ['https://$id.example'],
    'androidApps': <Object?>[],
  },
  'credentials': [
    {
      'type': 'basic-auth',
      'username': {'fieldType': 'string', 'value': 'ada'},
      'password': {'fieldType': 'concealed-string', 'value': 'pw-$id'},
    },
  ],
};

// Written from the CXF 1.0 specification: two accounts, "Personal" and "Family", the second with a
// collection shared with another user and an item outside it.
final Json _twoAccounts = {
  'version': {'major': 1, 'minor': 0},
  'exporterRpId': 'exporter.example.com',
  'exporterDisplayName': 'Exporter app',
  'timestamp': 1705228800,
  'accounts': [
    {
      'id': 'p',
      'username': 'Personal',
      'email': 'p@example.com',
      'items': [_login('mail', 'Mail')],
      'collections': <Object?>[],
    },
    {
      'id': 'f',
      'username': 'Family',
      'email': 'f@example.com',
      'items': [_login('router', 'Router'), _login('tv', 'Streaming')],
      'collections': [
        {
          'id': 'c1',
          'title': 'Household',
          'items': [
            {'item': 'router'},
          ],
          'extensions': [
            {
              'name': 'shared',
              'accessors': [
                {
                  'type': 'user',
                  'accountId': 'u2',
                  'name': 'bob',
                  'permissions': ['read'],
                },
              ],
            },
          ],
        },
      ],
    },
  ],
};

Future<ImportPreview> _preview() async {
  var next = 0;
  final result = await mapCxf(readCxf(_twoAccounts), newId: () => 'id-${next++}', now: 1800000000000);
  return ImportPreview.ofForeign(result);
}

void main() {
  test('the vault is preselected for each account and a new space for a shared collection', () async {
    final preview = await _preview();

    final destinations = defaultDestinations(preview.units);

    expect(destinations.of('account:0'), const ImportDestination.vault());
    expect(destinations.of('account:1'), const ImportDestination.vault());
    expect(destinations.of('account:1/collection:0'), const ImportDestination.newSpace('Household'));
  });

  test('each part of the import goes where its place does, the vault first', () async {
    final preview = await _preview();

    final placed = placeImport(preview, defaultDestinations(preview.units));

    expect([for (final part in placed) part.destination], [const ImportDestination.vault(), const ImportDestination.newSpace('Household')]);
    expect(placed[0].preview.logins.map((login) => login.name), ['Mail', 'Streaming']);
    expect(placed[1].preview.logins.map((login) => login.name), ['Router']);
  });

  test('the person can send an account to a new space, and back', () async {
    final preview = await _preview();
    var destinations = defaultDestinations(preview.units);

    destinations = destinations.choose('account:1', const ImportDestination.newSpace('Family'));
    final placed = placeImport(preview, destinations);

    expect(
      [for (final part in placed) part.destination],
      [const ImportDestination.vault(), const ImportDestination.newSpace('Family'), const ImportDestination.newSpace('Household')],
    );
    expect(placed[1].preview.logins.map((login) => login.name), ['Streaming']);
    expect(placed[2].preview.logins.map((login) => login.name), ['Router']);

    destinations = destinations.choose('account:1', const ImportDestination.vault());
    expect(placeImport(preview, destinations), hasLength(2));
  });

  test('nothing is counted twice: what was skipped and cut is in the first part only', () async {
    final preview = await _preview();

    final placed = placeImport(preview, defaultDestinations(preview.units));

    expect(placed[0].preview.units, preview.units);
    expect(placed[0].preview.skipped, preview.skipped);
    expect(placed[1].preview.skipped, 0);
    expect(placed[1].preview.skips, isEmpty);
    expect(placed[1].preview.cuts, isNull);
  });
}
