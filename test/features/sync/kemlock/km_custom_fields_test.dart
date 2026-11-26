@TestOn('vm')
library;

// `GET /kem/v1/custom-fields` (docs/custom-fields.md): the definitions an admin offers, read leniently.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_custom_fields.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/models/custom_field.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://kem.example.com');

const _answer = {
  'fields': [
    {'id': '7d0f0000-0000-4000-8000-000000000001', 'name': 'Employee ID', 'type': 'text', 'kinds': 'all'},
    {
      'id': '1b9e0000-0000-4000-8000-000000000002',
      'name': 'Cost center',
      'type': 'hidden',
      'kinds': ['login', 'card'],
    },
    {
      'id': '2c000000-0000-4000-8000-000000000003',
      'name': 'Remote',
      'type': 'checkbox',
      'kinds': ['note'],
    },
  ],
  'allowOwn': false,
};

void main() {
  group('KmCustomFields.fromJson', () {
    test('reads the definitions and allowOwn', () {
      final read = KmCustomFields.fromJson(_answer);
      expect(read.allowOwn, isFalse);
      expect(read.fields.map((field) => field.name), ['Employee ID', 'Cost center', 'Remote']);
      expect(read.fields.map((field) => field.kind), [CustomFieldKind.text, CustomFieldKind.hidden, CustomFieldKind.boolean]);
      expect(read.fields.map((field) => field.kinds), [
        null,
        ['login', 'card'],
        ['note'],
      ]);
      expect(read.definition('1b9e0000-0000-4000-8000-000000000002')!.name, 'Cost center');
      expect(read.definition('missing'), isNull);
    });

    test('leaves out what it cannot use, and ignores an unknown kind in a list', () {
      final read = KmCustomFields.fromJson({
        'fields': [
          {'id': 'a', 'name': 'Odd type', 'type': 'date', 'kinds': 'all'},
          {'id': 'b', 'name': 'No kinds', 'type': 'text'},
          {'id': 'c', 'name': '  ', 'type': 'text', 'kinds': 'all'},
          {'name': 'No id', 'type': 'text', 'kinds': 'all'},
          'nope',
          {
            'id': 'd',
            'name': ' Kept ',
            'type': 'text',
            'kinds': ['login', 'spaceship', 7],
          },
        ],
      });
      expect(read.fields, hasLength(1));
      expect(read.fields.single.name, 'Kept');
      expect(read.fields.single.kinds, ['login']);
      expect(read.allowOwn, isTrue);
    });

    test('an answer that is not an object means none, and people may add their own', () {
      for (final json in <Object?>[null, 'x', 5, <Object?>[]]) {
        final read = KmCustomFields.fromJson(json);
        expect(read.fields, isEmpty);
        expect(read.allowOwn, isTrue);
      }
    });
  });

  group('definitionsFor', () {
    final read = KmCustomFields.fromJson(_answer);

    test('gives the fields offered on a kind, in order, and those for every kind', () {
      expect(read.definitionsFor(KmKind.login).map((field) => field.name), ['Employee ID', 'Cost center']);
      expect(read.definitionsFor(KmKind.note).map((field) => field.name), ['Employee ID', 'Remote']);
      expect(read.definitionsFor(KmKind.identity).map((field) => field.name), ['Employee ID']);
    });

    test('gives none for a file or a passkey, whatever a definition says', () {
      expect(read.definitionsFor('file'), isEmpty);
      expect(read.definitionsFor(KmKind.passkey), isEmpty);
    });

    test('makes the empty field of a definition for an item', () {
      final field = read.fields[2].toField();
      expect(field.toJson(), {'name': 'Remote', 'value': 'false', 'kind': 'boolean', 'adminField': '2c000000-0000-4000-8000-000000000003'});
    });
  });

  group('the request', () {
    http.Response json(Object? body, [int status = 200]) =>
        http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

    test('is a GET of /kem/v1/custom-fields with the token', () async {
      final seen = <http.Request>[];
      final api = KmCustomFieldsApi(
        KmApi(
          MockClient((request) async {
            seen.add(request);
            return json(_answer);
          }),
        ),
      );
      final read = await api.list(_server, 'token-1');
      expect(read.fields, hasLength(3));
      expect(seen.single.method, 'GET');
      expect(seen.single.url.path, '/kem/v1/custom-fields');
      expect(seen.single.headers['authorization'], contains('token-1'));
    });

    test('a server without the route offers none', () async {
      final api = KmCustomFieldsApi(
        KmApi(MockClient((request) async => json({'type': 'urn:kemlock:problem:not-found', 'status': 404}, 404))),
      );
      final read = await api.list(_server, 'token-1');
      expect(read.fields, isEmpty);
      expect(read.allowOwn, isTrue);
    });
  });

  test('itemKindOf names the kind an entry is stored as', () {
    expect(itemKindOf(const Login(id: 'l', name: 'x', addedAt: 1)), KmKind.login);
    expect(itemKindOf(const PaymentCard(id: 'c', name: 'x', addedAt: 1)), KmKind.card);
  });
}
