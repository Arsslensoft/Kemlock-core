@TestOn('vm')
library;

// A long sync cursor (one vector per owner, about 43 bytes more for each space) goes in the body of
// POST /kem/v1/sync, {since, limit}; a short one stays in the query of the GET.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://kem.example.com');

http.Response _page() =>
    http.Response(jsonEncode({'items': <Object?>[], 'cursor': 'next', 'more': false}), 200, headers: {'content-type': 'application/json'});

KmApi _api(Future<http.Response> Function(http.Request request) handler, List<http.Request> seen) => KmApi(
  MockClient((request) async {
    seen.add(request);
    return handler(request);
  }),
);

void main() {
  final long = 'a' * (KmApi.postCursorLength + 1);

  test('a short cursor is asked with the GET, in the query', () async {
    final seen = <http.Request>[];
    await _api((_) async => _page(), seen).sync(_server, 't', since: 'short', limit: 100);

    expect(seen.single.method, 'GET');
    expect(seen.single.url.queryParameters, {'since': 'short', 'limit': '100'});
  });

  test('no cursor is asked with the GET', () async {
    final seen = <http.Request>[];
    await _api((_) async => _page(), seen).sync(_server, 't');

    expect(seen.single.method, 'GET');
    expect(seen.single.url.queryParameters, {'limit': '500'});
  });

  test('a long cursor is sent in the body of a POST, never in the URL', () async {
    final seen = <http.Request>[];
    final page = await _api((_) async => _page(), seen).sync(_server, 't', since: long, limit: 100);

    expect(page!.cursor, 'next');
    expect(seen.single.method, 'POST');
    expect(seen.single.url.path, '/kem/v1/sync');
    expect(seen.single.url.hasQuery, isFalse);
    expect(jsonDecode(seen.single.body), {'since': long, 'limit': 100});
    expect(seen.single.headers['Content-Type'], startsWith('application/json'));
  });

  test('a 304 and a 410 on the POST read as they do on the GET', () async {
    expect(await _api((_) async => http.Response('', 304), []).sync(_server, 't', since: long), isNull);
    await expectLater(
      _api(
        (_) async => http.Response('{}', 410, headers: {'content-type': 'application/problem+json'}),
        [],
      ).sync(_server, 't', since: long),
      throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.fullSync)),
    );
  });

  test('a server without the POST route is asked with the GET again', () async {
    final seen = <http.Request>[];
    final page = await _api(
      (request) async => request.method == 'POST' ? http.Response('', 405) : _page(),
      seen,
    ).sync(_server, 't', since: long);

    expect(page!.cursor, 'next');
    expect(seen.map((r) => r.method), ['POST', 'GET']);
    expect(seen.last.url.queryParameters['since'], long);
  });
}
