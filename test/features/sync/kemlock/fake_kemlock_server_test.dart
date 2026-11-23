@TestOn('vm')
library;

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';

const _id = '3f2c9a71-e4b0-4856-8a00-000000000001';

/// One write of a new login, as a batch carries it.
Map<String, Object?> _write({int revision = 1, int? expected, bool deleted = false, String text = 'A'}) => {
  'expectedRevision': expected,
  'item': {
    'id': _id,
    'owner': 'user:00000000-0000-4000-8000-000000000001',
    'kind': 'login',
    'format': 'kem1',
    'revision': revision,
    'keyVersion': 1,
    if (!deleted) 'ciphertext': b64urlEncode(List.filled(40, text.codeUnitAt(0))),
    if (!deleted) 'itemKey': b64urlEncode(List.filled(60, 2)),
    'deleted': deleted,
  },
};

void main() {
  late FakeKemlockServer server;
  late String token;

  // The smoke tests send plain requests with a token and no proof
  setUp(() {
    server = FakeKemlockServer()..checkTokens = false;
    token = server.issueTokens('jkt')['accessToken']! as String;
  });

  Uri at(String route) => Uri.parse('https://kem.example.com/kem/v1$route');

  Future<http.Response> post(String route, Object body) =>
      server.client.post(at(route), headers: {'Authorization': 'DPoP $token', 'Content-Type': 'application/json'}, body: jsonEncode(body));

  Future<http.Response> get(String route) => server.client.get(at(route), headers: {'Authorization': 'DPoP $token'});

  test('serves its config without a token', () async {
    final answer = await server.client.get(at('/config'));

    expect((jsonDecode(answer.body) as Map)['server'], 'kemlock-server');
    // The server lists `sends` among its features since it serves the Send routes
    expect((jsonDecode(answer.body) as Map)['features'], contains('sends'));
  });

  test('a batch put sent twice leaves one item', () async {
    final batch = {
      'writes': [_write()],
    };

    expect((await post('/items:batch', batch)).statusCode, 200);
    expect((await post('/items:batch', batch)).statusCode, 200);

    expect(server.items, hasLength(1));
    expect(server.items[_id]!.revision, 1);
  });

  test('a write of a revision other than the stored one plus one, or with a stale If-Match, is refused', () async {
    await post('/items:batch', {
      'writes': [_write()],
    });

    final stale = await post('/items:batch', {
      'writes': [_write(revision: 2, expected: 5)],
    });
    final skipped = await post('/items:batch', {
      'writes': [_write(revision: 3, expected: 1)],
    });

    expect(stale.statusCode, 409);
    expect(jsonDecode(stale.body), containsPair('currentRevision', 1));
    expect(jsonDecode(stale.body), containsPair('itemId', _id));
    expect(skipped.statusCode, 422);
  });

  test('a batch is all or none', () async {
    await post('/items:batch', {
      'writes': [_write()],
    });
    final other = _write();
    (other['item']! as Map<String, Object?>)['id'] = '3f2c9a71-e4b0-4856-8a00-000000000002';

    final answer = await post('/items:batch', {
      'writes': [other, _write(revision: 2, expected: 9)],
    });

    expect(answer.statusCode, 409);
    expect(server.items, hasLength(1));
  });

  test('a delta gives what changed since the cursor, 304 when nothing did, and a tombstone for a delete', () async {
    await post('/items:batch', {
      'writes': [_write()],
    });
    final first = jsonDecode((await get('/sync')).body) as Map<String, Object?>;
    final again = await get('/sync?since=${first['cursor']}');
    await post('/items:batch', {
      'writes': [_write(revision: 2, expected: 1, deleted: true)],
    });
    final after = jsonDecode((await get('/sync?since=${first['cursor']}')).body) as Map<String, Object?>;

    expect(first['items']! as List, hasLength(1));
    expect(again.statusCode, 304);
    expect(((after['items']! as List).single as Map)['deleted'], isTrue);
    expect(((after['items']! as List).single as Map).containsKey('ciphertext'), isFalse);
  });

  test('a file needs its item, arrives byte for byte, and must start like a KMA1 file', () async {
    final missing = await post('/items/$_id/files', {'size': 8});
    await post('/items:batch', {
      'writes': [_write()],
    });
    final started = jsonDecode((await post('/items/$_id/files', {'size': 8})).body) as Map<String, Object?>;
    final route = '/items/$_id/files/${started['fileId']}';
    final headers = {'Authorization': 'DPoP $token'};
    final bad = await server.client.put(at(route), headers: headers, body: List.filled(8, 1));
    final bytes = [...'KMA1'.codeUnits, 1, 2, 3, 4];
    final good = await server.client.put(at(route), headers: headers, body: bytes);
    final back = await server.client.get(at(route), headers: headers);

    expect(missing.statusCode, 404);
    expect(bad.statusCode, 415);
    expect(good.statusCode, 200);
    expect(back.bodyBytes, bytes);
  });

  test('it refuses a request with no proof while it checks proofs', () async {
    server.checkTokens = true;

    final answer = await get('/sync');

    expect(answer.statusCode, 401);
  });
}
