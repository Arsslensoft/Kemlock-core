@TestOn('vm')
library;

// The Kemlock API client's limits on what a server sends (design 16): no redirect
// is followed, an answer is capped before its length is believed, a pre-signed
// address gets no credentials, and a refresh token is used once.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://kem.example.com');

const _item = {
  'id': '3f2c9a71-e4b0-4856-8a00-000000000001',
  'owner': 'user:00000000-0000-4000-8000-000000000001',
  'kind': 'login',
  'format': 'kem1',
  'revision': 1,
  'keyVersion': 1,
  'ciphertext': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  'itemKey': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  'deleted': false,
};

http.Response _json(Object? body, [int status = 200, Map<String, String> headers = const {}]) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json', ...headers});

http.Response _problem(int status, String slug, [Map<String, Object?> extra = const {}]) => http.Response(
  jsonEncode({'type': 'urn:kemlock:problem:$slug', 'status': status, ...extra}),
  status,
  headers: {'content-type': 'application/problem+json'},
);

KmApi _api(Future<http.Response> Function(http.Request request) handler, {List<http.Request>? seen}) => KmApi(
  MockClient((request) async {
    seen?.add(request);
    return handler(request);
  }),
);

/// A client whose answers never end.
class _Endless extends http.BaseClient {
  var chunks = 0;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final stream = (() async* {
      while (true) {
        chunks++;
        yield Uint8List(64 * 1024);
      }
    })();
    return http.StreamedResponse(stream, 200, headers: {'content-type': 'application/json'});
  }
}

void main() {
  group('the address', () {
    test('only https is taken, with its path kept and a trailing slash dropped', () {
      expect(kmServerUrl('https://kem.example.com/').toString(), 'https://kem.example.com');
      expect(kmServerUrl(' https://kem.example.com:8443/vault/ ').toString(), 'https://kem.example.com:8443/vault');
      expect(() => kmServerUrl('http://kem.example.com'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.insecure)));
      expect(() => kmServerUrl('kem.example.com'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.address)));
      expect(() => kmServerUrl('https://user:pw@kem.example.com'), throwsA(isA<KmError>()));
    });

    test('a server is told from other servers by its config', () async {
      final api = _api(
        (_) async => _json({
          'server': 'vaultwarden',
          'apiVersions': ['v1'],
        }),
      );

      await expectLater(api.config(_server), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.address)));

      final real = _api(
        (_) async => _json({
          'server': 'kemlock-server',
          'apiVersions': ['v1'],
          'serverId': 's',
          'domain': 'https://kem.example.com',
        }),
      );
      expect((await real.config(_server)).domain, 'https://kem.example.com');
    });
  });

  group('the servers of a vault', () {
    const vault = 'user:00000000-0000-4000-8000-000000000001';
    final key = 'A' * 2646; // 1,984 bytes of base64url, no padding
    Map<String, Object?> entry(String id, String address, String role, [String? identityKey]) => {
      'serverId': id,
      'address': address,
      'identityKey': identityKey ?? key,
      'role': role,
    };
    Map<String, Object?> listed({List<Object?>? servers, Object? epoch = 2, Object? promotion = 'AAAA', String name = vault}) => {
      'vault': name,
      'epoch': epoch,
      'servers':
          servers ??
          [
            entry('00000000-0000-4000-8000-0000000000a1', 'https://home.example.com/', KemlockServer.home),
            entry('00000000-0000-4000-8000-0000000000a2', 'https://one.example.com', KemlockServer.replica),
          ],
      'promotion': promotion,
    };
    Future<KmConfig> config(List<Object?> vaults, {List<http.Request>? seen, List<String> ask = const [vault]}) {
      final api = _api(
        (_) async => _json({
          'server': 'kemlock-server',
          'apiVersions': ['v1'],
          'serverId': 's',
          'domain': 'https://kem.example.com',
          'vaults': vaults,
        }),
        seen: seen,
      );
      return api.config(_server, vaults: ask);
    }

    test('the vaults asked for go in the query, one parameter each, with no proof', () async {
      final seen = <http.Request>[];
      await config(const [], seen: seen, ask: [vault, 'user:00000000-0000-4000-8000-000000000002']);
      expect(seen.single.url.queryParametersAll['vault'], [vault, 'user:00000000-0000-4000-8000-000000000002']);
      expect(seen.single.headers.containsKey('DPoP'), isFalse);
      final none = <http.Request>[];
      await config(const [], seen: none, ask: const []);
      expect(none.single.url.hasQuery, isFalse);
    });

    test('a vault reads as its epoch, its servers with the home first, and its record', () async {
      final read = (await config([listed()])).vaults.single;
      expect(read.vault, vault);
      expect(read.epoch, 2);
      expect(read.home.address, 'https://home.example.com', reason: 'the address is written as the settings keep it');
      expect(read.servers.map((s) => s.role), [KemlockServer.home, KemlockServer.replica]);
      expect(read.servers.first.identityKey, hasLength(1984));
      expect(read.promotion, hasLength(3));
      expect(read.servers.first.toServer().identityKey, key);
      // At epoch 1 there is no record
      expect((await config([listed(epoch: 1, promotion: null)])).vaults.single.promotion, isNull);
    });

    test('a vault this version cannot read is left out, and the others stay', () async {
      const home = '00000000-0000-4000-8000-0000000000a1';
      const replica = '00000000-0000-4000-8000-0000000000a2';
      final bad = [
        listed(epoch: 0),
        listed(
          servers: [
            entry(replica, 'https://one.example.com', KemlockServer.replica),
            entry(home, 'https://home.example.com', KemlockServer.home),
          ],
        ),
        listed(
          servers: [
            entry(home, 'https://home.example.com', KemlockServer.home),
            entry(home, 'https://one.example.com', KemlockServer.replica),
          ],
        ),
        listed(servers: [entry(home, 'http://home.example.com', KemlockServer.home)]),
        listed(servers: [entry(home, 'https://home.example.com', KemlockServer.home, 'AAAA')]),
        listed(servers: [entry(home, 'https://home.example.com', 'primary')]),
        listed(name: 'vault:1'),
        listed(promotion: 5),
        'a vault',
      ];
      expect((await config([...bad, listed()])).vaults, hasLength(1));
    });
  });

  group('the approval poll', () {
    const account = '00000000-0000-4000-8000-000000000001';
    final sealed = b64urlEncode(Uint8List(8));

    Future<KmApprovalPoll> poll(Map<String, Object?> answer) =>
        KmAuthApi(_api((_) async => _json(answer))).approvalPoll(_server, 'request-1');

    test('reads the account the key opens from `accountId`, which the server answers with `approved`', () async {
      final read = await poll({'status': 'approved', 'sealedKey': sealed, 'accountId': account});

      expect(read.status, 'approved');
      expect(read.accountId, account);
      expect(read.sealedKey, hasLength(8));
    });

    test('reads no account from `userId`: the server names it `accountId` only', () async {
      expect((await poll({'status': 'approved', 'sealedKey': sealed, 'userId': account})).accountId, isNull);
      expect((await poll({'status': 'pending'})).accountId, isNull);
    });
  });

  group('siblings', () {
    Map<String, Object?> page({Object? siblings}) => {
      'items': [_item],
      'cursor': 'c',
      'more': false,
      'siblings': ?siblings,
    };
    const id = '3f2c9a71-e4b0-4856-8a00-000000000001';

    test('a page lists the versions held beside a head, each as an item', () async {
      final api = _api(
        (_) async => _json(
          page(
            siblings: [
              {
                'itemId': id,
                'versions': [
                  _item,
                  {..._item, 'revision': 2},
                ],
              },
            ],
          ),
        ),
      );

      final read = (await api.sync(_server, 't'))!;

      expect(read.siblings.single.itemId, id);
      expect(read.siblings.single.versions.map((version) => version.revision), [1, 2]);
    });

    test('a page of a server with no federation, or none listed, has none', () async {
      expect((await _api((_) async => _json(page())).sync(_server, 't'))!.siblings, isEmpty);
      expect((await _api((_) async => _json(page(siblings: const []))).sync(_server, 't'))!.siblings, isEmpty);
    });

    test('a set that is not a set of versions of one item is a server error', () async {
      for (final bad in <Object?>[
        'siblings',
        [
          <String, Object?>{'itemId': id, 'versions': <Object?>[]},
        ],
        [
          <String, Object?>{
            'itemId': 'not-a-uuid',
            'versions': [_item],
          },
        ],
        [
          <String, Object?>{
            'itemId': '3f2c9a71-e4b0-4856-8a00-000000000002',
            'versions': [_item],
          },
        ],
        [
          <String, Object?>{
            'itemId': id,
            'versions': ['no'],
          },
        ],
      ]) {
        await expectLater(
          _api((_) async => _json(page(siblings: bad))).sync(_server, 't'),
          throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server)),
          reason: '$bad',
        );
      }
    });

    test('resolving posts to the item\'s route with a token and says how many it dropped', () async {
      final seen = <http.Request>[];
      final api = _api((_) async => _json({'resolved': 2}), seen: seen);

      expect(await api.resolveSiblings(_server, 'tok', id), 2);

      expect(seen.single.method, 'POST');
      expect(seen.single.url.path, '/kem/v1/items/$id/siblings/resolve');
      expect(seen.single.headers['Authorization'], 'DPoP tok');
    });

    test('a head already sent to another server, or an item that is gone, is null, not an error; any other answer is', () async {
      expect(await _api((_) async => _problem(409, 'siblings-already-sent')).resolveSiblings(_server, 't', id), isNull);
      expect(await _api((_) async => _problem(404, 'not-found')).resolveSiblings(_server, 't', id), isNull);
      await expectLater(
        _api((_) async => _problem(409, 'stale-revision')).resolveSiblings(_server, 't', id),
        throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.stale)),
      );
      await expectLater(_api((_) async => _problem(500, 'internal')).resolveSiblings(_server, 't', id), throwsA(isA<KmError>()));
      await expectLater(_api((_) async => _json({'resolved': 'two'})).resolveSiblings(_server, 't', id), throwsA(isA<KmError>()));
    });
  });

  group('what the server can send', () {
    test('a redirect is not followed, on any route', () async {
      final seen = <http.Request>[];
      final api = _api((_) async => http.Response('', 302, headers: {'location': 'https://evil.example.com/'}), seen: seen);

      await expectLater(api.sync(_server, 't'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server)));
      await expectLater(api.refresh(_server, 'r'), throwsA(isA<KmError>()));
      await expectLater(api.config(_server), throwsA(isA<KmError>()));

      expect(seen, hasLength(3));
      expect(seen.every((r) => !r.followRedirects), isTrue);
      expect(seen.every((r) => r.url.host == 'kem.example.com'), isTrue);
    });

    test('a 3 MiB JSON answer is refused', () async {
      final big = http.Response('{"padding":"${'a' * (3 * 1024 * 1024)}"}', 200, headers: {'content-type': 'application/json'});
      final api = _api((_) async => big);

      await expectLater(api.refresh(_server, 'r'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.tooLarge)));
    });

    test('an answer that never ends is cut off at the cap, and not read on', () async {
      final endless = _Endless();
      final api = KmApi(endless);

      await expectLater(api.refresh(_server, 'r'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.tooLarge)));

      // 2 MiB is 32 chunks of 64 KiB; it stops soon after, not at some far end
      expect(endless.chunks, lessThan(40));
    });

    test('a sync page may be larger than a JSON answer, up to 8 MiB', () async {
      final page = _json({
        'items': [_item],
        'cursor': 'c',
        'more': false,
      });
      final api = _api((_) async => page);

      final read = await api.sync(_server, 't');

      expect(read!.items.single.id, _item['id']);
      expect(read.cursor, 'c');
      expect(read.more, isFalse);
    });

    test('a file stops at the size its note names, and nothing is returned', () async {
      final api = _api((_) async => http.Response.bytes(Uint8List(2000), 200));

      await expectLater(
        api.downloadFile(_server, 't', _item['id']! as String, 'f', maxBytes: 1000),
        throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.tooLarge)),
      );
      expect((await api.downloadFile(_server, 't', _item['id']! as String, 'f', maxBytes: 2000)), hasLength(2000));
    });

    test('a request that gets no answer in time is a network problem', () async {
      final api = KmApi(MockClient((_) => Completer<http.Response>().future), timeout: const Duration(milliseconds: 20));

      await expectLater(api.config(_server), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network)));
    });

    test('an item that is malformed makes the page unusable', () async {
      final api = _api(
        (_) async => _json({
          'items': [
            {..._item, 'id': 'acc-1'},
          ],
          'cursor': 'c',
          'more': false,
        }),
      );

      await expectLater(api.sync(_server, 't'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server)));
    });

    test('an item of a format this version does not open still reads', () async {
      final api = _api(
        (_) async => _json({
          'items': [
            {..._item, 'format': 'bw'},
          ],
          'cursor': 'c',
          'more': false,
        }),
      );

      final item = (await api.sync(_server, 't'))!.items.single;

      expect(item.isKem1, isFalse);
      expect(item.ciphertext, isNotNull);
    });

    test('304 is no page', () async {
      final api = _api((_) async => http.Response('', 304));

      expect(await api.sync(_server, 't', since: 'c'), isNull);
    });
  });

  group('files', () {
    const itemId = '3f2c9a71-e4b0-4856-8a00-000000000001';

    test('a pre-signed address is never used: the bytes go to the server's own route, with the token', () async {
      final seen = <http.Request>[];
      final api = _api((_) async => _json({}), seen: seen);
      final start = const KmFileStart(
        fileId: 'f1',
        size: 4,
        maxSize: 100,
        uploadUrl: 'https://bucket.example.net/put?sig=x',
        presigned: true,
      );

      await api.uploadFile(_server, 'token', itemId, start, Uint8List.fromList([75, 77, 65, 49]));

      expect(seen, hasLength(1), reason: 'one request, and no finish call');
      expect(seen.single.method, 'PUT');
      expect(seen.single.url.host, _server.host);
      expect(seen.single.url.path, endsWith('/items/$itemId/files/f1'));
      expect(seen.single.headers['Authorization'], 'DPoP token');
      expect(seen.single.bodyBytes, [75, 77, 65, 49]);
    });

    test('an upload address on another host is ignored too: nothing is sent there', () async {
      final seen = <http.Request>[];
      final api = _api((_) async => _json({}), seen: seen);
      final start = const KmFileStart(fileId: 'f1', size: 4, maxSize: 100, uploadUrl: 'https://evil.example.com/steal', presigned: false);

      await api.uploadFile(_server, 't', itemId, start, Uint8List(4));

      expect(seen.map((r) => r.url.host).toSet(), {_server.host});
    });
  });

  group('what the server says is wrong', () {
    test('a stale write names its item and the revision the server holds', () async {
      final api = _api((_) async => _problem(409, 'stale-revision', {'itemId': 'i', 'currentRevision': 7}));

      await expectLater(
        api.sync(_server, 't'),
        throwsA(
          isA<KmError>()
              .having((e) => e.problem, 'problem', KmProblem.stale)
              .having((e) => e.currentRevision, 'revision', 7)
              .having((e) => e.itemId, 'item', 'i'),
        ),
      );
    });

    test('a session that ended says why', () async {
      final api = _api((_) async => _problem(401, 'session-ended', {'reason': 'refresh-reuse'}));

      await expectLater(
        api.refresh(_server, 'r'),
        throwsA(
          isA<KmError>().having((e) => e.problem, 'problem', KmProblem.sessionEnded).having((e) => e.reason, 'reason', 'refresh-reuse'),
        ),
      );
    });

    test('410 asks for a full sync, 429 says how long to wait, 413 is too large', () async {
      Future<KmError> failure(http.Response answer) async {
        try {
          await _api((_) async => answer).sync(_server, 't');
        } on KmError catch (e) {
          return e;
        }
        fail('expected an error');
      }

      expect((await failure(_problem(410, 'full-sync-required'))).problem, KmProblem.fullSync);
      final limited = await failure(_problem(429, 'rate-limited', {'retryAfter': 12}));
      expect(limited.problem, KmProblem.rateLimited);
      expect(limited.retryAfter, 12);
      expect((await failure(_problem(413, 'payload-too-large'))).problem, KmProblem.tooLarge);
    });
  });

  group('the connection', () {
    KmSession session({int expires = 0}) => KmSession(
      userId: 'u',
      deviceId: 'd',
      tokens: KmTokens(access: 'a1', refresh: 'r1', accessExpiresAt: expires, refreshExpiresAt: 1 << 50),
    );

    Map<String, Object?> tokens(int n) => {'accessToken': 'a$n', 'expiresIn': 300, 'refreshToken': 'r$n', 'refreshExpiresIn': 3000};

    test('renews an access token that has ended, keeps the new session before using it, and uses each refresh token once', () async {
      final saved = <KmSession>[];
      final refreshed = <String>[];
      final api = _api((request) async {
        if (request.url.path.endsWith('/auth/token')) {
          refreshed.add((jsonDecode(request.body) as Map)['refreshToken']! as String);
          return _json(tokens(2));
        }
        return _json({'items': [], 'cursor': 'c', 'more': false});
      });
      final connection = KmConnection(api: api, server: _server, session: session(), save: (s) async => saved.add(s));

      // Two callers at once: one renewal
      await Future.wait([connection.call((token) => api.sync(_server, token)), connection.call((token) => api.sync(_server, token))]);

      expect(refreshed, ['r1']);
      expect(saved.single.tokens.refresh, 'r2');
      expect(connection.session.tokens.access, 'a2');
    });

    test('renews once when the server refuses the token, then tries again', () async {
      var calls = 0;
      final api = _api((request) async {
        if (request.url.path.endsWith('/auth/token')) return _json(tokens(2));
        calls++;
        return calls == 1 ? _problem(401, 'unauthorized') : _json({'items': [], 'cursor': 'c', 'more': false});
      });
      final connection = KmConnection(
        api: api,
        server: _server,
        session: session(expires: DateTime.now().millisecondsSinceEpoch + 3600000),
        save: (_) async {},
      );

      final page = await connection.call((token) => api.sync(_server, token));

      expect(page, isNotNull);
      expect(calls, 2);
    });

    test('a refresh token the server refuses is a session that ended', () async {
      final api = _api((_) async => _problem(401, 'unauthorized'));
      final connection = KmConnection(api: api, server: _server, session: session(), save: (_) async {});

      await expectLater(
        connection.call((token) => api.sync(_server, token)),
        throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.sessionEnded)),
      );
    });

    test('a session the server ended by reuse says so', () async {
      final api = _api((_) async => _problem(401, 'session-ended', {'reason': 'refresh-reuse'}));
      final connection = KmConnection(api: api, server: _server, session: session(), save: (_) async {});

      await expectLater(
        connection.call((token) => api.sync(_server, token)),
        throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'refresh-reuse')),
      );
    });
  });
}
