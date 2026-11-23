@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/webdav.dart';
import 'package:test/test.dart';

import 'fake_webdav.dart';

const account = DavAccount(url: 'https://dav.example.com/files/me/Kemlock', username: 'me', password: 'app-pw');

/// The problem [future] fails with, or what else happened.
Future<Object> problem(Future<Object?> future) async {
  try {
    await future;
  } on DavError catch (e) {
    return e.problem;
  } catch (e) {
    return '$e';
  }
  return 'no error';
}

Matcher davError(DavProblem problem, [int status = 0]) =>
    isA<DavError>().having((e) => e.problem, 'problem', problem).having((e) => e.status, 'status', status);

void main() {
  group('fileUrl', () {
    test('puts the file inside the folder, with or without a trailing slash', () {
      expect(fileUrl(account, 'backmycodes-sync.json').toString(), 'https://dav.example.com/files/me/Kemlock/backmycodes-sync.json');
      expect(
        fileUrl(account.copyWith(url: '${account.url}/'), 'a b.json').toString(),
        'https://dav.example.com/files/me/Kemlock/a%20b.json',
      );
    });

    test('takes a folder at the root of the server, with spaces around it', () {
      expect(fileUrl(account.copyWith(url: '  https://dav.example.com  '), 'f.json').toString(), 'https://dav.example.com/f.json');
    });

    test('refuses plain http, which would send the password in the clear', () {
      expect(() => fileUrl(account.copyWith(url: 'http://nas.local/dav/'), 'x'), throwsA(davError(DavProblem.insecure)));
      expect(() => fileUrl(account.copyWith(url: 'not a url'), 'x'), throwsA(davError(DavProblem.folder)));
    });
  });

  group('reading and writing', () {
    test('reports a missing file as null and creates it only if it is still missing', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);

      expect(await dav.readFile(account, 'f.json'), isNull);
      await dav.writeFile(account, 'f.json', '{"a":1}', mustNotExist: true);
      expect(server.requests.last.headers['If-None-Match'], '*');

      expect(await dav.readFile(account, 'f.json'), (text: '{"a":1}', etag: '"v1"'));
      // A second "create" means another device got there first
      expect(await problem(dav.writeFile(account, 'f.json', '{}', mustNotExist: true)), DavProblem.conflict);
    });

    test('overwrites only the version it read', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);
      await dav.writeFile(account, 'f.json', 'one', mustNotExist: true);
      final etag = (await dav.readFile(account, 'f.json'))!.etag;

      server.put('/files/me/Kemlock/f.json', 'someone else');

      expect(await problem(dav.writeFile(account, 'f.json', 'two', etag: etag)), DavProblem.conflict);
      expect(server.files['/files/me/Kemlock/f.json']?.text, 'someone else');
    });

    test('sends Basic auth and reports a rejected password', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);

      expect(await problem(dav.readFile(account.copyWith(password: 'wrong'), 'f.json')), DavProblem.auth);
      expect(server.requests.single.headers['Authorization'], 'Basic ${base64Encode(utf8.encode('me:wrong'))}');
    });

    test('writes the JSON as UTF-8 over the version it read', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);
      await dav.writeFile(account, 'f.json', '{"note":"one"}', mustNotExist: true);
      final etag = (await dav.readFile(account, 'f.json'))!.etag;

      await dav.writeFile(account, 'f.json', '{"note":"café ✓"}', etag: etag);

      final put = server.requests.last;
      expect(put.method, 'PUT');
      expect(put.headers['Content-Type'], 'application/json');
      expect(put.headers['If-Match'], '"v1"');
      expect(put.headers.containsKey('If-None-Match'), isFalse);
      expect(await dav.readFile(account, 'f.json'), (text: '{"note":"café ✓"}', etag: '"v2"'));
    });

    test('writes over any version when there is no ETag to check against', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);
      server.put('/files/me/Kemlock/f.json', 'old');

      await dav.writeFile(account, 'f.json', 'new');

      expect(server.requests.single.headers.containsKey('If-Match'), isFalse);
      expect(server.requests.single.headers.containsKey('If-None-Match'), isFalse);
      expect(server.files['/files/me/Kemlock/f.json']?.text, 'new');
    });

    for (final (status, expected) in [(409, DavProblem.folder), (500, DavProblem.server)]) {
      test('maps HTTP $status to ${expected.name}', () async {
        final dav = WebDav(MockClient((_) async => http.Response('', status)));

        await expectLater(dav.writeFile(account, 'f.json', 'x'), throwsA(davError(expected, status)));
      });
    }

    test('follows no redirect, to another host or the same, and reports it as the server’s error', () async {
      final server = FakeWebDav();
      final dav = WebDav(server.client);
      await dav.writeFile(account, 'f.json', '{}', mustNotExist: true);
      await dav.readFile(account, 'f.json');
      await dav.writeBytesIfAbsent(account, 'backmycodes-file-a', Uint8List(1));
      await dav.readBytes(account, 'backmycodes-file-a', maxBytes: 1);
      await dav.listFolder(account);
      await dav.deleteFile(account, 'backmycodes-file-a');
      expect([for (final request in server.requests) request.followRedirects], everyElement(isFalse));
      expect(server.requests, hasLength(6));

      final moved = WebDav(MockClient((_) async => http.Response('', 302, headers: {'location': 'http://elsewhere.example/old-file'})));
      await expectLater(moved.readFile(account, 'f.json'), throwsA(davError(DavProblem.server, 302)));
    });

    test('reports an unreachable server', () async {
      final dav = WebDav(MockClient((_) async => throw http.ClientException('Failed to fetch')));

      expect(await problem(dav.readFile(account, 'f.json')), DavProblem.network);
    });

    test('gives up on a server that does not answer', () async {
      final dav = WebDav(MockClient((_) => Completer<http.Response>().future), timeout: const Duration(milliseconds: 10));

      expect(await problem(dav.readFile(account, 'f.json')), DavProblem.network);
    });

    test('stops reading an answer that never ends at the sync file limit', () async {
      final chunk = Uint8List(1 << 20);
      var sent = 0;
      Stream<List<int>> endless() async* {
        while (true) {
          sent += chunk.length;
          yield chunk;
        }
      }

      final dav = WebDav(MockClient.streaming((request, _) async => http.StreamedResponse(endless(), 200)));

      await expectLater(dav.readFile(account, 'f.json'), throwsA(davError(DavProblem.server)));
      expect(sent, lessThanOrEqualTo(maxSyncFileBytes + 2 * chunk.length));
    });

    test('refuses an answer its length says is too long, and a file past the limit it is given', () async {
      final long = WebDav(
        MockClient.streaming(
          (request, _) async => http.StreamedResponse(Stream.value(utf8.encode('{}')), 200, contentLength: maxSyncFileBytes + 1),
        ),
      );
      await expectLater(long.readFile(account, 'f.json'), throwsA(davError(DavProblem.server)));

      final server = FakeWebDav()..put('/files/me/Kemlock/backmycodes-file-a', '123456789');
      final dav = WebDav(server.client);
      await expectLater(dav.readBytes(account, 'backmycodes-file-a', maxBytes: 8), throwsA(davError(DavProblem.server)));
      expect(utf8.decode((await dav.readBytes(account, 'backmycodes-file-a', maxBytes: 9))!), '123456789');
    });

    test('reads the body as text and the ETag header in any case, through the client it is given', () async {
      final sent = <http.Request>[];
      final dav = WebDav(
        MockClient((request) async {
          sent.add(request);
          return http.Response('body', 200, headers: {'etag': '"n1"'});
        }),
      );

      expect(await dav.readFile(account, 'f.json'), (text: 'body', etag: '"n1"'));
      expect(sent.single.method, 'GET');
      expect(sent.single.url.toString(), 'https://dav.example.com/files/me/Kemlock/f.json');
    });
  });
}
