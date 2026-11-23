@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/webdav.dart';
import 'package:test/test.dart';

import 'fake_webdav.dart';

const dav = DavAccount(url: 'https://dav.example.com/files/me/Kemlock/', username: 'me', password: 'app-pw');
const folder = '/files/me/Kemlock/';

void main() {
  late FakeWebDav server;
  late WebDav webDav;
  final bytes = Uint8List.fromList([0, 1, 2, 250, 255, ...utf8.encode('KMA1')]);

  setUp(() {
    server = FakeWebDav();
    webDav = WebDav(server.client);
  });

  test('writes a binary file once, and reads it back byte for byte', () async {
    expect(await webDav.writeBytesIfAbsent(dav, 'backmycodes-file-abc', bytes), isTrue);

    final put = server.requests.single;
    expect((put.method, put.headers['If-None-Match'], put.headers['Content-Type']), ('PUT', '*', 'application/octet-stream'));
    expect(await webDav.readBytes(dav, 'backmycodes-file-abc', maxBytes: 1024), bytes);
  });

  test('leaves a file that exists as it is: the 412 is no error', () async {
    await webDav.writeBytesIfAbsent(dav, 'backmycodes-file-abc', bytes);

    expect(await webDav.writeBytesIfAbsent(dav, 'backmycodes-file-abc', Uint8List.fromList([9, 9])), isFalse);
    expect(await webDav.readBytes(dav, 'backmycodes-file-abc', maxBytes: 1024), bytes);
  });

  test('reads a file the folder lacks as null', () async {
    expect(await webDav.readBytes(dav, 'backmycodes-file-none', maxBytes: 1024), isNull);
  });

  test('deletes a file, and counts one already gone as deleted', () async {
    await webDav.writeBytesIfAbsent(dav, 'backmycodes-file-abc', bytes);

    await webDav.deleteFile(dav, 'backmycodes-file-abc');
    await webDav.deleteFile(dav, 'backmycodes-file-abc');

    expect(await webDav.readBytes(dav, 'backmycodes-file-abc', maxBytes: 1024), isNull);
    expect(server.requests.where((r) => r.method == 'DELETE'), hasLength(2));
  });

  test('lists the files in the folder with their sizes, whatever else is there', () async {
    server.put('${folder}backmycodes-sync.json', '{"v":1}');
    server.put('${folder}holiday photo.jpg', 'not ours');
    server.put('/files/me/Elsewhere/backmycodes-file-x', 'another folder');
    server.put('${folder}inner/backmycodes-file-y', 'a folder inside');
    await webDav.writeBytesIfAbsent(dav, 'backmycodes-file-abc', bytes);

    final entries = await webDav.listFolder(dav);

    expect(
      {for (final entry in entries) entry.name: entry.size},
      {'backmycodes-sync.json': 7, 'holiday photo.jpg': 8, 'backmycodes-file-abc': bytes.length},
    );
    final propfind = server.requests.last;
    expect((propfind.method, propfind.headers['Depth'], propfind.url.path), ('PROPFIND', '1', folder));
  });

  test('reads a listing with other namespace prefixes and absolute hrefs', () async {
    final client = MockClient(
      (request) async => http.Response(
        '<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">'
        '<D:response><D:href>https://dav.example.com/files/me/Kemlock/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>'
        '<D:response><D:href>https://dav.example.com/files/me/Kemlock/backmycodes-file-a%2Db</D:href><D:propstat><D:prop><D:resourcetype/></D:prop></D:propstat></D:response>'
        '<D:response><D:href>/files/me/Kemlock/sub/</D:href><D:propstat><D:prop><D:resourcetype><D:collection/></D:resourcetype></D:prop></D:propstat></D:response>'
        '</D:multistatus>',
        207,
      ),
    );

    final entries = await WebDav(client).listFolder(dav);

    expect(entries, [(name: 'backmycodes-file-a-b', size: null)]);
  });

  test('names the problem with the folder or the login', () async {
    for (final (status, problem) in [(401, DavProblem.auth), (404, DavProblem.folder), (500, DavProblem.server)]) {
      final client = MockClient((request) async => http.Response('', status));
      await expectLater(
        WebDav(client).listFolder(dav),
        throwsA(isA<DavError>().having((e) => e.problem, 'problem', problem)),
        reason: '$status',
      );
      if (status != 404) {
        await expectLater(
          WebDav(client).writeBytesIfAbsent(dav, 'f', bytes),
          throwsA(isA<DavError>().having((e) => e.problem, 'problem', problem)),
        );
      }
    }
    final garbage = MockClient((request) async => http.Response('<not xml', 207));
    await expectLater(WebDav(garbage).listFolder(dav), throwsA(isA<DavError>()));
  });
}
