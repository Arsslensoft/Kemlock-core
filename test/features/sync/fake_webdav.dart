import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

/// A file in the fake folder, and the ETag of its version.
typedef FakeFile = ({String text, String etag});

/// An in-memory WebDAV folder behind a [MockClient], ported from
/// `src/test/fakeWebDav.ts`: GET and PUT with ETags, If-Match and
/// If-None-Match, and Basic auth for one user; and, for attached files,
/// binary files, DELETE, and PROPFIND of depth 1 on a folder.
///
/// Give [client] to the code under test, e.g. `WebDav(server.client)`. ETags
/// count up from `"v1"` across the whole folder.
class FakeWebDav {
  FakeWebDav({String username = 'me', String password = 'app-pw'}) : _auth = 'Basic ${base64Encode(utf8.encode('$username:$password'))}';

  final String _auth;
  int _version = 0;
  void Function()? _before;

  /// The files by URL path, e.g. `/files/me/Kemlock/backmycodes-sync.json`.
  final files = <String, FakeFile>{};

  /// Binary files, as attached files are written, by URL path.
  final blobs = <String, Uint8List>{};

  /// Every request the client sent, in order.
  final requests = <http.Request>[];

  /// Answers requests instead of the folder while set, e.g. to fail them
  /// all, or to act between another device's read and write. It can call
  /// [handle] for the folder's own answer, and clear itself to answer once.
  Future<http.Response> Function(http.Request request)? respond;

  /// The client that talks to this folder.
  late final http.Client client = MockClient((request) async {
    requests.add(request);
    final hook = _before;
    _before = null;
    hook?.call();
    final answer = respond;
    return answer != null ? answer(request) : handle(request);
  });

  /// Replaces a file as if another device wrote it.
  void put(String path, String text) => files[path] = (text: text, etag: '"v${++_version}"');

  /// Runs [fn] once before the next request is answered, e.g. to simulate another device writing.
  void beforeNextRequest(void Function() fn) => _before = fn;

  /// How the folder answers [request].
  Future<http.Response> handle(http.Request request) async {
    if (request.headers['Authorization'] != _auth) return http.Response('', 401);
    final path = request.url.path;
    final file = files[path];
    final blob = blobs[path];
    switch (request.method) {
      case 'GET':
        if (blob != null) return http.Response.bytes(blob, 200);
        if (file == null) return http.Response('', 404);
        return http.Response.bytes(utf8.encode(file.text), 200, headers: {'ETag': file.etag});
      case 'DELETE':
        final gone = files.remove(path) != null || blobs.remove(path) != null;
        return http.Response('', gone ? 204 : 404);
      case 'PROPFIND':
        return _list(path);
      case 'PUT':
        if (request.headers['If-None-Match'] == '*' && (file != null || blob != null)) return http.Response('', 412);
        if (request.headers['Content-Type'] == 'application/octet-stream') {
          blobs[path] = Uint8List.fromList(request.bodyBytes);
          return http.Response('', 201);
        }
        final ifMatch = request.headers['If-Match'];
        if (ifMatch != null && ifMatch.isNotEmpty && ifMatch != file?.etag) return http.Response('', 412);
        final etag = '"v${++_version}"';
        files[path] = (text: utf8.decode(request.bodyBytes), etag: etag);
        return http.Response('', file != null ? 204 : 201, headers: {'ETag': etag});
    }
    return http.Response('', 405);
  }

  /// A 207 multistatus of the folder at [path] and the files directly in it,
  /// with prefixes as Nextcloud writes them.
  http.Response _list(String path) {
    final folder = path.endsWith('/') ? path : '$path/';
    final children = <String, int>{
      for (final MapEntry(key: name, value: file) in files.entries) name: utf8.encode(file.text).length,
      for (final MapEntry(key: name, value: bytes) in blobs.entries) name: bytes.length,
    }..removeWhere((name, _) => !name.startsWith(folder) || name.substring(folder.length).contains('/'));
    final body = StringBuffer('<?xml version="1.0"?><d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">')
      ..write(
        '<d:response><d:href>$folder</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>',
      );
    for (final MapEntry(key: name, value: size) in children.entries) {
      body.write(
        '<d:response><d:href>${Uri.encodeFull(name)}</d:href><d:propstat><d:prop><d:resourcetype/><d:getcontentlength>$size</d:getcontentlength></d:prop>'
        '<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>',
      );
    }
    body.write('</d:multistatus>');
    return http.Response(body.toString(), 207, headers: {'Content-Type': 'application/xml; charset=utf-8'});
  }
}
