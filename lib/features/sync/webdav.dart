/// Just enough WebDAV for sync, ported from `webdav.ts`: read one file and
/// write it back, with ETags so two devices writing at once can't overwrite
/// each other unseen. The sync file needs only GET and PUT, which every
/// WebDAV server (Nextcloud, ownCloud, Synology, Koofr, …) supports; files
/// attached to notes also use DELETE, and PROPFIND to list the folder.
///
/// The app calls the server directly with `package:http`, so CORS doesn't
/// apply, as with Capacitor's native HTTP before.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:xml/xml.dart';

import '../../core/network/answers.dart';
import '../../models/json.dart';

/// A WebDAV folder and the login for it, as the sync settings store it.
/// Keys it doesn't know are kept in [extra] and written back.
class DavAccount {
  const DavAccount({required this.url, required this.username, required this.password, this.extra = const {}});

  factory DavAccount.fromJson(Map<String, Object?> json) => DavAccount(
    url: asString(json['url']),
    username: asString(json['username']),
    password: asString(json['password']),
    extra: extraKeys(json, const {'url', 'username', 'password'}),
  );

  /// The folder the files live in, e.g. https://cloud.example.com/remote.php/dav/files/me/Kemlock/
  final String url;
  final String username;
  final String password;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'url': url, 'username': username, 'password': password, ...extra};

  DavAccount copyWith({String? url, String? username, String? password}) =>
      DavAccount(url: url ?? this.url, username: username ?? this.username, password: password ?? this.password, extra: extra);

  @override
  bool operator ==(Object other) => other is DavAccount && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(url, username);

  /// Leaves the password out, so it never ends up in a log.
  @override
  String toString() => 'DavAccount($url, $username)';
}

/// What went wrong talking to the server. The names are the ends of the
/// `sync.problem.*` message ids.
enum DavProblem {
  /// The folder isn't https, which would send the password in the clear.
  insecure,

  /// The server refused the username or password (401, 403).
  auth,

  /// The folder isn't a URL, or isn't on the server (404, 409).
  folder,

  /// The file changed since it was read (412): read, merge and write again.
  conflict,

  /// The server couldn't be reached.
  network,

  /// Any other answer.
  server,
}

/// A failed WebDAV request.
class DavError implements Exception {
  const DavError(this.problem, [this.status = 0]);

  final DavProblem problem;

  /// The HTTP status, or 0 when there was no answer.
  final int status;

  @override
  String toString() => 'WebDAV ${problem.name}${status != 0 ? ' ($status)' : ''}';
}

/// A file read from the folder, and its ETag when the server gave one.
typedef DavFile = ({String text, String? etag});

/// A file the folder holds, as listing it finds it: its name, and its size
/// when the server says.
typedef DavEntry = ({String name, int? size});

/// The URL of [name] inside the account's folder. Throws a [DavError]: plain
/// http is `insecure`, and an address that isn't a URL is `folder`.
Uri fileUrl(DavAccount account, String name) {
  final folder = Uri.tryParse(account.url.trim());
  if (folder == null || !folder.hasScheme) throw const DavError(DavProblem.folder);
  if (folder.scheme != 'https') throw const DavError(DavProblem.insecure);
  if (folder.host.isEmpty) throw const DavError(DavProblem.folder);
  final inside = folder.path.endsWith('/') ? folder : folder.replace(path: '${folder.path}/');
  return inside.resolve(Uri.encodeComponent(name));
}

/// The most of a sync file [WebDav.readFile] reads. It holds a scope's
/// entries as JSON, encrypted and in base64; the export of a whole vault
/// may be 64 MiB of JSON (`archiveJsonLimit`), which is 86 MiB so.
const maxSyncFileBytes = 96 * 1024 * 1024;

/// The most of a folder's listing [WebDav.listFolder] reads: a few hundred
/// bytes a file, so tens of thousands of files.
const maxListingBytes = 16 * 1024 * 1024;

/// The most of any other answer, whose body sync doesn't use.
const _otherAnswerBytes = 1024 * 1024;

/// Reads and writes files in WebDAV folders through [client], which tests
/// replace with a `MockClient`.
///
/// Every answer is read with a limit ([readAnswer]): one past it is a
/// `server` problem, since the server chose to send it.
class WebDav {
  WebDav(this.client, {this.timeout = const Duration(seconds: 60)});

  final http.Client client;

  /// How long a request may take before it counts as a `network` problem.
  final Duration timeout;

  /// The file and its ETag, or null when the folder doesn't have it yet.
  Future<DavFile?> readFile(DavAccount account, String name) async {
    final res = await _request('GET', fileUrl(account, name), {'Authorization': _basicAuth(account)}, maxBytes: maxSyncFileBytes);
    if (res.statusCode == 404) return null;
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res.statusCode);
    return (text: utf8.decode(res.bodyBytes, allowMalformed: true), etag: _header(res.headers, 'ETag'));
  }

  /// Writes the file. [etag] is the version this write replaces: the file
  /// must still be that version. With [mustNotExist], the file must not exist
  /// yet. With neither, as when the server gave no ETag to check against, the
  /// write replaces any version. A newer version on the server throws a
  /// `conflict` error, after which the caller reads and merges again.
  Future<void> writeFile(DavAccount account, String name, String text, {String? etag, bool mustNotExist = false}) async {
    assert(etag == null || !mustNotExist, 'A write replaces a version or expects none, not both');
    final headers = {'Authorization': _basicAuth(account), 'Content-Type': 'application/json'};
    if (etag != null) {
      headers['If-Match'] = etag;
    } else if (mustNotExist) {
      headers['If-None-Match'] = '*';
    }
    final res = await _request('PUT', fileUrl(account, name), headers, body: text);
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res.statusCode);
  }

  /// The file's bytes, or null when the folder doesn't have it. A file
  /// longer than [maxBytes] is a `server` problem.
  Future<Uint8List?> readBytes(DavAccount account, String name, {required int maxBytes}) async {
    final res = await _request('GET', fileUrl(account, name), {'Authorization': _basicAuth(account)}, maxBytes: maxBytes);
    if (res.statusCode == 404) return null;
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res.statusCode);
    return res.bodyBytes;
  }

  /// Writes [bytes] as the file unless the folder has it already, as files
  /// that are never changed are written. False when the file was there.
  Future<bool> writeBytesIfAbsent(DavAccount account, String name, Uint8List bytes) async {
    final res = await _request('PUT', fileUrl(account, name), {
      'Authorization': _basicAuth(account),
      'Content-Type': 'application/octet-stream',
      'If-None-Match': '*',
    }, body: bytes);
    if (res.statusCode == 412) return false;
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res.statusCode);
    return true;
  }

  /// Deletes the file; one the folder doesn't have counts as deleted.
  Future<void> deleteFile(DavAccount account, String name) async {
    final res = await _request('DELETE', fileUrl(account, name), {'Authorization': _basicAuth(account)});
    if (res.statusCode == 404) return;
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res.statusCode);
  }

  /// The files directly in the account's folder, with their sizes, by one
  /// PROPFIND of depth 1. Folders inside it, and the folder itself, are left out.
  Future<List<DavEntry>> listFolder(DavAccount account) async {
    final folder = fileUrl(account, '');
    final res = await _request(
      'PROPFIND',
      folder,
      {'Authorization': _basicAuth(account), 'Depth': '1', 'Content-Type': 'application/xml'},
      body: utf8.encode(
        '<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/><d:getcontentlength/></d:prop></d:propfind>',
      ),
      maxBytes: maxListingBytes,
    );
    if (res.statusCode != 207 && (res.statusCode < 200 || res.statusCode >= 300)) throw _failure(res.statusCode);
    final XmlDocument xml;
    try {
      xml = XmlDocument.parse(utf8.decode(res.bodyBytes, allowMalformed: true));
    } on XmlException {
      throw DavError(DavProblem.server, res.statusCode);
    }
    final entries = <DavEntry>[];
    for (final response in xml.findAllElements('response', namespaceUri: 'DAV:')) {
      final href = response.findElements('href', namespaceUri: 'DAV:').firstOrNull?.innerText.trim();
      if (href == null || href.isEmpty) continue;
      final collection = response.findAllElements('collection', namespaceUri: 'DAV:').isNotEmpty;
      final segments = (Uri.tryParse(href)?.pathSegments ?? const <String>[]).where((segment) => segment.isNotEmpty).toList();
      if (collection || segments.isEmpty) continue;
      final length = response.findAllElements('getcontentlength', namespaceUri: 'DAV:').firstOrNull?.innerText.trim();
      entries.add((name: segments.last, size: length == null ? null : int.tryParse(length)));
    }
    return entries;
  }

  Future<http.Response> _request(
    String method,
    Uri url,
    Map<String, String> headers, {
    Object? body,
    int maxBytes = _otherAnswerBytes,
  }) async {
    // A redirect is never followed: it would take the phone wherever the server said, another host
    // or plain http. WebDAV needs none, and one is answered as the server's error it is.
    final request = http.Request(method, url)
      ..followRedirects = false
      ..headers.addAll(headers);
    // As bytes, so the content type goes out as given, without a charset added.
    if (body is String) request.bodyBytes = utf8.encode(body);
    if (body is List<int>) request.bodyBytes = body;
    Future<http.Response> send() async => readAnswer(await client.send(request), maxBytes);
    try {
      return await send().timeout(timeout);
    } on AnswerTooLarge {
      throw const DavError(DavProblem.server);
    } catch (_) {
      throw const DavError(DavProblem.network);
    }
  }
}

String _basicAuth(DavAccount account) => 'Basic ${base64Encode(utf8.encode('${account.username}:${account.password}'))}';

/// A response header, whatever the case of its name.
String? _header(Map<String, String> headers, String name) {
  final wanted = name.toLowerCase();
  for (final MapEntry(:key, :value) in headers.entries) {
    if (key.toLowerCase() == wanted) return value;
  }
  return null;
}

DavError _failure(int status) => switch (status) {
  401 || 403 => DavError(DavProblem.auth, status),
  404 || 409 => DavError(DavProblem.folder, status),
  412 => DavError(DavProblem.conflict, status),
  _ => DavError(DavProblem.server, status),
};
