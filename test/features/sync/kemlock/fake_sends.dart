// The Send routes of the fake Kemlock server, with the rules of the server's code
// (`crates/kemlock-api-kem/src/routes/sends.rs`, `kemlock-app/src/sends`): the owner's routes behind the server's
// token check, the public routes with none, a Send's open count (a text on access, a file on download), the password
// check with 10 wrong tries a minute, the plain 404 for anything closed, the upload's length and `KMA1` check, and the
// policy refusals. Every request to a Send route is logged.
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/encoding.dart';

import 'fake_kemlock_server.dart';

/// One Send as the fake server holds it.
class FakeSend {
  FakeSend({
    required this.id,
    required this.kind,
    required this.meta,
    required this.sealedKey,
    required this.payload,
    required this.deletionAt,
    required this.createdAt,
    this.fileSize,
    this.maxAccess,
    this.hideEmail = false,
    this.disabled = false,
    this.expiresAt,
    this.proof,
  });

  final String id;
  final String kind;
  Uint8List meta;
  final Uint8List sealedKey;
  Uint8List payload;
  final int? fileSize;
  Uint8List? fileBytes;
  int? maxAccess;
  int accessCount = 0;
  bool hideEmail;
  bool disabled;
  int? expiresAt;
  int deletionAt;
  final int createdAt;
  int revisedAt = 0;

  /// The password proof the Send was made or changed with, or null.
  Uint8List? proof;

  bool get ready => fileSize == null || fileBytes != null;

  String get accessId => b64urlEncode(uuidBytes(id));
}

/// The Send routes of a [FakeKemlockServer].
class FakeSends {
  FakeSends(this.server);

  final FakeKemlockServer server;

  /// The Sends by id, in the order they were made.
  final sends = <String, FakeSend>{};

  /// The time the fake reads, Unix seconds.
  DateTime Function() clock = DateTime.now;

  /// The Send routes' requests, in order: the owner's and the public ones.
  final requests = <http.Request>[];

  /// A policy of "Remove Send": making a Send is refused with this text.
  String? policyRemoveSend;

  /// A policy of "Always show the sender's email": hiding it is refused with this text.
  String? policyShowEmail;

  /// The largest file a Send may hold, in bytes (`max_file_size`).
  int maxFileSize = 100 * 1024 * 1024;

  /// The next uploads that fail with a 500, as many as this.
  int failUploads = 0;

  /// The email a recipient is told, unless the Send hides it.
  String senderEmail = 'ann@example.com';

  final _tries = <String, _Tries>{};

  int get _now => clock().millisecondsSinceEpoch ~/ 1000;

  /// Whether any request to a Send route held [secret]: its bytes, or its base64url, base64 or hex text, in the URL,
  /// the headers or the body. The link key and a password must never be found.
  bool requestsHold(List<int> secret) {
    final needles = <List<int>>[secret, utf8.encode(b64urlEncode(secret)), utf8.encode(base64.encode(secret)), utf8.encode(_hex(secret))];
    for (final request in requests) {
      final haystack = <int>[...utf8.encode(request.url.toString()), ...utf8.encode(request.headers.toString()), ...request.bodyBytes];
      for (final needle in needles) {
        if (_find(haystack, needle)) return true;
      }
    }
    return false;
  }

  /// Whether any request to a Send route held the text [secret].
  bool requestsHoldText(String secret) => requestsHold(utf8.encode(secret));

  /// The owner's routes: [route] is under `/kem/v1`. Null when it isn't a Send route.
  http.Response? owner(http.Request request, String route) {
    final match = RegExp(r'^/sends(?:/([^/]+)(/file)?)?$').firstMatch(route);
    if (match == null) return null;
    requests.add(request);
    final id = match[1];
    final file = match[2] != null;
    final method = request.method;
    if (id == null) {
      if (method == 'POST') return _create(request);
      if (method == 'GET') return server.answer([for (final send in sends.values.toList().reversed) _dto(send)]);
      return server.problem(405, 'method-not-allowed');
    }
    final send = sends[id];
    if (file) {
      if (method != 'PUT') return server.problem(405, 'method-not-allowed');
      return send == null ? server.problem(404, 'not-found') : _upload(request, send);
    }
    if (send == null) return server.problem(404, 'not-found');
    switch (method) {
      case 'GET':
        return server.answer(_dto(send));
      case 'PUT':
        return _update(request, send);
      case 'DELETE':
        sends.remove(id);
        return http.Response('', 204);
    }
    return server.problem(405, 'method-not-allowed');
  }

  /// The public routes: [route] is under `/kem/v1`, and no token is checked. Null when it isn't one.
  http.Response? public(http.Request request, String route) {
    final match = RegExp(r'^/send-access/([^/]+)(/file)?$').firstMatch(route);
    if (match == null || request.method != 'POST') return null;
    requests.add(request);
    final access = match[1]!;
    final download = match[2] != null;
    // The server reads the body first, then counts a try that carries a proof, then looks the Send up
    Uint8List? proof;
    if (request.bodyBytes.any((b) => b > 32)) {
      try {
        final body = jsonDecode(utf8.decode(request.bodyBytes));
        if (body is! Map<String, Object?> || body.keys.any((key) => key != 'password')) {
          throw const FormatException('not a request');
        }
        final password = body['password'];
        if (password != null) proof = b64urlDecode(password as String);
      } on Object {
        return server.problem(400, 'invalid-request', extra: {'detail': "the body isn't the JSON expected"});
      }
    }
    final now = _now;
    if (proof != null) {
      // The server counts every try with a proof, even for a Send that isn't there, and clears the count on a right one
      final wait = _count(access, now);
      if (wait != null) {
        return server.problem(429, 'rate-limited', extra: {'retryAfter': wait}, headers: {'retry-after': '$wait'});
      }
    }
    final found = sends.values.where((send) => send.accessId == access);
    if (found.isEmpty) return server.problem(404, 'not-found');
    final send = found.first;
    final expired = send.expiresAt != null && send.expiresAt! <= now;
    final usedUp = send.maxAccess != null && send.accessCount >= send.maxAccess!;
    if (send.disabled || expired || send.deletionAt <= now || usedUp || !send.ready || (download && send.fileSize == null)) {
      return server.problem(404, 'not-found');
    }
    if (send.proof != null) {
      if (proof == null) {
        return server.problem(401, 'send-password-required', headers: {'www-authenticate': 'KemlockSend'});
      }
      if (!_same(proof, send.proof!)) {
        return server.problem(401, 'send-wrong-password', headers: {'www-authenticate': 'KemlockSend'});
      }
    }
    if (proof != null) _tries.remove(access);
    if (download) {
      send.accessCount++;
      return http.Response.bytes(
        send.fileBytes!,
        200,
        headers: {'content-type': 'application/octet-stream', 'cache-control': 'private, no-store'},
      );
    }
    if (send.kind == 'text') send.accessCount++;
    return http.Response(
      jsonEncode({
        'id': send.accessId,
        'kind': send.kind,
        'payload': b64urlEncode(send.payload),
        'fileSize': send.fileSize,
        'expiresAt': send.expiresAt,
        'deletionAt': send.deletionAt,
        'senderEmail': send.hideEmail ? null : senderEmail,
      }),
      200,
      headers: {'content-type': 'application/json', 'cache-control': 'private, no-store'},
    );
  }

  /// Counts one try with a proof against [access] at [now], as the server's `Limiter` does: 10 in a minute, then every
  /// further try is refused and the Send waits 1 second, then 2, 4 and so on up to an hour. Null when the try is allowed,
  /// else the seconds to wait. A quiet minute earns one level of forgiveness back.
  int? _count(String access, int now) {
    final tries = _tries.putIfAbsent(access, () => _Tries(now));
    if (now < tries.blockedUntil) return tries.blockedUntil - now;
    if (now - tries.windowStart >= 60) {
      if (!tries.raised && tries.level > 0) tries.level--;
      tries
        ..windowStart = now
        ..count = 0
        ..raised = false;
    }
    tries.count++;
    if (tries.count <= 10) return null;
    tries
      ..level += 1
      ..raised = true;
    final wait = math.min(1 << math.min(tries.level - 1, 20), 3600);
    tries.blockedUntil = now + wait;
    return wait;
  }

  /// A Send the Bitwarden API made, as the server lists it from the same table: its `sealedKey` is the UTF-8 of the
  /// client's encrypted key string, never the 64 bytes of a Kemlock Send, and its meta and payload are that client's own
  /// encrypted strings, which no Kemlock key opens.
  FakeSend addBitwardenSend(String id, {String kind = 'text', int? maxAccess, int accessCount = 0, bool disabled = false}) {
    final send =
        FakeSend(
            id: id,
            kind: kind,
            meta: Uint8List.fromList(utf8.encode('{"name":"2.${'D' * 22}==|${'E' * 22}==|${'F' * 43}=","notes":null}')),
            sealedKey: Uint8List.fromList(utf8.encode('2.${'A' * 22}==|${'B' * 43}=|${'C' * 43}=')),
            payload: Uint8List.fromList(utf8.encode('{"text":"2.${'G' * 22}==|${'H' * 22}==|${'I' * 43}=","hidden":false}')),
            deletionAt: _now + 7 * 86400,
            createdAt: _now,
            fileSize: kind == 'file' ? 100 : null,
            maxAccess: maxAccess,
            disabled: disabled,
          )
          ..accessCount = accessCount
          ..revisedAt = _now;
    if (kind == 'file') send.fileBytes = Uint8List(100);
    sends[id] = send;
    return send;
  }

  Map<String, Object?> _dto(FakeSend send, {String? uploadUrl}) => {
    'id': send.id,
    'accessId': send.accessId,
    'kind': send.kind,
    'meta': b64urlEncode(send.meta),
    'sealedKey': b64urlEncode(send.sealedKey),
    'payload': b64urlEncode(send.payload),
    'file': send.fileSize == null ? null : {'size': send.fileSize, 'ready': send.ready},
    'hasPassword': send.proof != null,
    'maxAccess': send.maxAccess,
    'accessCount': send.accessCount,
    'hideEmail': send.hideEmail,
    'disabled': send.disabled,
    'expiresAt': send.expiresAt,
    'deletionAt': send.deletionAt,
    'createdAt': send.createdAt,
    'revisedAt': send.revisedAt,
    'uploadUrl': ?uploadUrl,
  };

  http.Response? _options(Map<String, Object?> body, {required int now}) {
    final deletion = body['deletionAt'];
    final expires = body['expiresAt'];
    final max = body['maxAccess'];
    if (deletion is! int || deletion <= now || deletion > now + 30 * 86400 + 3600) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'deletionAt must be in the future and at most 30 days away'});
    }
    if (expires != null && (expires is! int || expires > deletion)) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'expiresAt may not come after deletionAt'});
    }
    if (max != null && (max is! int || max < 1)) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'maxAccess is at least 1'});
    }
    return null;
  }

  Uint8List? _sealed(Object? value, {int? exactly, int least = 28}) {
    if (value is! String) return null;
    final Uint8List bytes;
    try {
      bytes = b64urlDecode(value);
    } on MalformedException {
      return null;
    }
    if (exactly != null ? bytes.length != exactly : bytes.length < least) return null;
    return bytes;
  }

  http.Response _create(http.Request request) {
    final body = jsonDecode(utf8.decode(request.bodyBytes));
    if (body is! Map<String, Object?>) return server.problem(400, 'invalid-request');
    const known = {
      'id',
      'kind',
      'meta',
      'sealedKey',
      'payload',
      'file',
      'maxAccess',
      'hideEmail',
      'disabled',
      'expiresAt',
      'deletionAt',
      'password',
    };
    if (body.keys.any((key) => !known.contains(key))) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'unknown field'});
    }
    final id = body['id'];
    if (id is! String || !RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$').hasMatch(id)) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'the Send id must be a version 4 UUID'});
    }
    final kind = body['kind'];
    if (kind != 'text' && kind != 'file') {
      return server.problem(400, 'invalid-request', extra: {'detail': 'the kind must be text or file'});
    }
    final meta = _sealed(body['meta']);
    final sealedKey = _sealed(body['sealedKey'], exactly: 64);
    final payload = _sealed(body['payload']);
    if (meta == null || sealedKey == null || payload == null) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'a sealed value'});
    }
    if (meta.length > 16 * 1024 || payload.length > 256 * 1024) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'too long'});
    }
    final password = body['password'];
    final proof = password == null ? null : _sealed(password, exactly: 32);
    if (password != null && proof == null) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'password is a 32-byte proof'});
    }
    final file = body['file'];
    int? fileSize;
    if (kind == 'file') {
      if (file is! Map<String, Object?> || file['size'] is! int || !isKma1Length(file['size']! as int)) {
        return server.problem(400, 'invalid-request', extra: {'detail': "file.size isn't the length of any KMA1 file"});
      }
      fileSize = file['size']! as int;
      if (fileSize > maxFileSize) return server.problem(413, 'file-too-large', extra: {'maxSize': maxFileSize});
    }
    final now = _now;
    final refused = _options(body, now: now);
    if (refused != null) return refused;
    final policy = policyRemoveSend;
    if (policy != null) return server.problem(403, 'send-policy', extra: {'detail': policy});
    final show = policyShowEmail;
    if (show != null && body['hideEmail'] == true) return server.problem(403, 'send-policy', extra: {'detail': show});
    if (sends.containsKey(id)) return server.problem(409, 'already-exists');
    final send = FakeSend(
      id: id,
      kind: kind! as String,
      meta: meta,
      sealedKey: sealedKey,
      payload: payload,
      fileSize: fileSize,
      maxAccess: body['maxAccess'] as int?,
      hideEmail: body['hideEmail'] == true,
      disabled: body['disabled'] == true,
      expiresAt: body['expiresAt'] as int?,
      deletionAt: body['deletionAt']! as int,
      createdAt: now,
      proof: proof,
    )..revisedAt = now;
    sends[id] = send;
    return server.answer(_dto(send, uploadUrl: fileSize == null ? null : '${FakeKemlockServer.url}/kem/v1/sends/$id/file'), status: 201);
  }

  http.Response _update(http.Request request, FakeSend send) {
    final body = jsonDecode(utf8.decode(request.bodyBytes));
    if (body is! Map<String, Object?>) return server.problem(400, 'invalid-request');
    const known = {'meta', 'payload', 'maxAccess', 'hideEmail', 'disabled', 'expiresAt', 'deletionAt', 'password', 'removePassword'};
    if (body.keys.any((key) => !known.contains(key))) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'unknown field'});
    }
    if (body['removePassword'] == true && body['password'] != null) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'give a new password or remove it, not both'});
    }
    final meta = _sealed(body['meta']);
    final payload = body['payload'] == null ? null : _sealed(body['payload']);
    if (meta == null || (body['payload'] != null && payload == null)) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'a sealed value'});
    }
    final password = body['password'];
    final proof = password == null ? null : _sealed(password, exactly: 32);
    if (password != null && proof == null) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'password is a 32-byte proof'});
    }
    // A policy that removes Sends refuses a change as much as a new Send, and only a delete is left
    final removed = policyRemoveSend;
    if (removed != null) return server.problem(403, 'send-policy', extra: {'detail': removed});
    final show = policyShowEmail;
    if (show != null && body['hideEmail'] == true) return server.problem(403, 'send-policy', extra: {'detail': show});
    final refused = _options(body, now: _now);
    if (refused != null) return refused;
    if (meta.length > 16 * 1024 || (payload != null && payload.length > 256 * 1024)) {
      return server.problem(400, 'invalid-request', extra: {'detail': 'too long'});
    }
    if (payload != null && send.fileSize != null) {
      return server.problem(400, 'invalid-request', extra: {'detail': "a file Send's content can't change"});
    }
    send
      ..meta = meta
      ..maxAccess = body['maxAccess'] as int?
      ..hideEmail = body['hideEmail'] == true
      ..disabled = body['disabled'] == true
      ..expiresAt = body['expiresAt'] as int?
      ..deletionAt = body['deletionAt']! as int
      ..revisedAt = _now;
    if (payload != null) send.payload = payload;
    if (body['removePassword'] == true) send.proof = null;
    if (proof != null) send.proof = proof;
    return server.answer(_dto(send));
  }

  http.Response _upload(http.Request request, FakeSend send) {
    if (send.fileSize == null) return server.problem(400, 'invalid-request', extra: {'detail': 'a note has no file'});
    if (failUploads > 0) {
      failUploads--;
      return server.problem(500, 'internal');
    }
    if (send.fileBytes != null) return server.problem(409, 'already-uploaded');
    final bytes = request.bodyBytes;
    if (bytes.length != send.fileSize) return server.problem(400, 'length-mismatch');
    if (bytes.length < 4 || utf8.decode(bytes.sublist(0, 4), allowMalformed: true) != 'KMA1') {
      return server.problem(415, 'not-kma1');
    }
    send.fileBytes = Uint8List.fromList(bytes);
    return server.answer(_dto(send));
  }
}

/// What the fake's limiter holds of one Send's password tries.
class _Tries {
  _Tries(this.windowStart);

  int windowStart;
  int count = 0;

  /// How many times in a row the limit was passed; each level doubles the wait.
  int level = 0;

  /// Whether the level was raised in this window.
  bool raised = false;
  int blockedUntil = 0;
}

/// Whether [size] is the length of a `KMA1` file: `12 + plain + 16 * max(1, ceil(plain / 65536))`.
bool isKma1Length(int size) {
  for (var chunks = 1; 12 + 16 * chunks <= size; chunks++) {
    final plain = size - 12 - 16 * chunks;
    if ((plain == 0 ? 1 : (plain + 65535) ~/ 65536) == chunks) return true;
  }
  return false;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

bool _find(List<int> haystack, List<int> needle) {
  if (needle.isEmpty || needle.length > haystack.length) return false;
  for (var i = 0; i <= haystack.length - needle.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}
