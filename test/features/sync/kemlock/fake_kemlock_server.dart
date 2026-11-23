import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/p256.dart';

import 'fake_sends.dart';
import 'openapi_checker.dart';

/// One item as the fake server holds it.
class FakeItem {
  FakeItem({
    required this.id,
    required this.owner,
    required this.kind,
    required this.revision,
    required this.keyVersion,
    required this.seq,
    this.ciphertext,
    this.itemKey,
  });

  final String id;
  final String owner;
  final String kind;
  int revision;
  int keyVersion;

  /// Where the item sits in the server's change order; the cursor is the highest one a client read.
  int seq;
  Uint8List? ciphertext;
  Uint8List? itemKey;

  /// When the server deleted it, by its own clock, as the contract's `deletedAt` says; null when it dates none.
  int? deletedAtMs;

  bool get deleted => ciphertext == null;

  Map<String, Object?> toJson() => {
    'id': id,
    'owner': owner,
    'kind': kind,
    'format': 'kem1',
    'revision': revision,
    'keyVersion': keyVersion,
    if (ciphertext != null) 'ciphertext': b64urlEncode(ciphertext!),
    if (itemKey != null) 'itemKey': b64urlEncode(itemKey!),
    'deleted': deleted,
    if (deleted && deletedAtMs != null) 'deletedAt': DateTime.fromMillisecondsSinceEpoch(deletedAtMs!, isUtc: true).toIso8601String(),
  };
}

/// An attachment's bytes, and whether they arrived.
class FakeFile {
  FakeFile(this.id, this.itemId, this.size);

  final String id;
  final String itemId;
  final int size;
  Uint8List? bytes;
}

/// An in-memory Kemlock Server behind a [MockClient], for one account, with the routes sync uses and the
/// rules the server's code (`crates/kemlock-api-kem`) has for them: DPoP proofs checked (ES256, `htm`,
/// `htu`, `iat`, a fresh `jti`, `ath`, the server's `nonce`), tokens bound to the proof's key, refresh
/// tokens that rotate and end the session when one is used twice, a revision that must be the stored one
/// plus one, `If-Match` and create-if-absent, a batch that is all or none, a delta by cursor, files that
/// need their item to exist, and the key copy. A resent write that is exactly what is stored answers as
/// the first time did, so a batch resent after a lost answer leaves one item.
///
/// It also serves the manifest routes of the server's app contract (`GET` and `PUT /kem/v1/manifests/{owner}`, not built on
/// the server yet): a counter at or below the stored one is a 409 `stale-manifest`.
///
/// ```dart
/// final server = FakeKemlockServer();
/// final api = KmApi(server.client, dpop: KmDpop(key));
/// ```
class FakeKemlockServer {
  FakeKemlockServer({String? userId}) : userId = userId ?? '00000000-0000-4000-8000-000000000001';

  static final url = Uri.parse('https://kem.example.com');

  final String userId;
  static const deviceId = '00000000-0000-4000-8000-0000000000d1';

  String get owner => 'user:$userId';

  /// What `/config` lists under `features`, as the server does; the contract's `manifest`, `device-list`, `bitwarden-enrol` and
  /// `account-keys` gate their uses, and `sends` says the Send routes are served.
  var features = <String>['opaque', 'dpop', 'totp', 'sync', 'live', 'manifest', 'device-list', 'bitwarden-enrol', 'account-keys', 'sends'];

  /// The federated vaults `/config?vault=` lists, each as the server's `VaultServersDto`.
  var vaults = <Map<String, Object?>>[];

  /// The versions held beside an item's head, by item id: `/sync` lists them as `siblings` and a resolve drops them.
  final siblings = <String, List<FakeItem>>{};

  /// The ids of items whose head counts as already sent to another server: resolving them is a 409.
  final headSent = <String>{};

  /// The items by id.
  final items = <String, FakeItem>{};

  /// Files by id.
  final files = <String, FakeFile>{};

  /// The Send routes, with the Sends they hold and a log of every request to them.
  late final sends = FakeSends(this);

  /// The latest manifest, as `{manifest, signature}` in base64url, or null.
  Map<String, String>? manifest;

  /// What the server did, in order: `batch`, `put`, `manifest`, `file`, `sync`.
  final events = <String>[];

  /// Every request the client sent, in order.
  final requests = <http.Request>[];

  /// Answers requests instead of the server while set, e.g. to fail them.
  Future<http.Response> Function(http.Request request)? respond;

  /// Runs once before the next request is answered, e.g. to act as another phone.
  void Function()? beforeNext;

  /// Whether proofs and tokens are checked. Tests of sync leave it on.
  bool checkTokens = true;

  /// The wrapped key copy, as `{wrappedKey, protection}`, or null.
  Map<String, String>? keyCopy;

  /// The `reason` the next refresh ends the session with, once set.
  String? endSession;

  /// The most bytes a file may hold.
  int maxFileSize = 64 * 1024 * 1024;

  /// The server clock's time (epoch ms) a deletion written now is dated with, or null for a server that dates none.
  int? deletionTime;

  /// Pages come this long, like the server's `limit` up to 500.
  int pageSize = 500;

  /// Items whose cursor is older than this answer 410, once set.
  int? staleBefore;

  /// How many batches were refused as stale.
  int staleBatches = 0;

  var _seq = 0;
  var _tokens = 0;
  var _nonce = 'nonce-1';
  var _nonces = 1;
  final _accessTokens = <String, String>{};
  final _refreshTokens = <String, String>{};
  final _used = <String>{};
  final _jtis = <String>{};
  var _fileCount = 0;

  /// The highest change number so far, which is what the cursor of a full read is.
  int get seq => _seq;

  /// Makes the next proof need a new nonce, as the server's rotates every five minutes.
  void rotateNonce() => _nonce = 'nonce-${++_nonces}';

  /// The thumbprint of a P-256 JWK, RFC 7638.
  static String thumbprint(Map<String, Object?> jwk) =>
      b64urlEncode(sha256.convert(utf8.encode('{"crv":"P-256","kty":"EC","x":"${jwk['x']}","y":"${jwk['y']}"}')).bytes);

  /// Tokens for the device whose key has [jkt], as a sign-in answers them.
  Map<String, Object?> issueTokens(String jkt) {
    final access = 'access-${++_tokens}';
    final refresh = 'refresh-$_tokens';
    _accessTokens[access] = jkt;
    _refreshTokens[refresh] = jkt;
    return {
      'tokenType': 'DPoP',
      'accessToken': access,
      'expiresIn': 300,
      'refreshToken': refresh,
      'refreshExpiresIn': 2592000,
      'userId': userId,
      'deviceId': deviceId,
      'admin': false,
    };
  }

  /// Stops every access token, as when they expire.
  void expireAccessTokens() => _accessTokens.clear();

  /// Adds or replaces an item as another device of the account did, and returns it.
  FakeItem write({
    required String id,
    required String kind,
    required int revision,
    Uint8List? ciphertext,
    Uint8List? itemKey,
    int keyVersion = 1,
  }) {
    final item = items[id];
    final deletedAt = ciphertext == null ? deletionTime : null;
    if (item == null) {
      return items[id] = FakeItem(
        id: id,
        owner: owner,
        kind: kind,
        revision: revision,
        keyVersion: keyVersion,
        seq: ++_seq,
        ciphertext: ciphertext,
        itemKey: itemKey,
      )..deletedAtMs = deletedAt;
    }
    item
      ..revision = revision
      ..keyVersion = keyVersion
      ..ciphertext = ciphertext
      ..itemKey = itemKey
      ..seq = ++_seq
      ..deletedAtMs = deletedAt;
    return item;
  }

  /// Adds a version beside the head of [id], as a replica's write that reached this server apart from the head's.
  FakeItem addSibling({required String id, required String kind, required int revision, Uint8List? ciphertext, Uint8List? itemKey}) {
    final version = FakeItem(
      id: id,
      owner: owner,
      kind: kind,
      revision: revision,
      keyVersion: 1,
      seq: ++_seq,
      ciphertext: ciphertext,
      itemKey: itemKey,
    )..deletedAtMs = ciphertext == null ? deletionTime : null;
    siblings.putIfAbsent(id, () => []).add(version);
    return version;
  }

  /// `POST /items/{id}/siblings/resolve`: drops the siblings of an item of the account, unless its head was sent
  /// to another server; 404 for an item that isn't there.
  http.Response _resolve(String id) {
    events.add('resolve');
    if (!items.containsKey(id)) return problem(404, 'not-found');
    if (headSent.contains(id)) return problem(409, 'siblings-already-sent');
    return _ok({'resolved': siblings.remove(id)?.length ?? 0});
  }

  /// The client that talks to this server. While a contract test runs ([OpenApiChecker.active]), each exchange is checked
  /// against the server's OpenAPI document; an answer that [respond] gives is not the server's, so only its request is.
  late final http.Client client = MockClient((request) async {
    requests.add(request);
    final hook = beforeNext;
    beforeNext = null;
    hook?.call();
    final answer = respond;
    if (answer != null) {
      final response = await answer(request);
      OpenApiChecker.active?.requestOnly(request);
      return response;
    }
    final response = await handle(request);
    OpenApiChecker.active?.exchange(request, response);
    return response;
  });

  http.Response _ok(Object? body, {int status = 200, Map<String, String> headers = const {}}) => status == 204
      ? http.Response('', status, headers: {'dpop-nonce': _nonce, ...headers})
      : http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json', 'dpop-nonce': _nonce, ...headers});

  http.Response problem(int status, String slug, {Map<String, Object?> extra = const {}, Map<String, String> headers = const {}}) =>
      http.Response(
        jsonEncode({'type': 'urn:kemlock:problem:$slug', 'title': slug, 'status': status, ...extra}),
        status,
        headers: {'content-type': 'application/problem+json', 'dpop-nonce': _nonce, ...headers},
      );

  /// How the server answers [request].
  Future<http.Response> handle(http.Request request) async {
    final path = request.url.path;
    if (!path.startsWith('/kem/v1/')) return await otherRoute(request, path) ?? http.Response('', 404);
    final route = path.substring('/kem/v1'.length);
    final method = request.method;
    if (route == '/config' && method == 'GET') {
      return _ok({
        'server': 'kemlock-server',
        'apiVersions': ['v1'],
        'version': '0.1.0',
        'serverId': '00000000-0000-4000-8000-0000000000a1',
        'domain': 'https://kem.example.com',
        'setup': 'complete',
        'signupsAllowed': false,
        'features': features,
        // As the server: the vaults asked for with `?vault=` that it federates, an empty list for none
        'vaults': [
          for (final vault in vaults)
            if (request.url.queryParametersAll['vault']?.contains(vault['vault']) ?? false) vault,
        ],
      });
    }
    if (route == '/auth/token' && method == 'POST') return _refresh(request);
    // Routes before a token: the email routes take no proof, the other sign-in routes take one
    if (route == '/auth/methods' || route == '/auth/prelogin') {
      final open = await openRoute(request, route);
      if (open != null) return open;
    }
    if (route.startsWith('/auth/')) {
      final proof = _proof(request);
      if (proof is http.Response) return proof;
      final answered = await signInRoute(request, route, proof as String);
      if (answered != null) return answered;
    }

    // A link's routes take no account: they are answered before any token is looked at
    final public = sends.public(request, route);
    if (public != null) return public;

    final auth = _authenticate(request);
    if (auth is http.Response) return auth;
    final more = await tokenRoute(request, route);
    if (more != null) return more;

    if (route == '/sync' && method == 'GET') return _sync(request);
    if (route == '/items:batch' && method == 'POST') return _batch(request);
    if (route == '/manifests/$owner') return _manifest(request);
    if (route == '/devices/key-copy') return _keyCopy(request);
    final send = sends.owner(request, route);
    if (send != null) return send;
    final file = RegExp(r'^/items/([^/]+)/files(?:/([^/]+))?$').firstMatch(route);
    if (file != null) return _files(request, file[1]!, file[2]);
    final resolve = RegExp(r'^/items/([^/]+)/siblings/resolve$').firstMatch(route);
    if (resolve != null && method == 'POST') return _resolve(resolve[1]!);
    final item = RegExp(r'^/items/([^/]+)$').firstMatch(route);
    if (item != null && method == 'PUT') return _put(request, item[1]!);
    return problem(404, 'not-found');
  }

  // ─── Hooks for the sign-in routes of `FakeKemlockAccountServer` ──────

  /// An answer for a path outside `/kem/v1`, such as the Bitwarden API's prelogin; null for none.
  Future<http.Response?> otherRoute(http.Request request, String path) async => null;

  /// An answer for `/auth/methods` or `/auth/prelogin`, which take no proof; null for none.
  Future<http.Response?> openRoute(http.Request request, String route) async => null;

  /// An answer for an `/auth/` route, after its proof was checked ([jkt] is the proof key's thumbprint, or
  /// `unchecked`); null for none.
  Future<http.Response?> signInRoute(http.Request request, String route, String jkt) async => null;

  /// An answer for a route that needs a token, after the token was checked; null for none.
  Future<http.Response?> tokenRoute(http.Request request, String route) async => null;

  /// The thumbprint of the key an access token is bound to.
  String? boundKey(http.Request request) {
    final header = request.headers['Authorization'] ?? request.headers['authorization'] ?? '';
    return header.startsWith('DPoP ') ? _accessTokens[header.substring(5)] : null;
  }

  /// A JSON answer, as every route of the server gives it.
  http.Response answer(Object? body, {int status = 200}) => _ok(body, status: status);

  /// The thumbprint of [request]'s proof, or the answer to refuse it with.
  Object proofOf(http.Request request) => _proof(request);

  // ─── DPoP and tokens ─────────────────────────────────────────────────

  /// The proof's thumbprint, or the answer to refuse it with.
  Object _proof(http.Request request, {String? accessToken}) {
    if (!checkTokens) return 'unchecked';
    final proofs = request.headers['DPoP'] ?? request.headers['dpop'];
    if (proofs == null) return problem(401, 'invalid-dpop-proof', headers: {'www-authenticate': 'DPoP error="invalid_dpop_proof"'});
    http.Response refuse(String why) => problem(401, 'invalid-dpop-proof', extra: {'detail': why});
    final parts = proofs.split('.');
    if (parts.length != 3) return refuse('not a compact JWS');
    try {
      final header = jsonDecode(utf8.decode(b64urlDecode(parts[0]))) as Map<String, Object?>;
      final claims = jsonDecode(utf8.decode(b64urlDecode(parts[1]))) as Map<String, Object?>;
      final signature = b64urlDecode(parts[2]);
      if (header['typ'] != 'dpop+jwt' || header['alg'] != 'ES256') return refuse('typ or alg');
      final jwk = header['jwk'] as Map<String, Object?>;
      if (jwk['kty'] != 'EC' || jwk['crv'] != 'P-256' || jwk.containsKey('d')) return refuse('jwk');
      if (signature.length != 64) return refuse('signature length');
      final point = Uint8List.fromList([4, ...b64urlDecode(jwk['x']! as String), ...b64urlDecode(jwk['y']! as String)]);
      final der = derSequence([derInteger(_big(signature.sublist(0, 32))), derInteger(_big(signature.sublist(32)))]);
      if (!es256Verify(point, Uint8List.fromList(utf8.encode('${parts[0]}.${parts[1]}')), der)) return refuse('signature');
      if (claims['htm'] != request.method) return refuse('htm');
      final expected = Uri(
        scheme: request.url.scheme,
        host: request.url.host,
        port: request.url.hasPort ? request.url.port : null,
        path: request.url.path,
      );
      if (claims['htu'] != expected.toString()) return refuse('htu ${claims['htu']} is not $expected');
      final iat = claims['iat'];
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      if (iat is! int || (now - iat).abs() > 60) return refuse('iat');
      final jkt = thumbprint(jwk);
      final jti = claims['jti'];
      if (jti is! String || jti.isEmpty) return refuse('jti');
      if (accessToken != null && claims['ath'] != b64urlEncode(sha256.convert(utf8.encode(accessToken)).bytes)) return refuse('ath');
      if (claims['nonce'] != _nonce) {
        return problem(
          401,
          'use-dpop-nonce',
          extra: {'error': 'use_dpop_nonce'},
          headers: {'www-authenticate': 'DPoP error="use_dpop_nonce"'},
        );
      }
      if (!_jtis.add('$jkt:$jti')) return refuse('already used');
      return jkt;
    } on Object {
      return refuse('unreadable');
    }
  }

  /// null when the request is allowed, else the answer.
  Object _authenticate(http.Request request) {
    final header = request.headers['Authorization'] ?? request.headers['authorization'] ?? '';
    if (!header.startsWith('DPoP ')) return problem(401, 'unauthorized', headers: {'www-authenticate': 'DPoP algs="ES256"'});
    final token = header.substring(5);
    final proof = _proof(request, accessToken: token);
    if (proof is http.Response) return proof;
    final bound = _accessTokens[token];
    if (bound == null || (checkTokens && bound != proof)) {
      return problem(401, 'unauthorized', headers: {'www-authenticate': 'DPoP error="invalid_token"'});
    }
    return true;
  }

  http.Response _refresh(http.Request request) {
    final proof = _proof(request);
    if (proof is http.Response) return proof;
    final body = jsonDecode(request.body) as Map<String, Object?>;
    if (body['grantType'] != 'refresh_token') return problem(400, 'invalid-request');
    final refresh = body['refreshToken'] as String?;
    final ending = endSession;
    if (ending != null) return problem(401, 'session-ended', extra: {'reason': ending});
    if (refresh != null && _used.contains(refresh)) {
      _refreshTokens.clear();
      _accessTokens.clear();
      return problem(401, 'session-ended', extra: {'reason': 'refresh-reuse'});
    }
    final bound = _refreshTokens.remove(refresh);
    if (bound == null || (checkTokens && bound != proof)) return problem(401, 'unauthorized');
    _used.add(refresh!);
    return _ok(issueTokens(bound));
  }

  // ─── Sync and items ──────────────────────────────────────────────────

  http.Response _sync(http.Request request) {
    events.add('sync');
    final since = request.url.queryParameters['since'];
    var from = 0;
    if (since != null) {
      try {
        from = int.parse(utf8.decode(b64urlDecode(since)));
      } on Object {
        return problem(410, 'full-sync-required');
      }
      final stale = staleBefore;
      if (stale != null && from < stale) return problem(410, 'full-sync-required');
    }
    final limit = (int.tryParse(request.url.queryParameters['limit'] ?? '') ?? pageSize).clamp(1, pageSize);
    final changed = [
      for (final item in items.values)
        if (item.seq > from) item,
    ]..sort((a, b) => a.seq.compareTo(b.seq));
    if (since != null && changed.isEmpty) return http.Response('', 304, headers: {'dpop-nonce': _nonce});
    final page = changed.take(limit).toList();
    final next = page.isEmpty ? from : page.last.seq;
    return _ok({
      'items': [for (final item in page) item.toJson()],
      'cursor': b64urlEncode(utf8.encode('${page.length == changed.length ? _seq : next}')),
      'more': page.length < changed.length,
      'siblings': [
        for (final MapEntry(:key, :value) in siblings.entries)
          if (value.isNotEmpty)
            {
              'itemId': key,
              'versions': [for (final version in value) version.toJson()],
            },
      ],
    });
  }

  /// null when [write] may be stored, else the problem. [stored] is what the server holds under the id.
  http.Response? _check(Map<String, Object?> body, int? expected, FakeItem? stored) {
    final id = body['id'] as String;
    final revision = body['revision'] as int;
    if (body['deleted'] != true && (body['ciphertext'] == null || body['itemKey'] == null)) return problem(400, 'invalid-request');
    if (body['deleted'] == true && (body.containsKey('ciphertext') || body.containsKey('itemKey'))) return problem(400, 'invalid-request');
    if (stored == null) {
      if (expected != null) return problem(409, 'stale-revision', extra: {'itemId': id, 'currentRevision': null});
      if (revision != 1) return problem(422, 'invalid-revision');
      return null;
    }
    if (expected != stored.revision) return problem(409, 'stale-revision', extra: {'itemId': id, 'currentRevision': stored.revision});
    if (revision != stored.revision + 1) return problem(422, 'invalid-revision');
    if (body['kind'] != stored.kind) return problem(422, 'invalid-revision');
    return null;
  }

  bool _sameAsStored(Map<String, Object?> body, FakeItem? stored) =>
      stored != null &&
      stored.revision == body['revision'] &&
      stored.kind == body['kind'] &&
      stored.deleted == (body['deleted'] == true) &&
      (stored.ciphertext == null || b64urlEncode(stored.ciphertext!) == body['ciphertext']);

  FakeItem _store(Map<String, Object?> body) {
    final ciphertext = body['ciphertext'] as String?;
    final itemKey = body['itemKey'] as String?;
    return write(
      id: body['id']! as String,
      kind: body['kind']! as String,
      revision: body['revision']! as int,
      keyVersion: body['keyVersion']! as int,
      ciphertext: ciphertext == null ? null : b64urlDecode(ciphertext),
      itemKey: itemKey == null ? null : b64urlDecode(itemKey),
    );
  }

  http.Response _batch(http.Request request) {
    events.add('batch');
    final body = jsonDecode(request.body) as Map<String, Object?>;
    final writes = (body['writes']! as List<Object?>).cast<Map<String, Object?>>();
    if (writes.length > 500) return problem(400, 'invalid-request');
    final stored = <FakeItem>[];
    // All or none: every write is checked first
    for (final entry in writes) {
      final item = entry['item']! as Map<String, Object?>;
      final current = items[item['id']];
      if (_sameAsStored(item, current)) continue;
      final refused = _check(item, entry['expectedRevision'] as int?, current);
      if (refused != null) {
        if (refused.statusCode == 409) staleBatches++;
        return refused;
      }
    }
    for (final entry in writes) {
      final item = entry['item']! as Map<String, Object?>;
      stored.add(_sameAsStored(item, items[item['id']]) ? items[item['id']]! : _store(item));
    }
    return _ok({
      'items': [for (final item in stored) item.toJson()],
    });
  }

  http.Response _put(http.Request request, String id) {
    events.add('put');
    final body = jsonDecode(request.body) as Map<String, Object?>;
    if (body['id'] != id) return problem(400, 'invalid-request');
    final ifMatch = request.headers['If-Match'] ?? request.headers['if-match'];
    final ifNone = request.headers['If-None-Match'] ?? request.headers['if-none-match'];
    if (ifMatch == null && ifNone == null) return problem(428, 'precondition-required');
    final expected = ifMatch == null ? null : int.parse(ifMatch.replaceAll(RegExp('[W/"]'), ''));
    final current = items[id];
    if (!_sameAsStored(body, current)) {
      final refused = _check(body, expected, current);
      if (refused != null) return refused;
    }
    final item = _sameAsStored(body, current) ? current! : _store(body);
    return _ok(item.toJson(), status: expected == null ? 201 : 200, headers: {'etag': '"${item.revision}"'});
  }

  // ─── The manifest, the key copy and files ────────────────────────────

  /// The highest counter stored, 0 for none.
  var manifestCounter = 0;

  Map<String, Object?> _manifestAnswer() => {
    'owner': owner,
    'counter': manifestCounter,
    ...manifest!,
    'signer': userId,
    'storedAt': '2026-11-21T00:00:00Z',
  };

  http.Response _manifest(http.Request request) {
    if (request.method == 'PUT') {
      events.add('manifest');
      final body = jsonDecode(request.body) as Map<String, Object?>;
      final bytes = b64urlDecode(body['manifest']! as String);
      final counter = Manifest.parse(bytes).counter;
      if (counter <= manifestCounter) return problem(409, 'stale-manifest', extra: {'currentCounter': manifestCounter});
      manifestCounter = counter;
      manifest = {'manifest': body['manifest']! as String, 'signature': body['signature']! as String};
      return _ok(_manifestAnswer());
    }
    return manifest == null ? problem(404, 'not-found') : _ok(_manifestAnswer());
  }

  http.Response _keyCopy(http.Request request) {
    switch (request.method) {
      case 'PUT':
        final body = jsonDecode(request.body) as Map<String, Object?>;
        keyCopy = {'wrappedKey': body['wrappedKey']! as String, 'protection': body['protection']! as String};
        return _ok({'deviceId': deviceId, ...keyCopy!, 'createdAt': '2026-11-21T00:00:00Z', 'updatedAt': '2026-11-21T00:00:00Z'});
      case 'GET':
        final copy = keyCopy;
        if (copy == null) return problem(404, 'not-found');
        return _ok({'deviceId': deviceId, ...copy, 'createdAt': '2026-11-21T00:00:00Z', 'updatedAt': '2026-11-21T00:00:00Z'});
      case 'DELETE':
        keyCopy = null;
        return http.Response('', 204, headers: {'dpop-nonce': _nonce});
    }
    return problem(405, 'invalid-request');
  }

  http.Response _files(http.Request request, String itemId, String? fileId) {
    final item = items[itemId];
    if (item == null || item.deleted) return problem(404, 'not-found');
    if (fileId == null) {
      if (request.method != 'POST') return problem(405, 'invalid-request');
      final size = (jsonDecode(request.body) as Map<String, Object?>)['size'] as int;
      if (size > maxFileSize) return problem(413, 'payload-too-large');
      final id = '00000000-0000-4000-8000-${(++_fileCount).toString().padLeft(12, '0')}';
      files[id] = FakeFile(id, itemId, size);
      return _ok({
        'fileId': id,
        'itemId': itemId,
        'size': size,
        'maxSize': maxFileSize,
        'uploadUrl': '${url.origin}/kem/v1/items/$itemId/files/$id',
        'presigned': false,
        'expiresIn': null,
      }, status: 201);
    }
    final file = files[fileId];
    if (file == null || file.itemId != itemId) return problem(404, 'not-found');
    switch (request.method) {
      case 'PUT':
        final bytes = request.bodyBytes;
        if (bytes.length != file.size) return problem(400, 'invalid-request');
        if (bytes.length < 4 || utf8.decode(bytes.sublist(0, 4), allowMalformed: true) != 'KMA1') return problem(415, 'invalid-request');
        events.add('file');
        file.bytes = Uint8List.fromList(bytes);
        return _ok({'fileId': fileId, 'itemId': itemId, 'size': file.size, 'status': 'ready'});
      case 'GET':
        final bytes = file.bytes;
        if (bytes == null) return problem(404, 'not-found');
        return http.Response.bytes(bytes, 200, headers: {'content-type': 'application/octet-stream', 'dpop-nonce': _nonce});
      case 'DELETE':
        files.remove(fileId);
        return http.Response('', 204, headers: {'dpop-nonce': _nonce});
    }
    return problem(405, 'invalid-request');
  }
}

BigInt _big(List<int> bytes) {
  var out = BigInt.zero;
  for (final b in bytes) {
    out = (out << 8) | BigInt.from(b);
  }
  return out;
}
