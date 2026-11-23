/// Just enough of the Kemlock API, `/kem/v1`, for sync: the server's config,
/// refreshing a token, the delta by cursor, the checked batch of writes, the
/// manifest and the files of notes. Written by hand in `vw_api.dart`'s style
/// (add-kemlock-server-sync, owner decision 9), against the shapes in
/// `test/fixtures/kemlock/README.md`.
///
/// Requests go straight to the server through a client the caller gives: the
/// app's gated client, which makes none while offline mode is on, pinned to
/// one certificate for a server whose own the system doesn't trust. This file
/// makes no client of its own. What the server can send is limited
/// (design 16):
///
/// - a redirect is never followed, on any route: it is the server's error;
/// - an answer is read up to a cap, whatever its `Content-Length` says: 2 MiB
///   of JSON (the server's own body cap), 8 MiB for a sync page, and for a file
///   the size its note names;
/// - every request has a timeout, 30 seconds, longer only for a file;
/// - an upload address on another host must be https, and a request to it
///   carries no `Authorization` and no DPoP proof;
/// - a request with a token carries a DPoP proof ([KmProofs]) and is retried
///   once when the server asks for its nonce.
///
/// Pure Dart, no Flutter.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../../../core/network/answers.dart' show AnswerTooLarge, readAnswer;
import '../../../core/network/tls_failure.dart';
import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/kem1.dart';
import '../../../models/json.dart';
import 'km_models.dart' show KemlockServer;
import 'km_session.dart';

/// What went wrong talking to the server. The names are the ends of
/// `kemlock.problem.*` ids where a sheet says them.
enum KmProblem {
  /// The address isn't https, which would send the sign-in in the clear.
  insecure,

  /// The address isn't a URL, or no Kemlock Server answers there.
  address,

  /// The server didn't accept the credentials, or the access token.
  auth,

  /// The server refused the sign-in after the caller proved who they are, because a space the account belongs to
  /// requires single sign-on (403 `sso-required`, naming the space in [KmError.spaceId]). Owners and admins are exempt.
  ssoRequired,

  /// The session ended, and the server said why ([KmError.reason]): sign in again.
  sessionEnded,

  /// A write named a revision that isn't the stored one: merge again.
  stale,

  /// The cursor is too old: sync again without one.
  fullSync,

  /// Too many tries: wait [KmError.retryAfter] seconds.
  rateLimited,

  /// The server refused a body or a file as too large.
  tooLarge,

  /// The server couldn't be reached, or its certificate isn't trusted.
  network,

  /// The server answers in a way this version can't use.
  unsupported,

  /// Any other answer.
  server,
}

/// A failed request.
class KmError implements Exception {
  const KmError(
    this.problem, {
    this.status = 0,
    this.message,
    this.reason,
    this.spaceId,
    this.itemId,
    this.currentRevision,
    this.slug,
    this.tagVersion,
    this.retryAfter,
    this.maxSize,
    this.head,
    this.seq,
    this.handshakeFailed = false,
    this.timedOut = false,
  });

  final KmProblem problem;

  /// The HTTP status, or 0 when there was no answer.
  final int status;

  /// The server's own words, for logs.
  final String? message;

  /// For [KmProblem.sessionEnded]: why, as the server said (`refresh-reuse`, `signed-out`, …).
  final String? reason;

  /// For [KmProblem.ssoRequired]: the space that requires single sign-on.
  final String? spaceId;

  /// For [KmProblem.stale]: the item the write was refused for, and the revision the server holds
  /// (null when it holds none).
  final String? itemId;
  final int? currentRevision;

  /// The server's problem slug, the end of `urn:kemlock:problem:<slug>`, when the answer named one: it tells a
  /// stale revision (`stale-revision`) from the tag routes' `server-matching-off` and `stale-dedup-version`, which
  /// are 409s too, and the Send routes' refusals (`send-policy`, `already-exists`) apart.
  final String? slug;

  /// For a `stale-dedup-version` problem: the dedup key version the server holds (`currentTagVersion`).
  final int? tagVersion;

  /// For [KmProblem.rateLimited]: seconds to wait.
  final int? retryAfter;

  /// For a 413 that says it: the largest file the server takes, in bytes (`maxSize`).
  final int? maxSize;

  /// For a 409 of a space's chain: the head the server holds, as it sent it, when the append named a position that
  /// is no longer the next.
  final Object? head;

  /// For a 422 of a space's chain: the `seq` of the record the server refused, and why in [reason].
  final int? seq;

  /// For [KmProblem.network]: the connection broke off at its TLS handshake, as it does when the
  /// phone refuses the server's certificate. Only then may setup offer to trust a certificate.
  final bool handshakeFailed;

  /// For [KmProblem.network]: the server gave no first byte within [KmApi.firstByte]. Failover moves on at once.
  final bool timedOut;

  @override
  String toString() =>
      'Kemlock ${problem.name}${handshakeFailed ? ' (handshake)' : ''}${status != 0 ? ' ($status)' : ''}${message != null ? ': $message' : ''}';
}

/// The problem the server answers a siblings resolve with when the merged head was already sent to another server.
const siblingsSent = 'siblings-already-sent';

/// The server's address, checked: https, with a host. Throws a [KmError]:
/// `insecure` for http, `address` for anything else that isn't a URL. A path
/// is kept as typed, without a trailing slash, so a server under a path works.
Uri kmServerUrl(String text) {
  final url = Uri.tryParse(text.trim());
  if (url == null || !url.hasScheme) throw const KmError(KmProblem.address);
  if (url.scheme == 'http') throw const KmError(KmProblem.insecure);
  if (url.scheme != 'https' || url.host.isEmpty || url.hasQuery || url.hasFragment || url.userInfo.isNotEmpty) {
    throw const KmError(KmProblem.address);
  }
  final path = url.path.endsWith('/') ? url.path.substring(0, url.path.length - 1) : url.path;
  return Uri(scheme: 'https', host: url.host, port: url.hasPort ? url.port : null, path: path);
}

/// The host a server is at, for status lines: `kem.example.com`, with the port when it isn't https's own.
String kmHost(String server) {
  final url = Uri.tryParse(server.trim());
  if (url == null || url.host.isEmpty) return server;
  return url.hasPort ? '${url.host}:${url.port}' : url.host;
}

/// Whether [url], absolute or relative to [server], is on [server]'s host: https, the same host and port.
bool kmSameServer(Uri server, String url) {
  final parsed = Uri.tryParse(url.trim());
  if (parsed == null) return false;
  if (!parsed.hasScheme && !parsed.hasAuthority) return true;
  return parsed.scheme == 'https' && parsed.host.toLowerCase() == server.host.toLowerCase() && parsed.port == server.port;
}

/// Makes the DPoP proofs (RFC 9449) the requests carry, and reads from each
/// answer what the next proof needs: the server's nonce and its clock.
abstract interface class KmProofs {
  /// A proof for [method] on [url], bound to [accessToken] with `ath` when there is one.
  Future<String> proof(String method, Uri url, {String? accessToken});

  /// Reads the `DPoP-Nonce` and `Date` of an answer to a request to [url].
  void observe(Uri url, Map<String, String> headers);
}

/// What `GET /kem/v1/config` says.
class KmConfig {
  const KmConfig({
    required this.serverId,
    required this.domain,
    required this.version,
    required this.features,
    required this.setup,
    this.vaults = const [],
  });

  final String serverId;

  /// The address the server believes it has; its DPoP check compares proofs with it.
  final String domain;
  final String version;
  final List<String> features;

  /// `needs-admin`, `pending` or `complete`.
  final String setup;

  /// The servers of each federated vault asked for with `?vault=`, as this server holds them. A vault that isn't
  /// federated there is left out, and so is one this version can't read.
  final List<KmVaultServers> vaults;
}

/// One server a federated vault is held on, as `/config` lists it (the server's `ServerEntryDto`).
class KmServerEntry {
  const KmServerEntry({required this.serverId, required this.address, required this.identityKey, required this.role});

  /// Reads one entry. A server id that isn't a UUID, an address that isn't https, an identity key that isn't a
  /// 1,984-byte `sig1` public key or a role other than `home` and `replica` is a [FormatException].
  factory KmServerEntry.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      throw const FormatException('a server entry is an object');
    }
    final id = json['serverId'];
    final address = json['address'];
    final key = json['identityKey'];
    final role = json['role'];
    if (id is! String || !isUuidText(id)) {
      throw const FormatException('a server entry names its server by UUID');
    }
    if (address is! String || key is! String) {
      throw const FormatException('a server entry has an address and an identity key');
    }
    if (role is! String || (role != KemlockServer.home && role != KemlockServer.replica)) {
      throw const FormatException('a server is the home or a replica');
    }
    try {
      final identityKey = b64urlDecode(key);
      if (identityKey.length != 1984) {
        throw const FormatException('an identity key is 1,984 bytes');
      }
      return KmServerEntry(serverId: id, address: kmServerUrl(address).toString(), identityKey: identityKey, role: role);
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    } on KmError {
      throw const FormatException('a server entry has an https address');
    }
  }

  /// The server's id, a UUID.
  final String serverId;

  /// The address a device reaches it at, as [kmServerUrl] writes it.
  final String address;

  /// Its federation identity key, a `sig1` public key of 1,984 bytes.
  final Uint8List identityKey;

  /// `home` or `replica`.
  final String role;

  /// The entry as a server of the vault's list, with its identity key as first seen.
  KemlockServer toServer() => KemlockServer(url: address, role: role, identityKey: b64urlEncode(identityKey));
}

/// A federated vault's servers in failover order, with the home's epoch and the signed record that made it.
class KmVaultServers {
  const KmVaultServers({required this.vault, required this.epoch, required this.servers, this.promotion});

  /// Reads one vault of `/config`'s `vaults`. The home must come first and be the only one; an epoch below 1, a
  /// repeated server or a record that isn't base64url is a [FormatException].
  factory KmVaultServers.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      throw const FormatException('a vault is an object');
    }
    final vault = json['vault'];
    final epoch = json['epoch'];
    final servers = json['servers'];
    final promotion = json['promotion'];
    if (vault is! String || !_vaultText.hasMatch(vault)) {
      throw const FormatException('a vault is user:<uuid> or space:<uuid>');
    }
    if (epoch is! int || epoch < 1) {
      throw const FormatException('an epoch starts at 1');
    }
    if (servers is! List<Object?> || servers.isEmpty || servers.length > 16) {
      throw const FormatException('a vault lists its servers');
    }
    final entries = [for (final server in servers) KmServerEntry.fromJson(server)];
    if (entries.first.role != KemlockServer.home || entries.skip(1).any((entry) => entry.role == KemlockServer.home)) {
      throw const FormatException('the home comes first and is alone');
    }
    if (entries.map((entry) => entry.serverId).toSet().length != entries.length) {
      throw const FormatException('a server is listed twice');
    }
    if (promotion != null && promotion is! String) {
      throw const FormatException('a promotion record is base64url');
    }
    try {
      return KmVaultServers(vault: vault, epoch: epoch, servers: entries, promotion: promotion is String ? b64urlDecode(promotion) : null);
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
  }

  static final _vaultText = RegExp(r'^(user|space):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

  /// `user:<uuid>` or `space:<uuid>`.
  final String vault;

  /// The vault's home epoch, from 1.
  final int epoch;

  /// The home first, then the replicas in failover order.
  final List<KmServerEntry> servers;

  /// The signed promotion record of this epoch (an envelope, `docs/federation.md`), or null at epoch 1.
  final Uint8List? promotion;

  KmServerEntry get home => servers.first;
}

/// An item as the server answers with it. Any format reads, so an item of a
/// format this version doesn't open (the Bitwarden one) still passes through
/// the cache and the manifest by its id, revision and ciphertext.
class KmWireItem {
  const KmWireItem({
    required this.id,
    required this.owner,
    required this.kind,
    required this.format,
    required this.revision,
    required this.keyVersion,
    required this.deleted,
    this.ciphertext,
    this.itemKey,
    this.deletedAt,
    this.collectionId,
    this.held = false,
  });

  /// Reads one item of an answer. A field of the wrong type, an id that isn't a UUID, base64url that
  /// isn't canonical, or a tombstone that carries a ciphertext is a [FormatException].
  factory KmWireItem.fromJson(Object? json) {
    if (json is! Map<String, Object?>) throw const FormatException('an item is an object');
    String string(String name) {
      final value = json[name];
      if (value is! String) throw FormatException('$name is a string');
      return value;
    }

    int number(String name) {
      final value = json[name];
      if (value is! int || value < 0) throw FormatException('$name is a whole number');
      return value;
    }

    final id = string('id');
    if (!isUuidText(id)) throw FormatException('not an item id: $id');
    final deleted = json['deleted'];
    if (deleted is! bool) throw const FormatException('deleted is a boolean');
    final ciphertext = json['ciphertext'];
    final itemKey = json['itemKey'];
    if (deleted && (ciphertext != null || itemKey != null)) throw const FormatException('a tombstone carries no ciphertext');
    if (!deleted && ciphertext is! String) throw const FormatException('an item carries a ciphertext');
    try {
      return KmWireItem(
        id: id,
        owner: string('owner'),
        kind: string('kind'),
        format: string('format'),
        revision: number('revision'),
        keyVersion: number('keyVersion'),
        deleted: deleted,
        ciphertext: ciphertext is String ? b64urlDecode(ciphertext) : null,
        itemKey: itemKey is String ? b64urlDecode(itemKey) : null,
        deletedAt: deleted ? DateTime.tryParse(asString(json['deletedAt']))?.millisecondsSinceEpoch : null,
        // server: to confirm
        held: json['held'] == true,
        collectionId: switch (json['collectionId']) {
          final String collection when isUuidText(collection) => collection,
          _ => null,
        },
      );
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
  }

  final String id;
  final String owner;
  final String kind;
  final String format;
  final int revision;
  final int keyVersion;
  final bool deleted;
  final Uint8List? ciphertext;
  final Uint8List? itemKey;

  /// For a tombstone: when the server says the item was deleted, epoch ms of its own clock (RFC 3339 `deletedAt`),
  /// or null when it dates none (a server before the contract). A deletion is dated by it when present.
  final int? deletedAt;

  /// For an item of a space: the collection it is in, which holds the key that wraps its item key. The server sends it
  /// beside `owner`; it is no part of the `kem1` envelope, so [toJson] leaves it out.
  final String? collectionId;

  /// For an item of a space: whether the server holds it, after a key replacement that did not accept it. Sync serves a
  /// held item to every confirmed member, with its old `keyVersion`; only a member with edit releases it. A new write of its id under the collection's current
  /// key version releases it (keep), and so does a tombstone (delete).
  ///
  /// server: to confirm (the name of the field)
  final bool held;

  /// Whether this version opens items of this format.
  bool get isKem1 => format == kem1Format;

  /// The item as `kem1` reads it; a [MalformedException] when it isn't one.
  Kem1Item toKem1() => Kem1Item.fromJson(toJson());

  Map<String, Object?> toJson() => {
    'id': id,
    'owner': owner,
    'kind': kind,
    'format': format,
    'revision': revision,
    'keyVersion': keyVersion,
    if (ciphertext != null) 'ciphertext': b64urlEncode(ciphertext!),
    if (itemKey != null) 'itemKey': b64urlEncode(itemKey!),
    'deleted': deleted,
  };
}

/// The versions of one item that two servers wrote apart: they sit beside the item the page lists, its head.
class KmSiblingSet {
  const KmSiblingSet({required this.itemId, required this.versions});

  /// Reads one set of a page's `siblings`. A set with no version, an id that isn't a UUID or a version of another
  /// item is a [FormatException].
  factory KmSiblingSet.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      throw const FormatException('a sibling set is an object');
    }
    final id = json['itemId'];
    final versions = json['versions'];
    if (id is! String || !isUuidText(id)) {
      throw const FormatException('a sibling set names its item by UUID');
    }
    if (versions is! List<Object?> || versions.isEmpty || versions.length > 64) {
      throw const FormatException('a sibling set lists versions');
    }
    final read = [for (final version in versions) KmWireItem.fromJson(version)];
    if (read.any((version) => version.id != id)) {
      throw const FormatException('a sibling is a version of another item');
    }
    return KmSiblingSet(itemId: id, versions: read);
  }

  final String itemId;

  /// The versions held beside the head, each with its own revision and ciphertext.
  final List<KmWireItem> versions;
}

/// One page of the delta.
class KmSyncPage {
  const KmSyncPage({required this.items, required this.cursor, required this.more, this.siblings = const []});

  final List<KmWireItem> items;

  /// Opaque: sent back unread as `since`.
  final String cursor;

  /// Whether another page follows.
  final bool more;

  /// Every set of versions held beside an item of the account's own vault, listed on every page that isn't a 304,
  /// not only for the items of this page. Empty on a server with no federation.
  final List<KmSiblingSet> siblings;
}

/// A write of a batch: [item] at its new revision, replacing [expected], or a new item when that is null.
typedef KmWrite = ({int? expected, Kem1Item item});

/// The tags that ride beside an item's ciphertext: 32 bytes each, made under the owner's dedup key at [version].
/// Only `cred` tags are ever made for the server (`km_dedup.dart`).
typedef KmTagSet = ({int version, List<Uint8List> tags});

/// The first step of a file upload, as the server answered it.
class KmFileStart {
  const KmFileStart({required this.fileId, required this.size, required this.maxSize, required this.uploadUrl, required this.presigned});

  final String fileId;
  final int size;
  final int maxSize;
  final String uploadUrl;

  /// Whether [uploadUrl] is a bucket address: the bytes go there with no `Authorization` or proof,
  /// and the upload is then finished with a request to the server.
  final bool presigned;
}

/// Talks to Kemlock servers through [client], which tests replace with a
/// `MockClient`, and which pins a certificate when setup asked for it.
class KmApi {
  KmApi(
    this.client, {
    this.proofs,
    this.timeout = const Duration(seconds: 30),
    this.fileTimeout = const Duration(minutes: 5),
    this.firstByte,
    this.clock = DateTime.now,
  });

  final http.Client client;

  /// Makes the DPoP proofs; null sends none, as a test of the transport alone does.
  final KmProofs? proofs;

  /// How long a request may take before it counts as a `network` problem.
  final Duration timeout;

  /// The same for a file's bytes.
  final Duration fileTimeout;

  /// How long a JSON request may go without a first answer before it fails as a `timedOut` network problem: the
  /// failover rule's 10 seconds. Null waits for the whole [timeout]. Files wait for the whole of theirs.
  final Duration? firstByte;

  final DateTime Function() clock;

  /// What a JSON answer may hold: the server's own body cap.
  static const maxJsonBytes = 2 * 1024 * 1024;

  /// What a config may hold, with the server lists of a few dozen vaults.
  static const maxConfigBytes = 512 * 1024;

  /// What a page of the delta or a manifest may hold.
  static const maxPageBytes = 8 * 1024 * 1024;

  /// What a problem answer may hold.
  static const _maxProblemBytes = 64 * 1024;

  /// The most items one batch carries, the server's limit.
  static const batchSize = 500;

  /// A cursor longer than this goes in the body of a POST, not in the URL.
  static const postCursorLength = 1500;

  Uri _api(Uri server, String route) => server.replace(path: '${server.path}/kem/v1$route');

  // ─── Before signing in ─────────────────────────────────────────────────

  /// The server's `/kem/v1/config`. Throws an `address` [KmError] when what answers isn't a Kemlock
  /// Server that speaks `v1`. With [vaults] (`user:<uuid>`, at most 32) it also reads the servers of those the
  /// server federates; the route is public, so no proof is sent.
  Future<KmConfig> config(Uri server, {List<String> vaults = const []}) async {
    var url = _api(server, '/config');
    if (vaults.isNotEmpty) {
      url = url.replace(queryParameters: {'vault': vaults});
    }
    final res = await _send('GET', url, maxBytes: maxConfigBytes, proof: false);
    final json = _jsonOrNull(res);
    final versions = json?['apiVersions'];
    if (res.statusCode != 200 || json == null || json['server'] != 'kemlock-server' || versions is! List || !versions.contains('v1')) {
      throw KmError(KmProblem.address, status: res.statusCode);
    }
    final listed = json['vaults'];
    return KmConfig(
      serverId: asString(json['serverId']),
      domain: asString(json['domain']),
      version: asString(json['version']),
      features: asStrings(json['features']) ?? const [],
      setup: asString(json['setup']),
      vaults: [
        if (listed is List<Object?>)
          for (final vault in listed) ?_vaultOrNull(vault),
      ],
    );
  }

  /// A vault of `/config` this version can read, else null: a list it can't read changes nothing.
  KmVaultServers? _vaultOrNull(Object? json) {
    try {
      return KmVaultServers.fromJson(json);
    } on FormatException {
      return null;
    }
  }

  /// The statements of `/.well-known/assetlinks.json` on [host] (the server's own host unless the config names
  /// another domain), which name the apps that may use its passkeys. Null when the file isn't there or isn't a
  /// list. Nothing is sent but the request: no credentials and no proof.
  Future<List<Object?>?> assetLinks(Uri server, {String? host}) async {
    final url = Uri(
      scheme: 'https',
      host: host != null && host.isNotEmpty ? host : server.host,
      port: host != null && host.isNotEmpty ? null : (server.hasPort ? server.port : null),
      path: '/.well-known/assetlinks.json',
    );
    final res = await _send('GET', url, maxBytes: 256 * 1024, proof: false);
    if (res.statusCode != 200) return null;
    try {
      final value = jsonDecode(utf8.decode(res.bodyBytes));
      return value is List<Object?> ? value : null;
    } on FormatException {
      return null;
    }
  }

  /// Renews the access token with [refreshToken], which the answer's replaces: each is used once. A
  /// session the server ended throws a `sessionEnded` [KmError] with its reason.
  Future<KmTokens> refresh(Uri server, String refreshToken) async {
    final res = await _send('POST', _api(server, '/auth/token'), json: {'grantType': 'refresh_token', 'refreshToken': refreshToken});
    final json = _expect(res);
    try {
      return KmTokens.fromResponse(json, clock().millisecondsSinceEpoch);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, status: res.statusCode, message: e.message);
    }
  }

  /// One JSON request to [route] under `/kem/v1`, for the routes `KmAuthApi` and the approvals use. Returns
  /// the answer's JSON object, an empty one for a 204, and null for a 404 when [absentIsNull] is set. A
  /// request with a [token] carries it and a proof; one without carries a proof only, as a sign-in does.
  /// [proof] false sends neither (a route no key is bound to yet).
  Future<Map<String, Object?>?> call(
    String method,
    Uri server,
    String route, {
    String? token,
    Object? body,
    Map<String, String>? query,
    bool proof = true,
    bool absentIsNull = false,
    bool root = false,
    int maxBytes = maxJsonBytes,
    Map<String, String>? headers,
  }) async {
    // [root]: [route] is a path of the server itself (the Bitwarden API), not under `/kem/v1`
    var url = root ? server.replace(path: '${server.path}$route') : _api(server, route);
    if (query != null) url = url.replace(queryParameters: query);
    final res = await _send(method, url, token: token, json: body, proof: proof, maxBytes: maxBytes, headers: headers);
    if (absentIsNull && res.statusCode == 404) return null;
    if (res.statusCode == 204) return const {};
    return _expect(res);
  }

  /// One request to [route] under `/kem/v1` whose answer or body isn't a JSON object: a list, a file's bytes. [body]
  /// is JSON and [bytes] an octet stream; at most one is given. Returns the answer's bytes, never more than
  /// [maxBytes], when the status is 2xx; any other answer throws its [KmError]. [proof] false sends neither a token
  /// nor a proof, as a public route does. [timeout] stands in for the JSON timeout, for a file's.
  Future<Uint8List> callBytes(
    String method,
    Uri server,
    String route, {
    String? token,
    Object? body,
    Uint8List? bytes,
    bool proof = true,
    int maxBytes = maxJsonBytes,
    Duration? timeout,
    String accept = 'application/json',
  }) async {
    final res = await _send(
      method,
      _api(server, route),
      token: token,
      json: body,
      bytes: bytes,
      timeout: timeout,
      maxBytes: maxBytes,
      accept: accept,
      proof: proof,
    );
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
    return res.bodyBytes;
  }

  /// Like [call], for a route whose answer isn't an object, such as the list of a person's spaces: the answer's JSON,
  /// null for a 404 when [absentIsNull] is set. A 204 answers null too.
  Future<Object?> callValue(
    String method,
    Uri server,
    String route, {
    String? token,
    Object? body,
    Map<String, String>? query,
    bool absentIsNull = false,
    int maxBytes = maxPageBytes,
  }) async {
    var url = _api(server, route);
    if (query != null) {
      url = url.replace(queryParameters: query);
    }
    final res = await _send(method, url, token: token, json: body, maxBytes: maxBytes);
    if (absentIsNull && res.statusCode == 404) return null;
    if (res.statusCode == 204) return null;
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
    try {
      return jsonDecode(utf8.decode(res.bodyBytes));
    } on FormatException {
      throw KmError(KmProblem.server, status: res.statusCode, message: 'not JSON');
    }
  }

  // ─── Items ─────────────────────────────────────────────────────────────

  /// What changed since [since], the cursor of the last page read, or everything when null. Null when
  /// nothing did (304). A cursor the server no longer trusts throws a `fullSync` [KmError].
  ///
  /// The cursor holds one vector per owner and grows about 43 bytes with each space, so a long one goes in a
  /// `POST /kem/v1/sync` body, `{since, limit}`, which answers as the `GET` does. A server that has no such route
  /// (a 404 or 405) is asked with the `GET` again.
  // server: to confirm
  // `/config`'s `features` has no name for the POST route yet. When it has one, gate on it instead of the cursor's
  // length, so the `GET` stays for a server that doesn't list it.
  Future<KmSyncPage?> sync(Uri server, String token, {String? since, int limit = batchSize}) async {
    http.Response? res;
    if (since != null && since.length > postCursorLength) {
      final posted = await _send(
        'POST',
        _api(server, '/sync'),
        token: token,
        json: {'since': since, 'limit': limit},
        maxBytes: maxPageBytes,
      );
      if (posted.statusCode != 404 && posted.statusCode != 405) res = posted;
    }
    res ??= await _send(
      'GET',
      _api(server, '/sync').replace(queryParameters: {'since': ?since, 'limit': '$limit'}),
      token: token,
      maxBytes: maxPageBytes,
    );
    if (res.statusCode == 304) return null;
    final json = _expect(res);
    final items = json['items'];
    final cursor = json['cursor'];
    final more = json['more'];
    final siblings = json['siblings'];
    if (items is! List || cursor is! String || more is! bool || (siblings != null && siblings is! List)) {
      throw KmError(KmProblem.server, status: res.statusCode, message: 'a sync page');
    }
    try {
      return KmSyncPage(
        items: [for (final item in items) KmWireItem.fromJson(item)],
        cursor: cursor,
        more: more,
        siblings: [
          if (siblings is List<Object?>)
            for (final set in siblings) KmSiblingSet.fromJson(set),
        ],
      );
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, status: res.statusCode, message: e.message);
    }
  }

  /// Tells the server that the item's head, a merge of its siblings written as the next revision, replaces them
  /// (`POST /items/{id}/siblings/resolve`); returns how many it dropped. Null when it can't be done now: the head
  /// was already sent to another server (a 409 `siblings-already-sent`, which a newer version fixes at the next
  /// run), or the item isn't in the vault any more or the server has no federation (a 404).
  Future<int?> resolveSiblings(Uri server, String token, String itemId) async {
    final res = await _send('POST', _api(server, '/items/$itemId/siblings/resolve'), token: token);
    if (res.statusCode == 404) {
      return null;
    }
    if (res.statusCode == 409 && _slug(_jsonOrNull(res)) == siblingsSent) {
      return null;
    }
    final resolved = _expect(res)['resolved'];
    if (resolved is! int) {
      throw KmError(KmProblem.server, status: res.statusCode, message: 'a resolve answer');
    }
    return resolved;
  }

  /// Sends up to [batchSize] writes, all or none. A stale write throws a `stale` [KmError] naming its
  /// item, and nothing was stored. Returns the items as stored.
  Future<List<KmWireItem>> batch(Uri server, String token, List<KmWrite> writes) async => (await batchTagged(server, token, writes)).items;

  /// [batch] with the `cred` tags of some of the writes, by item id, sent beside each item's ciphertext as `tags`
  /// and `tagVersion` (the server takes both or neither, and drops them when server matching is off for the owner
  /// or they were made under another key version: the item is written either way). Returns the items as stored and
  /// the ids of those whose tags the server stored. A write with no entry in [tags] clears the item's tags there.
  Future<({List<KmWireItem> items, Set<String> tagged})> batchTagged(
    Uri server,
    String token,
    List<KmWrite> writes, {
    Map<String, KmTagSet> tags = const {},
  }) async {
    if (writes.isEmpty || writes.length > batchSize) throw ArgumentError.value(writes.length, 'writes', 'between 1 and $batchSize');
    final res = await _send(
      'POST',
      _api(server, '/items:batch'),
      token: token,
      json: {
        'writes': [
          for (final write in writes)
            {
              'expectedRevision': write.expected,
              'item': {...write.item.toJson(), ..._tagFields(tags[write.item.id])},
            },
        ],
      },
    );
    final json = _expect(res);
    final items = json['items'];
    if (items is! List) throw KmError(KmProblem.server, status: res.statusCode, message: 'a batch answer');
    final outcomes = json['tags'];
    try {
      return (
        items: [for (final item in items) KmWireItem.fromJson(item)],
        tagged: {
          if (outcomes is List<Object?>)
            for (final outcome in outcomes)
              if (outcome is Map<String, Object?> && outcome['stored'] == true && outcome['item'] is String) outcome['item']! as String,
        },
      );
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, status: res.statusCode, message: e.message);
    }
  }

  // ─── The manifest ──────────────────────────────────────────────────────

  /// The latest signed manifest of [owner] (`user:<uuid>`), `{manifest, signature}` as base64url among what
  /// the server answers (`{owner, counter, manifest, signature, signer, storedAt}`), or null when there is none yet.
  Future<({Uint8List manifest, Uint8List signature})?> manifest(Uri server, String token, String owner) async {
    final res = await _send('GET', _api(server, '/manifests/$owner'), token: token, maxBytes: maxPageBytes);
    if (res.statusCode == 404) return null;
    return _manifest(_expect(res), res.statusCode);
  }

  /// Sends the manifest a run signed, for [owner]. The counter is inside the manifest bytes; a counter at or
  /// below the stored one is a 409 `stale-manifest`, which the run reads as another device writing first.
  Future<void> putManifest(Uri server, String token, String owner, Uint8List manifest, Uint8List signature) async {
    final res = await _send(
      'PUT',
      _api(server, '/manifests/$owner'),
      token: token,
      json: {'manifest': b64urlEncode(manifest), 'signature': b64urlEncode(signature)},
    );
    _expect(res);
  }

  ({Uint8List manifest, Uint8List signature}) _manifest(Map<String, Object?> json, int status) {
    final manifest = json['manifest'];
    final signature = json['signature'];
    if (manifest is! String || signature is! String) throw KmError(KmProblem.server, status: status, message: 'a manifest answer');
    try {
      return (manifest: b64urlDecode(manifest), signature: b64urlDecode(signature));
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, status: status, message: e.message);
    }
  }

  // ─── The trusted-device copy ───────────────────────────────────────────

  /// This device's wrapped copy of the root key, with the `protection` it was stored under, or null
  /// when the server holds none (the phone is not trusted).
  Future<({Uint8List wrappedKey, String protection})?> keyCopy(Uri server, String token) async {
    final res = await _send('GET', _api(server, '/devices/key-copy'), token: token);
    if (res.statusCode == 404) return null;
    final json = _expect(res);
    final wrapped = json['wrappedKey'];
    final protection = json['protection'];
    if (wrapped is! String || protection is! String) throw KmError(KmProblem.server, status: res.statusCode, message: 'a key copy answer');
    try {
      return (wrappedKey: b64urlDecode(wrapped), protection: protection);
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, status: res.statusCode, message: e.message);
    }
  }

  /// Stores this device's wrapped copy of the root key, 1 to 1,024 bytes. [protection] is one of
  /// `secure-enclave`, `keystore`, `web-crypto` and `software`.
  Future<void> putKeyCopy(Uri server, String token, Uint8List wrappedKey, String protection) async {
    final res = await _send(
      'PUT',
      _api(server, '/devices/key-copy'),
      token: token,
      json: {'wrappedKey': b64urlEncode(wrappedKey), 'protection': protection},
    );
    _expect(res);
  }

  /// Deletes this device's copy: the phone is no longer trusted.
  Future<void> deleteKeyCopy(Uri server, String token) async {
    final res = await _send('DELETE', _api(server, '/devices/key-copy'), token: token);
    if (res.statusCode != 204 && res.statusCode != 404) throw _failure(res, _jsonOrNull(res));
  }

  // ─── Files ─────────────────────────────────────────────────────────────

  /// Starts an upload of a `KMA1` file of [size] bytes for the note [itemId]. The item must exist.
  Future<KmFileStart> startFile(Uri server, String token, String itemId, int size) async {
    final res = await _send('POST', _api(server, '/items/$itemId/files'), token: token, json: {'size': size});
    final json = _expect(res);
    final fileId = json['fileId'];
    final url = json['uploadUrl'];
    final max = asInt(json['maxSize']);
    if (fileId is! String || url is! String || max == null) {
      throw KmError(KmProblem.server, status: res.statusCode, message: 'a file answer');
    }
    return KmFileStart(
      fileId: fileId,
      size: asInt(json['size']) ?? size,
      maxSize: max,
      uploadUrl: url,
      presigned: json['presigned'] == true,
    );
  }

  /// Sends the file's [bytes] to where [start] says. The server's own address gets the token and a
  /// proof. A bucket address must be https and gets neither; the upload is then finished with a
  /// request to the server. An address on another host that isn't pre-signed is refused.
  Future<void> uploadFile(Uri server, String token, String itemId, KmFileStart start, Uint8List bytes) async {
    if (start.presigned) {
      final target = Uri.tryParse(start.uploadUrl);
      if (target == null || target.scheme != 'https' || target.host.isEmpty) throw const KmError(KmProblem.insecure);
      final res = await _send(
        'PUT',
        target,
        bytes: bytes,
        contentType: 'application/octet-stream',
        timeout: fileTimeout,
        proof: false,
        maxBytes: _maxProblemBytes,
      );
      if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
      final done = await _send('POST', _api(server, '/items/$itemId/files/${start.fileId}/finish'), token: token);
      _expect(done);
      return;
    }
    if (!kmSameServer(server, start.uploadUrl)) throw const KmError(KmProblem.server, message: 'the upload address is another host');
    final res = await _send(
      'PUT',
      _api(server, '/items/$itemId/files/${start.fileId}'),
      token: token,
      bytes: bytes,
      contentType: 'application/octet-stream',
      timeout: fileTimeout,
    );
    _expect(res);
  }

  /// A file's bytes, never more than [maxBytes]: an answer that promises or sends more is dropped
  /// and throws a `tooLarge` [KmError], and nothing is returned.
  Future<Uint8List> downloadFile(Uri server, String token, String itemId, String fileId, {required int maxBytes}) async {
    final res = await _send(
      'GET',
      _api(server, '/items/$itemId/files/$fileId'),
      token: token,
      timeout: fileTimeout,
      maxBytes: maxBytes,
      accept: 'application/octet-stream',
    );
    if (res.statusCode != 200) throw _failure(res, _jsonOrNull(res));
    return res.bodyBytes;
  }

  /// Removes a file's bytes from the server.
  Future<void> deleteFile(Uri server, String token, String itemId, String fileId) async {
    final res = await _send('DELETE', _api(server, '/items/$itemId/files/$fileId'), token: token);
    if (res.statusCode != 204 && res.statusCode != 404) throw _failure(res, _jsonOrNull(res));
  }

  // ─── Transport ─────────────────────────────────────────────────────────

  Future<http.Response> _send(
    String method,
    Uri url, {
    String? token,
    Object? json,
    Uint8List? bytes,
    String? contentType,
    Duration? timeout,
    int maxBytes = maxJsonBytes,
    String accept = 'application/json',
    bool proof = true,
    Map<String, String>? headers,
  }) async {
    for (var attempt = 0; ; attempt++) {
      // A redirect is never followed: it would take the phone, and its credentials, wherever the server
      // said, another host or plain http. The Kemlock API needs none; one is the server's error.
      final request = http.Request(method, url)
        ..followRedirects = false
        ..headers['Accept'] = accept;
      if (headers != null) {
        request.headers.addAll(headers);
      }
      final signer = proofs;
      if (proof) {
        if (token != null) request.headers['Authorization'] = 'DPoP $token';
        if (signer != null) request.headers['DPoP'] = await signer.proof(method, url, accessToken: token);
      }
      if (json != null) {
        request.headers['Content-Type'] = 'application/json';
        request.bodyBytes = utf8.encode(jsonEncode(json));
      } else if (bytes != null) {
        request.headers['Content-Type'] = contentType ?? 'application/octet-stream';
        request.bodyBytes = bytes;
      }
      final http.Response res;
      try {
        // Read up to a limit: the server could send an answer that never ends
        // The first byte is the answer's headers: a server that gives none in time is down, as far as failover goes
        final first = timeout == null ? firstByte : null;
        res = await (() async {
          final started = client.send(request);
          final streamed = first == null ? await started : await started.timeout(first, onTimeout: () => throw const _NoFirstByte());
          return readAnswer(streamed, maxBytes);
        })().timeout(timeout ?? this.timeout);
      } on _NoFirstByte {
        throw const KmError(KmProblem.network, timedOut: true);
      } on AnswerTooLarge {
        throw const KmError(KmProblem.tooLarge, message: 'The answer is larger than it should be');
      } on KmError {
        rethrow;
      } catch (error) {
        // A handshake failure is as over a certificate the phone refused
        if (isTlsFailure(error)) throw const KmError(KmProblem.network, handshakeFailed: true);
        throw const KmError(KmProblem.network);
      }
      signer?.observe(url, res.headers);
      if (res.statusCode >= 300 && res.statusCode < 400 && res.statusCode != 304) {
        throw KmError(KmProblem.server, status: res.statusCode, message: 'The server answered with a redirect');
      }
      // The server hands out its nonce with a 401 and wants the proof made again, once
      if (proof && signer != null && attempt == 0 && res.statusCode == 401 && _wantsNonce(res)) continue;
      return res;
    }
  }

  bool _wantsNonce(http.Response res) {
    if ((res.headers['www-authenticate'] ?? '').contains('use_dpop_nonce')) return true;
    final json = _jsonOrNull(res);
    return json?['error'] == 'use_dpop_nonce' || '${json?['type']}'.endsWith(':use-dpop-nonce');
  }
}

/// `tags` and `tagVersion` of [set], which an item of a write carries beside its ciphertext; none for no tags.
Map<String, Object?> _tagFields(KmTagSet? set) => set == null
    ? const {}
    : {
        'tags': [for (final tag in set.tags) b64urlEncode(tag)],
        'tagVersion': set.version,
      };

Map<String, Object?>? _jsonOrNull(http.Response res) {
  try {
    final value = jsonDecode(utf8.decode(res.bodyBytes, allowMalformed: true));
    return value is Map<String, Object?> ? value : null;
  } on FormatException {
    return null;
  }
}

Map<String, Object?> _expect(http.Response res) {
  final json = _jsonOrNull(res);
  if (res.statusCode >= 200 && res.statusCode < 300 && json != null) return json;
  if (res.statusCode >= 200 && res.statusCode < 300) throw KmError(KmProblem.server, status: res.statusCode, message: 'not JSON');
  throw _failure(res, json);
}

/// The problem an answer says: its `type`'s last part, `urn:kemlock:problem:<slug>`.
String? _slug(Map<String, Object?>? json) {
  final type = json?['type'];
  if (type is! String) return null;
  const prefix = 'urn:kemlock:problem:';
  return type.startsWith(prefix) ? type.substring(prefix.length) : null;
}

KmError _failure(http.Response res, Map<String, Object?>? json) {
  final slug = _slug(json);
  final message = asOptionalString(json?['detail']) ?? asOptionalString(json?['title']);
  final status = res.statusCode;
  if (status == 401 && slug == 'session-ended') {
    return KmError(KmProblem.sessionEnded, status: status, message: message, reason: asOptionalString(json?['reason']));
  }
  if (status == 403 && slug == 'sso-required') {
    return KmError(KmProblem.ssoRequired, status: status, message: message, spaceId: asOptionalString(json?['spaceId']));
  }
  if (status == 409) {
    return KmError(
      KmProblem.stale,
      status: status,
      message: message,
      itemId: asOptionalString(json?['itemId']),
      currentRevision: asInt(json?['currentRevision']),
      head: json?['head'],
      slug: slug,
      tagVersion: asInt(json?['currentTagVersion']),
    );
  }
  return switch (status) {
    401 || 403 => KmError(KmProblem.auth, status: status, message: message, slug: slug),
    410 => KmError(KmProblem.fullSync, status: status, message: message, slug: slug),
    413 => KmError(KmProblem.tooLarge, status: status, message: message, slug: slug, maxSize: asInt(json?['maxSize'])),
    422 => KmError(
      KmProblem.server,
      status: status,
      message: message,
      reason: asOptionalString(json?['reason']),
      seq: asInt(json?['seq']),
      slug: slug,
    ),
    429 => KmError(
      KmProblem.rateLimited,
      status: status,
      message: message,
      retryAfter: asInt(json?['retryAfter']) ?? int.tryParse(res.headers['retry-after'] ?? ''),
      slug: slug,
    ),
    _ => KmError(KmProblem.server, status: status, message: message, slug: slug),
  };
}

/// Calls the API with a live access token: renews it when it is about to end, or when the server
/// refuses it, and keeps each new session before the request that uses it, so a crash never leaves
/// the phone holding a refresh token the server has already used (which ends the session).
/// One renewal runs at a time: a second caller waits for it.
class KmConnection {
  KmConnection({required this.api, required this.server, required this._session, required this.save, this.clock = DateTime.now});

  final KmApi api;
  final Uri server;

  /// Stores a session whose tokens were renewed, sealed, before it is used.
  final Future<void> Function(KmSession session) save;
  final DateTime Function() clock;

  KmSession _session;
  Future<void>? _renewing;

  /// The session as it is now.
  KmSession get session => _session;

  /// How long before an access token ends it is renewed.
  static const _margin = Duration(seconds: 30);

  /// Runs [request] with the access token. A token that ended, or that the server refuses, is renewed
  /// once; a session the server ended throws its `sessionEnded` [KmError].
  Future<T> call<T>(Future<T> Function(String token) request) async {
    if (clock().millisecondsSinceEpoch + _margin.inMilliseconds >= _session.tokens.accessExpiresAt) await _renew(_session.tokens.refresh);
    try {
      return await request(_session.tokens.access);
    } on KmError catch (e) {
      if (e.problem != KmProblem.auth || e.status != 401) rethrow;
      await _renew(_session.tokens.refresh);
      return request(_session.tokens.access);
    }
  }

  Future<void> _renew(String refreshToken) {
    // A renewal that already ran for this token is not run again
    if (_session.tokens.refresh != refreshToken) return Future.value();
    return _renewing ??= _doRenew(refreshToken).whenComplete(() => _renewing = null);
  }

  Future<void> _doRenew(String refreshToken) async {
    try {
      final tokens = await api.refresh(server, refreshToken);
      final next = _session.withTokens(tokens);
      await save(next);
      _session = next;
    } on KmError catch (e) {
      // A refresh token the server doesn't know is a session that is over
      if (e.problem == KmProblem.auth) throw KmError(KmProblem.sessionEnded, status: e.status, message: e.message, reason: 'expired');
      rethrow;
    }
  }
}

/// No first byte came within [KmApi.firstByte].
class _NoFirstByte implements Exception {
  const _NoFirstByte();
}
