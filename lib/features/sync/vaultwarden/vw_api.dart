/// Just enough of the Bitwarden API, as Vaultwarden serves it, for sync:
/// signing in (with a second step or a personal API key), refreshing the
/// token, the account's revision date, the whole vault, creating, updating,
/// trashing and restoring items and folders, and items' attachments.
///
/// Requests go straight to the server with `package:http`; nothing passes
/// through a Kemlock server. Only https servers are accepted, and an
/// attachment's data is sent to and fetched from the server's own host
/// only ([sameServer]).
library;

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../../../core/network/answers.dart' show AnswerTooLarge, readAnswer;
import '../../../core/network/tls_failure.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import 'vw_items.dart' show sshKeyItemsVersion, versionAtLeast;

/// What went wrong talking to the server. The names are the ends of the
/// `vaultwarden.problem.*` message ids.
enum VwProblem {
  /// The address isn't https, which would send the password in the clear.
  insecure,

  /// The address isn't a URL, or no Bitwarden-compatible server answers there.
  address,

  /// The email, master password or API key is wrong.
  auth,

  /// The code for the second step is wrong.
  code,

  /// The session ended (password changed, device removed, sessions revoked):
  /// sign in again.
  signedOut,

  /// The item changed on the server since it was read: read again and merge.
  outOfDate,

  /// The server couldn't be reached, or its certificate isn't trusted.
  network,

  /// The account uses something this app can't do yet, such as another kind
  /// of encryption.
  unsupported,

  /// Any other answer.
  server,
}

/// A failed request.
class VwError implements Exception {
  const VwError(this.problem, {this.status = 0, this.message, this.handshakeFailed = false});

  final VwProblem problem;

  /// The HTTP status, or 0 when there was no answer.
  final int status;

  /// The server's own words, for logs.
  final String? message;

  /// For [VwProblem.network]: the connection broke off at its TLS
  /// handshake, as it does when the phone refuses the server's certificate.
  /// Only then may setup offer to trust a certificate.
  final bool handshakeFailed;

  @override
  String toString() =>
      'Vaultwarden ${problem.name}${handshakeFailed ? ' (handshake)' : ''}${status != 0 ? ' ($status)' : ''}${message != null ? ': $message' : ''}';
}

/// The server's address, checked: https, with a host. Throws a [VwError]:
/// `insecure` for http, `address` for anything else that isn't a URL. A
/// trailing slash and anything after the host's path are kept as typed, so a
/// server under a path (`https://example.com/vault`) works.
Uri vwServerUrl(String text) {
  final url = Uri.tryParse(text.trim());
  if (url == null || !url.hasScheme) throw const VwError(VwProblem.address);
  if (url.scheme == 'http') throw const VwError(VwProblem.insecure);
  if (url.scheme != 'https' || url.host.isEmpty) throw const VwError(VwProblem.address);
  final path = url.path.endsWith('/') ? url.path.substring(0, url.path.length - 1) : url.path;
  return Uri(scheme: 'https', host: url.host, port: url.hasPort ? url.port : null, path: path);
}

/// Where [server]'s web vault shows the item [cipherId]: the web vault's
/// own link to an item, which opens it to view.
Uri vwWebVaultItem(String server, String cipherId) =>
    Uri.parse('${vwServerUrl(server)}/#/vault?itemId=${Uri.encodeQueryComponent(cipherId)}');

/// The host a server is at, for status lines: `vault.example.com`, with the
/// port when it isn't https's own.
String vwHost(String server) {
  final url = Uri.tryParse(server.trim());
  if (url == null || url.host.isEmpty) return server;
  return url.hasPort ? '${url.host}:${url.port}' : url.host;
}

/// Who the app says it is to the server: the Bitwarden device type, and the names and version sent as the client's.
/// The app makes it from the phone it runs on (iOS is device type 1, Android 0); the defaults are the Android phone's,
/// and a build that isn't the phone (the browser extension's core) passes its own. Pure Dart.
class VwClientInfo {
  const VwClientInfo({
    this.deviceType = 0,
    this.deviceName = 'Kemlock',
    this.clientName = 'kemlock',
    this.clientVersion = '1.1.0',
    this.clientId = 'mobile',
  });

  /// Bitwarden's device type: 0 for Android, 1 for iOS.
  final int deviceType;

  /// How the device shows up in the account's list of devices.
  final String deviceName;

  /// Sent as `Bitwarden-Client-Name`.
  final String clientName;

  /// This app's version, sent as `Bitwarden-Client-Version`: Vaultwarden logs an error for each sync without it.
  final String clientVersion;

  /// Sent as the token request's `client_id`.
  final String clientId;
}

/// How this phone shows up in the account's list of devices.
class VwDevice {
  const VwDevice({required this.id, required this.type, this.name = 'Kemlock'});

  /// A UUID, made once per vault.
  final String id;

  /// Bitwarden's device type: 0 for Android, 1 for iOS.
  final int type;
  final String name;
}

/// The second step's providers, by Bitwarden's numbers.
abstract final class VwTwoFactor {
  static const authenticator = 0;
  static const email = 1;
  static const duo = 2;
  static const yubikey = 3;
  static const remember = 5;
  static const webauthn = 7;

  /// The ones this app can do: each is a code typed in.
  static const supported = {authenticator, email, yubikey};
}

/// The code for the second step, as sent with the password again.
class VwSecondStep {
  const VwSecondStep({required this.provider, required this.code, this.remember = false});

  final int provider;
  final String code;

  /// Ask the server to remember this device, so the next sign-in skips the step.
  final bool remember;
}

/// An access token, the refresh token that renews it, and when it ends.
class VwTokens {
  const VwTokens({required this.access, required this.refresh, required this.expiresAt});

  final String access;

  /// Empty after signing in with an API key, which gives none: the key signs
  /// in again instead.
  final String refresh;

  /// Epoch ms.
  final int expiresAt;

  /// Leaves the tokens out, so they never end up in a log.
  @override
  String toString() => 'VwTokens(expiresAt: $expiresAt)';
}

/// What a sign-in returned.
sealed class VwLogin {
  const VwLogin();
}

/// Signed in.
class VwSignedIn extends VwLogin {
  const VwSignedIn({required this.tokens, required this.userId, this.key, this.kdf, this.rememberToken});

  final VwTokens tokens;

  /// The account's id, from the access token.
  final String userId;

  /// The user key, encrypted (`Key`).
  final String? key;

  /// The account's KDF, when the answer has it.
  final BwKdf? kdf;

  /// The token that skips the second step next time (`TwoFactorToken`).
  final String? rememberToken;

  @override
  String toString() => 'VwSignedIn($userId, $tokens)';
}

/// The account has a second step; send the password again with a code.
class VwSecondStepNeeded extends VwLogin {
  const VwSecondStepNeeded({required this.providers, this.details = const {}});

  /// The providers the account has, by number.
  final List<int> providers;

  /// What each provider said, by number as text: for email, the obscured
  /// address (`{"Email": "m***@example.com"}`).
  final Map<String, Object?> details;

  @override
  String toString() => 'VwSecondStepNeeded($providers)';
}

/// A JSON value's key, whatever its case: Vaultwarden answers in camelCase,
/// and older releases in PascalCase.
Object? jsonKey(Map<String, Object?> json, String key) {
  if (json.containsKey(key)) return json[key];
  final wanted = key.toLowerCase();
  for (final MapEntry(key: name, :value) in json.entries) {
    if (name.toLowerCase() == wanted) return value;
  }
  return null;
}

/// Talks to Vaultwarden servers through [client], which tests replace with
/// a `MockClient`, and which pins a certificate when setup asked for it.
class VwApi {
  VwApi(this.client, {this.timeout = const Duration(seconds: 60), this.clock = DateTime.now, this.info = const VwClientInfo()});

  final http.Client client;

  /// Who this app says it is: the device type, and the client's name, version and id.
  final VwClientInfo info;

  /// This app's version, sent as `Bitwarden-Client-Version`.
  String get clientVersion => info.clientVersion;

  /// How long a request may take before it counts as a `network` problem.
  final Duration timeout;

  final DateTime Function() clock;

  // ─── Before signing in ─────────────────────────────────────────────────

  /// The server's `/api/config`. Throws an `address` [VwError] when what
  /// answers isn't a Bitwarden-compatible server.
  Future<Map<String, Object?>> config(Uri server) async {
    final res = await _send('GET', _api(server, '/config'));
    final json = _jsonOrNull(res);
    if (res.statusCode != 200 || json == null || jsonKey(json, 'object') != 'config') {
      throw VwError(VwProblem.address, status: res.statusCode);
    }
    return json;
  }

  /// The account's KDF. Vaultwarden answers for any email, made-up ones too,
  /// so as not to say which accounts exist.
  Future<BwKdf> prelogin(Uri server, String email) async {
    final res = await _send('POST', _identity(server, '/accounts/prelogin'), json: {'email': email.trim()});
    final json = _expect(res);
    try {
      return BwKdf.fromJson(json);
    } on FormatException catch (e) {
      throw VwError(VwProblem.unsupported, status: res.statusCode, message: e.message);
    }
  }

  /// Signs in with the master password's hash ([bwMasterPasswordHash]), and
  /// the second step's code when [step] is given. A wrong password throws an
  /// `auth` [VwError], a wrong code a `code` one.
  Future<VwLogin> signIn(
    Uri server, {
    required String email,
    required String passwordHash,
    required VwDevice device,
    VwSecondStep? step,
    String? rememberToken,
  }) => _token(server, {
    'grant_type': 'password',
    'username': email.trim(),
    'password': passwordHash,
    'scope': 'api offline_access',
    'client_id': info.clientId,
    ..._deviceFields(device),
    if (step != null) ...{
      'twoFactorProvider': '${step.provider}',
      'twoFactorToken': step.code.trim(),
      'twoFactorRemember': step.remember ? '1' : '0',
    } else if (rememberToken != null) ...{
      'twoFactorProvider': '${VwTwoFactor.remember}',
      'twoFactorToken': rememberToken,
      'twoFactorRemember': '0',
    },
  }, step: step);

  /// Signs in with the account's personal API key, which skips the second
  /// step. The master password is still needed to open the user key.
  Future<VwSignedIn> signInWithApiKey(
    Uri server, {
    required String clientId,
    required String clientSecret,
    required VwDevice device,
  }) async {
    final login = await _token(server, {
      'grant_type': 'client_credentials',
      'client_id': clientId.trim(),
      'client_secret': clientSecret.trim(),
      'scope': 'api',
      ..._deviceFields(device),
    }, apiKey: true);
    if (login is! VwSignedIn) throw const VwError(VwProblem.auth);
    return login;
  }

  /// Renews the access token. A refused refresh token throws a `signedOut`
  /// [VwError]. The answer's refresh token replaces the old one when it has
  /// one.
  Future<VwTokens> refresh(Uri server, String refreshToken) async {
    final res = await _send(
      'POST',
      _identity(server, '/connect/token'),
      form: {'grant_type': 'refresh_token', 'client_id': info.clientId, 'refresh_token': refreshToken},
    );
    final json = _jsonOrNull(res);
    if (res.statusCode == 400 || res.statusCode == 401) throw VwError(VwProblem.signedOut, status: res.statusCode, message: _message(json));
    if (res.statusCode != 200 || json == null) throw _failure(res, json);
    return _tokens(json, fallbackRefresh: refreshToken);
  }

  /// Asks the server to email the second step's code.
  Future<void> sendEmailCode(Uri server, {required String email, required String passwordHash, required VwDevice device}) async {
    final res = await _send(
      'POST',
      _api(server, '/two-factor/send-email-login'),
      json: {'email': email.trim(), 'masterPasswordHash': passwordHash, 'deviceIdentifier': device.id},
    );
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
  }

  // ─── Signed in ─────────────────────────────────────────────────────────

  /// When anything in the account last changed, epoch ms.
  Future<int> revisionDate(Uri server, String token) async {
    final res = await _send('GET', _api(server, '/accounts/revision-date'), token: token);
    if (res.statusCode != 200) throw _failure(res, _jsonOrNull(res));
    final value = jsonDecode(res.body);
    if (value is! num) throw VwError(VwProblem.server, status: res.statusCode);
    return value.toInt();
  }

  /// The whole vault, still encrypted: `profile`, `folders`, `ciphers`, ….
  /// Vaultwarden leaves SSH key items out for clients that say they are
  /// older than Bitwarden's [sshKeyItemsVersion], so this asks as that
  /// version at least.
  Future<Map<String, Object?>> sync(Uri server, String token) async {
    final version = versionAtLeast(clientVersion, sshKeyItemsVersion) ? clientVersion : sshKeyItemsVersion;
    final res = await _send(
      'GET',
      _api(server, '/sync', {'excludeDomains': 'true'}),
      token: token,
      clientVersion: version,
      maxBytes: maxVaultBytes,
    );
    return _expect(res);
  }

  /// Makes a folder; [name] is already encrypted. Returns it as the server keeps it.
  Future<Map<String, Object?>> createFolder(Uri server, String token, String name) async =>
      _expect(await _send('POST', _api(server, '/folders'), token: token, json: {'name': name}));

  /// Makes an item from [cipher], an encrypted item as `/api/sync` shows
  /// one. Returns it as the server keeps it.
  Future<Map<String, Object?>> createCipher(Uri server, String token, Map<String, Object?> cipher) async =>
      _expect(await _send('POST', _api(server, '/ciphers'), token: token, json: cipher));

  /// Replaces the item [id] with [cipher]. With `lastKnownRevisionDate` in
  /// [cipher], an item changed since then throws an `outOfDate` [VwError].
  Future<Map<String, Object?>> updateCipher(Uri server, String token, String id, Map<String, Object?> cipher) async =>
      _expect(await _send('PUT', _api(server, '/ciphers/${Uri.encodeComponent(id)}'), token: token, json: cipher));

  /// Moves the item [id] to the trash.
  Future<void> trashCipher(Uri server, String token, String id) async {
    final res = await _send('PUT', _api(server, '/ciphers/${Uri.encodeComponent(id)}/delete'), token: token);
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
  }

  /// Takes the item [id] back out of the trash, and returns it.
  Future<Map<String, Object?>> restoreCipher(Uri server, String token, String id) async =>
      _expect(await _send('PUT', _api(server, '/ciphers/${Uri.encodeComponent(id)}/restore'), token: token));

  // ─── Attachments ───────────────────────────────────────────────────────

  /// Asks the server to keep an attachment of the item [cipherId], the
  /// first of the two steps of Bitwarden's upload: [key] and [fileName] are
  /// already encrypted with the item's key, and [fileSize] is the encrypted
  /// data's length. Throws a [VwFilesRefused] (`none`) when the server takes
  /// no files: attachments off, its storage full, or a file too large.
  Future<VwAttachmentUpload> startAttachmentUpload(
    Uri server,
    String token,
    String cipherId, {
    required String key,
    required String fileName,
    required int fileSize,
  }) async {
    final res = await _send(
      'POST',
      _api(server, '/ciphers/${Uri.encodeComponent(cipherId)}/attachment/v2'),
      token: token,
      json: {'key': key, 'fileName': fileName, 'fileSize': fileSize, 'adminRequest': false},
    );
    final json = _jsonOrNull(res);
    if (_takesNoFiles(res.statusCode, _message(json))) throw VwFilesRefused(VwFilesRefusal.none, message: _message(json));
    final body = _expect(res);
    final id = jsonKey(body, 'attachmentId');
    if (id is! String || id.isEmpty) throw const VwError(VwProblem.server, message: 'No attachment id');
    final type = jsonKey(body, 'fileUploadType');
    final url = jsonKey(body, 'url');
    final cipher = jsonKey(body, 'cipherResponse');
    return VwAttachmentUpload(
      attachmentId: id,
      url: url is String ? url : null,
      fileUploadType: type is num ? type.toInt() : 0,
      cipher: cipher is Map<String, Object?> ? cipher : null,
    );
  }

  /// Sends an attachment's [data], the second step, to the server's own
  /// API. A server that wants the data elsewhere (another upload type, or
  /// an address on another host) gets nothing: a [VwFilesRefused]
  /// (`elsewhere`) is thrown before anything is sent, and the caller deletes
  /// the attachment the first step made. [fileName] is the encrypted name.
  Future<void> uploadAttachment(
    Uri server,
    String token,
    String cipherId,
    VwAttachmentUpload upload,
    Uint8List data, {
    String fileName = 'data',
  }) async {
    if (upload.fileUploadType != directUpload || (upload.url != null && !sameServer(server, upload.url!))) {
      throw const VwFilesRefused(VwFilesRefusal.elsewhere);
    }
    const boundary = '----kemlock-attachment-boundary-7MA4YWxkTrZu0gW';
    final head = utf8.encode(
      '--$boundary\r\n'
      'Content-Disposition: form-data; name="data"; filename="${fileName.replaceAll('"', '')}"\r\n'
      'Content-Type: application/octet-stream\r\n\r\n',
    );
    final tail = utf8.encode('\r\n--$boundary--\r\n');
    final res = await _send(
      'POST',
      _api(server, '/ciphers/${Uri.encodeComponent(cipherId)}/attachment/${Uri.encodeComponent(upload.attachmentId)}'),
      token: token,
      bytes: concatBytes([head, data, tail]),
      contentType: 'multipart/form-data; boundary=$boundary',
      timeout: transferTimeout,
    );
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
  }

  /// Where the attachment [attachmentId] of the item [cipherId] can be
  /// downloaded from. A [VwFilesRefused] (`elsewhere`) when the server keeps
  /// it on another host.
  Future<Uri> attachmentAddress(Uri server, String token, String cipherId, String attachmentId) async {
    final json = _expect(
      await _send(
        'GET',
        _api(server, '/ciphers/${Uri.encodeComponent(cipherId)}/attachment/${Uri.encodeComponent(attachmentId)}'),
        token: token,
      ),
    );
    final url = jsonKey(json, 'url');
    if (url is! String || url.isEmpty) throw const VwError(VwProblem.server, message: 'No attachment address');
    if (!sameServer(server, url)) throw const VwFilesRefused(VwFilesRefusal.elsewhere);
    return _resolve(server, url);
  }

  /// The encrypted data at [address], from [attachmentAddress]: refused with
  /// a [VwFilesRefused] without being contacted when it's on another host
  /// than [server], and with a `server` [VwError] past [maxBytes].
  Future<Uint8List> downloadAttachment(Uri server, Uri address, {required int maxBytes}) async {
    if (!sameServer(server, address.toString())) throw const VwFilesRefused(VwFilesRefusal.elsewhere);
    final request = http.Request('GET', address)
      ..headers['Accept'] = 'application/octet-stream'
      ..headers['Bitwarden-Client-Name'] = info.clientName
      ..headers['Bitwarden-Client-Version'] = clientVersion
      ..followRedirects = false;
    final http.StreamedResponse res;
    try {
      res = await client.send(request).timeout(transferTimeout);
    } catch (_) {
      throw const VwError(VwProblem.network);
    }
    if (res.statusCode != 200) {
      await res.stream.drain<void>().catchError((Object _) {});
      throw VwError(res.statusCode == 401 ? VwProblem.signedOut : VwProblem.server, status: res.statusCode);
    }
    final out = BytesBuilder(copy: false);
    try {
      await for (final chunk in res.stream.timeout(transferTimeout)) {
        out.add(chunk);
        if (out.length > maxBytes) throw const VwError(VwProblem.server, message: 'The attachment is larger than it should be');
      }
    } on VwError {
      rethrow;
    } catch (_) {
      throw const VwError(VwProblem.network);
    }
    return out.takeBytes();
  }

  /// Deletes the attachment [attachmentId] of the item [cipherId].
  Future<void> deleteAttachment(Uri server, String token, String cipherId, String attachmentId) async {
    final res = await _send(
      'DELETE',
      _api(server, '/ciphers/${Uri.encodeComponent(cipherId)}/attachment/${Uri.encodeComponent(attachmentId)}'),
      token: token,
    );
    if (res.statusCode < 200 || res.statusCode >= 300) throw _failure(res, _jsonOrNull(res));
  }

  /// How long an attachment's data may take to send or fetch.
  static const transferTimeout = Duration(minutes: 10);

  /// The most of the whole vault ([sync]) read from a server: an item is a
  /// few kilobytes, its notes 10,000 characters at most, so this holds tens
  /// of thousands of them.
  static const maxVaultBytes = 128 * 1024 * 1024;

  /// The most of any other answer: one item, a folder, a token or the
  /// server's settings.
  static const maxAnswerBytes = 4 * 1024 * 1024;

  /// Bitwarden's upload type for data sent to the server's own API.
  static const directUpload = 0;

  // ─── Plumbing ──────────────────────────────────────────────────────────

  Uri _api(Uri server, String path, [Map<String, String>? query]) =>
      server.replace(path: '${server.path}/api$path', queryParameters: query);

  Uri _identity(Uri server, String path) => server.replace(path: '${server.path}/identity$path');

  Map<String, String> _deviceFields(VwDevice device) => {
    'deviceType': '${device.type}',
    'deviceIdentifier': device.id,
    'deviceName': device.name,
  };

  Future<VwLogin> _token(Uri server, Map<String, String> form, {VwSecondStep? step, bool apiKey = false}) async {
    final res = await _send('POST', _identity(server, '/connect/token'), form: form);
    final json = _jsonOrNull(res);
    if (res.statusCode == 200 && json != null) {
      final tokens = _tokens(json, fallbackRefresh: apiKey ? '' : null);
      final key = jsonKey(json, 'Key');
      final remember = jsonKey(json, 'TwoFactorToken');
      BwKdf? kdf;
      try {
        kdf = BwKdf.fromJson({
          'kdf': jsonKey(json, 'Kdf'),
          'kdfIterations': jsonKey(json, 'KdfIterations'),
          'kdfMemory': jsonKey(json, 'KdfMemory'),
          'kdfParallelism': jsonKey(json, 'KdfParallelism'),
        });
      } on FormatException {
        kdf = null;
      }
      return VwSignedIn(
        tokens: tokens,
        userId: _subject(tokens.access),
        key: key is String && key.isNotEmpty ? key : null,
        kdf: kdf,
        rememberToken: remember is String && remember.isNotEmpty ? remember : null,
      );
    }
    if (json != null && (res.statusCode == 400 || res.statusCode == 401)) {
      final providers = jsonKey(json, 'TwoFactorProviders');
      if (providers is List && providers.isNotEmpty) {
        final details = jsonKey(json, 'TwoFactorProviders2');
        return VwSecondStepNeeded(
          providers: [for (final provider in providers) ?int.tryParse('$provider')],
          details: details is Map<String, Object?> ? details : const {},
        );
      }
      throw VwError(step != null ? VwProblem.code : VwProblem.auth, status: res.statusCode, message: _message(json));
    }
    throw _failure(res, json);
  }

  VwTokens _tokens(Map<String, Object?> json, {String? fallbackRefresh}) {
    final access = jsonKey(json, 'access_token');
    final refresh = jsonKey(json, 'refresh_token');
    final expires = jsonKey(json, 'expires_in');
    if (access is! String || access.isEmpty) throw const VwError(VwProblem.server, message: 'No access token');
    final refreshToken = refresh is String && refresh.isNotEmpty ? refresh : fallbackRefresh;
    if (refreshToken == null) throw const VwError(VwProblem.server, message: 'No refresh token');
    final seconds = expires is num ? expires.toInt() : 3600;
    return VwTokens(access: access, refresh: refreshToken, expiresAt: clock().millisecondsSinceEpoch + seconds * 1000);
  }

  Future<http.Response> _send(
    String method,
    Uri url, {
    String? token,
    Map<String, Object?>? json,
    Map<String, String>? form,
    String? clientVersion,
    Uint8List? bytes,
    String? contentType,
    Duration? timeout,
    int maxBytes = maxAnswerBytes,
  }) async {
    // A redirect is never followed, as for attachments: it would take the phone wherever the server
    // said, another host or plain http. Bitwarden's API needs none; one is the server's error.
    final request = http.Request(method, url)
      ..followRedirects = false
      ..headers['Accept'] = 'application/json'
      ..headers['Bitwarden-Client-Name'] = info.clientName
      ..headers['Bitwarden-Client-Version'] = clientVersion ?? info.clientVersion;
    if (token != null) request.headers['Authorization'] = 'Bearer $token';
    if (json != null) {
      request.headers['Content-Type'] = 'application/json';
      request.bodyBytes = utf8.encode(jsonEncode(json));
    } else if (form != null) {
      request.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=utf-8';
      request.bodyBytes = utf8.encode(Uri(queryParameters: form).query);
    } else if (bytes != null) {
      request.headers['Content-Type'] = contentType ?? 'application/octet-stream';
      request.bodyBytes = bytes;
    }
    // Read up to a limit: the server could send an answer that never ends
    Future<http.Response> send() async => readAnswer(await client.send(request), maxBytes);
    try {
      return await send().timeout(timeout ?? this.timeout);
    } on AnswerTooLarge {
      throw const VwError(VwProblem.server, message: 'The answer is larger than it should be');
    } catch (error) {
      // A handshake failure is as over a certificate the phone refused
      if (isTlsFailure(error)) throw const VwError(VwProblem.network, handshakeFailed: true);
      throw const VwError(VwProblem.network);
    }
  }
}

/// Why attached files don't go to a server.
enum VwFilesRefusal {
  /// It takes none: attachments are off, its storage is full, or the file
  /// is too large.
  none,

  /// It keeps them at another address, which Kemlock never contacts.
  elsewhere,
}

/// Attached files can't go to this server: nothing was sent, and sync goes
/// on without them.
class VwFilesRefused implements Exception {
  const VwFilesRefused(this.reason, {this.message});

  final VwFilesRefusal reason;

  /// The server's own words, for logs.
  final String? message;

  @override
  String toString() => 'VwFilesRefused(${reason.name}${message != null ? ': $message' : ''})';
}

/// The first step of an upload, as the server answered it.
class VwAttachmentUpload {
  const VwAttachmentUpload({required this.attachmentId, required this.fileUploadType, this.url, this.cipher});

  final String attachmentId;

  /// Bitwarden's upload type: 0 for the server's own API, 1 for Azure.
  final int fileUploadType;

  /// Where the data goes; for the server's own API, relative to it.
  final String? url;

  /// The item as it is now, attachment included.
  final Map<String, Object?>? cipher;

  @override
  String toString() => 'VwAttachmentUpload($attachmentId, type $fileUploadType)';
}

/// Whether [url], absolute or relative to [server], is on [server]'s host:
/// https, the same host and the same port.
bool sameServer(Uri server, String url) {
  final parsed = Uri.tryParse(url.trim());
  if (parsed == null) return false;
  if (!parsed.hasScheme && !parsed.hasAuthority) return true;
  return parsed.scheme == 'https' && parsed.host.toLowerCase() == server.host.toLowerCase() && parsed.port == server.port;
}

Uri _resolve(Uri server, String url) {
  final parsed = Uri.parse(url.trim());
  return parsed.hasScheme ? parsed : server.replace(path: '${server.path}${parsed.path}', query: parsed.hasQuery ? parsed.query : null);
}

/// Whether an answer to the first step of an upload says the server takes
/// no files, rather than that something else went wrong.
bool _takesNoFiles(int status, String? message) {
  if (status < 400 || status == 401 || status >= 500 && status != 501) return false;
  return !(message ?? '').toLowerCase().contains('cipher');
}

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
  throw _failure(res, json);
}

String? _message(Map<String, Object?>? json) {
  if (json == null) return null;
  for (final key in const ['message', 'error_description', 'error']) {
    final value = jsonKey(json, key);
    if (value is String && value.isNotEmpty) return value;
  }
  return null;
}

VwError _failure(http.Response res, Map<String, Object?>? json) {
  final message = _message(json);
  return switch (res.statusCode) {
    401 => VwError(VwProblem.signedOut, status: res.statusCode, message: message),
    400 when message != null && message.contains('out of date') => VwError(VwProblem.outOfDate, status: res.statusCode, message: message),
    _ => VwError(VwProblem.server, status: res.statusCode, message: message),
  };
}

/// The `sub` claim of a JWT, the account's id for Bitwarden's tokens.
String _subject(String jwt) {
  final parts = jwt.split('.');
  if (parts.length != 3) throw const VwError(VwProblem.server, message: 'The access token is not a JWT');
  try {
    final claims = jsonDecode(utf8.decode(unb64url(parts[1])));
    final sub = claims is Map<String, Object?> ? claims['sub'] : null;
    if (sub is String && sub.isNotEmpty) return sub;
  } catch (_) {
    // Falls through
  }
  throw const VwError(VwProblem.server, message: 'The access token has no subject');
}
