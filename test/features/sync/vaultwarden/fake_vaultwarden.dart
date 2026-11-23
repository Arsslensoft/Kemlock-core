import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/crypto/pbkdf2.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_backend.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_items.dart' show versionAtLeast;
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';

/// The fake account's KDF, cheap enough for widget tests.
const fakeKdf = BwKdf(type: BwKdfType.pbkdf2, iterations: 5000);

/// The master key and hash without an isolate, which widget tests' fake
/// time can't wait for.
class CheapKeyDerivation implements VwKeyDerivation {
  const CheapKeyDerivation();

  @override
  Future<Uint8List> masterKey(String password, String email, BwKdf kdf) async =>
      pbkdf2Sha256(utf8.encode(password), utf8.encode(bwSaltEmail(email)), kdf.iterations, 32);

  @override
  Future<String> passwordHash(Uint8List masterKey, String password) async => b64(pbkdf2Sha256(masterKey, utf8.encode(password), 1, 32));
}

/// An in-memory Vaultwarden behind a [MockClient], for one account, with
/// the routes sync uses and Vaultwarden's rules for them, as checked against
/// a real server in test/vaultwarden_server: `encryptedFor` must be the
/// account, an update with a `lastKnownRevisionDate` more than a second
/// before the item's revision is refused as out of date, items keep what
/// they're sent, and every change moves the account's revision date.
///
/// Its clock moves two seconds with each change, so a stale copy is always
/// caught.
///
/// ```dart
/// final server = FakeVaultwarden();
/// final api = VwApi(server.client);
/// final credentials = server.credentials();
/// ```
class FakeVaultwarden {
  FakeVaultwarden({this.email = 'me@example.com', this.password = 'master password'});

  static final url = Uri.parse('https://vault.example.com');

  final String email;
  final String password;
  static const userId = '00000000-0000-4000-8000-000000000001';

  /// The account's user key.
  final userKey = BwKey.random();

  final ciphers = <String, Map<String, Object?>>{};
  final folders = <String, Map<String, Object?>>{};

  /// Every request the client sent, in order.
  final requests = <http.Request>[];

  /// Answers requests instead of the server while set, e.g. to fail them.
  Future<http.Response> Function(http.Request request)? respond;

  /// Runs once before the next request is answered, e.g. to act as another phone.
  void Function()? beforeNext;

  var _now = DateTime.utc(2026, 11, 7, 9);
  var _ids = 0;
  var _tokens = 0;
  int revision = DateTime.utc(2026, 11, 7, 9).millisecondsSinceEpoch;
  final _refreshTokens = <String>{};

  /// Refresh tokens stop working, as when the user changes their password.
  bool revoked = false;

  /// The Bitwarden server version `/api/config` reports: Vaultwarden 1.37.5's.
  String configVersion = '2026.6.0';

  /// The `kemlock` member of `/api/config`, which a server that also speaks Kemlock's own API sends
  /// (`{"api": "https://host/kem/v1", "versions": ["v1"]}`); none leaves it out.
  Object? kemlockConfig;

  /// Each attachment's data, encrypted, by attachment id.
  final attachmentData = <String, Uint8List>{};

  /// Whether the server keeps attachments; false answers as Vaultwarden
  /// with `USER_ATTACHMENT_LIMIT=0`.
  bool takesFiles = true;

  /// The upload type the first step answers: 0, the server's own API.
  int uploadType = 0;

  /// Another host to give download addresses on, as a server keeping its
  /// files in object storage would.
  String? filesHost;

  var _attachments = 0;

  /// Adds an attachment to the item [cipherId] as another app would, and
  /// returns its id.
  String putAttachment(String cipherId, {required String fileName, required String key, required Uint8List data}) {
    final id = 'att-${++_attachments}';
    _tick();
    final cipher = ciphers[cipherId]!;
    ciphers[cipherId] = {
      ...cipher,
      'attachments': [
        ...?(cipher['attachments'] as List<Object?>?),
        _attachment(cipherId, id, fileName: fileName, key: key, size: data.length),
      ],
    };
    attachmentData[id] = data;
    return id;
  }

  /// Deletes an attachment, as another app would.
  void removeAttachment(String cipherId, String attachmentId) {
    _tick();
    final cipher = ciphers[cipherId]!;
    ciphers[cipherId] = {
      ...cipher,
      'attachments': [
        for (final attachment in (cipher['attachments'] as List<Object?>? ?? const []).cast<Map<String, Object?>>())
          if (attachment['id'] != attachmentId) attachment,
      ],
    };
    attachmentData.remove(attachmentId);
  }

  /// The attachments of the item [cipherId].
  List<Map<String, Object?>> attachmentsOf(String cipherId) => [
    ...?(ciphers[cipherId]?['attachments'] as List<Object?>?)?.cast<Map<String, Object?>>(),
  ];

  Map<String, Object?> _attachment(String cipherId, String id, {required String fileName, required String key, required int size}) => {
    'id': id,
    'url': '${filesHost == null ? url : 'https://$filesHost'}/attachments/$cipherId/$id?token=download-token',
    'fileName': fileName,
    'size': '$size',
    'sizeName': '$size Bytes',
    'key': key,
    'object': 'attachment',
  };

  /// Answers the attachment routes, or null for any other request.
  http.Response? _attachmentRoute(http.Request request) {
    final path = request.url.path;
    final download = RegExp(r'^/attachments/([^/]+)/([^/]+)$').firstMatch(path);
    if (download != null && request.method == 'GET') {
      final data = attachmentData[download[2]];
      if (data == null || request.url.queryParameters['token'] != 'download-token') return _error('Not found', 404);
      return http.Response.bytes(data, 200);
    }
    final match = RegExp(r'^/api/ciphers/([^/]+)/attachment/([^/]+)$').firstMatch(path);
    if (match == null) return null;
    final cipherId = match[1]!;
    final cipher = ciphers[cipherId];
    if (cipher == null) return _error("Cipher doesn't exist");
    final attachmentId = match[2]!;
    if (attachmentId == 'v2' && request.method == 'POST') {
      final body = jsonDecode(request.body) as Map<String, Object?>;
      if (!takesFiles) return _error('Attachments are disabled');
      final id = 'att-${++_attachments}';
      _tick();
      ciphers[cipherId] = {
        ...cipher,
        'attachments': [
          ...?(cipher['attachments'] as List<Object?>?),
          _attachment(cipherId, id, fileName: body['fileName']! as String, key: body['key']! as String, size: body['fileSize']! as int),
        ],
      };
      return _json({
        'object': 'attachment-fileUpload',
        'attachmentId': id,
        'url': uploadType == 0 ? '/ciphers/$cipherId/attachment/$id' : 'https://blob.example.net/$id?sig=1',
        'fileUploadType': uploadType,
        'cipherResponse': ciphers[cipherId],
      });
    }
    final attachment = attachmentsOf(cipherId).where((attachment) => attachment['id'] == attachmentId).firstOrNull;
    if (attachment == null) return _error("Attachment doesn't exist");
    switch (request.method) {
      case 'POST':
        final type = request.headers['Content-Type'] ?? '';
        final boundary = RegExp(r'boundary=(.+)$').firstMatch(type)?[1];
        if (!type.startsWith('multipart/form-data') || boundary == null) return _error('Not a form', 415);
        final body = request.bodyBytes;
        final text = latin1.decode(body);
        final start = text.indexOf('\r\n\r\n') + 4;
        final end = text.lastIndexOf('\r\n--$boundary--');
        if (!text.contains('name="data"') || start < 4 || end < start) return _error('No data');
        final data = Uint8List.sublistView(body, start, end);
        if ((data.length - int.parse(attachment['size']! as String)).abs() > 1024 * 1024) return _error('Attachment size mismatch');
        attachmentData[attachmentId] = Uint8List.fromList(data);
        return http.Response('', 200);
      case 'GET':
        return _json(attachment);
      case 'DELETE':
        removeAttachment(cipherId, attachmentId);
        return _json({'object': 'cipherDetails'});
    }
    return _error('Not found', 404);
  }

  /// The second-step providers the account has, by Bitwarden's numbers.
  Set<int> twoFactor = {};

  /// The code the second step takes.
  String twoFactorCode = '123456';

  /// How many times the email code was asked for.
  int emailsSent = 0;

  // ─── Security keys (provider 7), as Vaultwarden 1.37.5 was seen to do ──
  // (test/fixtures/vaultwarden/webauthn/README.md)

  /// The server's own address, Vaultwarden's `DOMAIN`: the name it asks
  /// keys about is its host, and the only origin it accepts is its own.
  /// Null is a server without the setting, which asks about `localhost`.
  String? domain = 'https://vault.example.com';

  /// The security keys registered with the account. With provider 7 in
  /// [twoFactor] and none here, the server lists the method and gives no
  /// challenge.
  final webauthnKeys = <FakeWebauthnKey>[];

  /// Whether the "two factor required" answer carries a challenge for the
  /// registered keys. Off is a server that lists the method without one.
  bool webauthnChallenges = true;

  /// The challenge the last "two factor required" answer gave, until an
  /// answer to it arrives. One at a time, as the server keeps it.
  String? webauthnChallenge;

  /// How many challenges were given.
  int webauthnChallengesGiven = 0;

  /// Why the last security key token was refused, or null.
  String? webauthnRefusal;

  /// The remember tokens handed out, which skip the step as provider 5.
  final rememberTokens = <String>{};

  /// Registers a security key with the account, as the web vault does: the
  /// credential's [id] and its public [point].
  void registerKey(List<int> id, List<int> point) {
    twoFactor = {...twoFactor, VwTwoFactor.webauthn};
    webauthnKeys.add(FakeWebauthnKey(Uint8List.fromList(id), Uint8List.fromList(point)));
  }

  Uri get _domain => Uri.parse(domain ?? 'http://localhost');

  /// The request options under `"7"`, with a new challenge that replaces
  /// the one before; null when the server has none to give.
  Map<String, Object?>? _webauthnOptions() {
    if (!webauthnChallenges || webauthnKeys.isEmpty) return null;
    final n = ++webauthnChallengesGiven;
    final challenge = webauthnChallenge = b64url(sha256.convert(utf8.encode('fake challenge $n')).bytes);
    return {
      'allowCredentials': [
        for (final key in webauthnKeys) {'id': b64url(key.id), 'type': 'public-key'},
      ],
      'challenge': challenge,
      'extensions': {'appid': '${domain ?? 'http://localhost'}/app-id.json'},
      'rpId': _domain.host,
      'timeout': 60000,
      'userVerification': 'discouraged',
    };
  }

  /// Checks a security key's token as the server does. Null when it is
  /// accepted, else why not. Any answer uses the challenge up.
  String? _checkWebauthn(String token) {
    final challenge = webauthnChallenge;
    webauthnChallenge = null;
    if (challenge == null) return "Can't recover login challenge";
    try {
      final credential = jsonDecode(token) as Map<String, Object?>;
      if (credential['type'] != 'public-key') return 'not a public-key credential';
      final response = credential['response']! as Map<String, Object?>;
      final clientData = unb64url((response['clientDataJson'] ?? response['clientDataJSON'])! as String);
      final client = jsonDecode(utf8.decode(clientData)) as Map<String, Object?>;
      if (client['type'] != 'webauthn.get') return 'not an assertion';
      if (client['challenge'] != challenge) return 'another challenge';
      // Origins are compared as URLs: the scheme, the host and the port
      final origin = Uri.parse(client['origin']! as String);
      if (origin.scheme != _domain.scheme || origin.host != _domain.host || origin.port != _domain.port) return 'another origin';
      final authenticatorData = unb64url(response['authenticatorData']! as String);
      if (authenticatorData.length < 37) return 'short authenticator data';
      final rpIdHash = sha256.convert(utf8.encode(_domain.host)).bytes;
      for (var i = 0; i < 32; i++) {
        if (authenticatorData[i] != rpIdHash[i]) return 'another rpId';
      }
      if (authenticatorData[32] & 0x01 == 0) return 'the user was not present';
      final id = b64url(unb64url(credential['rawId']! as String));
      final key = webauthnKeys.where((key) => b64url(key.id) == id).firstOrNull;
      if (key == null) return 'Credential not present';
      final signed = Uint8List.fromList([...authenticatorData, ...sha256.convert(clientData).bytes]);
      if (!es256Verify(key.point, signed, unb64url(response['signature']! as String))) return 'bad signature';
      final counter = ByteData.sublistView(authenticatorData, 33, 37).getUint32(0);
      if ((counter != 0 || key.counter != 0) && counter <= key.counter) return 'the counter did not grow';
      key.counter = counter;
      return null;
    } on Object catch (e) {
      return 'malformed token: $e';
    }
  }

  /// The account's personal API key, as client_id and client_secret.
  static const apiKey = (clientId: 'user.00000000-0000-4000-8000-000000000001', clientSecret: 'api-secret');

  /// How many times the API key signed in.
  int apiKeySignIns = 0;

  String? _hash;
  String? _encryptedKey;

  /// Lets the account sign in with [password], as [CheapKeyDerivation] derives it.
  Future<void> allowSignIn() async {
    const derive = CheapKeyDerivation();
    final masterKey = await derive.masterKey(password, email, fakeKdf);
    _hash = await derive.passwordHash(masterKey, password);
    _encryptedKey = (await bwEncrypt(userKey.bytes, bwStretch(masterKey))).toString();
  }

  String _date() => '${_now.toIso8601String().replaceFirst(RegExp(r'\.\d+Z$'), '').replaceFirst('Z', '')}.000000Z';

  void _tick() {
    _now = _now.add(const Duration(seconds: 2));
    revision = _now.millisecondsSinceEpoch;
  }

  String _newId() => '00000000-0000-4000-8000-${(++_ids).toString().padLeft(12, '0')}';

  /// A signed-in session, as setup stores it.
  VwCredentials credentials({int expiresAt = 1 << 52}) {
    final refresh = 'refresh-${++_tokens}';
    _refreshTokens.add(refresh);
    return VwCredentials(
      deviceId: 'device',
      userId: userId,
      userKey: b64(userKey.bytes),
      accessToken: _jwt(),
      refreshToken: refresh,
      expiresAt: expiresAt,
    );
  }

  String _jwt() => '${b64url(utf8.encode('{}'))}.${b64url(utf8.encode(jsonEncode({'sub': userId, 'n': ++_tokens})))}.sig';

  /// A client for the server; each call makes a new one, as the app's
  /// backend closes its clients when it's done.
  http.Client newClient() => MockClient(_answer);

  late final http.Client client = newClient();

  Future<http.Response> _answer(http.Request request) async {
    requests.add(request);
    final hook = beforeNext;
    beforeNext = null;
    hook?.call();
    final answer = respond;
    return answer != null ? answer(request) : handle(request);
  }

  /// Adds an item as another app would, and returns it as /api/sync shows it.
  Map<String, Object?> put(Map<String, Object?> body, {String? id}) {
    _tick();
    final cipherId = id ?? _newId();
    final stored = _store(cipherId, body, created: ciphers[cipherId]?['creationDate'] as String?);
    ciphers[cipherId] = stored;
    return stored;
  }

  /// Moves an item to the trash, as another app would.
  void trash(String id) {
    _tick();
    ciphers[id] = {...ciphers[id]!, 'deletedDate': _date(), 'revisionDate': _date()};
  }

  /// Deletes an item for good, as emptying the trash does.
  void purge(String id) {
    _tick();
    ciphers.remove(id);
  }

  Map<String, Object?> _store(String id, Map<String, Object?> body, {String? created}) {
    final type = body['type'];
    return {
      'object': 'cipherDetails',
      'id': id,
      'type': type,
      'creationDate': created ?? _date(),
      'revisionDate': _date(),
      'deletedDate': null,
      'archivedDate': body['archivedDate'],
      'reprompt': body['reprompt'] ?? 0,
      'organizationId': body['organizationId'],
      'key': body['key'],
      // Attachments aren't part of what an item is sent with: they stay
      'attachments': ciphers[id]?['attachments'],
      'organizationUseTotp': true,
      'collectionIds': const <Object?>[],
      'name': body['name'],
      'notes': body['notes'],
      'fields': body['fields'],
      'passwordHistory': body['passwordHistory'],
      'folderId': body['folderId'],
      'favorite': body['favorite'] ?? false,
      'edit': true,
      'viewPassword': true,
      'permissions': {'delete': true, 'restore': true},
      'login': type == 1 ? body['login'] : null,
      'secureNote': type == 2 ? body['secureNote'] : null,
      'card': null,
      'identity': null,
      'sshKey': type == 5 ? body['sshKey'] : null,
    };
  }

  http.Response _json(Object? value, [int status = 200]) =>
      http.Response.bytes(utf8.encode(jsonEncode(value)), status, headers: {'content-type': 'application/json'});

  http.Response _error(String message, [int status = 400]) => _json({'message': message, 'object': 'error'}, status);

  /// How the server answers [request].
  Future<http.Response> handle(http.Request request) async {
    final path = request.url.path;
    final method = request.method;
    if (path == '/api/config') {
      return _json({
        'object': 'config',
        'version': configVersion,
        'server': {'name': 'Vaultwarden'},
        'featureStates': {'pm-19148-innovation-archive': true},
        'kemlock': ?kemlockConfig,
      });
    }
    if (path == '/identity/accounts/prelogin') return _json(fakeKdf.toJson());
    if (path == '/api/two-factor/send-email-login') {
      emailsSent++;
      return http.Response('', 200);
    }
    if (path == '/identity/connect/token') return _token(request);
    if (path.startsWith('/attachments/')) return _attachmentRoute(request) ?? _error('Not found', 404);
    if (request.headers['Authorization']?.startsWith('Bearer ') != true) return _error('Unauthorized', 401);
    if (_attachmentRoute(request) case final answer?) return answer;

    final body = request.body.isEmpty ? const <String, Object?>{} : jsonDecode(request.body) as Map<String, Object?>;
    if (path == '/api/accounts/revision-date' && method == 'GET') return _json(revision);
    if (path == '/api/sync' && method == 'GET') {
      // As Vaultwarden: SSH key items only for clients of 2024.12.0 or later
      final version = request.headers['Bitwarden-Client-Version'] ?? '';
      final sshKeys = versionAtLeast(version, '2024.12.0');
      return _json({
        'object': 'sync',
        'profile': {'id': userId, 'email': email},
        'folders': folders.values.toList(),
        'ciphers': [
          for (final cipher in ciphers.values)
            if (sshKeys || cipher['type'] != 5) cipher,
        ],
      });
    }
    if (path == '/api/folders' && method == 'POST') {
      _tick();
      final folder = {'id': _newId(), 'name': body['name'], 'revisionDate': _date(), 'object': 'folder'};
      folders[folder['id']! as String] = folder;
      return _json(folder);
    }
    if (body['notes'] case final String notes when notes.length > 10000) {
      return _error('The field Notes exceeds the maximum encrypted value length of 10000 characters.');
    }
    if (path == '/api/ciphers' && method == 'POST') {
      if (body['encryptedFor'] != userId) return _error('Invalid user cipher', 422);
      if (body['folderId'] case final String folder when !folders.containsKey(folder)) return _error('Invalid folder');
      return _json(put(body));
    }
    final match = RegExp(r'^/api/ciphers/([^/]+)(/delete|/restore)?$').firstMatch(path);
    if (match != null && method == 'PUT') {
      final id = match[1]!;
      final cipher = ciphers[id];
      if (cipher == null) return _error('Cipher does not exist', 404);
      switch (match[2]) {
        case '/delete':
          trash(id);
          return http.Response('', 200);
        case '/restore':
          _tick();
          ciphers[id] = {...cipher, 'deletedDate': null, 'revisionDate': _date()};
          return _json(ciphers[id]);
      }
      if (body['encryptedFor'] != userId) return _error('Invalid user cipher', 422);
      final known = body['lastKnownRevisionDate'];
      if (known is String) {
        final ahead = DateTime.parse(cipher['revisionDate']! as String).difference(DateTime.parse(known));
        if (ahead.inSeconds > 1) return _error('The client copy of this cipher is out of date. Resync the client and try again.');
      }
      return _json(put(body, id: id));
    }
    return _error('Not found', 404);
  }

  Future<http.Response> _token(http.Request request) async {
    final form = Uri.splitQueryString(request.body);
    if (form['grant_type'] == 'refresh_token') {
      if (revoked || !_refreshTokens.contains(form['refresh_token'])) return _json({'error': 'invalid_grant'}, 400);
      final refresh = 'refresh-${++_tokens}';
      _refreshTokens.add(refresh);
      return _json({'access_token': _jwt(), 'expires_in': 7200, 'refresh_token': refresh, 'token_type': 'Bearer'});
    }
    if (form['grant_type'] == 'client_credentials') {
      if (form['client_id'] != apiKey.clientId || form['client_secret'] != apiKey.clientSecret) {
        return _json({'error': 'invalid_client'}, 400);
      }
      apiKeySignIns++;
      // As Vaultwarden: no refresh token for an API key's session
      return _json({'access_token': _jwt(), 'expires_in': 3600, 'token_type': 'Bearer', 'Key': _encryptedKey, 'scope': 'api'});
    }
    if (form['grant_type'] == 'password' && _hash != null && form['username'] == email && form['password'] == _hash) {
      if (twoFactor.isNotEmpty) {
        final provider = form['twoFactorProvider'];
        // A remember token the server does not know is answered as no step at all
        if (provider == null || (provider == '${VwTwoFactor.remember}' && !rememberTokens.contains(form['twoFactorToken']))) {
          return _json({
            'error': 'invalid_grant',
            'error_description': 'Two factor required.',
            'TwoFactorProviders': [for (final provider in twoFactor) '$provider'],
            'TwoFactorProviders2': {
              for (final provider in twoFactor)
                '$provider': switch (provider) {
                  VwTwoFactor.email => {'Email': 'm***@example.com'},
                  VwTwoFactor.webauthn => _webauthnOptions(),
                  _ => null,
                },
            },
          }, 400);
        }
        if (provider == '${VwTwoFactor.webauthn}') {
          webauthnRefusal = twoFactor.contains(VwTwoFactor.webauthn)
              ? _checkWebauthn(form['twoFactorToken'] ?? '')
              : 'not a method of the account';
          if (webauthnRefusal != null) return _error('Webauthn');
        } else if (provider != '${VwTwoFactor.remember}' && form['twoFactorToken'] != twoFactorCode) {
          return _json({'error': 'invalid_grant', 'error_description': 'Invalid TOTP code'}, 400);
        }
      }
      final refresh = 'refresh-${++_tokens}';
      _refreshTokens.add(refresh);
      String? remember;
      if (form['twoFactorRemember'] == '1') rememberTokens.add(remember = 'remember-${++_tokens}');
      return _json({
        'access_token': _jwt(),
        'expires_in': 7200,
        'refresh_token': refresh,
        'token_type': 'Bearer',
        'Key': _encryptedKey,
        'Kdf': fakeKdf.type.index,
        'KdfIterations': fakeKdf.iterations,
        'TwoFactorToken': ?remember,
      });
    }
    return _json({'error': 'invalid_grant', 'error_description': 'Username or password is incorrect. Try again'}, 400);
  }
}

/// A security key registered with the fake account: what a server keeps.
class FakeWebauthnKey {
  FakeWebauthnKey(this.id, this.point);

  final Uint8List id;

  /// The credential's P-256 public point, 65 bytes.
  final Uint8List point;

  /// The signature counter of the last answer accepted.
  int counter = 0;
}

/// A connection-free [VwApi] on [server].
VwApi fakeApi(FakeVaultwarden server) => VwApi(server.client);
