import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/password_wrap.dart';
import 'package:kemlock_core/crypto/account/private_keys.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/opaque/opaque_client.dart';
import 'package:kemlock_core/features/sync/kemlock/km_phrase.dart';
import 'package:kemlock_core/features/sync/kemlock/km_signin.dart';

import 'fake_kemlock_server.dart';

/// Argon2id for tests: a SHA-256 in its place, so a sign-in takes no time. The settings still reach it.
Future<Uint8List> cheapArgon2(Uint8List password, Uint8List salt, Argon2idSettings settings) async =>
    Uint8List.fromList(sha256.convert([...password, ...salt, settings.iterations]).bytes);

/// The 16-byte salt the fake server keeps.
final fakeSalt = Uint8List.fromList(List.generate(16, (i) => i + 1));

/// The members of the server's `DeviceDto`.
const _deviceMembers = {'id', 'name', 'kind', 'bitwardenDeviceIdentifier'};

/// OPAQUE as bytes with no group arithmetic: the server's record is a hash of the master key, and the messages are hashes of
/// the record, so a wrong password fails at the phone's check of the server's proof, as the real client's does, and a server
/// that doesn't hold the record gives an answer nothing verifies.
class FakeKmOpaque implements KmOpaque {
  static Uint8List _hash(String label, List<int> data) => Uint8List.fromList(sha256.convert([...utf8.encode(label), ...data]).bytes);

  /// What the server stores for [masterKey].
  static Uint8List record(Uint8List masterKey) => _hash('record', masterKey);

  /// The server's answer to a login for [record].
  static Uint8List response(Uint8List record) => _hash('response', record);

  /// The client's last message for [record].
  static Uint8List finalization(Uint8List record) => _hash('finalization', record);

  /// The export key of [masterKey]: 64 bytes.
  static Uint8List exportKey(Uint8List masterKey) => Uint8List.fromList(sha512.convert([...utf8.encode('export'), ...masterKey]).bytes);

  @override
  ({Uint8List request, Object state}) start(Uint8List masterKey) => (request: record(masterKey), state: Uint8List.fromList(masterKey));

  @override
  ({Uint8List finalization, Uint8List exportKey}) finish(Object state, Uint8List response) {
    final master = state as Uint8List;
    if (!constantTimeEquals(response, FakeKmOpaque.response(record(master)))) {
      throw const OpaqueException(OpaqueFailure.authentication, 'the server proof does not verify');
    }
    return (finalization: finalization(record(master)), exportKey: exportKey(master));
  }

  @override
  ({Uint8List request, Object state}) registerStart(Uint8List masterKey) =>
      (request: record(masterKey), state: Uint8List.fromList(masterKey));

  @override
  ({Uint8List upload, Uint8List exportKey}) registerFinish(Object state, Uint8List response) {
    final master = state as Uint8List;
    return (upload: record(master), exportKey: exportKey(master));
  }
}

/// An account with real keys: its root key, `kx1` and `sig1` pairs, bundle, signature and sealed private keys, as registration
/// uploads them. Made once, as `sig1` is slow in pure Dart.
class KmTestAccount {
  KmTestAccount._(this.userId, this.root, this.keyVersion, this.kx1, this.sig1, this.bundle, this.signature, this.sealed);

  static Future<KmTestAccount> create(String userId, {Uint8List? root, int keyVersion = 1}) async {
    final rootKey = root ?? newRootKey();
    final kx1 = await Kx1.generate();
    final sig1 = await Sig1.generate();
    final bundle = KeyBundle(
      accountId: uuidBytes(userId),
      keyVersion: keyVersion,
      kx1PublicKey: kx1.publicKey,
      sig1PublicKey: sig1.publicKey,
    );
    final keys = AccountKeys.fromRoot(rootKey);
    final sealed = await sealPrivateKeys(
      privateKeysKey: keys.privateKeysKey,
      accountId: uuidBytes(userId),
      keyVersion: keyVersion,
      kx1PrivateKey: kx1.privateKey,
      sig1PrivateKey: sig1.privateKey,
    );
    keys.dispose();
    return KmTestAccount._(userId, rootKey, keyVersion, kx1, sig1, bundle, await signBundle(bundle, sig1.privateKey), sealed);
  }

  final String userId;
  final Uint8List root;
  final int keyVersion;
  final ({Uint8List publicKey, Uint8List privateKey}) kx1;
  final ({Uint8List publicKey, Uint8List privateKey}) sig1;
  final KeyBundle bundle;
  final Uint8List signature;
  final Uint8List sealed;

  /// What `GET /account/keys` answers, with the root key wrapped as [wrappedRoot] says.
  Map<String, Object?> material({Uint8List? wrappedRoot}) => {
    'keyVersion': keyVersion,
    if (wrappedRoot != null) 'wrappedRootKey': b64urlEncode(wrappedRoot),
    'publicBundle': b64urlEncode(bundle.bytes),
    'bundleSignature': b64urlEncode(signature),
    'sealedPrivateKeys': b64urlEncode(sealed),
  };

  /// The root key wrapped under [password] as the server stores it for an OPAQUE account.
  Future<Uint8List> wrapFor(String password) async {
    final master = await deriveMasterKey(password, fakeSalt, runner: cheapArgon2);
    return wrapRootWithPassword(
      masterKey: master,
      exportKey: FakeKmOpaque.exportKey(master),
      accountId: uuidBytes(userId),
      keyVersion: keyVersion,
      rootKey: root,
    );
  }
}

/// A request for approval as the fake server holds it.
class FakeApproval {
  FakeApproval({
    required this.id,
    required this.publicKey,
    required this.jkt,
    required this.deviceName,
    required this.createdAt,
    required this.phrase,
  });

  final String id;
  final Uint8List publicKey;
  final String jkt;
  final String deviceName;
  final DateTime createdAt;
  final String phrase;

  /// `pending`, `approved`, `denied`, or `used` once the device signed in.
  String status = 'pending';
  Uint8List? sealedKey;

  DateTime get expiresAt => createdAt.add(const Duration(minutes: 15));
}

/// [FakeKemlockServer] with the sign-in routes: the ways in, prelogin, OPAQUE (the fake's), the Bitwarden-hash route, enrolment,
/// the second step and the account's keys. It keeps what it saw, so a test can check what was sent: the Bitwarden hashes
/// received, the devices that signed in, and how many OPAQUE starts there were.
class FakeKemlockAccountServer extends FakeKemlockServer {
  FakeKemlockAccountServer({super.userId});

  /// What `/auth/methods` answers.
  Map<String, Object?> methods = {
    'methods': ['password'],
  };

  /// The OPAQUE record the server holds, or null for an account that has none.
  Uint8List? opaqueRecord;

  /// The Argon2id settings prelogin answers.
  var memoryKib = 65536;
  var iterations = 3;
  var parallelism = 4;

  /// The Bitwarden API's prelogin answer for the account (`/identity/accounts/prelogin`).
  Map<String, Object?>? bitwarden;

  /// The second-step methods the Bitwarden enrolment owes, and how many times the Bitwarden prelogin was read.
  var enrolTwoFactor = <String>[];
  var bitwardenPrelogins = 0;

  /// The Bitwarden hash the route takes, and the user key it hands back as an `EncString`.
  String? bitwardenHashExpected;
  String? bitwardenUserKey;

  /// What `GET /account/keys` answers.
  Map<String, Object?> material = {};

  /// The account has no keys yet, as one that single sign-on made does: `GET /account/keys` answers [noKeysAnswer], or
  /// 404 (what the server's code does) when that is null, and `POST /account/keys/enrol` takes the first keys.
  var noKeys = false;
  Map<String, Object?>? noKeysAnswer;

  /// Another device enrols first: the next enrolment is a 409 (`already-exists`), and the account has keys from
  /// then on.
  var enrolConflict = false;

  /// The bodies `POST /account/keys/enrol` accepted, and how many it refused.
  final keyEnrolments = <Map<String, Object?>>[];
  var enrolRefusals = 0;

  /// The space whose Require SSO binds the account: each sign-in answers it with a 403 `sso-required` naming the space,
  /// once the caller's proof is right (the server's order). Null for an account no space binds.
  String? ssoRequiredSpace;

  /// The second-step methods owed after the first step, or null for none.
  List<String>? secondStep;
  var totpCode = '123456';

  /// What was seen.
  final bitwardenHashes = <String>[];
  final devicesSeen = <Map<String, Object?>>[];
  final enrolments = <Map<String, Object?>>[];
  var opaqueStarts = 0;
  var preloginCalls = 0;
  final signedOut = <String>[];

  /// What `POST` and `DELETE /devices/push-token` were given, in order: the kind and token, or null for a delete.
  final pushTokens = <({String kind, String token})?>[];

  /// The device ids this server knows, which it signs in on a replica with their key and no password.
  final knownDevices = <String>{};
  final replicaJkts = <String, String>{};

  /// What `GET /devices` lists, as the server's contract words each device.
  var deviceList = <Map<String, Object?>>[];
  final ssoStarts = <Map<String, Object?>>[];

  /// Approval requests by id, and the answers posted for them.
  final approvals = <String, FakeApproval>{};
  final answers = <Map<String, Object?>>[];
  var polls = 0;
  var _approvalCount = 0;

  /// EFF's large word list, for the server's own phrase, and a phrase to send instead of it.
  List<String> approvalWords = const [];
  String? phraseOverride;

  /// The server's list leaves out each request's public key, as the server's list does today.
  var hidePublicKey = false;

  /// What time a new request is made at, and the age of the ones listed is counted from.
  DateTime Function() approvalNow = DateTime.now;

  /// The passkey the account has registered, its PRF copy of the root key as the server answers it (`{wrappedKey,
  /// keyVersion}`, or null for a passkey made without one), and the verifications and PRF copies received.
  final passkeyId = 'a1000000-0000-4000-8000-000000000001';
  Map<String, Object?>? passkeyWrap;
  final passkeyPrfPuts = <Map<String, Object?>>[];
  final passkeyOptionBodies = <String>[];

  var passkeyCredential = Uint8List.fromList(List.generate(16, (i) => 100 + i));
  final passkeyVerifies = <Map<String, Object?>>[];

  /// The one-time code the SSO redirect carries.
  var ssoCode = 'code-1';

  /// The provider address SSO start hands out.
  var ssoUrl = 'https://idp.example.com/authorize?state=server-state';

  final _loginStates = <String, String>{};
  var _states = 0;

  /// Registers [password] for [account] over OPAQUE, as the fake client would.
  Future<void> registerOpaque(String password, KmTestAccount account) async {
    final master = await deriveMasterKey(password, fakeSalt, runner: cheapArgon2);
    opaqueRecord = FakeKmOpaque.record(master);
    material = account.material(wrappedRoot: await account.wrapFor(password));
  }

  @override
  Future<http.Response?> otherRoute(http.Request request, String path) async {
    if (path != '/identity/accounts/prelogin') return null;
    bitwardenPrelogins++;
    final bw = bitwarden;
    return bw == null ? problem(404, 'not-found') : answer(bw);
  }

  @override
  Future<http.Response?> openRoute(http.Request request, String route) async {
    if (route == '/auth/methods') return answer(methods);
    preloginCalls++;
    return answer({
      'kdf': {'memoryKib': memoryKib, 'iterations': iterations, 'parallelism': parallelism, 'salt': b64urlEncode(fakeSalt)},
    });
  }

  http.Response _signedIn(String jkt, {Map<String, Object?> extra = const {}}) {
    final owed = secondStep;
    if (owed != null) {
      return answer({'status': 'two_factor_required', 'challenge': 'challenge-1', 'methods': owed, ...extra});
    }
    return answer({'status': 'signed_in', 'tokens': issueTokens(jkt), ...extra});
  }

  @override
  Future<http.Response?> signInRoute(http.Request request, String route, String jkt) async {
    final body = request.body.isEmpty ? const <String, Object?>{} : jsonDecode(request.body) as Map<String, Object?>;
    // As the server's `DeviceDto` (`deny_unknown_fields`): a device body with a member it doesn't list is a 400
    final device = body['device'];
    if (device is Map<String, Object?> && !_deviceMembers.containsAll(device.keys)) {
      return problem(400, 'invalid-request', extra: {'detail': 'unknown field in device'});
    }
    if (request.method == 'GET' && route.startsWith('/auth/device/request/')) {
      final asked = approvals[route.substring('/auth/device/request/'.length)];
      if (asked == null || asked.jkt != jkt) return problem(404, 'not-found');
      polls++;
      // As the server's poll: the account the key opens comes with `approved` only, as `accountId`
      return answer({
        'status': asked.status,
        if (asked.status == 'approved') ...{'sealedKey': b64urlEncode(asked.sealedKey!), 'accountId': userId},
      });
    }
    switch (route) {
      case '/auth/opaque/start':
        opaqueStarts++;
        final record = opaqueRecord ?? Uint8List(32);
        final state = 'login-state-${++_states}';
        _loginStates[state] = jkt;
        return answer({'response': b64urlEncode(FakeKmOpaque.response(record)), 'loginState': state});
      case '/auth/opaque/finish':
        final state = body['loginState'];
        final record = opaqueRecord;
        if (record == null || _loginStates.remove(state) != jkt) return problem(401, 'unauthorized');
        if (!constantTimeEquals(b64urlDecode(body['finalization']! as String), FakeKmOpaque.finalization(record))) {
          return problem(401, 'unauthorized');
        }
        final space = ssoRequiredSpace;
        if (space != null) return problem(403, 'sso-required', extra: {'spaceId': space});
        devicesSeen.add(body['device']! as Map<String, Object?>);
        return _signedIn(jkt);
      case '/auth/bitwarden/start':
        bitwardenHashes.add(body['masterPasswordHash']! as String);
        // An account that has OPAQUE or keys is a 409, as the contract says, which is how a wrong password looks here
        if (opaqueRecord != null || material.containsKey('publicBundle')) return problem(409, 'already-enrolled');
        if (body['masterPasswordHash'] != bitwardenHashExpected) return problem(401, 'unauthorized');
        return answer({
          'response': b64urlEncode(Uint8List(32)),
          'ticket': 'ticket-1',
          'twoFactor': enrolTwoFactor,
          'key': bitwardenUserKey,
          'userId': userId,
        });
      case '/auth/bitwarden/finish':
        if (body['ticket'] != 'ticket-1') return problem(401, 'unauthorized');
        if (enrolTwoFactor.isNotEmpty && body['twoFactorCode'] != totpCode) return problem(401, 'unauthorized');
        enrolments.add(body);
        opaqueRecord = b64urlDecode(body['upload']! as String);
        material = {
          ...material,
          'keyVersion': 1,
          'wrappedRootKey': body['wrappedRootKey'],
          for (final key in const ['publicBundle', 'bundleSignature', 'sealedPrivateKeys']) key: body[key],
        };
        return answer({}, status: 204);
      case '/auth/sso/start':
        final state = body['state'];
        if (state is! String || state.length < 16) return problem(400, 'invalid-request');
        ssoStarts.add({'challenge': body['challenge'], 'state': state, 'jkt': jkt});
        return answer({'authorizationUrl': ssoUrl, 'providerName': 'Example Co'});
      case '/auth/sso/finish':
        final started = ssoStarts.isEmpty ? null : ssoStarts.last;
        final verifier = body['verifier'];
        if (started == null || verifier is! String || body['code'] != ssoCode) return problem(400, 'sso-state-invalid');
        // PKCE: the verifier must hash to the challenge, and the key that finishes is the one that started
        final challenge = b64urlEncode(sha256.convert(utf8.encode(verifier)).bytes);
        if (challenge != started['challenge'] || started['jkt'] != jkt) return problem(401, 'unauthorized');
        devicesSeen.add(body['device']! as Map<String, Object?>);
        return _signedIn(jkt, extra: {'newAccount': false, 'mfaViaSso': false});
      case '/auth/passkey/options':
        passkeyOptionBodies.add(request.body);
        return answer({
          'options': {
            'challenge': b64urlEncode(List.generate(32, (i) => 255 - i)),
            'timeout': 300000,
            'rpId': 'kem.example.com',
            'allowCredentials': <Object?>[],
            'userVerification': 'required',
          },
          'challenge': 'sealed-challenge-1',
        });
      case '/auth/passkey/verify':
        if (body['challenge'] != 'sealed-challenge-1' || body['credential'] is! Map<String, Object?>) {
          return problem(400, 'invalid-request');
        }
        passkeyVerifies.add(body);
        devicesSeen.add(body['device']! as Map<String, Object?>);
        return answer({'tokens': issueTokens(jkt), 'passkeyId': passkeyId, 'prf': passkeyWrap, 'keyVersion': 1});
      case '/auth/device/request':
        final publicKey = b64urlDecode(body['publicKey']! as String);
        final id = 'a0000000-0000-4000-8000-${(++_approvalCount).toString().padLeft(12, '0')}';
        final created = approvalNow();
        final request = FakeApproval(
          id: id,
          publicKey: publicKey,
          jkt: jkt,
          deviceName: (body['device']! as Map<String, Object?>)['name']! as String,
          createdAt: created,
          phrase: phraseOverride ?? approvalPhrase(publicKey, approvalWords),
        );
        approvals[id] = request;
        return answer({'requestId': id, 'phrase': request.phrase, 'expiresAt': request.expiresAt.toIso8601String()}, status: 201);
      case '/auth/device/challenge':
        final asked = approvals[body['requestId']];
        if (asked == null || asked.jkt != jkt || asked.status != 'approved') return problem(400, 'invalid-request');
        return answer({'challenge': 'device-challenge-${asked.id}'});
      case '/auth/device/verify':
        final challenge = '${body['challenge']}';
        final answered = approvals[challenge.replaceFirst('device-challenge-', '')];
        if (answered == null || answered.jkt != jkt) return problem(401, 'unauthorized');
        answered.status = 'used';
        return answer(issueTokens(jkt));
      case '/auth/device-key/challenge':
        if (!knownDevices.contains(body['deviceId'])) return problem(401, 'unauthorized');
        replicaJkts['replica-challenge-1'] = jkt;
        return answer({'challenge': 'replica-challenge-1'});
      case '/auth/device-key/verify':
        if (replicaJkts[body['challenge']] != jkt) return problem(401, 'unauthorized');
        return answer(issueTokens(jkt));
      case '/auth/two-factor':
        if (body['challenge'] != 'challenge-1' || body['method'] != 'totp' || body['code'] != totpCode) return problem(401, 'unauthorized');
        return answer(issueTokens(jkt));
    }
    return null;
  }

  /// As the server's `handle_enrol_keys`: `EnrolKeysRequest` with `deny_unknown_fields`, a bundle for this account
  /// at key version 1 that its own `sig1` key signed, sealed private keys and a device copy of 1 to 1,024 bytes
  /// under one of the four protections; 409 once the account has keys. The keys are stored, and the copy as the
  /// device's key copy.
  Future<http.Response> _enrolKeys(http.Request request) async {
    if (enrolConflict || !noKeys) {
      noKeys = false;
      enrolConflict = false;
      return problem(409, 'already-exists');
    }
    final Map<String, Object?> body;
    try {
      body = jsonDecode(request.body) as Map<String, Object?>;
    } on FormatException {
      return _refuseEnrol();
    }
    const members = {'publicBundle', 'bundleSignature', 'sealedPrivateKeys', 'deviceCopy'};
    final copy = body['deviceCopy'];
    if (!members.containsAll(body.keys) || !body.keys.toSet().containsAll(members) || copy is! Map<String, Object?>) {
      return _refuseEnrol();
    }
    if (copy.keys.length != 2 ||
        !{'wrappedKey', 'protection'}.containsAll(copy.keys) ||
        !const {'secure-enclave', 'keystore', 'web-crypto', 'software'}.contains(copy['protection'])) {
      return _refuseEnrol();
    }
    try {
      final bundle = KeyBundle.parse(b64urlDecode(body['publicBundle']! as String));
      final signature = b64urlDecode(body['bundleSignature']! as String);
      final sealed = b64urlDecode(body['sealedPrivateKeys']! as String);
      final wrapped = b64urlDecode(copy['wrappedKey']! as String);
      final ok =
          uuidText(bundle.accountId) == userId &&
          bundle.keyVersion == 1 &&
          signature.length == 3309 + 64 &&
          sealed.length >= 28 &&
          wrapped.isNotEmpty &&
          wrapped.length <= 1024 &&
          await verifyBundle(bundle, signature);
      if (!ok) return _refuseEnrol();
    } on MalformedException {
      return _refuseEnrol();
    } on TypeError {
      return _refuseEnrol();
    }
    keyEnrolments.add(body);
    keyCopy = {'wrappedKey': copy['wrappedKey']! as String, 'protection': copy['protection']! as String};
    material = {
      'keyVersion': 1,
      'wrappedRootKey': '',
      'publicBundle': body['publicBundle'],
      'bundleSignature': body['bundleSignature'],
      'sealedPrivateKeys': body['sealedPrivateKeys'],
    };
    noKeys = false;
    return answer({'keyVersion': 1});
  }

  http.Response _refuseEnrol() {
    enrolRefusals++;
    return problem(400, 'invalid-request');
  }

  @override
  Future<http.Response?> tokenRoute(http.Request request, String route) async {
    if (route == '/devices/push-token') {
      if (request.method == 'DELETE') {
        pushTokens.add(null);
        return answer({}, status: 204);
      }
      if (request.method == 'POST') {
        final body = jsonDecode(request.body) as Map<String, Object?>;
        final token = body['token'];
        // As the server's `PushTokenRequest`: only kind and token, fcm or apns, 1 to 512 characters, no whitespace
        if (!{'kind', 'token'}.containsAll(body.keys) ||
            !{'fcm', 'apns'}.contains(body['kind']) ||
            token is! String ||
            token.isEmpty ||
            token.length > 512 ||
            token.contains(RegExp(r'\s'))) {
          return problem(400, 'invalid-request');
        }
        pushTokens.add((kind: body['kind']! as String, token: token));
        return answer({}, status: 204);
      }
    }
    if (request.method == 'POST' && route.startsWith('/devices/approvals/')) {
      final asked = approvals[route.substring('/devices/approvals/'.length)];
      final body = jsonDecode(request.body) as Map<String, Object?>;
      if (asked == null || asked.status != 'pending') return problem(404, 'not-found');
      answers.add(body);
      if (body['decision'] == 'approve') {
        asked
          ..status = 'approved'
          ..sealedKey = b64urlDecode(body['sealedKey']! as String);
      } else {
        asked.status = 'denied';
      }
      return answer({}, status: 204);
    }
    if (request.method == 'PUT' && route == '/account/passkeys/$passkeyId/prf') {
      final put = jsonDecode(request.body) as Map<String, Object?>;
      // As the server: 92 bytes, and the account's current key version
      if (b64urlDecode(put['wrappedKey']! as String).length != 92 || put['keyVersion'] != 1) {
        return problem(400, 'invalid-request');
      }
      passkeyPrfPuts.add(put);
      passkeyWrap = {'wrappedKey': put['wrappedKey'], 'keyVersion': put['keyVersion']};
      return answer({}, status: 204);
    }
    switch ('${request.method} $route') {
      case 'GET /devices/approvals':
        return answer({
          'approvals': [
            for (final request in approvals.values)
              if (request.status == 'pending')
                {
                  'id': request.id,
                  'deviceName': request.deviceName,
                  'deviceKind': 'kemlock-android',
                  'ip': '203.0.113.0/24',
                  'phrase': request.phrase,
                  if (!hidePublicKey) 'publicKey': b64urlEncode(request.publicKey),
                  'createdAt': request.createdAt.toIso8601String(),
                  'expiresAt': request.expiresAt.toIso8601String(),
                  'ageSeconds': approvalNow().difference(request.createdAt).inSeconds,
                },
          ],
        });
      case 'GET /devices':
        return answer({'devices': deviceList});
      case 'GET /account/passkeys':
        return answer({
          'passkeys': [
            {
              'id': passkeyId,
              'name': 'Laptop',
              'prf': passkeyWrap != null,
              'prfKeyVersion': passkeyWrap?['keyVersion'],
              'createdAt': '2026-11-21T00:00:00Z',
              'lastUsedAt': null,
            },
          ],
        });
      case 'GET /account/keys':
        if (noKeys) {
          final bare = noKeysAnswer;
          return bare == null ? problem(404, 'not-found') : answer(bare);
        }
        // The spec's AccountKeysResponse always names the password wrap and the KDF, empty and the prelogin's for an
        // account that has no wrap (one that single sign-on made)
        return answer({
          'wrappedRootKey': '',
          'kdf': {'memoryKib': memoryKib, 'iterations': iterations, 'parallelism': parallelism, 'salt': b64urlEncode(fakeSalt)},
          ...material,
        });
      case 'POST /account/keys/enrol':
        return _enrolKeys(request);
      case 'POST /devices/sign-out':
        signedOut.add((jsonDecode(request.body) as Map<String, Object?>)['deviceId']! as String);
        return answer({}, status: 204);
    }
    return null;
  }
}
