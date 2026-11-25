/// The Kemlock API's routes for signing in, approving devices and listing
/// them, over [KmApi.call] (so they share its limits: no redirect, a body cap,
/// a timeout, a DPoP proof on every request). Shapes are the server's where it
/// has the route (`test/fixtures/kemlock/README.md`), and the plan's where it
/// has not; each such route says so.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../../../crypto/account/argon2id.dart';
import '../../../crypto/account/encoding.dart';
import '../../../models/json.dart';
import 'km_api.dart';
import 'km_session.dart';

/// What a device says about itself when it signs in or asks for approval: the server's `DeviceDto`, which refuses
/// a member it doesn't list (`deny_unknown_fields`). The push token is not one: it goes to
/// [KmAuthApi.registerPushToken] once the device is signed in.
class KmDeviceInfo {
  const KmDeviceInfo({required this.name, required this.kind, this.id, this.bitwardenDeviceId, this.deviceType});

  /// The device id this phone kept from an earlier sign-in, null on the first.
  final String? id;

  /// "Kemlock on Pixel 9".
  final String name;

  /// `kemlock-android` or `kemlock-ios`.
  final String kind;

  /// The vault's Vaultwarden device identifier (`VwCredentials.deviceId`), when it syncs or synced with
  /// Vaultwarden on this server's Bitwarden API, so the server shows one device for both (sent as
  /// `device.bitwardenDeviceIdentifier`, 1 to 256 bytes; binding the first DPoP key to that row doesn't sign the
  /// phone out of Vaultwarden sync). Sent only when there is one.
  final String? bitwardenDeviceId;

  /// With kind `kemlock-browser`: the browser, numbered as Bitwarden numbers its device types (2 Chrome, 3 Firefox, 5
  /// Edge). The server refuses it with any other kind, so only the browser extension sets it.
  final int? deviceType;

  Map<String, Object?> toJson() => {
    'id': ?id,
    'name': name,
    'kind': kind,
    'deviceType': ?deviceType,
    'bitwardenDeviceIdentifier': ?bitwardenDeviceId,
  };
}

/// The push relay's token for this phone, and the service that gave it: `apns`, on iOS (the server also takes
/// `fcm`, which no build sends). Only the relay's token: the nudges it brings carry a type and nothing else.
typedef KmPushToken = ({String kind, String token});

/// The ways in an email has, from `POST /auth/methods`: `password`, and `sso` when the account's space has a provider.
/// The provider's name and "Require SSO" are the plan's shape; the server answers neither.
class KmMethods {
  const KmMethods({required this.methods, this.ssoProvider, this.ssoRequired = false});

  factory KmMethods.fromJson(Map<String, Object?> json) => KmMethods(
    methods: asStrings(json['methods']) ?? const [],
    ssoProvider: json['sso'] is Map<String, Object?> ? asOptionalString((json['sso']! as Map<String, Object?>)['providerName']) : null,
    ssoRequired: json['ssoRequired'] == true,
  );

  final List<String> methods;

  /// What the company's provider is called, for "Continue with Example Co SSO".
  final String? ssoProvider;

  /// What the server says of a space's "Require SSO". It is no policy: the app reads the policy from the space's verified
  /// chain (`SpacePolicies.requiresSso`) and offers SSO alone from that, never from this flag.
  final bool ssoRequired;

  bool get password => methods.contains('password');
  bool get sso => methods.contains('sso');

  /// Passkeys are discoverable: the server names no account in its options, so it cannot list one for an email,
  /// and offers a sign-in with one on every server. A person with none gets the authenticator's own refusal.
  bool get passkey => true;
}

/// What `POST /auth/prelogin` says: the Argon2id settings and salt for OPAQUE (`crypto.md` "Master key"), the same
/// shape for an unknown email.
class KmPrelogin {
  const KmPrelogin({this.settings, this.salt});

  factory KmPrelogin.fromJson(Map<String, Object?> json) {
    final kdf = json['kdf'];
    Argon2idSettings? settings;
    Uint8List? salt;
    if (kdf is Map<String, Object?>) {
      final memory = asInt(kdf['memoryKib']);
      final iterations = asInt(kdf['iterations']);
      final parallelism = asInt(kdf['parallelism']);
      final saltText = kdf['salt'];
      if (memory == null || iterations == null || parallelism == null || saltText is! String) {
        throw const FormatException('the Argon2id settings are incomplete');
      }
      try {
        salt = b64urlDecode(saltText);
      } on MalformedException catch (e) {
        throw FormatException(e.message);
      }
      settings = Argon2idSettings(memoryKiB: memory, iterations: iterations, parallelism: parallelism);
    }
    return KmPrelogin(settings: settings, salt: salt);
  }

  /// The Argon2id settings OPAQUE's master key takes, or null when the account has no OPAQUE record.
  final Argon2idSettings? settings;
  final Uint8List? salt;

  /// Whether the server says this account signs in through OPAQUE.
  bool get opaque => settings != null;
}

/// The tokens a sign-in gives, with the account and device they belong to.
class KmGrant {
  const KmGrant({required this.tokens, required this.userId, required this.deviceId});

  /// Reads a token answer. A body without tokens, or without the ids, is a [FormatException].
  factory KmGrant.fromJson(Map<String, Object?> json, int now) {
    final userId = json['userId'];
    final deviceId = json['deviceId'];
    if (userId is! String || deviceId is! String) throw const FormatException('a token answer names its user and device');
    return KmGrant(tokens: KmTokens.fromResponse(json, now), userId: userId, deviceId: deviceId);
  }

  final KmTokens tokens;
  final String userId;
  final String deviceId;
}

/// What `POST /auth/bitwarden/start` answers: OPAQUE's registration response, the ticket the last message carries,
/// and the second-step methods the account owes. The Compatible account's user key as Bitwarden keeps it (an
/// `EncString` under the Bitwarden master key) and its id are not in the contract's answer; the client reads them
/// from `key` and `userId` when the server sends them, and stops when it doesn't.
class KmBitwardenStart {
  const KmBitwardenStart({required this.response, required this.ticket, this.twoFactor = const [], this.key, this.userId});

  final Uint8List response;
  final String ticket;
  final List<String> twoFactor;
  final String? key;
  final String? userId;
}

/// A sign-in's answer: tokens, or the second step the account owes (`status` `signed_in` or `two_factor_required`).
class KmSignInAnswer {
  const KmSignInAnswer({this.grant, this.challenge, this.methods = const [], this.newAccount = false, this.mfaViaSso = false});

  factory KmSignInAnswer.fromJson(Map<String, Object?> json, int now) {
    final status = json['status'];
    final tokens = json['tokens'];
    if (status == 'signed_in' && tokens is Map<String, Object?>) {
      return KmSignInAnswer(
        grant: KmGrant.fromJson(tokens, now),
        newAccount: json['newAccount'] == true,
        mfaViaSso: json['mfaViaSso'] == true,
      );
    }
    final challenge = json['challenge'];
    if (status == 'two_factor_required' && challenge is String) {
      return KmSignInAnswer(
        challenge: challenge,
        methods: asStrings(json['methods']) ?? const [],
        newAccount: json['newAccount'] == true,
        mfaViaSso: json['mfaViaSso'] == true,
      );
    }
    throw FormatException('a sign-in answer with status $status');
  }

  /// Set when the sign-in is done.
  final KmGrant? grant;

  /// Set when a second step is owed: send it back with the code.
  final String? challenge;

  /// The second-step methods the account has (`totp`, `webauthn`, `email`, `duo`, …).
  final List<String> methods;

  /// This sign-in made the account (SSO): its device makes the keys.
  final bool newAccount;

  /// The provider did multi-factor authentication, so Kemlock's own second step was skipped.
  final bool mfaViaSso;

  bool get needsSecondStep => grant == null;
}

/// What the server holds of an account's keys, for opening it after sign-in: `GET /kem/v1/account/keys`. It has no
/// PRF wraps: a passkey sign-in answers with the one for its own credential ([KmPasskeyGrant.prf]).
class KmAccountMaterial {
  const KmAccountMaterial({required this.keyVersion, this.wrappedRootKey, this.publicBundle, this.bundleSignature, this.sealedPrivateKeys});

  factory KmAccountMaterial.fromJson(Map<String, Object?> json) {
    Uint8List? bytes(String name) {
      final value = json[name];
      if (value == null) {
        return null;
      }
      if (value is! String) {
        throw FormatException('$name is base64url');
      }
      try {
        return b64urlDecode(value);
      } on MalformedException catch (e) {
        throw FormatException(e.message);
      }
    }

    return KmAccountMaterial(
      keyVersion: asInt(json['keyVersion']) ?? 1,
      wrappedRootKey: bytes('wrappedRootKey'),
      publicBundle: bytes('publicBundle'),
      bundleSignature: bytes('bundleSignature'),
      sealedPrivateKeys: bytes('sealedPrivateKeys'),
    );
  }

  final int keyVersion;

  /// The root key under the master key and the OPAQUE export key (`crypto.md` "The password wrap").
  final Uint8List? wrappedRootKey;
  final Uint8List? publicBundle;
  final Uint8List? bundleSignature;
  final Uint8List? sealedPrivateKeys;

  /// Whether the account has a key bundle at all. A Compatible account that never signed in to Kemlock has none, and
  /// nor has an SSO account before its first device makes its keys, whose fields the server leaves empty.
  bool get hasKeys => (publicBundle?.isNotEmpty ?? false) && (sealedPrivateKeys?.isNotEmpty ?? false);
}

/// A passkey sign-in's options, from `POST /auth/passkey/options`: WebAuthn's request options and the server's
/// sealed challenge, which goes back with the answer. The credentials are discoverable: no account is named, and
/// the allow list is empty, so the authenticator offers its own credential for the server.
class KmPasskeyOptions {
  const KmPasskeyOptions({
    required this.sealedChallenge,
    required this.challenge,
    required this.rpId,
    this.credentialIds = const [],
    this.userVerification = 'required',
  });

  factory KmPasskeyOptions.fromJson(Map<String, Object?> json) {
    final sealed = json['challenge'];
    final wrapped = json['options'];
    if (sealed is! String || sealed.isEmpty || wrapped is! Map<String, Object?>) {
      throw const FormatException('passkey options');
    }
    // The options of a browser are `publicKey`'s members, or those inside `publicKey`
    final inner = wrapped['publicKey'];
    final options = inner is Map<String, Object?> ? inner : wrapped;
    final challenge = options['challenge'];
    final rpId = options['rpId'];
    if (challenge is! String || rpId is! String || rpId.isEmpty) {
      throw const FormatException('passkey options');
    }
    final allowed = options['allowCredentials'];
    final verification = options['userVerification'];
    try {
      return KmPasskeyOptions(
        sealedChallenge: sealed,
        challenge: b64urlDecode(challenge),
        rpId: rpId,
        credentialIds: [
          if (allowed is List<Object?>)
            for (final credential in allowed.whereType<Map<String, Object?>>())
              if (credential['id'] is String) b64urlDecode(credential['id']! as String),
        ],
        userVerification: verification is String ? verification : 'required',
      );
    } on MalformedException catch (e) {
      throw FormatException(e.message);
    }
  }

  /// The server's sealed challenge, sent back unread to `/auth/passkey/verify` within five minutes.
  final String sealedChallenge;

  /// The WebAuthn challenge the authenticator signs.
  final Uint8List challenge;
  final String rpId;

  /// The credentials the authenticator may use; empty for a discoverable credential.
  final List<Uint8List> credentialIds;

  /// WebAuthn's `userVerification`, `required` as the server asks it.
  final String userVerification;
}

/// A passkey's copy of the root key, wrapped under its PRF output (`crypto.md` "The passkey PRF wrap"), for the
/// account's key version.
class KmPrfWrap {
  const KmPrfWrap({required this.wrapped, required this.keyVersion});

  final Uint8List wrapped;
  final int keyVersion;
}

/// What `POST /auth/passkey/verify` answers: tokens, which passkey signed in, and its PRF copy of the root key
/// when it has one for the account's current key version (without it the sign-in opens no vault).
class KmPasskeyGrant {
  const KmPasskeyGrant({required this.grant, required this.passkeyId, required this.keyVersion, this.prf});

  factory KmPasskeyGrant.fromJson(Map<String, Object?> json, int now) {
    final tokens = json['tokens'];
    final passkeyId = json['passkeyId'];
    final keyVersion = json['keyVersion'];
    final prf = json['prf'];
    if (tokens is! Map<String, Object?> || passkeyId is! String || keyVersion is! int) {
      throw const FormatException('a passkey sign-in answer');
    }
    KmPrfWrap? wrap;
    if (prf != null) {
      final wrapped = prf is Map<String, Object?> ? prf['wrappedKey'] : null;
      final version = prf is Map<String, Object?> ? prf['keyVersion'] : null;
      if (wrapped is! String || version is! int) {
        throw const FormatException('a PRF copy');
      }
      try {
        wrap = KmPrfWrap(wrapped: b64urlDecode(wrapped), keyVersion: version);
      } on MalformedException catch (e) {
        throw FormatException(e.message);
      }
    }
    return KmPasskeyGrant(grant: KmGrant.fromJson(tokens, now), passkeyId: passkeyId, keyVersion: keyVersion, prf: wrap);
  }

  final KmGrant grant;

  /// The id of the passkey on the account.
  final String passkeyId;

  /// The account's key version now.
  final int keyVersion;

  /// The PRF copy of the root key for [keyVersion], or null.
  final KmPrfWrap? prf;
}

/// One of the account's passkeys, from `GET /kem/v1/account/passkeys`.
class KmAccountPasskey {
  const KmAccountPasskey({required this.id, required this.name, required this.prf, this.prfKeyVersion});

  factory KmAccountPasskey.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      throw const FormatException('a passkey is an object');
    }
    final id = json['id'];
    final prf = json['prf'];
    if (id is! String || !isUuidText(id) || prf is! bool) {
      throw const FormatException('a passkey');
    }
    return KmAccountPasskey(id: id, name: asString(json['name']), prf: prf, prfKeyVersion: asInt(json['prfKeyVersion']));
  }

  final String id;
  final String name;

  /// Whether the passkey holds a PRF copy of the root key.
  final bool prf;

  /// The key version of that copy.
  final int? prfKeyVersion;
}

/// A request for approval as the new device sees its answer.
class KmApprovalTicket {
  const KmApprovalTicket({required this.id, required this.phrase, required this.expiresAt});

  final String id;

  /// The server's five words: a cross-check, never shown.
  final String phrase;
  final DateTime expiresAt;
}

/// How a request stands, as the new device polls it.
class KmApprovalPoll {
  const KmApprovalPoll({required this.status, this.sealedKey, this.accountId});

  /// `pending`, `approved`, `denied`, `expired` or `used`.
  final String status;

  /// With `approved`: the root key sealed to the request's one-time key, bound to the account id and the request id.
  final Uint8List? sealedKey;

  /// The account the key opens, which the box is bound to: the server answers it with `approved` only.
  final String? accountId;
}

/// A pending request on an open device.
class KmApprovalRequest {
  const KmApprovalRequest({
    required this.id,
    required this.deviceName,
    required this.deviceKind,
    required this.ip,
    required this.phrase,
    required this.createdAt,
    required this.expiresAt,
    this.publicKey,
  });

  factory KmApprovalRequest.fromJson(Map<String, Object?> json) {
    final id = json['id'];
    final created = DateTime.tryParse(asString(json['createdAt']));
    final expires = DateTime.tryParse(asString(json['expiresAt']));
    if (id is! String || !isUuidText(id) || created == null || expires == null) throw const FormatException('an approval request');
    // The request's one-time `kx1` public key, base64url, 1,600 bytes: the phrase is computed from it here
    final key = json['publicKey'];
    Uint8List? publicKey;
    if (key is String) {
      try {
        publicKey = b64urlDecode(key);
      } on MalformedException catch (e) {
        throw FormatException(e.message);
      }
    }
    return KmApprovalRequest(
      id: id,
      deviceName: asString(json['deviceName']),
      deviceKind: asString(json['deviceKind'], 'other'),
      ip: asString(json['ip']),
      phrase: asString(json['phrase']),
      createdAt: created,
      expiresAt: expires,
      publicKey: publicKey,
    );
  }

  final String id;
  final String deviceName;
  final String deviceKind;

  /// The requester's address, cut to its /24 or /48.
  final String ip;

  /// The server's five words: a cross-check only.
  final String phrase;
  final DateTime createdAt;
  final DateTime expiresAt;

  /// The request's one-time `kx1` public key, 1,600 bytes. The server's list doesn't return it yet (it
  /// returns only its own `phrase`), so an approving phone has nothing to seal to or to compute the words
  /// from; the client is written to a `publicKey` member of each request.
  final Uint8List? publicKey;
}

/// One of the account's devices with each API's last use, as `GET /kem/v1/devices` lists them (the server's app
/// contract, not built yet).
class KmDevice {
  const KmDevice({
    required this.id,
    required this.name,
    required this.kind,
    this.createdAt,
    this.lastSeen,
    this.lastKemlock,
    this.lastBitwarden,
    this.current = false,
    this.trusted = false,
  });

  factory KmDevice.fromJson(Map<String, Object?> json) {
    final id = json['id'];
    if (id is! String) throw const FormatException('a device');
    return KmDevice(
      id: id,
      name: asString(json['name']),
      kind: asString(json['kind'], 'other'),
      createdAt: DateTime.tryParse(asString(json['createdAt'])),
      lastSeen: DateTime.tryParse(asString(json['lastSeenAt'])),
      lastKemlock: DateTime.tryParse(asString(json['lastKemlockUseAt'])),
      lastBitwarden: DateTime.tryParse(asString(json['lastBitwardenUseAt'])),
      current: json['current'] == true,
      trusted: json['trusted'] == true,
    );
  }

  final String id;
  final String name;
  final String kind;
  final DateTime? createdAt;

  /// Its last request on either API.
  final DateTime? lastSeen;

  /// Its last use of the Kemlock API, or null for never.
  final DateTime? lastKemlock;

  /// Its last use of the Bitwarden API, or null for never.
  final DateTime? lastBitwarden;

  /// This phone.
  final bool current;

  /// Whether the server holds a trusted-device copy for it.
  final bool trusted;
}

/// The sign-in and device routes.
class KmAuthApi {
  KmAuthApi(this.api, {this.clock = DateTime.now});

  final KmApi api;
  final DateTime Function() clock;

  int get _now => clock().millisecondsSinceEpoch;

  Future<KmMethods> methods(Uri server, String email) async =>
      KmMethods.fromJson((await api.call('POST', server, '/auth/methods', body: {'email': email.trim()}, proof: false))!);

  Future<KmPrelogin> prelogin(Uri server, String email) async {
    final json = (await api.call('POST', server, '/auth/prelogin', body: {'email': email.trim()}, proof: false))!;
    try {
      return KmPrelogin.fromJson(json);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  // ─── OPAQUE ────────────────────────────────────────────────────────────

  /// The first message: KE1 in, `{response, loginState}` out. The login state is bound to the DPoP key.
  Future<({Uint8List response, String loginState})> opaqueStart(Uri server, String email, Uint8List request) async {
    final json = (await api.call('POST', server, '/auth/opaque/start', body: {'email': email.trim(), 'request': b64urlEncode(request)}))!;
    final response = json['response'];
    final state = json['loginState'];
    if (response is! String || state is! String) throw const KmError(KmProblem.server, message: 'an OPAQUE start answer');
    return (response: _bytes(response), loginState: state);
  }

  /// The last message: KE3 and the device. A wrong password is a 401 `auth` error.
  Future<KmSignInAnswer> opaqueFinish(Uri server, String email, String loginState, Uint8List finalization, KmDeviceInfo device) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/opaque/finish',
      body: {'email': email.trim(), 'loginState': loginState, 'finalization': b64urlEncode(finalization), 'device': device.toJson()},
    ))!;
    return _answer(json);
  }

  /// The answer to a second step, with the code. Each method has its route: `totp` answers at `/auth/two-factor`, an
  /// emailed code at `/auth/two-factor/email`, and the account's recovery code at `/auth/two-factor/recovery`, which
  /// turns every method of the account off and is spent.
  Future<KmGrant> twoFactor(Uri server, String challenge, String method, String code) async {
    if (method == 'webauthn') {
      // A security key's answer is a credential, not a code: [code] is its JSON
      final Object? credential;
      try {
        credential = jsonDecode(code);
      } on FormatException {
        throw const KmError(KmProblem.auth, message: 'a security key answer that is not JSON');
      }
      if (credential is! Map<String, Object?>) throw const KmError(KmProblem.auth, message: 'a security key answer that is no object');
      return securityKeyStep(server, challenge, credential);
    }
    final route = switch (method) {
      'email' => '/auth/two-factor/email',
      'recovery' => '/auth/two-factor/recovery',
      _ => null,
    };
    final json = (await api.call(
      'POST',
      server,
      route ?? '/auth/two-factor',
      body: {'challenge': challenge, if (route == null) 'method': method, 'code': code},
    ))!;
    return _grant(json);
  }

  /// The request options for the account's security keys (`POST /auth/two-factor/webauthn/options`), for a sign-in that owes
  /// its second step. The sealed [challenge] is the one the password step gave, sent back with the key's answer.
  Future<KmPasskeyOptions> securityKeyOptions(Uri server, String challenge) async {
    final json = (await api.call('POST', server, '/auth/two-factor/webauthn/options', body: {'challenge': challenge}))!;
    try {
      return KmPasskeyOptions.fromJson({'challenge': challenge, 'options': json['options']});
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// The security key's answer, `PublicKeyCredential.toJSON()` as the server wants it (`POST /auth/two-factor/webauthn`).
  Future<KmGrant> securityKeyStep(Uri server, String challenge, Map<String, Object?> credential) async {
    final json = (await api.call('POST', server, '/auth/two-factor/webauthn', body: {'challenge': challenge, 'credential': credential}))!;
    return _grant(json);
  }

  /// Mails the code of the email second step to the address the account set up (`POST /auth/two-factor/email/send`),
  /// for the sign-in that owes it. Answers 204.
  Future<void> sendEmailCode(Uri server, String challenge) async {
    await api.call('POST', server, '/auth/two-factor/email/send', body: {'challenge': challenge});
  }

  // ─── A Compatible account's first sign-in (the server's app contract; not built on the server yet) ────

  /// The account's Bitwarden KDF from the Bitwarden API's own prelogin, `POST /identity/accounts/prelogin`. The
  /// caller reads it with `BwKdf.fromJson`'s bounds before anything is derived.
  Future<Map<String, Object?>> bitwardenPrelogin(Uri server, String email) async =>
      (await api.call('POST', server, '/identity/accounts/prelogin', body: {'email': email.trim()}, proof: false, root: true))!;

  /// `POST /auth/bitwarden/start`: the Bitwarden master-password hash, once, with OPAQUE's registration request,
  /// needing only a DPoP proof. A 409 says the account already has OPAQUE or keys.
  Future<KmBitwardenStart> bitwardenStart(Uri server, String email, String masterPasswordHash, Uint8List request) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/bitwarden/start',
      body: {'email': email.trim(), 'masterPasswordHash': masterPasswordHash, 'request': b64urlEncode(request)},
    ))!;
    final response = json['response'];
    final ticket = json['ticket'];
    if (response is! String || ticket is! String) throw const KmError(KmProblem.server, message: 'a Bitwarden start answer');
    return KmBitwardenStart(
      response: _bytes(response),
      ticket: ticket,
      twoFactor: asStrings(json['twoFactor']) ?? const [],
      key: asOptionalString(json['key']),
      userId: asOptionalString(json['userId']),
    );
  }

  /// `POST /auth/bitwarden/finish` (204): the ticket, the OPAQUE record, the Argon2id settings and salt, the key
  /// fields as `register/finish` has them, and the second step's code when one was owed.
  Future<void> bitwardenFinish(Uri server, Map<String, Object?> body) async {
    await api.call('POST', server, '/auth/bitwarden/finish', body: body);
  }

  // ─── Keys ──────────────────────────────────────────────────────────────

  /// The account's key material, for opening it: `GET /kem/v1/account/keys`.
  Future<KmAccountMaterial> accountKeys(Uri server, String token) async {
    final json = (await api.call('GET', server, '/account/keys', token: token))!;
    try {
      return KmAccountMaterial.fromJson(json);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// `POST /kem/v1/account/keys/enrol`: the first keys of an account that has none, made by this device, with this
  /// device's copy of the root key ([deviceCopy], held under [protection]). [keys] is `publicBundle`,
  /// `bundleSignature` and `sealedPrivateKeys`, base64url, for key version 1. Answers the key version, 1. A 409 (a
  /// [KmProblem.stale] error) says the account has keys already, and nothing was changed.
  Future<int> enrolKeys(Uri server, String token, Map<String, Object?> keys, Uint8List deviceCopy, String protection) async {
    final json = (await api.call(
      'POST',
      server,
      '/account/keys/enrol',
      token: token,
      body: {
        ...keys,
        'deviceCopy': {'wrappedKey': b64urlEncode(deviceCopy), 'protection': protection},
      },
    ))!;
    final version = asInt(json['keyVersion']);
    if (version == null) throw const KmError(KmProblem.server, message: 'an enrol answer with no key version');
    return version;
  }

  // ─── Passkeys ──────────────────────────────────────────────────────────

  /// The options for a sign-in with a discoverable passkey: no email and no body, a proof of the device key, which
  /// binds the challenge so that only this key may answer it.
  Future<KmPasskeyOptions> passkeyOptions(Uri server) async {
    final json = (await api.call('POST', server, '/auth/passkey/options'))!;
    try {
      return KmPasskeyOptions.fromJson(json);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// The authenticator's answer for tokens: the sealed [challenge] of [passkeyOptions] and [credential], the
  /// browser's `PublicKeyCredential.toJSON()` (`kmPasskeyCredential` writes it, with no PRF output in it). A
  /// challenge is good once, right answer or wrong; "Require SSO" answers a 403.
  Future<KmPasskeyGrant> passkeyVerify(Uri server, String challenge, Map<String, Object?> credential, KmDeviceInfo device) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/passkey/verify',
      body: {'challenge': challenge, 'credential': credential, 'device': device.toJson()},
    ))!;
    try {
      return KmPasskeyGrant.fromJson(json, _now);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// The account's passkeys (at most five), and whether each holds a PRF copy of the root key.
  Future<List<KmAccountPasskey>> accountPasskeys(Uri server, String token) async {
    final json = (await api.call('GET', server, '/account/passkeys', token: token))!;
    final list = json['passkeys'];
    if (list is! List<Object?>) {
      throw const KmError(KmProblem.server, message: 'a passkeys answer');
    }
    try {
      return [for (final passkey in list) KmAccountPasskey.fromJson(passkey)];
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// Stores the PRF copy of the root key of a passkey that was made without one: [wrapped] is 92 bytes and
  /// [keyVersion] must be the account's current one (a 400 otherwise).
  Future<void> setPasskeyPrf(Uri server, String token, String passkeyId, Uint8List wrapped, int keyVersion) async {
    await api.call(
      'PUT',
      server,
      '/account/passkeys/$passkeyId/prf',
      token: token,
      body: {'wrappedKey': b64urlEncode(wrapped), 'keyVersion': keyVersion},
    );
  }

  // ─── SSO ───────────────────────────────────────────────────────────────

  /// Starts SSO: the PKCE [challenge] (the base64url SHA-256 of a verifier the phone keeps) and its own
  /// [state], 16 to 256 URL-safe characters, with a proof of the device key, which the server binds the
  /// flow to. Returns the provider's address to open in the system browser.
  ///
  /// The browser extension also gives its own [redirect] (`https://<id>.chromiumapp.org/`, where the browser's identity API
  /// ends the trip) and its device [kind], `kemlock-browser`, which the server needs to allow that address.
  Future<({String url, String providerName})> ssoStart(Uri server, String challenge, String state, {String? redirect, String? kind}) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/sso/start',
      body: {'challenge': challenge, 'state': state, 'redirect': ?redirect, 'kind': ?kind},
    ))!;
    final url = json['authorizationUrl'];
    if (url is! String) throw const KmError(KmProblem.server, message: 'an SSO start answer');
    return (url: url, providerName: asString(json['providerName']));
  }

  /// Ends SSO: the one-time [code] from the redirect and the PKCE [verifier], with a proof of the same key.
  Future<KmSignInAnswer> ssoFinish(Uri server, String code, String verifier, KmDeviceInfo device) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/sso/finish',
      body: {'code': code, 'verifier': verifier, 'device': device.toJson()},
    ))!;
    return _answer(json);
  }

  // ─── A new device asks to be approved ──────────────────────────────────

  /// Asks the account's open devices to approve this one, with its one-time `kx1` [publicKey].
  Future<KmApprovalTicket> approvalRequest(Uri server, String email, Uint8List publicKey, KmDeviceInfo device) async {
    final json = (await api.call(
      'POST',
      server,
      '/auth/device/request',
      body: {'email': email.trim(), 'publicKey': b64urlEncode(publicKey), 'device': device.toJson()},
    ))!;
    final id = json['requestId'];
    final expires = DateTime.tryParse(asString(json['expiresAt']));
    if (id is! String || expires == null) throw const KmError(KmProblem.server, message: 'an approval answer');
    return KmApprovalTicket(id: id, phrase: asString(json['phrase']), expiresAt: expires);
  }

  /// How the request stands. Signed with the key that made it.
  Future<KmApprovalPoll> approvalPoll(Uri server, String id) async {
    final json = (await api.call('GET', server, '/auth/device/request/$id'))!;
    final sealed = json['sealedKey'];
    return KmApprovalPoll(
      status: asString(json['status']),
      sealedKey: sealed is String ? _bytes(sealed) : null,
      accountId: asOptionalString(json['accountId']),
    );
  }

  /// A challenge for an approved request: sent back to [deviceVerify] within five minutes with a proof of the same key.
  Future<String> deviceChallenge(Uri server, String requestId) async {
    final json = (await api.call('POST', server, '/auth/device/challenge', body: {'requestId': requestId}))!;
    final challenge = json['challenge'];
    if (challenge is! String) throw const KmError(KmProblem.server, message: 'a device challenge');
    return challenge;
  }

  Future<KmGrant> deviceVerify(Uri server, String challenge) async =>
      _grant((await api.call('POST', server, '/auth/device/verify', body: {'challenge': challenge}))!);

  // ─── A replica signs this device in with its key (`/auth/device-key`, for a vault copied from its home) ──

  /// A challenge for this device on a replica, which holds the device's registration copied from the home and
  /// knows it by its key: the request is signed with that key, and a device it doesn't know, or another key, is a 401.
  /// A server with no federation answers 404, and one that holds the account itself refuses with a 401: this route
  /// is for copies.
  Future<String> replicaChallenge(Uri server, String deviceId) async {
    final json = (await api.call('POST', server, '/auth/device-key/challenge', body: {'deviceId': deviceId}))!;
    final challenge = json['challenge'];
    if (challenge is! String) throw const KmError(KmProblem.server, message: 'a replica challenge');
    return challenge;
  }

  Future<KmGrant> replicaVerify(Uri server, String challenge) async =>
      _grant((await api.call('POST', server, '/auth/device-key/verify', body: {'challenge': challenge}))!);

  // ─── An open device answers, and lists devices ─────────────────────────

  Future<List<KmApprovalRequest>> approvals(Uri server, String token) async {
    final json = (await api.call('GET', server, '/devices/approvals', token: token))!;
    final list = json['approvals'];
    if (list is! List<Object?>) throw const KmError(KmProblem.server, message: 'an approvals answer');
    try {
      return [for (final request in list) KmApprovalRequest.fromJson(request as Map<String, Object?>)];
    } on Object catch (e) {
      throw KmError(KmProblem.server, message: '$e');
    }
  }

  /// Approves with the root key sealed to the request's key, or denies when [sealedKey] is null.
  Future<void> answerApproval(Uri server, String token, String id, {Uint8List? sealedKey}) async {
    await api.call(
      'POST',
      server,
      '/devices/approvals/$id',
      token: token,
      body: {'decision': sealedKey == null ? 'deny' : 'approve', 'sealedKey': ?(sealedKey == null ? null : b64urlEncode(sealedKey))},
    );
  }

  /// The account's devices with each API's last use.
  Future<List<KmDevice>> devices(Uri server, String token) async {
    final json = (await api.call('GET', server, '/devices', token: token))!;
    final list = json['devices'];
    if (list is! List<Object?>) throw const KmError(KmProblem.server, message: 'a devices answer');
    try {
      return [for (final device in list) KmDevice.fromJson(device as Map<String, Object?>)];
    } on Object catch (e) {
      throw KmError(KmProblem.server, message: '$e');
    }
  }

  /// Gives the server this device's push token, `POST /devices/push-token` (the server's `PushTokenRequest`: `kind`
  /// `fcm` or `apns`, and a token of 1 to 512 characters with no whitespace). Answers 204.
  Future<void> registerPushToken(Uri server, String accessToken, KmPushToken push) async {
    await api.call('POST', server, '/devices/push-token', token: accessToken, body: {'kind': push.kind, 'token': push.token});
  }

  /// Takes this device's push token back, `DELETE /devices/push-token`. Answers 204, also when there was none.
  Future<void> unregisterPushToken(Uri server, String accessToken) async {
    await api.call('DELETE', server, '/devices/push-token', token: accessToken);
  }

  /// Ends [deviceId]'s session and deletes its key copy.
  Future<void> signOutDevice(Uri server, String token, String deviceId) async {
    await api.call('POST', server, '/devices/sign-out', token: token, body: {'deviceId': deviceId});
  }

  KmSignInAnswer _answer(Map<String, Object?> json) {
    try {
      return KmSignInAnswer.fromJson(json, _now);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  KmGrant _grant(Map<String, Object?> json) {
    try {
      return KmGrant.fromJson(json, _now);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  Uint8List _bytes(String text) {
    try {
      return b64urlDecode(text);
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }
}
