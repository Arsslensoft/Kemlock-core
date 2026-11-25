/// Signing in to a Kemlock Server, step by step, as data. [KmSignIn] is one
/// sign-in attempt: each call returns a [KmSignInStep] that a sheet draws and
/// a test reads, as `VwSignInStep` does for Vaultwarden.
///
/// 1. [KmSignIn.ways]: `GET /config` on the typed address (it must be a
///    Kemlock Server that speaks `v1`), then `POST /auth/methods`.
/// 2. One of:
///    - [KmSignIn.password]: `POST /auth/prelogin` first, so the master key
///      exists before KE1, with the Argon2id settings held to fixed bounds
///      before any work; then OPAQUE (`/auth/opaque/start`, `/finish`). The
///      export key and the master key open the root key.
///    - A Compatible account that has no OPAQUE record, which the phone learns
///      only when OPAQUE fails (the server answers the same for every email):
///      Bitwarden's KDF is checked by `bitwarden.dart`'s bounds, the Bitwarden
///      hash goes once to `/auth/bitwarden/start` with OPAQUE's registration
///      request, `/auth/bitwarden/finish` enrols it, and the phone signs in
///      through OPAQUE. The account stays Compatible: its root key is the
///      Bitwarden user key.
///    - [KmSignIn.continueWith], for the answer of a passkey or of SSO.
/// 3. [KmSignIn.secondStep] when the server owes one: an authenticator code,
///    an email code or a security key. Other methods go to the web vault.
/// 4. The account opens by the password, by [KmSignIn.openWithTrust], by a
///    passkey's PRF output ([KmSignIn.openWithPrf]) or by an approval's root
///    key ([KmSignIn.openWithRoot]). An account that single sign-on made, and
///    that has no keys yet, has none of these to open with: this device makes
///    its keys and its trusted-device copy of the root key with
///    [KmSignIn.enrolKeys], which opens it at once.
///
/// **No downgrade.** Once this phone has seen an account enrolled in OPAQUE (a
/// successful OPAQUE sign-in or registration) it remembers that, and refuses
/// the Bitwarden-hash route for the account from then on, whatever the server
/// says, before anything derived from the password is made or sent. Only the
/// phone's own record can close that route: a hostile or rolled-back server
/// can always claim OPAQUE isn't enrolled.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/argon2id.dart';
import '../../../crypto/account/bundle.dart';
import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/keys.dart';
import '../../../crypto/account/kx1.dart';
import '../../../crypto/account/password_wrap.dart';
import '../../../crypto/account/prf_wrap.dart';
import '../../../crypto/account/private_keys.dart';
import '../../../crypto/account/sig1.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart' show randomBytes;
import '../../../crypto/opaque/opaque_client.dart';
import '../../../crypto/opaque/opaque_messages.dart';
import 'km_account.dart';
import 'km_api.dart';
import 'km_auth_api.dart';
import 'km_session.dart';
import 'km_trust.dart';

/// Why a sign-in stopped. The names are the ends of the `kemlock.signin.*` message ids where a sheet says them.
enum KmSignInIssue {
  /// "Wrong email or password." No lockout, and nothing says which.
  wrongPassword,

  /// The server answered as if an account this phone saw enrolled in OPAQUE had no OPAQUE record, and Kemlock
  /// refused the older, weaker route; nothing derived from the password was sent. OPAQUE can't tell a plain
  /// wrong password from a server that isn't the one set up, so the sheet says both, and points to the
  /// server's address. The phone never falls back to the Bitwarden-hash route for the account.
  downgrade,

  /// The server's key-derivation cost is outside the bounds Kemlock holds it to. Stopped before any work.
  kdfBounds,

  /// The account's second step is one the phone can't answer (Duo, a YubiKey OTP, a recovery code): sign
  /// in from the web vault.
  webVaultOnly,

  /// The phone has no way in the account offers: no password, no passkey, no SSO.
  noWay,

  /// The account's keys don't open or aren't the account's own.
  unreadable,

  /// The account has no keys yet and this phone must make them, but it has no hardware key to hold the copy of the
  /// root key that opens the account here again, and a software key would keep that copy no safer than the vault.
  noDeviceKey,

  /// The person closed the browser sheet: the phone is still signed out.
  cancelled,

  /// The browser sheet couldn't be opened, or the redirect wasn't this sign-in's or carried the provider's error.
  ssoFailed,

  /// The server doesn't speak what this version needs for this step (a route or a field the server lacks).
  unsupported,

  /// A space the account belongs to requires single sign-on, and the server said so once the person had proved who
  /// they are, whichever way they signed in: "Sign in with SSO instead." [KmSignInError.detail] names the space.
  ssoRequired,
}

/// What a sheet or a test makes of [error]: a server's `sso-required` answer as the [KmSignInIssue.ssoRequired] it
/// means, and anything else as it is.
Object kmSignInFailure(Object error) => switch (error) {
  KmError(problem: KmProblem.ssoRequired, :final spaceId) => KmSignInError(KmSignInIssue.ssoRequired, detail: spaceId),
  _ => error,
};

/// A sign-in that stopped.
class KmSignInError implements Exception {
  const KmSignInError(this.issue, {this.detail});

  final KmSignInIssue issue;

  /// What stopped it, for logs: the methods named, the cost refused.
  final String? detail;

  @override
  String toString() => 'KmSignInError(${issue.name}${detail != null ? ': $detail' : ''})';
}

/// The OPAQUE messages as bytes, the seam tests put a fake server's in place of the real client behind.
abstract interface class KmOpaque {
  /// KE1 for the 32-byte master key; [state] goes to [finish].
  ({Uint8List request, Object state}) start(Uint8List masterKey);

  /// KE3 and the 64-byte export key from the server's KE2. A wrong password, a changed server key and an
  /// unknown account all throw an [OpaqueException] of kind authentication.
  ({Uint8List finalization, Uint8List exportKey}) finish(Object state, Uint8List response);

  /// The blinded registration request for the master key.
  ({Uint8List request, Object state}) registerStart(Uint8List masterKey);

  /// The record to store and the export key, from the server's registration response.
  ({Uint8List upload, Uint8List exportKey}) registerFinish(Object state, Uint8List response);
}

/// [KmOpaque] over `lib/crypto/opaque`'s client.
class OpaqueKmOpaque implements KmOpaque {
  OpaqueKmOpaque([OpaqueClient? client]) : _client = client ?? OpaqueClient();

  final OpaqueClient _client;

  @override
  ({Uint8List request, Object state}) start(Uint8List masterKey) {
    final ke1 = _client.generateKe1(masterKey);
    return (request: ke1.ke1.bytes, state: ke1.state);
  }

  @override
  ({Uint8List finalization, Uint8List exportKey}) finish(Object state, Uint8List response) {
    final Ke2 ke2;
    try {
      ke2 = Ke2.parse(response);
    } on MalformedException catch (e) {
      throw OpaqueException(OpaqueFailure.protocol, e.message);
    }
    final ke3 = _client.generateKe3(state as OpaqueLoginState, ke2);
    wipe(ke3.sessionKey);
    return (finalization: ke3.ke3.bytes, exportKey: ke3.exportKey);
  }

  @override
  ({Uint8List request, Object state}) registerStart(Uint8List masterKey) {
    final registration = _client.createRegistrationRequest(masterKey);
    return (request: registration.request.bytes, state: registration.state);
  }

  @override
  ({Uint8List upload, Uint8List exportKey}) registerFinish(Object state, Uint8List response) {
    final RegistrationResponse parsed;
    try {
      parsed = RegistrationResponse.parse(response);
    } on MalformedException catch (e) {
      throw OpaqueException(OpaqueFailure.protocol, e.message);
    }
    final done = _client.finalizeRegistrationRequest(state as OpaqueRegistrationState, parsed);
    return (upload: done.record.bytes, exportKey: done.exportKey);
  }
}

/// The fixed bounds the server's Argon2id settings are held to before any work (Amethystora's, in the design):
/// 2 to 10 passes, 16 to 1,024 MiB and 1 to 16 lanes, over a 16-byte salt.
void checkArgon2Bounds(Argon2idSettings settings, Uint8List salt) {
  final ok =
      settings.iterations >= 2 &&
      settings.iterations <= 10 &&
      settings.memoryKiB >= 16 * 1024 &&
      settings.memoryKiB <= 1024 * 1024 &&
      settings.parallelism >= 1 &&
      settings.parallelism <= 16 &&
      salt.length == Argon2idSettings.saltLength;
  if (!ok) throw KmSignInError(KmSignInIssue.kdfBounds, detail: '$settings, salt ${salt.length} bytes');
}

/// The second-step methods the phone answers. `recovery` is the account's recovery code, which the server takes whatever
/// methods the account has, so it is never in the list the server gives.
const kmAnswerableSecondSteps = {'totp', 'email', 'webauthn', 'recovery'};

/// A step of the sign-in.
sealed class KmSignInStep {
  const KmSignInStep();
}

/// The server owes a second step. [methods] are those the phone can answer, [unsupported] the others the
/// account has, which the sheet names and sends to the web vault.
class KmSecondStep extends KmSignInStep {
  const KmSecondStep({required this.methods, this.unsupported = const []});

  final List<String> methods;
  final List<String> unsupported;
}

/// Signed in. [account] is null when the account isn't open yet (SSO, or a passkey without PRF): open it
/// with the trusted-device copy, an approval or the password, or, when it has no keys yet, make them
/// ([KmSignIn.enrolKeys]).
class KmSignedIn extends KmSignInStep {
  const KmSignedIn({
    required this.session,
    this.account,
    this.bitwardenHashSent = false,
    this.enrolledOpaque = false,
    this.newAccount = false,
    this.mfaViaSso = false,
  });

  final KmSession session;
  final KmAccount? account;

  /// The Bitwarden hash went to the server once, on a Compatible account's first sign-in.
  final bool bitwardenHashSent;

  /// This sign-in enrolled OPAQUE.
  final bool enrolledOpaque;

  /// This sign-in made the account (SSO): this device makes its keys ([KmSignIn.enrolKeys]).
  final bool newAccount;

  /// The provider did multi-factor authentication, so Kemlock's own second step was skipped.
  final bool mfaViaSso;
}

/// The key version of the first keys an account has.
const _firstKeyVersion = 1;

enum _Route { opaque, external }

/// One sign-in attempt to one server, as one device. Stateful between its steps: it holds the master key and
/// export key while a second step is owed, and wipes them when the sign-in ends.
class KmSignIn {
  KmSignIn({
    required this.api,
    required this.server,
    required this.device,
    required this.opaque,
    this.deviceKey,
    this.opaqueSeen = false,
    this.rememberOpaque,
    this.argon2 = isolateArgon2id,
    this.bitwardenKey = bwMasterKey,
    this.clock = DateTime.now,
  }) : auth = KmAuthApi(api, clock: clock);

  final KmApi api;
  final KmAuthApi auth;
  final Uri server;

  /// What this device says about itself, with the Vaultwarden device identifier when there is one.
  final KmDeviceInfo device;
  final KmOpaque opaque;

  /// How the session finds the device key again (`DeviceKeyChoice.reference`).
  final Map<String, Object?>? deviceKey;

  /// This phone has seen the account enrolled in OPAQUE: the Bitwarden-hash route is closed.
  final bool opaqueSeen;

  /// Called once OPAQUE has been seen to work (a sign-in whose server proof verified, or a registration), so
  /// the host records it before anything else can fail.
  final Future<void> Function()? rememberOpaque;
  final Argon2idRunner argon2;

  /// Bitwarden's master key, `bwMasterKey` unless a test gives a cheaper one.
  final Future<Uint8List> Function(String password, String email, BwKdf kdf) bitwardenKey;
  final DateTime Function() clock;

  _Route? _route;
  String? _email;
  String? _password;
  String? _challenge;
  Uint8List? _masterKey;
  Uint8List? _exportKey;
  _Enrolment? _enrolment;
  Set<String>? _features;
  String? _domain;
  var _seen = false;
  var _hashSent = false;
  var _enrolled = false;
  var _newAccount = false;
  var _mfaViaSso = false;

  /// The domain the server says it is for (its passkeys' relying party), once [ways] ran.
  String? get domain => _domain;

  /// Whether this attempt has seen OPAQUE work, or this phone had before.
  bool get opaqueConfirmed => opaqueSeen || _seen;

  // ─── The ways in ───────────────────────────────────────────────────────

  /// Reads the server's config (a server that isn't a Kemlock Server, or doesn't speak `v1`, throws an
  /// `address` [KmError]) and the ways in [email] has. The answer is the same for an unknown email.
  Future<KmMethods> ways(String email) async {
    final config = await api.config(server);
    _features = config.features.toSet();
    _domain = config.domain;
    return auth.methods(server, email);
  }

  /// Whether the server lists [feature] in its config. Before the config was read, everything is allowed.
  bool _has(String feature) => _features?.contains(feature) ?? true;

  /// The account's keys, from `GET /account/keys` when the server lists `account-keys`.
  Future<KmAccountMaterial> _material(KmSession session) {
    if (!_has('account-keys')) throw const KmSignInError(KmSignInIssue.unsupported, detail: 'the server has no account-keys');
    return auth.accountKeys(server, session.tokens.access);
  }

  // ─── The password ──────────────────────────────────────────────────────

  /// Signs in with the master password. The server answers the same for every email (prelogin and the ways in),
  /// so the phone learns that a Compatible account has no OPAQUE record only when OPAQUE fails: the server's proof
  /// doesn't verify. It then falls back to the Bitwarden-hash route, but only when this phone has never seen that
  /// account enrolled in OPAQUE; otherwise it refuses ([KmSignInIssue.downgrade]: a wrong password, or a server
  /// that isn't the one set up, and the phone can't tell which), before the Bitwarden cost is read or anything
  /// derived from the password is made.
  Future<KmSignInStep> password(String email, String password) async {
    _email = email.trim();
    _password = password;
    final prelogin = await auth.prelogin(server, _email!);
    final settings = prelogin.settings;
    final salt = prelogin.salt;
    if (settings != null && salt != null) {
      checkArgon2Bounds(settings, salt);
      final masterKey = await deriveMasterKey(password, salt, settings: settings, runner: argon2);
      _masterKey = masterKey;
      try {
        return await _opaqueWith(masterKey);
      } on _NoOpaqueRecord {
        // Fall through to the Bitwarden route, if this phone may
      }
    }
    return _bitwardenEnrol();
  }

  /// KE1, KE2, KE3 with [masterKey], then the answer. An OPAQUE server proof that doesn't verify is a
  /// [_NoOpaqueRecord]: a wrong password, an account with no record or a server that isn't the one registered.
  Future<KmSignInStep> _opaqueWith(Uint8List masterKey) async {
    final email = _email!;
    final started = opaque.start(masterKey);
    final first = await auth.opaqueStart(server, email, started.request);
    final ({Uint8List finalization, Uint8List exportKey}) finished;
    try {
      finished = opaque.finish(started.state, first.response);
    } on OpaqueException catch (e) {
      if (e.failure == OpaqueFailure.authentication) throw const _NoOpaqueRecord();
      throw KmSignInError(KmSignInIssue.unsupported, detail: e.message);
    }
    _exportKey = finished.exportKey;
    // The server's proof verified: this account has an OPAQUE record, for good
    await _markOpaque();
    _route = _Route.opaque;
    final KmSignInAnswer answer;
    try {
      answer = await auth.opaqueFinish(server, email, first.loginState, finished.finalization, device);
    } on KmError catch (e) {
      if (e.problem == KmProblem.auth) throw const KmSignInError(KmSignInIssue.wrongPassword);
      rethrow;
    }
    return _afterAnswer(answer);
  }

  /// A Compatible account's first Kemlock sign-in, after OPAQUE failed (the plan's shape for the server's
  /// `/auth/bitwarden/start` and `/finish`, needing only a DPoP proof): the Bitwarden hash goes once with the
  /// OPAQUE registration request, the server answers the registration response and a ticket, and the phone
  /// finishes with the record, the Argon2id settings and salt and the keys (a second step first when the
  /// account owes one). The account stays Compatible: its root key is the Bitwarden user key. Then the phone
  /// signs in through OPAQUE as usual with the key it just enrolled under, with no second prompt.
  Future<KmSignInStep> _bitwardenEnrol() async {
    // The server can always claim OPAQUE isn't enrolled; only this phone's own record closes the route
    if (opaqueConfirmed) throw const KmSignInError(KmSignInIssue.downgrade);
    if (!_has('bitwarden-enrol')) throw const KmSignInError(KmSignInIssue.wrongPassword);
    final email = _email!;
    final password = _password!;
    final BwKdf kdf;
    try {
      kdf = BwKdf.fromJson(await auth.bitwardenPrelogin(server, email));
    } on FormatException catch (e) {
      throw KmSignInError(KmSignInIssue.kdfBounds, detail: '${e.message} ${e.source}');
    } on KmError {
      throw const KmSignInError(KmSignInIssue.wrongPassword);
    }
    final bitwardenMaster = await bitwardenKey(password, email, kdf);
    final hash = await bwMasterPasswordHash(bitwardenMaster, password);
    const settings = Argon2idSettings();
    final salt = randomBytes(Argon2idSettings.saltLength);
    final newMaster = await deriveMasterKey(password, salt, settings: settings, runner: argon2);
    final registration = opaque.registerStart(newMaster);
    final KmBitwardenStart started;
    try {
      _hashSent = true;
      started = await auth.bitwardenStart(server, email, hash, registration.request);
    } on KmError catch (e) {
      wipe(bitwardenMaster);
      wipe(newMaster);
      // 409: the account already has OPAQUE or keys, so it was a wrong password; 401: the hash was refused
      if (e.problem == KmProblem.stale || e.problem == KmProblem.auth) throw const KmSignInError(KmSignInIssue.wrongPassword);
      rethrow;
    }
    final userKey = started.key;
    final userId = started.userId;
    if (userKey == null || userId == null) {
      wipe(bitwardenMaster);
      wipe(newMaster);
      throw const KmSignInError(KmSignInIssue.unsupported, detail: 'the server sent no user key or account id');
    }
    final Uint8List root;
    try {
      root = (await bwOpenUserKey(userKey, bitwardenMaster)).bytes;
    } on BwCryptoError {
      throw const KmSignInError(KmSignInIssue.wrongPassword);
    } finally {
      wipe(bitwardenMaster);
    }
    _masterKey = newMaster;
    final pending = _Enrolment(started.ticket, registration.state, started.response, root, userId, settings, salt);
    _enrolment = pending;
    if (started.twoFactor.isEmpty) return _finishEnrol(null);
    final answerable = [
      for (final method in started.twoFactor)
        if (kmAnswerableSecondSteps.contains(method)) method,
    ];
    final others = [
      for (final method in started.twoFactor)
        if (!kmAnswerableSecondSteps.contains(method)) method,
    ];
    if (answerable.isEmpty) {
      close();
      throw KmSignInError(KmSignInIssue.webVaultOnly, detail: others.join(', '));
    }
    return KmSecondStep(methods: answerable, unsupported: others);
  }

  /// Sends the enrolment's last message, with the second step's code when there was one, then signs in
  /// through OPAQUE with the key it was enrolled under.
  Future<KmSignInStep> _finishEnrol(String? twoFactorCode) async {
    final pending = _enrolment!;
    final newMaster = _masterKey!;
    Uint8List? exportKey;
    try {
      final registered = opaque.registerFinish(pending.state, pending.response);
      exportKey = registered.exportKey;
      final wrapped = await wrapRootWithPassword(
        masterKey: newMaster,
        exportKey: exportKey,
        accountId: uuidBytes(pending.userId),
        keyVersion: 1,
        rootKey: pending.root,
      );
      await auth.bitwardenFinish(server, {
        'ticket': pending.ticket,
        'upload': b64urlEncode(registered.upload),
        'kdf': {
          'memoryKib': pending.settings.memoryKiB,
          'iterations': pending.settings.iterations,
          'parallelism': pending.settings.parallelism,
          'salt': b64urlEncode(pending.salt),
        },
        'wrappedRootKey': b64urlEncode(wrapped),
        ...await _newKeys(pending.userId, pending.root, 1),
        'twoFactorCode': ?twoFactorCode,
      });
      // OPAQUE is enrolled: the Bitwarden-hash route closes for this account
      await _markOpaque();
      _enrolled = true;
    } on OpaqueException catch (e) {
      throw KmSignInError(KmSignInIssue.unsupported, detail: e.message);
    } finally {
      wipe(pending.root);
      if (exportKey != null) wipe(exportKey);
      _enrolment = null;
    }
    try {
      return await _opaqueWith(newMaster);
    } on _NoOpaqueRecord {
      throw const KmSignInError(KmSignInIssue.unsupported, detail: 'the server didn’t keep the enrolment');
    }
  }

  // ─── Passkeys and SSO ──────────────────────────────────────────────────

  /// Goes on from the answer of a passkey or SSO sign-in: tokens, or a second step. The account isn't open
  /// after it.
  Future<KmSignInStep> continueWith(KmSignInAnswer answer, {String? email}) {
    _route = _Route.external;
    if (email != null) _email = email.trim();
    return _afterAnswer(answer);
  }

  // ─── A second step ─────────────────────────────────────────────────────

  /// Mails the code of the email second step, for the sign-in that owes one. A second request mails a new code.
  Future<void> sendEmailCode() async {
    final challenge = _challenge;
    if (challenge == null) throw StateError('no second step is owed');
    await auth.sendEmailCode(server, challenge);
  }

  /// Answers the second step with [code]: an authenticator code, an email code, the account's recovery code, or a
  /// security key's assertion as the sheet encodes it.
  Future<KmSignInStep> secondStep(String method, String code) async {
    if (!kmAnswerableSecondSteps.contains(method)) throw KmSignInError(KmSignInIssue.webVaultOnly, detail: method);
    // An enrolment waiting for its code finishes with it
    if (_enrolment != null) return _finishEnrol(code);
    final challenge = _challenge;
    if (challenge == null) throw StateError('no second step is owed');
    final grant = await auth.twoFactor(server, challenge, method, code);
    _challenge = null;
    return _afterGrant(grant);
  }

  Future<KmSignInStep> _afterAnswer(KmSignInAnswer answer) async {
    _newAccount = answer.newAccount;
    _mfaViaSso = answer.mfaViaSso;
    final grant = answer.grant;
    if (grant != null) return _afterGrant(grant);
    final answerable = [
      for (final method in answer.methods)
        if (kmAnswerableSecondSteps.contains(method)) method,
    ];
    final others = [
      for (final method in answer.methods)
        if (!kmAnswerableSecondSteps.contains(method)) method,
    ];
    if (answerable.isEmpty) {
      close();
      throw KmSignInError(KmSignInIssue.webVaultOnly, detail: others.join(', '));
    }
    _challenge = answer.challenge;
    return KmSecondStep(methods: answerable, unsupported: others);
  }

  Future<KmSignInStep> _afterGrant(KmGrant grant) async {
    final session = KmSession(userId: grant.userId, deviceId: grant.deviceId, tokens: grant.tokens, deviceKey: deviceKey);
    try {
      final KmSignInStep step;
      if (_route == _Route.opaque) {
        step = KmSignedIn(
          session: session,
          account: await _openWithPassword(session),
          newAccount: _newAccount,
          mfaViaSso: _mfaViaSso,
          enrolledOpaque: _enrolled,
          bitwardenHashSent: _hashSent,
        );
      } else {
        step = KmSignedIn(session: session, newAccount: _newAccount, mfaViaSso: _mfaViaSso);
      }
      // A second step still owed after enrolment needs the keys it was made with
      if (step is KmSignedIn) close();
      return step;
    } catch (_) {
      close();
      rethrow;
    }
  }

  /// The root key under the master key and the export key, then the account.
  Future<KmAccount> _openWithPassword(KmSession session) async {
    final material = await _material(session);
    final wrapped = material.wrappedRootKey;
    if (wrapped == null) throw const KmSignInError(KmSignInIssue.unreadable, detail: 'no wrapped root key');
    final Uint8List root;
    try {
      root = await unwrapRootWithPassword(
        masterKey: _masterKey!,
        exportKey: _exportKey!,
        accountId: uuidBytes(session.userId),
        keyVersion: material.keyVersion,
        wrapped: wrapped,
      );
    } on CorruptedException {
      throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the root key doesn’t open');
    } on MalformedException catch (e) {
      throw KmSignInError(KmSignInIssue.unreadable, detail: e.message);
    }
    try {
      return await _open(session.userId, root, material, opaqueEnrolled: true);
    } finally {
      wipe(root);
    }
  }

  /// A bundle, its signature and the sealed private keys for an account that has none yet.
  Future<Map<String, Object?>> _newKeys(String accountId, Uint8List root, int keyVersion) async {
    final kx1 = await Kx1.generate();
    final sig1 = await Sig1.generate();
    final bundle = KeyBundle(
      accountId: uuidBytes(accountId),
      keyVersion: keyVersion,
      kx1PublicKey: kx1.publicKey,
      sig1PublicKey: sig1.publicKey,
    );
    final keys = AccountKeys.fromRoot(root);
    try {
      return {
        'publicBundle': b64urlEncode(bundle.bytes),
        'bundleSignature': b64urlEncode(await signBundle(bundle, sig1.privateKey)),
        'sealedPrivateKeys': b64urlEncode(
          await sealPrivateKeys(
            privateKeysKey: keys.privateKeysKey,
            accountId: uuidBytes(accountId),
            keyVersion: keyVersion,
            kx1PrivateKey: kx1.privateKey,
            sig1PrivateKey: sig1.privateKey,
          ),
        ),
      };
    } finally {
      keys.dispose();
      wipe(kx1.privateKey);
      wipe(sig1.privateKey);
    }
  }

  // ─── Opening an account that signed in without opening ─────────────────

  /// Opens the account from [root], which an approval, the trusted-device copy or a passkey's PRF gave.
  /// The caller wipes [root].
  Future<KmAccount> openWithRoot(KmSession session, Uint8List root) async {
    final material = await _material(session);
    return _open(session.userId, root, material, opaqueEnrolled: opaqueConfirmed);
  }

  /// Opens the account with this phone's trusted-device key, or returns null when the phone is not trusted
  /// (no copy, or no key for it) so the sign-in goes on to an approval or the password. A copy the phone
  /// can't open throws a [KmTrustUnreadable].
  Future<KmAccount?> openWithTrust(KmSession session, KmTrust trust, String tag) async {
    final material = await _material(session);
    final root = await trust.openAfterSso(
      api: api,
      server: server,
      token: session.tokens.access,
      tag: tag,
      accountId: uuidBytes(session.userId),
      deviceId: uuidBytes(session.deviceId),
      keyVersion: material.keyVersion,
    );
    if (root == null) return null;
    try {
      return await _open(session.userId, root, material, opaqueEnrolled: opaqueConfirmed);
    } finally {
      wipe(root);
    }
  }

  /// Opens the account with a passkey's PRF output and the copy of the root key the server answered the sign-in
  /// with ([wrap]), or returns null when the copy is for another key version than the account's now, so the
  /// sign-in goes on to an approval or the password.
  Future<KmAccount?> openWithPrf(KmSession session, Uint8List prfOutput, Uint8List credentialId, KmPrfWrap wrap) async {
    final material = await _material(session);
    if (wrap.keyVersion != material.keyVersion) {
      return null;
    }
    final Uint8List root;
    try {
      root = await unwrapRootWithPrf(
        prfOutput: prfOutput,
        credentialId: credentialId,
        accountId: uuidBytes(session.userId),
        keyVersion: wrap.keyVersion,
        wrapped: wrap.wrapped,
      );
    } on CorruptedException {
      throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the PRF wrap doesn’t open');
    } on MalformedException catch (e) {
      throw KmSignInError(KmSignInIssue.unreadable, detail: e.message);
    }
    try {
      return await _open(session.userId, root, material, opaqueEnrolled: opaqueConfirmed);
    } finally {
      wipe(root);
    }
  }

  /// Makes the first keys of an account that has none, on this phone, and opens the account with them. A first
  /// single sign-on sign-in makes the account with key version 0 and no key material ([newAccount] says so, which
  /// saves asking), and this device is the one to make its keys: a fresh root key, the bundle, its signature and the
  /// sealed private keys at key version 1, and this phone's trusted-device copy of the root key, all sent to
  /// `POST /account/keys/enrol` (`crypto.md`, "Keys of an account that has no password"). The account has no
  /// password and no other device yet, so the copy is how this phone opens it again, and it is part of the
  /// enrolment, not the optional "Trust this phone".
  ///
  /// Without [newAccount] the server is asked for the account's keys first, so a first device that was killed
  /// before it enrolled (the server answers 404) is enrolled at its next sign-in.
  ///
  /// Returns null when the account has keys, because the server says so or answers 409 to the enrolment: another
  /// device enrolled first. Nothing of this phone's is kept then, and the sign-in goes on as for any account with
  /// keys, by this phone's copy, an approval or the password. A phone with no hardware key can't hold the copy and
  /// throws [KmSignInIssue.noDeviceKey]. The root key and the private keys are wiped before this returns.
  Future<KmAccount?> enrolKeys(KmSession session, KmTrust trust, String tag, {bool newAccount = false}) async {
    if (!_has('account-keys')) {
      throw const KmSignInError(KmSignInIssue.unsupported, detail: 'the server has no account-keys');
    }
    if (!newAccount && await _holdsKeys(session)) {
      return null;
    }
    final root = newRootKey();
    try {
      final Uint8List copy;
      try {
        copy = await trust.seal(
          tag: tag,
          rootKey: root,
          accountId: uuidBytes(session.userId),
          deviceId: uuidBytes(session.deviceId),
          keyVersion: _firstKeyVersion,
        );
      } on KmTrustUnavailable {
        throw const KmSignInError(KmSignInIssue.noDeviceKey);
      }
      final int version;
      try {
        version = await auth.enrolKeys(
          server,
          session.tokens.access,
          await _newKeys(session.userId, root, _firstKeyVersion),
          copy,
          trust.wrapper.protection,
        );
      } catch (e) {
        // Only the server's refusal says nothing was stored, and then the key that would have opened the copy is of
        // no use. A failure with no answer (the network, a timeout) may come after the server stored the keys, and
        // this phone's copy is then the only way into an account with no password and no other device: the key stays,
        // so the next sign-in finds the account with keys and opens it with the copy
        if (e is KmError && e.status >= 400 && e.status < 500) {
          await trust.wrapper.delete(tag);
        }
        if (e is KmError && e.problem == KmProblem.stale) {
          return null;
        }
        rethrow;
      }
      if (version != _firstKeyVersion) {
        throw KmSignInError(KmSignInIssue.unsupported, detail: 'the keys were stored at key version $version');
      }
      return await _open(session.userId, root, await _material(session), opaqueEnrolled: opaqueConfirmed);
    } finally {
      wipe(root);
    }
  }

  /// Whether the account has keys, or the server would refuse to enrol them (a key version above 0). Only a 404 is
  /// an account with none yet: the server answers keys once they exist, so key version 0 with no bundle is an answer
  /// it never gives, and it is refused rather than taken as a reason to make new keys.
  Future<bool> _holdsKeys(KmSession session) async {
    try {
      final material = await _material(session);
      if (!material.hasKeys && material.keyVersion == 0) {
        throw const KmSignInError(KmSignInIssue.unreadable, detail: 'the server answered keys with none in them');
      }
      return true;
    } on KmError catch (e) {
      if (e.problem == KmProblem.server && e.status == 404) {
        return false;
      }
      rethrow;
    }
  }

  /// "Trust this phone": keeps a copy of the root key on the server that only this phone's hardware opens, so
  /// turning sync off and on again with SSO opens the account without an approval.
  Future<void> trustThisPhone(KmSession session, KmAccount account, KmTrust trust, String tag) => trust.trust(
    api: api,
    server: server,
    token: session.tokens.access,
    tag: tag,
    rootKey: account.rootKey,
    accountId: uuidBytes(account.accountId),
    deviceId: uuidBytes(session.deviceId),
    keyVersion: account.keyVersion,
  );

  Future<KmAccount> _open(String accountId, Uint8List root, KmAccountMaterial material, {required bool opaqueEnrolled}) async {
    try {
      return await openKmAccount(accountId: accountId, rootKey: root, material: material, opaqueEnrolled: opaqueEnrolled);
    } on KmAccountUnreadable catch (e) {
      throw KmSignInError(KmSignInIssue.unreadable, detail: e.reason);
    }
  }

  Future<void> _markOpaque() async {
    if (_seen) return;
    _seen = true;
    await rememberOpaque?.call();
  }

  /// Wipes the master key and export key, and forgets the password. Called when the sign-in ends, however it does.
  void close() {
    for (final key in [_masterKey, _exportKey]) {
      if (key != null) wipe(key);
    }
    _masterKey = null;
    _exportKey = null;
    _password = null;
    _challenge = null;
    final pending = _enrolment;
    if (pending != null) wipe(pending.root);
    _enrolment = null;
  }
}

/// OPAQUE's server proof didn't verify: a wrong password, an account with no record, or another server.
class _NoOpaqueRecord implements Exception {
  const _NoOpaqueRecord();
}

/// A Compatible account's enrolment between the Bitwarden hash and its last message.
class _Enrolment {
  _Enrolment(this.ticket, this.state, this.response, this.root, this.userId, this.settings, this.salt);

  final String ticket;
  final Object state;
  final Uint8List response;
  final Uint8List root;
  final String userId;
  final Argon2idSettings settings;
  final Uint8List salt;
}
