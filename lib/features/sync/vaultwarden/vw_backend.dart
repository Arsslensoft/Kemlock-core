/// Vaultwarden sync for the open vault: [VaultwardenBackend] keeps the
/// session (encrypted with the vault, as `backmycodes_vaultwarden`) and runs
/// syncs for the scheduler; [VwAccountSetup] takes the screens through
/// signing in, choosing or making a home, changing how it keeps entries,
/// and taking Kemlock out of the vault again.
library;

import 'dart:convert';
import 'dart:math' show min;
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:http/http.dart' as http;

import '../../../core/ids.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../models/otp_account.dart';
import '../../../vault/vault_store.dart';
import '../sync.dart';
import '../sync_crypto.dart';
import '../sync_merge.dart';
import 'vw_api.dart';
import 'vw_codec.dart';
import 'vw_file_sync.dart';
import 'vw_formats.dart';
import 'vw_models.dart';
import 'vw_sync.dart';
import 'vw_webauthn.dart';

/// Where the session is kept, per vault and encrypted with it.
const keyVaultwardenSession = 'backmycodes_vaultwarden';

/// Where the user's own logins that hold codes are kept between syncs, as
/// the server gave them (still encrypted with the account's keys), so the
/// account sheet shows their passwords offline.
const keyVaultwardenCache = 'backmycodes_vaultwarden_cache';

/// Loads and stores the open vault's session, and syncs with it.
class VaultwardenBackend {
  VaultwardenBackend({
    required this.vault,
    required this.session,
    required this.clientFor,
    this.websiteFor,
    this.files,
    this.clock = DateTime.now,
    this.info = const VwClientInfo(),
  });

  final VaultStore vault;
  final VaultSession session;
  final http.Client Function(String? pin) clientFor;

  /// Who this app says it is to the server; the phone's values come from the app.
  final VwClientInfo info;

  /// A new plain login's website, from the 2FA directory.
  final String? Function(String issuer)? websiteFor;

  /// The vault's attached files, synced with their notes' items; null
  /// leaves them out.
  final VwFiles? files;
  final DateTime Function() clock;

  final _clients = <String, http.Client>{};
  VwReader? _reader;
  String? _readerKey;

  /// The stored session, or null when signed out.
  Future<VwCredentials?> loadCredentials() async {
    final value = await vault.loadEncryptedValue(keyVaultwardenSession, session);
    return value is Map<String, Object?> ? VwCredentials.fromJson(value) : null;
  }

  Future<void> saveCredentials(VwCredentials credentials) => vault.saveEncryptedValue(keyVaultwardenSession, credentials.toJson(), session);

  void forgetCredentials() => vault.removeEncryptedValue(keyVaultwardenSession);

  /// The API on a client for [pin], made once and kept.
  VwApi api(String? pin) => VwApi(_clients[pin ?? ''] ??= clientFor(pin), clock: clock, info: info);

  /// A connection with the stored session. Throws a `signedOut` [VwError]
  /// when there's none.
  Future<VwConnection> connect(VaultwardenTarget target) async {
    final credentials = await loadCredentials();
    if (credentials == null) throw const VwError(VwProblem.signedOut);
    return VwConnection(
      api: api(target.pin),
      server: vwServerUrl(target.server),
      credentials: credentials,
      onCredentials: saveCredentials,
      clock: clock,
    );
  }

  /// A reader for the account's key, kept with what it decrypted.
  VwReader reader(VwCredentials credentials) {
    if (_readerKey != credentials.userKey) {
      _reader = VwReader(credentials.key);
      _readerKey = credentials.userKey;
    }
    return _reader!;
  }

  /// Syncs the vault's own entries with [target]'s home; see
  /// [VaultwardenScopeSync.sync]. Keeps the linked logins it read.
  Future<VwSyncResult> sync(VaultwardenTarget target, Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final connection = await connect(target);
    final scope = VaultwardenScopeSync(
      connection: connection,
      reader: reader(connection.credentials),
      target: target,
      websiteFor: websiteFor,
      files: files,
    );
    final result = await scope.sync(local, state, now: now, choice: choice);
    if (result.linked case final linked?) await vault.saveEncryptedValue(keyVaultwardenCache, {'linked': linked}, session);
    return result;
  }

  /// The linked logins the last sync kept, by entry id.
  Future<Map<String, Map<String, Object?>>> loadLinked() async {
    final value = await vault.loadEncryptedValue(keyVaultwardenCache, session);
    final linked = value is Map<String, Object?> ? value['linked'] : null;
    if (linked is! Map<String, Object?>) return {};
    return {
      for (final MapEntry(:key, :value) in linked.entries)
        if (value is Map<String, Object?>) key: value,
    };
  }

  /// Forgets the session and the cache, when sync turns off.
  void forgetAll() {
    forgetCredentials();
    vault.removeEncryptedValue(keyVaultwardenCache);
  }

  /// The user's own login that holds [entryId]'s code, from the last sync,
  /// or null when it's in no login of theirs.
  Future<VwLinkedLogin?> linkedLogin(String entryId) async {
    final cipher = (await loadLinked())[entryId];
    final credentials = await loadCredentials();
    if (cipher == null || credentials == null) return null;
    final item = VwCipher(cipher);
    try {
      final key = await cipherKey(item, credentials.key);
      final login = item.login ?? const {};
      final uris = (login['uris'] as List<Object?>? ?? const []).whereType<Map<String, Object?>>();
      return VwLinkedLogin(
        cipherId: item.id,
        name: await _openOrNull(item.json['name'], key) ?? '',
        username: await _openOrNull(login['username'], key),
        website: uris.isEmpty ? null : await _openOrNull(uris.first['uri'], key),
        reprompt: item.reprompt == 1,
        hasPassword: login['password'] is String,
        password: () => _openOrNull(login['password'], key),
      );
    } on BwCryptoError {
      return null;
    }
  }

  /// The user's own logins, for linking an account to one: every login of
  /// the account's own (not an organization's) that no home claims.
  Future<List<VwLoginChoice>> loginsToLink(VaultwardenTarget target) async {
    final connection = await connect(target);
    final ciphers = await connection.ciphers();
    final read = await reader(connection.credentials).read(ciphers, home: target.home);
    final choices = <VwLoginChoice>[];
    for (final cipher in ciphers) {
      if (cipher.type != CipherType.login || cipher.inTrash || cipher.organizationId != null || read.fielded.contains(cipher.id)) continue;
      try {
        final key = await cipherKey(cipher, connection.credentials.key);
        final login = cipher.login ?? const {};
        final uris = (login['uris'] as List<Object?>? ?? const []).whereType<Map<String, Object?>>();
        choices.add(
          VwLoginChoice(
            cipherId: cipher.id,
            name: await _openOrNull(cipher.json['name'], key) ?? '',
            username: await _openOrNull(login['username'], key),
            website: uris.isEmpty ? null : await _openOrNull(uris.first['uri'], key),
          ),
        );
      } on BwCryptoError {
        continue;
      }
    }
    choices.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return choices;
  }

  /// Puts [account]'s code in the user's login [cipherId] instead of a login
  /// of Kemlock's own, which goes to the trash. Plain storage only.
  Future<void> link(VaultwardenTarget target, OtpAccount account, String cipherId) async {
    final connection = await connect(target);
    final ciphers = await connection.ciphers();
    final read = await reader(connection.credentials).read(ciphers, home: target.home, pickUp: target.pickUp);
    final cipher = ciphers.firstWhere((cipher) => cipher.id == cipherId, orElse: () => throw const VwError(VwProblem.outOfDate));
    final writer = VwWriter(userKey: connection.credentials.key, userId: connection.credentials.userId);
    final claim = EntryClaim(cipher, id: account.id, kind: EntryKind.account, form: VaultwardenMode.plain, own: false, pickedUp: true);
    final body = await writer.update(claim, account, home: target.home);
    await connection.call((token) => connection.api.updateCipher(connection.server, token, cipher.id, body));
    for (final own in read.entries) {
      if (own.id == account.id && own.own && !own.cipher.inTrash) {
        await connection.call((token) => connection.api.trashCipher(connection.server, token, own.cipher.id));
      }
    }
  }

  /// Gives [account]'s code a login of Kemlock's own again, and takes it off
  /// the user's login, which keeps everything else.
  Future<void> unlink(VaultwardenTarget target, OtpAccount account) async {
    final connection = await connect(target);
    final read = await reader(connection.credentials).read(await connection.ciphers(), home: target.home, pickUp: target.pickUp);
    final writer = VwWriter(userKey: connection.credentials.key, userId: connection.credentials.userId);
    final linked = [
      for (final claim in read.entries)
        if (claim.id == account.id && !claim.own && !claim.cipher.inTrash) claim,
    ];
    if (linked.isEmpty) return;
    final body = await writer.create(account, form: VaultwardenMode.plain, home: target.home, folderId: target.folderId);
    await connection.call((token) => connection.api.createCipher(connection.server, token, body));
    for (final claim in linked) {
      final stripped = await writer.unlink(claim);
      await connection.call((token) => connection.api.updateCipher(connection.server, token, claim.cipher.id, stripped));
    }
  }

  /// Closes [target]'s sealed home after a move; see [VwAccountSetup.closeHome].
  Future<VwCloseResult> closeHome(VaultwardenTarget target, {required Set<String> confirmed}) async =>
      VwAccountSetup.closeHome(await connect(target), target, confirmed: confirmed);

  /// Takes a closed home out of the trash; see [VwAccountSetup.restoreHome].
  Future<int> restoreHome(VaultwardenTarget target) async => VwAccountSetup.restoreHome(await connect(target), target);

  /// Closes the clients made for syncing.
  void dispose() {
    for (final client in _clients.values) {
      client.close();
    }
    _clients.clear();
  }
}

Future<String?> _openOrNull(Object? value, BwKey key) async => value is String ? bwDecryptString(value, key) : null;

/// A login of the user's that holds an entry's code. The password is only
/// decrypted when asked for.
class VwLinkedLogin {
  const VwLinkedLogin({
    required this.cipherId,
    required this.name,
    required this.reprompt,
    required this.hasPassword,
    required this.password,
    this.username,
    this.website,
  });

  final String cipherId;
  final String name;
  final String? username;
  final String? website;

  /// Bitwarden's "master password re-prompt": ask before showing the password.
  final bool reprompt;
  final bool hasPassword;

  /// Decrypts the password.
  final Future<String?> Function() password;

  @override
  String toString() => 'VwLinkedLogin($cipherId)';
}

/// A login of the user's that an account's code could go in.
class VwLoginChoice {
  const VwLoginChoice({required this.cipherId, required this.name, this.username, this.website});

  final String cipherId;
  final String name;
  final String? username;
  final String? website;

  @override
  String toString() => 'VwLoginChoice($cipherId)';
}

/// Where a sign-in stands.
sealed class VwSignInStep {
  const VwSignInStep();
}

/// Signed in: the session to store.
class VwSignInDone extends VwSignInStep {
  const VwSignInDone(this.credentials);

  final VwCredentials credentials;
}

/// Whether a security key can be the second step, and why not.
enum VwKeyOffer {
  /// A security key is not one of the account's methods.
  notAMethod,

  /// The server gave a challenge and the phone can reach a key.
  offered,

  /// The phone has no way to reach a security key.
  noReach,

  /// The server lists the method and gave no challenge Kemlock can use:
  /// it is not set up for security keys.
  noChallenge,
}

/// The account has a second step. [providers] are the ones it has, by
/// Bitwarden's numbers; [emailHint] is the obscured address for email;
/// [keyChallenge] is the server's challenge for a security key, when it
/// gave one, and [canReachKey] whether this phone can reach a key at all.
class VwSignInNeedsStep extends VwSignInStep {
  const VwSignInNeedsStep({required this.providers, this.emailHint, this.keyChallenge, this.canReachKey = false});

  final List<int> providers;
  final String? emailHint;
  final VwKeyChallenge? keyChallenge;
  final bool canReachKey;

  /// Where the security key method stands for this account and phone.
  VwKeyOffer get keyOffer {
    if (!providers.contains(VwTwoFactor.webauthn)) return VwKeyOffer.notAMethod;
    if (!canReachKey) return VwKeyOffer.noReach;
    return keyChallenge == null ? VwKeyOffer.noChallenge : VwKeyOffer.offered;
  }

  /// The ones this app can do, in the order to offer them: the typed codes
  /// first, then a security key.
  List<int> get supported => [
    for (final provider in const [VwTwoFactor.authenticator, VwTwoFactor.email, VwTwoFactor.yubikey])
      if (providers.contains(provider)) provider,
    if (keyOffer == VwKeyOffer.offered) VwTwoFactor.webauthn,
  ];
}

/// A home found in the vault, for setup to offer joining.
class VwHomeInfo {
  const VwHomeInfo({required this.claim, required this.entries});

  final HomeClaim claim;
  HomeNote get home => claim.home;

  /// How many entries it has.
  final int entries;
}

/// What setup found in the vault.
class VwVaultInfo {
  const VwVaultInfo({required this.homes, required this.foreignLogins});

  final List<VwHomeInfo> homes;

  /// Logins with a code that no home claims, which plain storage can pick up.
  final int foreignLogins;
}

/// Thrown when the sealing passphrase doesn't open a home.
class VwPassphraseError implements Exception {
  const VwPassphraseError();

  @override
  String toString() => 'VwPassphraseError: the passphrase does not open this home';
}

/// What closing a sealed home did.
enum VwCloseOutcome {
  /// The home note and its items went to the trash.
  closed,

  /// The home note was already in the trash: another phone closed it.
  alreadyGone,

  /// The home holds something that can't be moved safely, and nothing was touched.
  blocked,
}

/// The result of [VwAccountSetup.closeHome]: how it ended, how many items changed, and for a blocked home
/// how many items this build can't read and how many live entries the move's check didn't confirm.
class VwCloseResult {
  const VwCloseResult(this.outcome, {this.changed = 0, this.unreadable = 0, this.unconfirmed = 0});

  final VwCloseOutcome outcome;
  final int changed;
  final int unreadable;
  final int unconfirmed;

  @override
  String toString() => 'VwCloseResult(${outcome.name}, $changed changed, $unreadable unreadable, $unconfirmed unconfirmed)';
}

/// How the master password becomes the master key and the hash the server
/// checks: [bwMasterKey] and [bwMasterPasswordHash], in background isolates.
class VwKeyDerivation {
  const VwKeyDerivation();

  Future<Uint8List> masterKey(String password, String email, BwKdf kdf) => bwMasterKey(password, email, kdf);

  Future<String> passwordHash(Uint8List masterKey, String password) => bwMasterPasswordHash(masterKey, password);
}

/// The scrypt the sealing passphrase goes through: the vault's.
typedef VwDeriveKey = Future<Uint8List> Function(String passphrase, Uint8List salt);

/// Signs in to a Vaultwarden account and sets a home up there, step by step,
/// for the setup screens.
class VwAccountSetup {
  VwAccountSetup(this.api, {this.clock = DateTime.now, this.derive = const VwKeyDerivation()});

  final VwApi api;
  final DateTime Function() clock;

  /// The master key and password hash, off the UI isolate; tests pass cheap ones.
  final VwKeyDerivation derive;

  late Uri server;
  late String email;
  late BwKdf kdf;
  Uint8List? _masterKey;
  String? _passwordHash;
  String? _password;
  VwDevice? _device;

  /// Whether this phone can reach a security key, which decides whether one
  /// is offered as the second step. The screens set it from the phone's
  /// capabilities before signing in.
  bool canReachKey = false;

  /// Checks [serverText] answers as a Bitwarden-compatible server and reads
  /// [address]'s KDF. Throws a [VwError].
  Future<void> connect(String serverText, String address) async {
    server = vwServerUrl(serverText);
    email = address.trim();
    await api.config(server);
    kdf = await api.prelogin(server, email);
    _masterKey = null;
  }

  /// Signs in with the master password, and the second step's code when
  /// asked for one. [deviceId] is the vault's device, kept across sign-ins.
  Future<VwSignInStep> signIn(String password, {required String deviceId, VwSecondStep? step, String? rememberToken}) async {
    if (_masterKey == null || _password != password) {
      _masterKey = await derive.masterKey(password, email, kdf);
      _passwordHash = await derive.passwordHash(_masterKey!, password);
      _password = password;
    }
    final device = _device = VwDevice(id: deviceId, type: api.info.deviceType, name: api.info.deviceName);
    final login = await api.signIn(
      server,
      email: email,
      passwordHash: _passwordHash!,
      device: device,
      step: step,
      rememberToken: step == null ? rememberToken : null,
    );
    return switch (login) {
      VwSignedIn() => VwSignInDone(await _credentials(login, deviceId)),
      VwSecondStepNeeded(:final providers, :final details) => VwSignInNeedsStep(
        providers: providers,
        emailHint: _emailHint(details),
        keyChallenge: _keyChallenge(details),
        canReachKey: canReachKey,
      ),
    };
  }

  /// Asks the server for the second step again, which gives a new security
  /// key challenge: the server keeps one at a time and any answer uses it
  /// up. The master key is kept from the first sign-in, so this is one
  /// request and no second key derivation.
  Future<VwSignInStep> askStepAgain(String password, {required String deviceId, String? rememberToken}) =>
      signIn(password, deviceId: deviceId, rememberToken: rememberToken);

  /// The server's security key challenge in [details], stamped with now.
  /// A server without its own address set (Vaultwarden's `DOMAIN`) asks
  /// about `localhost`, which no phone signs in to: that is no challenge.
  VwKeyChallenge? _keyChallenge(Map<String, Object?> details) {
    final challenge = VwKeyChallenge.parse(details['${VwTwoFactor.webauthn}'], receivedAt: clock());
    if (challenge == null || (challenge.rpId == 'localhost' && server.host != 'localhost')) return null;
    return challenge;
  }

  /// Signs in with the personal API key, which skips the second step; the
  /// master password still opens the user key.
  Future<VwSignInDone> signInWithApiKey(String clientId, String clientSecret, String password, {required String deviceId}) async {
    _masterKey = await derive.masterKey(password, email, kdf);
    _password = password;
    final device = _device = VwDevice(id: deviceId, type: api.info.deviceType, name: api.info.deviceName);
    final login = await api.signInWithApiKey(server, clientId: clientId, clientSecret: clientSecret, device: device);
    return VwSignInDone(await _credentials(login, deviceId, apiKey: (clientId: clientId.trim(), clientSecret: clientSecret.trim())));
  }

  /// Asks the server to email the second step's code.
  Future<void> sendEmailCode() => api.sendEmailCode(
    server,
    email: email,
    passwordHash: _passwordHash!,
    device: _device ?? VwDevice(id: newUuid(), type: api.info.deviceType, name: api.info.deviceName),
  );

  Future<VwCredentials> _credentials(VwSignedIn login, String deviceId, {({String clientId, String clientSecret})? apiKey}) async {
    final key = login.key;
    if (key == null) throw const VwError(VwProblem.unsupported, message: 'The account has no user key');
    final BwKey userKey;
    try {
      userKey = await bwOpenUserKey(key, _masterKey!);
    } on BwCryptoError catch (e) {
      throw VwError(VwProblem.unsupported, message: e.message);
    }
    return VwCredentials(
      deviceId: deviceId,
      userId: login.userId,
      userKey: b64(userKey.bytes),
      accessToken: login.tokens.access,
      refreshToken: login.tokens.refresh,
      expiresAt: login.tokens.expiresAt,
      kdf: login.kdf ?? kdf,
      rememberToken: login.rememberToken,
      clientId: apiKey?.clientId,
      clientSecret: apiKey?.clientSecret,
    );
  }

  /// A connection with [credentials], storing renewed tokens through [onCredentials].
  VwConnection connection(VwCredentials credentials, {Future<void> Function(VwCredentials)? onCredentials}) =>
      VwConnection(api: api, server: server, credentials: credentials, onCredentials: onCredentials ?? (_) async {}, clock: clock);

  /// The homes in the vault, and how many logins have a code outside any.
  Future<VwVaultInfo> readVault(VwConnection connection) async {
    final read = await VwReader(connection.credentials.key).read(await connection.ciphers());
    return VwVaultInfo(
      homes: [
        for (final claim in read.homes)
          if (!claim.cipher.inTrash) VwHomeInfo(claim: claim, entries: read.counts[claim.home.id] ?? 0),
      ],
      foreignLogins: read.foreign,
    );
  }

  /// Makes a new home: a folder and its note. Sealed storage seals with
  /// [passphrase] through [derive].
  Future<VaultwardenTarget> createHome(
    VwConnection connection, {
    required VaultwardenMode mode,
    String? passphrase,
    VwDeriveKey? derive,
    bool pickUp = false,
    String? pin,
  }) async {
    final key = connection.credentials.key;
    final writer = VwWriter(userKey: key, userId: connection.credentials.userId);
    final folder = await connection.call((token) async => api.createFolder(server, token, await bwEncryptString(defaultFolderName, key)));
    final folderId = folder['id']! as String;
    final seal = mode == VaultwardenMode.sealed ? await _newSeal(passphrase!, derive!) : null;
    final home = HomeNote(id: newHomeId(), name: defaultFolderName, mode: mode, seal: seal?.file);
    final body = await writer.createHome(home, folderId: folderId);
    await connection.call((token) => api.createCipher(server, token, body));
    return VaultwardenTarget(
      server: server.toString(),
      email: email,
      home: home.id,
      mode: mode,
      folderId: folderId,
      seal: seal?.seal,
      pickUp: pickUp && mode == VaultwardenMode.plain,
      pin: pin,
    );
  }

  /// What the first sync of [local] would do, writing nothing: with
  /// [target], a home joined with [joinHome]; without, a new home that
  /// keeps entries as [mode], picking up logins with codes when [pickUp].
  Future<VwSyncPreview> previewFirstSync(
    VwConnection connection,
    Lists local, {
    VaultwardenTarget? target,
    VaultwardenMode mode = VaultwardenMode.sealed,
    bool pickUp = false,
  }) => VaultwardenScopeSync(
    connection: connection,
    reader: VwReader(connection.credentials.key),
    target:
        target ??
        VaultwardenTarget(
          server: server.toString(),
          email: email,
          home: newHomeId(),
          mode: mode,
          folderId: '',
          pickUp: pickUp && mode == VaultwardenMode.plain,
        ),
  ).preview(local, now: clock().millisecondsSinceEpoch, newHome: target == null);

  /// Joins a home found in the vault. A sealed home needs its passphrase,
  /// which must open it: else a [VwPassphraseError].
  Future<VaultwardenTarget> joinHome(VwHomeInfo info, {String? passphrase, VwDeriveKey? derive, bool pickUp = false, String? pin}) async {
    final home = info.home;
    VwSeal? seal;
    if (home.mode == VaultwardenMode.sealed) seal = await openSeal(home, passphrase!, derive!);
    return VaultwardenTarget(
      server: server.toString(),
      email: email,
      home: home.id,
      mode: home.mode,
      folderId: info.claim.cipher.folderId ?? '',
      seal: seal,
      pickUp: pickUp && home.mode == VaultwardenMode.plain,
      pin: pin,
    );
  }

  /// The seal key [passphrase] gives for [home]. Throws a [VwPassphraseError]
  /// when it doesn't open the home.
  static Future<VwSeal> openSeal(HomeNote home, String passphrase, VwDeriveKey derive) async {
    final file = home.seal;
    if (file == null) throw const VwPassphraseError();
    final text = jsonEncode(file);
    final kdf = readKdf(text);
    if (kdf == null) throw const VwPassphraseError();
    final key = await deriveSyncKey(passphrase, kdf, derive: derive);
    try {
      await decryptSyncFile(text, key);
    } on SyncFileError {
      throw const VwPassphraseError();
    }
    return VwSeal(key: b64(key), kdf: kdf);
  }

  static Future<({VwSeal seal, Map<String, Object?> file})> _newSeal(String passphrase, VwDeriveKey derive) async {
    final kdf = newKdf();
    final key = await deriveSyncKey(passphrase, kdf, derive: derive);
    final file = jsonDecode(await encryptSyncFile(const SyncDoc(), key, kdf: kdf)) as Map<String, Object?>;
    return (seal: VwSeal(key: b64(key), kdf: kdf), file: file);
  }

  /// Changes how [target]'s home keeps its entries: the home note first, so
  /// other phones stop before touching anything, then the settings to keep.
  /// The next sync moves every entry. Going sealed needs a [passphrase];
  /// going plain keeps the seal key until every entry is moved.
  static Future<VaultwardenTarget> changeMode(
    VwConnection connection,
    VaultwardenTarget target,
    VaultwardenMode mode, {
    String? passphrase,
    VwDeriveKey? derive,
  }) async {
    final claim = await _home(connection, target);
    var seal = target.seal;
    Map<String, Object?>? file = claim.home.seal;
    if (mode == VaultwardenMode.sealed) {
      final made = await _newSeal(passphrase!, derive!);
      seal = made.seal;
      file = made.file;
    }
    final writer = VwWriter(userKey: connection.credentials.key, userId: connection.credentials.userId);
    final body = await writer.updateHome(claim, claim.home.copyWith(mode: mode, seal: file));
    await connection.call((token) => connection.api.updateCipher(connection.server, token, claim.cipher.id, body));
    return target.copyWith(mode: mode, seal: seal, pickUp: mode == VaultwardenMode.plain && target.pickUp);
  }

  /// Takes Kemlock out of the vault: the home note goes to the trash first, then its own items, and linked
  /// logins lose their codes. Returns how many items changed.
  ///
  /// The home note goes first, so a phone still syncing this home stops at "home gone" before it can count
  /// the items that are missing as deletions: items first would let that run tombstone them on that phone.
  static Future<int> removeFromVault(VwConnection connection, VaultwardenTarget target) async {
    final read = await _readHome(connection, target);
    await _trashHome(connection, target, read);
    return _takeOut(connection, read.entries);
  }

  /// Closes a sealed home once a move to Kemlock Server copied and checked it (move-off-vaultwarden-sync,
  /// design 6): the home note goes to the trash, then each sealed item, then the codes come off the
  /// person's own logins in the home. Nothing is deleted for good. [confirmed] is the entry ids the move's
  /// check read back from the Kemlock API.
  ///
  /// A home that holds an item this build can't read (a kind or version it doesn't know, or one that doesn't
  /// open), or a live entry the check didn't confirm (another phone added it since the last sync), is not
  /// closed and nothing in it is touched: the result says why, and the home keeps syncing beside the Kemlock
  /// API. A home note already in the trash (another phone closed it first) is [VwCloseOutcome.alreadyGone].
  static Future<VwCloseResult> closeHome(VwConnection connection, VaultwardenTarget target, {required Set<String> confirmed}) async {
    final read = await _readHome(connection, target);
    final homes = [
      for (final home in read.homes)
        if (home.home.id == target.home && !home.cipher.inTrash) home,
    ];
    if (homes.isEmpty) {
      return const VwCloseResult(VwCloseOutcome.alreadyGone);
    }
    final live = [
      for (final claim in read.entries)
        if (!claim.cipher.inTrash && !claim.pickedUp) claim,
    ];
    final unreadable = live.where((claim) => claim.unreadable).length;
    final unconfirmed = live.where((claim) => !claim.unreadable && !confirmed.contains(claim.id)).length;
    if (unreadable > 0 || unconfirmed > 0) {
      return VwCloseResult(VwCloseOutcome.blocked, unreadable: unreadable, unconfirmed: unconfirmed);
    }
    await _trashHome(connection, target, read);
    return VwCloseResult(VwCloseOutcome.closed, changed: await _takeOut(connection, live));
  }

  /// Takes a home closed by [closeHome] out of the trash again (design 9): the home note, then the own items
  /// that went to the trash with it, which is those trashed at or after the note, so an entry deleted
  /// before the close stays deleted. Returns how many items came back, the note not counted. A home that
  /// isn't in the trash comes back as nothing.
  static Future<int> restoreHome(VwConnection connection, VaultwardenTarget target) async {
    final read = await _readHome(connection, target);
    final trashed = [
      for (final home in read.homes)
        if (home.home.id == target.home && home.cipher.inTrash) home,
    ];
    if (trashed.isEmpty) {
      return 0;
    }
    final since = trashed.map((home) => home.cipher.deletedMs ?? 0).reduce(min);
    for (final home in trashed) {
      await connection.call((token) => connection.api.restoreCipher(connection.server, token, home.cipher.id));
    }
    var restored = 0;
    for (final claim in read.entries) {
      if (claim.cipher.inTrash && claim.own && !claim.unreadable && (claim.cipher.deletedMs ?? 0) >= since) {
        await connection.call((token) => connection.api.restoreCipher(connection.server, token, claim.cipher.id));
        restored++;
      }
    }
    return restored;
  }

  static Future<VwRead> _readHome(VwConnection connection, VaultwardenTarget target) async =>
      VwReader(connection.credentials.key)
          .read(await connection.ciphers(), home: target.home, sealKey: target.seal == null ? null : unb64(target.seal!.key));

  static Future<void> _trashHome(VwConnection connection, VaultwardenTarget target, VwRead read) async {
    for (final home in read.homes) {
      if (home.home.id == target.home && !home.cipher.inTrash) {
        await connection.call((token) => connection.api.trashCipher(connection.server, token, home.cipher.id));
      }
    }
  }

  /// Trashes the items of [claims] Kemlock made and takes the code off the user's own; returns how many.
  static Future<int> _takeOut(VwConnection connection, List<EntryClaim> claims) async {
    final writer = VwWriter(userKey: connection.credentials.key, userId: connection.credentials.userId);
    var changed = 0;
    for (final claim in claims) {
      if (claim.cipher.inTrash || claim.pickedUp) continue;
      if (claim.own) {
        await connection.call((token) => connection.api.trashCipher(connection.server, token, claim.cipher.id));
      } else {
        final body = await writer.unlink(claim);
        await connection.call((token) => connection.api.updateCipher(connection.server, token, claim.cipher.id, body));
      }
      changed++;
    }
    return changed;
  }

  static Future<HomeClaim> _home(VwConnection connection, VaultwardenTarget target) async {
    final read = await VwReader(connection.credentials.key).read(await connection.ciphers());
    final claim = read.homes.firstWhereOrNull((claim) => claim.home.id == target.home && !claim.cipher.inTrash);
    if (claim == null) throw const VwSyncError(VwSyncIssue.homeMissing);
    return claim;
  }
}

String? _emailHint(Map<String, Object?> details) {
  final email = details['${VwTwoFactor.email}'];
  if (email is Map<String, Object?>) {
    final address = jsonKey(email, 'Email');
    if (address is String) return address;
  }
  return null;
}
