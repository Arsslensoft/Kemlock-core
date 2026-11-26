/// What the app's host needs around [KmScopeSync]: keeping a sign-in sealed,
/// and the [KemlockBackend] the scheduler runs, which opens the sealed session
/// and account for each run (add-kemlock-server-sync, task 5.3).
///
/// - [KmVaultValues] is the vault's sealed values (`VaultStore`'s
///   `saveEncryptedValue` and kin, for the open vault session): the session
///   ([keyKemlockSession]), the account ([keyKemlockAccount]) and the cache
///   ([keyKemlockCache]).
/// - [kmKeepSignIn] seals a finished sign-in; [kmRememberOpaque] records, apart
///   from any keys, that this phone saw the account enrolled in OPAQUE.
/// - [KmHost.sync] opens them, renews the access token when it ends (each new
///   session is sealed before the request that uses it, so a crash never leaves
///   the phone holding a refresh token the server has used), and runs the
///   sync. When the server ends the session, the phone records why and says so
///   at every run until the person signs in again; every entry stays.
///
/// Pure Dart, no Flutter.
library;

import 'dart:async';

import 'package:http/http.dart' as http;

import '../../../crypto/account/bundle.dart';
import '../../../crypto/account/encoding.dart' show MalformedException, uuidBytes;
import '../../../crypto/account/session.dart';
import '../../duplicates/duplicate_normalise.dart' show SiteResolver;
import '../removal_guard.dart';
import '../sync.dart';
import '../sync_merge.dart';
import 'km_account.dart';
import 'km_api.dart';
import 'km_auth_api.dart';
import 'km_backend.dart';
import 'km_cache.dart';
import 'km_dedup.dart';
import 'km_dedup_api.dart' show KmHints;
import 'km_failover.dart';
import 'km_files.dart';
import 'km_kinds.dart';
import 'km_live.dart';
import 'km_models.dart';
import 'km_push.dart';
import 'km_session.dart';
import 'km_signin.dart';
import 'km_sync.dart';

/// The open vault's sealed values: reads and writes under [keyKemlockSession] and its kin.
abstract interface class KmVaultValues {
  Future<Object?> load(String key);
  Future<void> save(String key, Object? value);

  /// Forgets a value (turning sync off).
  void remove(String key);
}

/// Seals a finished sign-in: the session, and the account when the sign-in opened it. A different
/// account than the one stored drops the old cache, which belongs to another account's items.
Future<void> kmKeepSignIn(KmVaultValues values, KmSignedIn signedIn) async {
  final stored = await values.load(keyKemlockAccount);
  final storedId = stored is Map<String, Object?> ? stored['accountId'] : null;
  if (storedId != null && storedId != signedIn.session.userId) values.remove(keyKemlockCache);
  await values.save(keyKemlockSession, signedIn.session.toJson());
  final account = signedIn.account;
  if (account != null) await values.save(keyKemlockAccount, account.toJson());
}

/// Seals an account opened after the session was kept (SSO's approval, a trusted-device copy, a passkey).
Future<void> kmKeepAccount(KmVaultValues values, KmAccount account) => values.save(keyKemlockAccount, account.toJson());

/// Records that this phone saw an account enrolled in OPAQUE, so the Bitwarden-hash route stays closed for
/// it. The value holds only that mark until the account is opened, and then the account's keys beside it.
Future<void> kmRememberOpaque(KmVaultValues values) async {
  final stored = await values.load(keyKemlockAccount);
  await values.save(keyKemlockAccount, {if (stored is Map<String, Object?>) ...stored, 'opaqueEnrolled': true});
}

/// Whether this phone saw the account enrolled in OPAQUE.
Future<bool> kmOpaqueSeen(KmVaultValues values) async => storedOpaqueSeen(await values.load(keyKemlockAccount));

/// The session the server ended, with why: kept sealed so the next runs say so without asking.
const endedKey = 'ended';

/// Runs Kemlock Server sync for the open vault.
class KmHost implements KemlockBackend {
  KmHost({
    required this.values,
    required this.clientFor,
    required this.proofsFor,
    this.fileStore,
    this.fetchMissing = true,
    this.anchors,
    this.clock = DateTime.now,
    this.onAway,
    this.pushToken,
    this.onList,
    this.dedupSites,
    this.onHints,
    this.onMatching,
  });

  final KmVaultValues values;

  /// The gated, certificate-pinning client for a server (`kemlockClientFactoryProvider`).
  final http.Client Function(String? pin) clientFor;

  /// The proof maker for a session's device key, or null when the key is gone (a phone that lost it):
  /// the session can't be used and the sign-in must be made again.
  final Future<KmProofs?> Function(KmSession session) proofsFor;

  /// The phone's attached files, when its sync handles them.
  final KmFileStore? fileStore;

  /// Whether a run fetches the files its merged notes and File items name and the [fileStore] lacks (`KmFiles.fetchMissing`). A
  /// host that keeps no file bytes, such as the browser extension, turns it off so a sync never downloads every file; it fetches
  /// one when asked (`KmFiles.fetchPlain`). Passed to every `KmFiles` the host builds.
  final bool fetchMissing;

  /// The anchors of the account's server spaces, carried in an item of their own beside the entries.
  final KmAnchors? anchors;
  final DateTime Function() clock;

  /// Told after each run where the phone is: a [KmAway] while it is on a replica, null on the home.
  final void Function(KmAway? away)? onAway;

  /// This phone's push token now, or null when there is none (no push in the build, notifications refused, no
  /// token yet). Asked after each run while the push switch is on, never waited for: the run doesn't depend on it.
  final Future<KmPushToken?> Function()? pushToken;

  /// Told when the vault's server list changed: a list the home gave, which passed the checks of [acceptServerList]. The
  /// app keeps it in the settings; until then the host runs on it from memory.
  final void Function(KemlockTarget next)? onList;

  /// How a website becomes a site for the vault's `cred` tags: the Public Suffix List the cleaner reads sites with. Without
  /// it a host stays whole.
  final Future<SiteResolver> Function()? dedupSites;

  /// Told the server's groups of the vault's logins after a run on the home with matching on, with what the phone knows
  /// of its own tags. The cleaner reads them as hints, which it checks again.
  final void Function(KmHints hints)? onHints;

  /// Told whether the home has server matching on for the vault, each time a run asks it. The app keeps the answer in the
  /// settings, so matching turned off on another device is off here too.
  final void Function(bool enabled)? onMatching;

  final _clients = <http.Client>[];

  /// The token the server holds for this phone, and where: a run on another server, or a token that changed,
  /// registers it again.
  ({String server, KmPushToken push})? _registered;
  Future<void>? _registering;

  /// Completes when the push registration a run started is over, whether it worked or not.
  Future<void> get pushIdle => _registering ?? Future<void>.value();

  /// The server list the last accepted `/config` gave, in front of the target's own until the settings hold it.
  KemlockTarget? _learned;

  KmFailover? _failover;
  String? _failoverKey;

  /// The sessions the replicas gave this device when it signed in there with its key. They are kept in memory
  /// only: a restart signs in again, with no password, and the home's stored session is never touched.
  final _replicas = <String, KmSession>{};

  /// [target] with the server list this host learned from its home, when that is newer than the settings' own
  /// (the settings catch up through [onList]). A list learned for another account, or an older epoch, is not used.
  KemlockTarget _effective(KemlockTarget target) {
    final learned = _learned;
    if (learned == null || learned.accountId != target.accountId || learned.homeEpoch < target.homeEpoch) {
      return target;
    }
    return target.copyWith(servers: learned.servers, homeEpoch: learned.homeEpoch);
  }

  /// Takes the account's own vault from a `/config?vault=user:<uuid>` answer as its server list, if
  /// [acceptServerList] passes it; a list it refuses changes nothing and the old one stays. The list is in use from
  /// the next run, and [onList] hears of it.
  Future<void> _learnList(KemlockTarget target, KmConfig config) async {
    final current = _effective(target);
    for (final vault in config.vaults) {
      if (vault.vault != 'user:${current.accountId}') {
        continue;
      }
      try {
        final next = await acceptServerList(current, vault);
        if (next != current) {
          _learned = next;
          onList?.call(next);
        }
      } on Object {
        // A list that fails the checks (KmListRefused) is never half taken: the old one is kept
      }
      return;
    }
  }

  /// Reads the account's vault from the `/config` of the server in use after a run that went through, to learn its
  /// replicas. Best effort: a server that doesn't answer, or answers badly, leaves the list as it was.
  Future<void> _readList(KemlockTarget target, KmFailover failover, KmProofs proofs) async {
    final server = failover.current;
    final client = clientFor(server.pin);
    try {
      final config = await KmApi(
        client,
        proofs: proofs,
        firstByte: failoverFirstByte,
        clock: clock,
      ).config(Uri.parse(server.url), vaults: ['user:${target.accountId}']);
      await _learnList(target, config);
    } on Object {
      // The run went through; the list is read again at the next
    } finally {
      client.close();
    }
  }

  /// The vault's server list as the failover runs it: the home first, then its replicas. It is kept from one run
  /// to the next, and made again when the list changes.
  KmFailover _failoverFor(KemlockTarget given) {
    final target = _effective(given);
    final servers = [target.home, ...target.servers.where((server) => server.url != target.home.url)];
    final key = [for (final server in servers) '${server.url}|${server.pin}'].join('\n');
    final current = _failover;
    if (current != null && _failoverKey == key) return current;
    _replicas.clear();
    _failoverKey = key;
    return _failover = KmFailover(servers, clock: clock);
  }

  void _report(KmFailover failover) =>
      onAway?.call(failover.onHome ? null : KmAway(using: failover.current, since: failover.since ?? clock()));

  /// Refuses a change only the home may accept (the master password, two-step login) while the phone is on a
  /// replica, with a [KmHomeAway] that says where it is and since when. Items keep syncing.
  void requireHome(KemlockTarget target) => _failoverFor(target).requireHome();

  /// The address of [target]'s home server, which the connection of an action that must reach the home is compared with.
  Uri homeUrl(KemlockTarget target) => Uri.parse(_failoverFor(target).home.url);

  @override
  Future<KmSyncResult> sync(KemlockTarget target, Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final stored = await _load();
    final ended = stored.session.extra[endedKey];
    if (ended is String) throw KmError(KmProblem.sessionEnded, reason: ended);
    final proofs = await proofsFor(stored.session);
    if (proofs == null) throw const KmError(KmProblem.sessionEnded, reason: 'device-key-lost');
    final failover = _failoverFor(target);
    final accountSession = stored.account.openSession();
    try {
      // On a replica, each run also asks whether the home is back (at most once a minute)
      if (!failover.onHome) await failover.checkHome((home) => _probe(target, home, proofs));
      final result = await failover.send<KmSyncResult>(
        (server) => _runOn(failover, server, stored, proofs, accountSession, target, local, state, now, choice),
        signInTo: (server) => _signInTo(failover, server, stored.session, proofs),
        perRequest: true,
      );
      await _readList(target, failover, proofs);
      _startPushRegistration(target);
      return result;
    } on KmFailoverExhausted {
      throw const KmError(KmProblem.network);
    } finally {
      _report(failover);
      accountSession.dispose();
      stored.account.wipeSecrets();
    }
  }

  /// One run on [server]: with the stored session on the home, with the replica's own anywhere else.
  Future<KmSyncResult> _runOn(
    KmFailover failover,
    KemlockServer server,
    ({KmSession session, KmAccount account}) stored,
    KmProofs proofs,
    AccountSession accountSession,
    KemlockTarget target,
    Lists local,
    ScopeState state,
    int now,
    RemovalChoice? choice,
  ) => _onScope(
    failover,
    server,
    stored,
    proofs,
    accountSession,
    target,
    (scope) => scope.sync(target, local, state, now: now, choice: choice),
  );

  /// Writes the one entry [entry] to the server now, with the files it names that this phone holds ([fileStore]) and the server
  /// lacks, without a full sync: what a client calls to upload a note or File item at once.
  ///
  /// ```dart
  /// Future<KmPushResult> pushEntry(KemlockTarget target, KmEntry entry, {int? now, int? lastSyncAt})
  /// ```
  ///
  /// It runs as [sync] does on the server in use (the home, or a replica when the phone is on one, with the same sign-in, session
  /// renewal and failover) and uses the host's own cache, so the item is written over the revision the server holds, with the dedup
  /// tags of the vault when matching is on, and the account's signed manifest lists it. It first reads what changed on the server
  /// since the last run (`KmScopeSync.pushEntry`), merges [entry] with the server's copy of the item when another device wrote it,
  /// and stores the cache with the item at its new revision, so the next [sync] has nothing to do for it. No other entry is written
  /// and no deletion is decided: the vault itself is the caller's to keep.
  ///
  /// [now] (epoch ms) defaults to the host's clock; [lastSyncAt] is when this phone last finished a run, for dating a deletion the
  /// read first sees. Returns the [KmPushResult] of `kmPushItemWithFiles`: the entry as the server holds it now (the files named
  /// once they went up: the caller keeps that entry in its vault), its revision, and the attachment ids that could not be sent.
  /// Throws what [sync] throws: a [KmError] (a `stale` one when the item changed during the call: call it again), a [KmSyncError]
  /// when the server's state is older than this phone saw.
  Future<KmPushResult> pushEntry(KemlockTarget target, KmEntry entry, {int? now, int? lastSyncAt}) async {
    final stored = await _load();
    final ended = stored.session.extra[endedKey];
    if (ended is String) throw KmError(KmProblem.sessionEnded, reason: ended);
    final proofs = await proofsFor(stored.session);
    if (proofs == null) throw const KmError(KmProblem.sessionEnded, reason: 'device-key-lost');
    final failover = _failoverFor(target);
    final accountSession = stored.account.openSession();
    final at = now ?? clock().millisecondsSinceEpoch;
    try {
      if (!failover.onHome) await failover.checkHome((home) => _probe(target, home, proofs));
      return await failover.send<KmPushResult>(
        (server) => _onScope(
          failover,
          server,
          stored,
          proofs,
          accountSession,
          target,
          (scope) => scope.pushEntry(entry, now: at, lastSyncAt: lastSyncAt),
        ),
        signInTo: (server) => _signInTo(failover, server, stored.session, proofs),
        perRequest: true,
      );
    } on KmFailoverExhausted {
      throw const KmError(KmProblem.network);
    } finally {
      _report(failover);
      accountSession.dispose();
      stored.account.wipeSecrets();
    }
  }

  /// [action] with the scope engine for [server]: with the stored session on the home, with the replica's own anywhere else.
  Future<T> _onScope<T>(
    KmFailover failover,
    KemlockServer server,
    ({KmSession session, KmAccount account}) stored,
    KmProofs proofs,
    AccountSession accountSession,
    KemlockTarget target,
    Future<T> Function(KmScopeSync scope) action,
  ) async {
    final onHome = server.url == failover.home.url;
    if (!onHome && _replicas[server.url] == null) await _signInTo(failover, server, stored.session, proofs);
    final client = clientFor(server.pin);
    _clients.add(client);
    try {
      final api = KmApi(client, proofs: proofs, firstByte: failoverFirstByte, clock: clock);
      final connection = _connectionTo(failover, server, api, stored.session);
      final url = Uri.parse(server.url);
      final crypto = stored.account.itemCrypto(accountSession);
      // Server matching only on the home and only when the person turned it on: a replica has its own switch, which
      // says nothing of the vault's, and a vault with it off sends no tag
      final dedup = target.matching
          ? KmDedup(
              keys: crypto,
              sites: await (dedupSites?.call() ?? Future.value(const SiteResolver())),
              onHints: onHome ? onHints : null,
              onSettings: onHome ? onMatching : null,
            )
          : null;
      final scope = KmScopeSync(
        connection: connection,
        server: url,
        crypto: crypto,
        dedup: dedup,
        files: fileStore == null ? null : KmFiles(store: fileStore!, connection: connection, server: url, fetchMissing: fetchMissing),
        anchors: anchors,
        loadCache: () async => KmCache.fromJson(await values.load(keyKemlockCache)),
        saveCache: (cache) => values.save(keyKemlockCache, cache.toJson()),
        clock: clock,
      );
      try {
        return await action(scope);
      } on KmError catch (e) {
        if (e.problem == KmProblem.sessionEnded) {
          // The home's session is over for good; a replica's is only made again
          if (onHome) {
            await _end(connection.session, e.reason ?? 'ended');
          } else {
            _replicas.remove(server.url);
          }
        }
        rethrow;
      }
    } finally {
      client.close();
      _clients.remove(client);
    }
  }

  /// A connection to [server]: the stored session on the home, whose renewals are sealed, and the replica's own,
  /// whose renewals stay in memory.
  KmConnection _connectionTo(KmFailover failover, KemlockServer server, KmApi api, KmSession stored) {
    final onHome = server.url == failover.home.url;
    return KmConnection(
      api: api,
      server: Uri.parse(server.url),
      session: onHome ? stored : _replicas[server.url]!,
      save: onHome ? (next) => values.save(keyKemlockSession, next.toJson()) : (next) async => _replicas[server.url] = next,
      clock: clock,
    );
  }

  /// Signs this device in on [server] with its device key, with no password. The home needs nothing: the stored
  /// session still stands. A replica that doesn't know the device throws the server's [KmError].
  Future<void> _signInTo(KmFailover failover, KemlockServer server, KmSession stored, KmProofs proofs) async {
    if (server.url == failover.home.url) return;
    final client = clientFor(server.pin);
    try {
      final auth = KmAuthApi(
        KmApi(client, proofs: proofs, firstByte: failoverFirstByte, clock: clock),
        clock: clock,
      );
      final grant = await kmReplicaSignIn(auth, Uri.parse(server.url), stored.deviceId);
      _replicas[server.url] = KmSession(userId: grant.userId, deviceId: grant.deviceId, tokens: grant.tokens, deviceKey: stored.deviceKey);
    } finally {
      client.close();
    }
  }

  /// Whether the home answers its config: the check that returns the phone to it after five healthy minutes.
  Future<bool> _probe(KemlockTarget target, KemlockServer home, KmProofs proofs) async {
    final client = clientFor(home.pin);
    try {
      final config = await KmApi(
        client,
        proofs: proofs,
        firstByte: failoverFirstByte,
        clock: clock,
      ).config(Uri.parse(home.url), vaults: ['user:${target.accountId}']);
      await _learnList(target, config);
      return true;
    } on KmError {
      return false;
    } finally {
      client.close();
    }
  }

  /// Starts the push registration of a run that went through, unless one is going. With the push switch off nothing
  /// is registered and the next time it is on, the token is sent again.
  void _startPushRegistration(KemlockTarget target) {
    final read = pushToken;
    if (read == null || _registering != null) {
      return;
    }
    if (!target.push) {
      _registered = null;
      return;
    }
    final registering = _registerPush(target, read);
    _registering = registering;
    unawaited(
      registering.whenComplete(() {
        if (identical(_registering, registering)) {
          _registering = null;
        }
      }),
    );
  }

  /// Registers this phone's token with the server in use when it isn't the one the server holds. The route is
  /// `POST /kem/v1/devices/push-token`; any failure is let go, and the next run tries again.
  Future<void> _registerPush(KemlockTarget target, Future<KmPushToken?> Function() read) async {
    try {
      final push = await read();
      if (push == null) {
        return;
      }
      await withAccount(target, (connection, account) async {
        final held = _registered;
        if (held != null && held.server == connection.server.toString() && held.push == push) {
          return;
        }
        await connection.call((token) => KmAuthApi(connection.api).registerPushToken(connection.server, token, push));
        _registered = (server: connection.server.toString(), push: push);
      });
    } on Object {
      // Best effort: a failure never fails a run, and a token not yet registered is sent at the next one
    }
  }

  /// Takes this phone's push token back from the server in use, when the push switch is turned off. Throws what the
  /// request throws; the sheet lets it go, as the phone stops asking for nudges either way.
  Future<void> unregisterPush(KemlockTarget target) async {
    _registered = null;
    await withAccount(
      target,
      (connection, account) => connection.call((token) => KmAuthApi(connection.api).unregisterPushToken(connection.server, token)),
    );
  }

  /// Runs [action] with a connection to the server in use and the open account, for what happens outside a sync
  /// run (approving a device, listing devices). The account's keys are wiped when it returns.
  Future<T> withAccount<T>(KemlockTarget target, Future<T> Function(KmConnection connection, KmAccount account) action) async {
    final stored = await _load();
    final ended = stored.session.extra[endedKey];
    if (ended is String) throw KmError(KmProblem.sessionEnded, reason: ended);
    final proofs = await proofsFor(stored.session);
    if (proofs == null) throw const KmError(KmProblem.sessionEnded, reason: 'device-key-lost');
    final failover = _failoverFor(target);
    final server = failover.current;
    final client = clientFor(server.pin);
    _clients.add(client);
    try {
      if (!failover.onHome && _replicas[server.url] == null) await _signInTo(failover, server, stored.session, proofs);
      final api = KmApi(client, proofs: proofs, firstByte: failoverFirstByte, clock: clock);
      return await action(_connectionTo(failover, server, api, stored.session), stored.account);
    } finally {
      stored.account.wipeSecrets();
      client.close();
      _clients.remove(client);
    }
  }

  /// The account's public keys as this phone holds them, which its fingerprint is of (Settings, Account security). No
  /// request is made, and the record's secrets are wiped before it returns. Null when the phone holds no opened account.
  Future<KeyBundle?> ownBundle() async {
    final stored = await values.load(keyKemlockAccount);
    if (stored is! Map<String, Object?>) {
      return null;
    }
    final KmAccount account;
    try {
      account = KmAccount.fromJson(stored);
    } on FormatException {
      return null;
    } on MalformedException {
      return null;
    }
    try {
      return KeyBundle(
        accountId: uuidBytes(account.accountId),
        keyVersion: account.keyVersion,
        kx1PublicKey: account.kx1PublicKey,
        sig1PublicKey: account.sig1PublicKey,
      );
    } finally {
      account.wipeSecrets();
    }
  }

  /// The upgrade request of the live socket, `/kem/v1/live`, on the server in use: its `wss` address, and the access
  /// token and a fresh DPoP proof for the `GET` of the upgrade (the proof names the https address, which is what the
  /// server sees). A token about to end is renewed first. Throws what a sync would: a session the server ended, or a
  /// device key the phone lost.
  Future<KmLiveUpgrade> liveUpgrade(KemlockTarget target) async {
    final stored = await _load();
    try {
      final ended = stored.session.extra[endedKey];
      if (ended is String) {
        throw KmError(KmProblem.sessionEnded, reason: ended);
      }
      final proofs = await proofsFor(stored.session);
      if (proofs == null) {
        throw const KmError(KmProblem.sessionEnded, reason: 'device-key-lost');
      }
      final failover = _failoverFor(target);
      final server = failover.current;
      final client = clientFor(server.pin);
      _clients.add(client);
      try {
        if (!failover.onHome && _replicas[server.url] == null) {
          await _signInTo(failover, server, stored.session, proofs);
        }
        final api = KmApi(client, proofs: proofs, firstByte: failoverFirstByte, clock: clock);
        final base = Uri.parse(server.url);
        final upgrade = base.replace(path: '${base.path}/kem/v1/live');
        return await _connectionTo(failover, server, api, stored.session).call((token) async {
          final proof = await proofs.proof('GET', upgrade, accessToken: token);
          return KmLiveUpgrade(
            url: upgrade.replace(scheme: 'wss'),
            headers: {'Authorization': 'DPoP $token', 'DPoP': proof},
            pin: server.pin,
          );
        });
      } finally {
        client.close();
        _clients.remove(client);
      }
    } finally {
      stored.account.wipeSecrets();
    }
  }

  Future<void> _end(KmSession session, String reason) {
    final ended = KmSession(
      userId: session.userId,
      deviceId: session.deviceId,
      tokens: session.tokens,
      deviceKey: session.deviceKey,
      extra: {...session.extra, endedKey: reason},
    );
    return values.save(keyKemlockSession, ended.toJson());
  }

  Future<({KmSession session, KmAccount account})> _load() async {
    final session = await values.load(keyKemlockSession);
    final account = await values.load(keyKemlockAccount);
    if (session is! Map<String, Object?> || account is! Map<String, Object?>) {
      throw const KmError(KmProblem.sessionEnded, reason: 'signed-out');
    }
    try {
      return (session: KmSession.fromJson(session), account: KmAccount.fromJson(account));
    } on FormatException {
      // An account with only the OPAQUE mark: the sign-in never got as far as opening it
      throw const KmError(KmProblem.sessionEnded, reason: 'signed-out');
    }
  }

  /// Signs this phone out on the server: ends this device's session. A server that can't be reached
  /// throws, and "Turn off" forgets the session here anyway.
  Future<void> signOut(KemlockTarget target) async {
    final session = await values.load(keyKemlockSession);
    if (session is! Map<String, Object?>) return;
    final stored = KmSession.fromJson(session);
    final proofs = await proofsFor(stored);
    if (proofs == null) return;
    final server = target.home;
    final client = clientFor(server.pin);
    try {
      final url = Uri.parse(server.url);
      final connection = KmConnection(
        api: KmApi(client, proofs: proofs, clock: clock),
        server: url,
        session: stored,
        save: (next) => values.save(keyKemlockSession, next.toJson()),
        clock: clock,
      );
      final auth = KmAuthApi(connection.api, clock: clock);
      await connection.call((token) => auth.signOutDevice(url, token, stored.deviceId));
    } finally {
      client.close();
    }
  }

  @override
  void dispose() {
    for (final client in _clients) {
      client.close();
    }
    _clients.clear();
  }
}
