/// Failover between a vault's servers (add-kemlock-server-sync, design 12): a
/// small state machine with an injected clock, so each behaviour is a unit test.
///
/// - **Failures.** [KmFailover.send] runs every request. One that doesn't
///   connect ([KmProblem.network]) or gets no answer within the first-byte
///   timeout is a failure; any answer, even 500 or 409, counts as reached.
/// - **Switching.** Two failures in a row, or one timeout, move the phone to
///   the next server. It signs in there with the device key, with no password
///   ([kmReplicaSignIn]); a replica that doesn't know the device yet is
///   reported ([KmFailover.unknown]) and the phone tries the others.
/// - **Returning.** On a replica, [KmFailover.checkHome] reads the home's
///   `/kem/v1/config`, at most once a minute. Five minutes of unbroken answers
///   return to the home; one miss resets the clock.
/// - **A new list** ([acceptServerList], from `GET /kem/v1/config?vault=user:<uuid>`) must name at least one known
///   server. A new home, or a later epoch, also needs the signed promotion record, checked with the identity key
///   already pinned for the new home, at an epoch above the stored one.
/// - **Home-only changes** (the master password, two-step login) are refused
///   on a replica with [KmHomeAway] ([KmFailover.requireHome]).
///
/// The server list, the promotion record and the replica sign-in (`/auth/device-key/challenge` and `/verify`) are
/// the server's.
///
/// Pure Dart, no Flutter.
library;

import 'dart:async';
import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/sig1.dart';
import '../../../crypto/bytes.dart' show concatBytes;
import '../../../security_key/cbor.dart';
import 'km_api.dart';
import 'km_auth_api.dart';
import 'km_models.dart';

/// How long a request may go without a first answer before the phone moves on.
const failoverFirstByte = Duration(seconds: 10);

/// How many failures in a row move the phone.
const failoverFailures = 2;

/// How long the home must answer, unbroken, before the phone returns to it.
const failoverReturnAfter = Duration(minutes: 5);

/// The least time between two health checks of the home.
const failoverCheckEvery = Duration(minutes: 1);

/// A change only the home may accept was asked for while the phone is on a replica: the master password, two-step
/// login. Items keep syncing.
class KmHomeAway implements Exception {
  const KmHomeAway({required this.using, required this.since});

  /// The replica in use.
  final KemlockServer using;

  /// When the phone moved to it.
  final DateTime since;

  @override
  String toString() => 'The home server is away since $since; this change waits for it.';
}

/// Where the phone is while the vault's home is away: the replica in use, and since when. The sheet shows it.
class KmAway {
  const KmAway({required this.using, required this.since});

  final KemlockServer using;
  final DateTime since;

  @override
  bool operator ==(Object other) => other is KmAway && other.using == using && other.since == since;

  @override
  int get hashCode => Object.hash(using, since);
}

/// No server of the list answered, or none would sign this device in.
class KmFailoverExhausted implements Exception {
  const KmFailoverExhausted(this.last);

  final Object last;

  @override
  String toString() => 'No server of the list answered: $last';
}

/// Which side of the list the phone is on.
enum KmFailoverMode {
  /// On the home.
  onHome,

  /// On a replica, the home not known to be back.
  onReplica,

  /// On a replica, the home has answered since [KmFailover.healthySince] and the phone returns once that is five minutes.
  returning,
}

/// The vault's server list and which server is in use.
class KmFailover {
  KmFailover(this.servers, {this.clock = DateTime.now, this.firstByte = failoverFirstByte});

  /// The home first, then its replicas.
  final List<KemlockServer> servers;
  final DateTime Function() clock;
  final Duration firstByte;

  var _index = 0;
  var _failures = 0;
  DateTime? _since;
  DateTime? _healthySince;
  DateTime? _lastCheck;

  /// Servers that wouldn't sign this device in, which the sheet reports: a replica that doesn't know it yet.
  final unknown = <String>{};

  /// The server in use.
  KemlockServer get current => servers[_index];
  KemlockServer get home => servers.first;
  bool get onHome => _index == 0;

  /// When the phone moved off the home, or null on it.
  DateTime? get since => _since;

  /// Since when the home has answered every check, or null.
  DateTime? get healthySince => _healthySince;

  KmFailoverMode get mode => onHome
      ? KmFailoverMode.onHome
      : _healthySince == null
      ? KmFailoverMode.onReplica
      : KmFailoverMode.returning;

  /// Runs [request] on the server in use. A failure counts and the request goes again; after two in a row, or a
  /// timeout, the phone moves to the next server that signs this device in ([signInTo]) and tries there. Any answer,
  /// whatever its status, ends the request: a [KmError] other than a network failure is rethrown as the server's.
  /// Throws a [KmFailoverExhausted] when every server failed. With [perRequest], [request] is a whole run of
  /// requests that times each of its own (`KmApi.firstByte`, which fails with a `timedOut` [KmError]): no timer is
  /// put on the run, and a failed run is begun again, as a run killed midway is.
  Future<T> send<T>(
    Future<T> Function(KemlockServer server) request, {
    required Future<void> Function(KemlockServer server) signInTo,
    Duration? timeout,
    bool perRequest = false,
  }) async {
    Object last = StateError('no request was made');
    final failedHere = <int>{};
    while (true) {
      final server = current;
      var timedOut = false;
      try {
        final pending = request(server);
        final result = await (perRequest ? pending : pending.timeout(timeout ?? firstByte));
        _failures = 0;
        return result;
      } on KmError catch (e) {
        if (e.problem != KmProblem.network) {
          // The server answered: reached, even when it refused
          _failures = 0;
          rethrow;
        }
        last = e;
        timedOut = e.timedOut;
      } on TimeoutException catch (e) {
        last = e;
        timedOut = true;
      }
      _failures++;
      if (!timedOut && _failures < failoverFailures) continue;
      failedHere.add(_index);
      if (!await _moveOn(failedHere, signInTo)) throw KmFailoverExhausted(last);
    }
  }

  /// Moves to the next server that wasn't tried and signs this device in there; false when none is left.
  Future<bool> _moveOn(Set<int> tried, Future<void> Function(KemlockServer server) signInTo) async {
    for (var step = 1; step <= servers.length; step++) {
      final next = (_index + step) % servers.length;
      if (tried.contains(next)) continue;
      try {
        await signInTo(servers[next]);
      } on KmError catch (e) {
        // A replica that doesn't know the device yet, or can't be reached: report it and try the others
        tried.add(next);
        if (e.problem != KmProblem.network) unknown.add(servers[next].url);
        continue;
      } on TimeoutException {
        tried.add(next);
        continue;
      }
      _switchTo(next);
      return true;
    }
    return false;
  }

  void _switchTo(int index) {
    _index = index;
    _failures = 0;
    _healthySince = null;
    _lastCheck = null;
    _since = index == 0 ? null : clock();
  }

  /// On a replica, asks the home whether it answers, at most once a minute ([probe] reads its `/kem/v1/config`
  /// and says whether anything answered). Five minutes of unbroken answers return the phone to the home, which
  /// this reports as true; one miss resets the clock.
  Future<bool> checkHome(Future<bool> Function(KemlockServer home) probe) async {
    if (onHome) return false;
    final now = clock();
    final last = _lastCheck;
    if (last != null && now.difference(last) < failoverCheckEvery) return false;
    _lastCheck = now;
    var answered = false;
    try {
      answered = await probe(home).timeout(firstByte);
    } on KmError {
      answered = false;
    } on TimeoutException {
      answered = false;
    }
    if (!answered) {
      _healthySince = null;
      return false;
    }
    final healthy = _healthySince ??= now;
    if (now.difference(healthy) < failoverReturnAfter) return false;
    _switchTo(0);
    return true;
  }

  /// Refuses a home-only change while on a replica.
  void requireHome() {
    if (!onHome) throw KmHomeAway(using: current, since: _since ?? clock());
  }
}

/// Signs this device in on a replica with its device key, no password: a challenge for the device, answered with
/// a proof of the same key. A replica that doesn't know the device throws the server's [KmError].
Future<KmGrant> kmReplicaSignIn(KmAuthApi auth, Uri replica, String deviceId) async {
  final challenge = await auth.replicaChallenge(replica, deviceId);
  return auth.replicaVerify(replica, challenge);
}

// ─── A new server list ─────────────────────────────────────────────────

/// The `sig1` context of a promotion record's signature (`docs/federation.md`, "Home epochs, promotion and the
/// fence").
const promotionContext = 'federation-promotion';

/// A promotion record, the signed envelope `GET /kem/v1/config` carries for a vault's current epoch: the new home
/// vouches for itself. The envelope is `CBOR { 0: body, 1: signature }` with `signature = sig1("federation-promotion",
/// body)` made by the new home's identity key, and the body is `CBOR { 0: 1, 1: vault (17 bytes), 2: new epoch,
/// 3: new home (server id), 4: previous home, 5: issued at (Unix seconds), 6: replicas after the promotion }`, the
/// others in their order and the old home last.
class KmPromotion {
  const KmPromotion._({
    required this.body,
    required this.signature,
    required this.vault,
    required this.epoch,
    required this.newHome,
    required this.previousHome,
    required this.issuedAt,
    required this.replicas,
  });

  /// Reads an envelope. Anything off the format (a key that isn't there or is extra, a length that is wrong, an
  /// unknown version, bytes that aren't CBOR) is a [FormatException]; nothing is verified here.
  factory KmPromotion.parse(Uint8List envelope) {
    final Object? outer;
    final Object? inner;
    try {
      outer = cborDecode(envelope);
      final signed = outer is Map<Object, Object?> ? outer[0] : null;
      inner = signed is Uint8List ? cborDecode(signed) : null;
    } on CborError catch (e) {
      throw FormatException(e.message);
    }
    if (outer is! Map<Object, Object?> || outer.length != 2) {
      throw const FormatException('a record is a body and a signature');
    }
    final body = outer[0];
    final signature = outer[1];
    if (body is! Uint8List || signature is! Uint8List || signature.length != Sig1.signatureLength) {
      throw const FormatException('a record is a body and a signature of 3,373 bytes');
    }
    if (inner is! Map<Object, Object?> || inner.length != 7 || inner[0] != 1) {
      throw const FormatException('a promotion body, version 1');
    }
    final vault = inner[1];
    final epoch = inner[2];
    final newHome = inner[3];
    final previousHome = inner[4];
    final issuedAt = inner[5];
    final replicas = inner[6];
    if (vault is! Uint8List || vault.length != 17) {
      throw const FormatException('a vault is 17 bytes');
    }
    if (epoch is! int || epoch < 1 || issuedAt is! int) {
      throw const FormatException('an epoch and a time are whole numbers');
    }
    if (newHome is! Uint8List || newHome.length != 16 || previousHome is! Uint8List || previousHome.length != 16) {
      throw const FormatException('a server id is 16 bytes');
    }
    if (replicas is! List<Object?> || replicas.length > 16 || replicas.any((id) => id is! Uint8List || id.length != 16)) {
      throw const FormatException('the replicas are server ids');
    }
    return KmPromotion._(
      body: body,
      signature: signature,
      vault: vault,
      epoch: epoch,
      newHome: uuidText(newHome),
      previousHome: uuidText(previousHome),
      issuedAt: issuedAt,
      replicas: [for (final id in replicas) uuidText(id! as Uint8List)],
    );
  }

  /// The exact bytes the signature covers.
  final Uint8List body;

  /// The 3,373-byte `sig1` signature.
  final Uint8List signature;

  /// The vault, `u8(type) || uuid`.
  final Uint8List vault;

  /// The epoch the record starts.
  final int epoch;

  /// The new home's server id: the signer.
  final String newHome;

  /// The home before the promotion.
  final String previousHome;

  /// When it was issued, Unix seconds.
  final int issuedAt;

  /// The servers after the new home, in failover order, the old home last.
  final List<String> replicas;
}

/// Checks a promotion record's signature over [body] with a server's identity key; the default is `sig1`'s, in
/// [promotionContext].
typedef KmVerifyPromotion = Future<bool> Function(Uint8List identityKey, Uint8List body, Uint8List signature);

Future<bool> sig1VerifyPromotion(Uint8List identityKey, Uint8List body, Uint8List signature) =>
    Sig1.verify(identityKey, body, signature, context: promotionContext);

/// Why a new server list was refused. The names are the ends of the `kemlock.failover.list.*` message ids.
enum KmListIssue {
  /// It is for another vault, or names no server this phone already knows.
  strangers,

  /// A known server's identity key differs from the one pinned at first sight.
  keyChanged,

  /// It moves the home, or the epoch, and carries no promotion record.
  noPromotion,

  /// The record isn't for this list, isn't signed by the new home's pinned identity key, or doesn't verify.
  badPromotion,

  /// The list's epoch is below the stored one, or isn't above it when the home moves.
  oldEpoch,
}

/// A server list the phone didn't take: it keeps the old one and shows why.
class KmListRefused implements Exception {
  const KmListRefused(this.issue);

  final KmListIssue issue;

  @override
  String toString() => 'KmListRefused(${issue.name})';
}

/// The target with [incoming], one vault of `GET /kem/v1/config?vault=user:<uuid>`, as its server list, or a
/// [KmListRefused]. The list must be for this account's vault and name at least one known server; a known server
/// keeps the identity key and certificate pin it was first seen with. A new home, or an epoch above a stored one,
/// needs the promotion record: signed by the new home with the identity key already pinned for it, for this vault
/// and epoch, naming the list's own servers. An epoch below the stored one is old news.
Future<KemlockTarget> acceptServerList(
  KemlockTarget current,
  KmVaultServers incoming, {
  KmVerifyPromotion verify = sig1VerifyPromotion,
}) async {
  if (incoming.vault != 'user:${current.accountId}') {
    throw const KmListRefused(KmListIssue.strangers);
  }
  final known = {for (final server in current.servers) server.url: server};
  if (!incoming.servers.any((entry) => known.containsKey(entry.address))) {
    throw const KmListRefused(KmListIssue.strangers);
  }
  if (incoming.epoch < current.homeEpoch) {
    throw const KmListRefused(KmListIssue.oldEpoch);
  }
  final merged = <KemlockServer>[];
  for (final entry in incoming.servers) {
    final server = entry.toServer();
    final old = known[server.url];
    if (old == null) {
      merged.add(server);
      continue;
    }
    if (old.identityKey != null && old.identityKey != server.identityKey) {
      throw const KmListRefused(KmListIssue.keyChanged);
    }
    // First sight is kept
    merged.add(
      KemlockServer(url: old.url, role: server.role, pin: old.pin, identityKey: old.identityKey ?? server.identityKey, extra: old.extra),
    );
  }
  final homeMoved = incoming.home.address != current.home.url;
  // A phone that never took a list trusts the first it reads, as it does a key at first sight
  final epochMoved = current.homeEpoch > 0 && incoming.epoch > current.homeEpoch;
  if (!homeMoved && !epochMoved) {
    return current.copyWith(servers: merged, homeEpoch: incoming.epoch);
  }
  if (incoming.epoch <= current.homeEpoch) {
    throw const KmListRefused(KmListIssue.oldEpoch);
  }
  final envelope = incoming.promotion;
  if (envelope == null) {
    throw const KmListRefused(KmListIssue.noPromotion);
  }
  final KmPromotion record;
  try {
    record = KmPromotion.parse(envelope);
  } on FormatException {
    throw const KmListRefused(KmListIssue.badPromotion);
  }
  final replicas = [for (final entry in incoming.servers.skip(1)) entry.serverId];
  final forThisList =
      _sameBytes(record.vault, concatBytes([u8(OwnerType.user.code), uuidBytes(current.accountId)])) &&
      record.epoch == incoming.epoch &&
      record.newHome == incoming.home.serverId &&
      _sameTexts(record.replicas, replicas) &&
      replicas.contains(record.previousHome);
  if (!forThisList) {
    throw const KmListRefused(KmListIssue.badPromotion);
  }
  final key = known[incoming.home.address]?.identityKey;
  if (key == null) {
    throw const KmListRefused(KmListIssue.badPromotion);
  }
  final bool ok;
  try {
    ok = await verify(b64urlDecode(key), record.body, record.signature);
  } on Object {
    throw const KmListRefused(KmListIssue.badPromotion);
  }
  if (!ok) {
    throw const KmListRefused(KmListIssue.badPromotion);
  }
  return current.copyWith(servers: merged, homeEpoch: incoming.epoch);
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

bool _sameTexts(List<String> a, List<String> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
