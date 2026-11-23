import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_backend.dart';
import 'package:kemlock_core/features/sync/kemlock/km_cache.dart';
import 'package:kemlock_core/features/sync/kemlock/km_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sync.dart';
import 'package:kemlock_core/features/sync/removal_guard.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';

import 'fake_kemlock_server.dart';
import 'fake_km_crypto.dart';

const kmTarget = KemlockTarget(
  accountId: '00000000-0000-4000-8000-000000000001',
  email: 'me@example.com',
  servers: [KemlockServer(url: 'https://kem.example.com')],
  deviceId: FakeKemlockServer.deviceId,
);

/// What a phone seals and signs with unless it is given one: the fake, or, between `useRealCrypto` and
/// `useFakeCrypto` (real_km_crypto.dart), the production crypto over a test account's keys.
FakeKmCrypto Function() kmDefaultCrypto = FakeKmCrypto.new;

/// The time every phone of one test shares, so their syncs and edits have one order. Each run takes a minute.
class KmClock {
  int ms = DateTime.utc(2026, 11, 21, 12).millisecondsSinceEpoch;

  int tick() => ms += 60000;
}

OtpAccount acct(String id, {int at = 1, String? secret, String? label, int? updatedAt}) =>
    OtpAccount(id: id, issuer: id, label: label ?? '', secret: secret ?? 'JBSWY3DPEHPK3PXP', addedAt: at, updatedAt: updatedAt);

Login login(String id, {String? password, int at = 1, int? updatedAt}) =>
    Login(id: id, name: 'Site $id', username: 'me', password: password ?? 'pw', addedAt: at, updatedAt: updatedAt);

/// The phone's attached files, in memory, as KMA1 bytes by attachment id.
class FakeFileStore implements KmFileStore {
  final files = <String, Uint8List>{};

  @override
  Future<bool> exists(String id) async => files.containsKey(id);

  @override
  Future<Uint8List?> readSealed(String id) async => files[id];

  @override
  Future<void> writeSealed(String id, Uint8List sealed) async => files[id] = sealed;
}

/// One phone of the account: its entries, what its last run kept, its sealed cache (kept as JSON, as the
/// vault keeps it), and a Kemlock Server sync over the shared fake server.
class KmPhone {
  KmPhone(this.server, {required this.clock, FakeKmCrypto? crypto, this.lists = const Lists(), this.fileStore, this.anchors})
    : crypto = crypto ?? kmDefaultCrypto() {
    final token = server.issueTokens('jkt')['accessToken']! as String;
    final session = KmSession(
      userId: server.userId,
      deviceId: FakeKemlockServer.deviceId,
      tokens: KmTokens(access: token, refresh: 'refresh', accessExpiresAt: 1 << 50, refreshExpiresAt: 1 << 50),
    );
    api = KmApi(server.client);
    connection = KmConnection(api: api, server: FakeKemlockServer.url, session: session, save: (_) async {});
    scope = KmScopeSync(
      connection: connection,
      server: FakeKemlockServer.url,
      crypto: this.crypto,
      files: fileStore == null ? null : KmFiles(store: fileStore!, connection: connection, server: FakeKemlockServer.url),
      anchors: anchors,
      loadCache: () async => KmCache.fromJson(stored == null ? null : jsonDecode(jsonEncode(stored))),
      saveCache: (cache) async {
        if (failStore) throw StateError('the phone died before it stored anything');
        stored = jsonDecode(jsonEncode(cache.toJson()));
        stores++;
      },
    );
  }

  final FakeKemlockServer server;
  final KmClock clock;
  final FakeKmCrypto crypto;

  /// This phone's attached files, when its sync handles them.
  final FakeFileStore? fileStore;

  /// The anchors of this phone's vault, carried to the server and back, when the run carries them.
  final KmAnchors? anchors;
  late final KmApi api;
  late final KmConnection connection;
  late final KmScopeSync scope;

  /// This phone's entries in the scope.
  Lists lists;

  /// What the last run kept.
  ScopeState state = const ScopeState(known: []);

  /// The sealed cache, as stored JSON; null before the first run.
  Object? stored;
  var stores = 0;
  var failStore = false;

  /// Another phone of the same account, as a new install would be.
  KmPhone another({Lists lists = const Lists(), FakeFileStore? fileStore}) =>
      KmPhone(server, clock: clock, crypto: crypto.alike(), lists: lists, fileStore: fileStore);

  /// The cache as stored.
  KmCache get cache => KmCache.fromJson(stored);

  /// Runs once and takes the merged document, as the scheduler does. A run that throws changes nothing.
  Future<KmSyncResult> run({RemovalChoice? choice}) async {
    final now = clock.tick();
    final result = await scope.sync(kmTarget, lists, state, now: now, choice: choice);
    lists = result.doc;
    state = ScopeState(known: result.known, lastSyncAt: now, extra: result.state);
    return result;
  }

  /// The ids of this phone's entries.
  List<String> get ids => [...lists.ids]..sort();
}
