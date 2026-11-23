// A phone that moves its vault to the fake Kemlock Server: the move's steps over one connection, the fake
// crypto, and a record, for the tests of the copy, files, check and runner of move-off-vaultwarden-sync.
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_cache.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_plan.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_record.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_server.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';

import 'fake_kemlock_server.dart';
import 'fake_km_crypto.dart';
import 'km_sync_kit.dart';

/// The server's address a record names, and the time a move's steps run at.
const moveNow = 1795300000000;

/// A new record, as a move begins.
KmMoveRecord newRecord({KmMoveStep step = KmMoveStep.copy}) =>
    KmMoveRecord(source: vaultwardenSource, server: 'https://vault.example.com', home: 'home-1', mode: 'sealed', startedAt: 1, step: step);

/// One phone's connection to the fake server, with the account crypto it shares with its other phones.
class MoveRig {
  MoveRig({FakeKemlockServer? server, FakeKmCrypto? crypto})
    : server = server ?? (FakeKemlockServer()..checkTokens = false),
      crypto = crypto ?? kmDefaultCrypto() {
    final token = this.server.issueTokens('jkt')['accessToken']! as String;
    connection = KmConnection(
      api: KmApi(this.server.client),
      server: FakeKemlockServer.url,
      session: KmSession(
        userId: this.server.userId,
        deviceId: FakeKemlockServer.deviceId,
        tokens: KmTokens(access: token, refresh: 'refresh', accessExpiresAt: 1 << 50, refreshExpiresAt: 1 << 50),
      ),
      save: (_) async {},
    );
    moveServer = KmMoveServer(connection: connection, server: FakeKemlockServer.url, crypto: this.crypto);
  }

  final FakeKemlockServer server;
  final FakeKmCrypto crypto;
  late final KmConnection connection;
  late final KmMoveServer moveServer;

  Owner get owner => crypto.owner;

  /// Another phone of the same account, on the same server.
  MoveRig another() => MoveRig(server: server, crypto: crypto.alike());

  /// The plan of [lists] for this account.
  KmMovePlan plan(Lists lists, {int batchSize = KmApi.batchSize}) => planKmMove(lists, owner, batchSize: batchSize);

  /// Writes [account] as another device of the account would, at [revision] (1 for a new item), over
  /// [expected] when it replaces one.
  Future<void> put(OtpAccount account, {int revision = 1, int? expected}) async {
    final json = account.toJson();
    await moveServer.send([
      KmMoveWrite(itemId: itemUuidOf(account.id), entryId: account.id, kind: 'otp', revision: revision, expected: expected, json: json),
    ]);
  }

  String itemUuidOf(String entryId) => kmItemId(entryId, owner);

  /// The server's items, opened.
  Future<KmCache> read() => moveServer.read();

  /// How many batch requests the server answered.
  int get batches => server.events.where((event) => event == 'batch').length;
}

/// An account of the tests.
OtpAccount account(String id, {String? issuer, int at = 1, int? updatedAt}) =>
    OtpAccount(id: id, issuer: issuer ?? id, label: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', addedAt: at, updatedAt: updatedAt);

/// An entry id that is a UUID, the n-th.
String uuidN(int n) => '3f2c9a71-e4b0-4856-8a00-${n.toRadixString(16).padLeft(12, '0')}';
