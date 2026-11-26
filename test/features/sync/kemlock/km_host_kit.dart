import 'dart:convert';

import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_backend.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_host.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

/// The vault's sealed values, in memory as JSON, as the vault keeps them.
class MemoryValues implements KmVaultValues {
  final values = <String, Object?>{};

  @override
  Future<Object?> load(String key) async => values[key] == null ? null : jsonDecode(jsonEncode(values[key]));

  @override
  Future<void> save(String key, Object? value) async => values[key] = jsonDecode(jsonEncode(value));

  @override
  void remove(String key) => values.remove(key);
}

/// The account every [HostPhone] is signed in to; made once by the test's `setUpAll`.
late KmTestAccount hostAccount;

KmAccount _account() => KmAccount(
  accountId: hostAccount.userId,
  keyVersion: 1,
  rootKey: hostAccount.root,
  kx1PrivateKey: hostAccount.kx1.privateKey,
  sig1PrivateKey: hostAccount.sig1.privateKey,
  kx1PublicKey: hostAccount.kx1.publicKey,
  sig1PublicKey: hostAccount.sig1.publicKey,
  opaqueEnrolled: true,
);

/// One phone of the account: a host over the shared server, and the files it keeps.
class HostPhone {
  HostPhone(this.host, this.store, this.values);

  final KmHost host;
  final FakeFileStore store;
  final MemoryValues values;

  /// Runs a sync of [local] at [now] (epoch ms), with no memory of an earlier run.
  Future<KmSyncResult> sync(int now, [Lists local = const Lists()]) => host.sync(kmTarget, local, const ScopeState(known: []), now: now);
}

/// A phone signed in to [server] with a device key of its own, with a host that fetches missing files unless [fetchMissing] is false.
Future<HostPhone> hostPhone(FakeKemlockAccountServer server, {bool fetchMissing = true}) async {
  final key = SoftwareDeviceKey.generate();
  final tokens = server.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk));
  final values = MemoryValues();
  await values.save(
    keyKemlockSession,
    KmSession(
      userId: hostAccount.userId,
      deviceId: FakeKemlockServer.deviceId,
      tokens: KmTokens(
        access: tokens['accessToken']! as String,
        refresh: tokens['refreshToken']! as String,
        accessExpiresAt: 1 << 50,
        refreshExpiresAt: 1 << 50,
      ),
      deviceKey: const {'protection': 'software'},
    ).toJson(),
  );
  await values.save(keyKemlockAccount, _account().toJson());
  final store = FakeFileStore();
  final host = KmHost(
    values: values,
    clientFor: (pin) => server.client,
    proofsFor: (session) async => KmDpop(key),
    fileStore: store,
    fetchMissing: fetchMissing,
  );
  return HostPhone(host, store, values);
}
