@TestOn('vm')
library;

// The server list the home gives (add-kemlock-server-sync, task 10.2's wiring): after a run the host reads
// `/kem/v1/config?vault=user:<account>` from the server in use and takes the account's vault through
// `acceptServerList`. An accepted list gives the failover its replica; one that fails the checks leaves the old
// list as it was. The home and the replica are two fake servers, told apart by the certificate pin their client
// is asked for.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_host.dart';
import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

const _homeId = '00000000-0000-4000-8000-0000000000a1';
const _replicaId = '00000000-0000-4000-8000-0000000000a2';
const _replicaUrl = 'https://replica.example.com';

/// A phone whose vault names the home only.
const _target = KemlockTarget(
  accountId: '00000000-0000-4000-8000-000000000001',
  email: 'me@example.com',
  servers: [KemlockServer(url: 'https://kem.example.com', pin: 'home')],
  deviceId: FakeKemlockServer.deviceId,
);

late KmTestAccount _test;

class _Values implements KmVaultValues {
  final values = <String, Object?>{};

  @override
  Future<Object?> load(String key) async => values[key] == null ? null : jsonDecode(jsonEncode(values[key]));

  @override
  Future<void> save(String key, Object? value) async => values[key] = jsonDecode(jsonEncode(value));

  @override
  void remove(String key) => values.remove(key);
}

class _Rig {
  _Rig(this.home, this.replica);

  final FakeKemlockAccountServer home;
  final FakeKemlockAccountServer replica;
  late final KmHost host;

  /// The lists the host handed to its owner to keep in the settings.
  final kept = <KemlockTarget>[];

  Future<void> sync() =>
      host.sync(_target, const Lists(), const ScopeState(known: []), now: DateTime.utc(2026, 11, 22).millisecondsSinceEpoch);
}

Map<String, Object?> _entry(String id, String address, String role) => {
  'serverId': id,
  'address': address,
  'identityKey': b64urlEncode(Uint8List(1984)),
  'role': role,
};

Map<String, Object?> _vault(List<Map<String, Object?>> servers, {int epoch = 1, String? owner}) => {
  'vault': owner ?? 'user:${_target.accountId}',
  'epoch': epoch,
  'servers': servers,
  'promotion': null,
};

Future<_Rig> _rig() async {
  final home = FakeKemlockAccountServer(userId: _test.userId);
  final replica = FakeKemlockAccountServer(userId: _test.userId)..knownDevices.add(FakeKemlockServer.deviceId);
  final key = SoftwareDeviceKey.generate();
  final tokens = home.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk));
  final values = _Values();
  await values.save(
    keyKemlockSession,
    KmSession(
      userId: _test.userId,
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
  await values.save(
    keyKemlockAccount,
    KmAccount(
      accountId: _test.userId,
      keyVersion: 1,
      rootKey: _test.root,
      kx1PrivateKey: _test.kx1.privateKey,
      sig1PrivateKey: _test.sig1.privateKey,
      kx1PublicKey: _test.kx1.publicKey,
      sig1PublicKey: _test.sig1.publicKey,
      opaqueEnrolled: true,
    ).toJson(),
  );
  final rig = _Rig(home, replica);
  rig.host = KmHost(
    values: values,
    clientFor: (pin) => pin == 'home' ? home.client : replica.client,
    proofsFor: (session) async => KmDpop(key),
    onList: rig.kept.add,
  );
  return rig;
}

http.Response _down(http.Request request) => throw http.ClientException('the server is down');

void main() {
  setUpAll(() async {
    _test = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  test('a config naming a replica lets the host fail over to it', () async {
    final rig = await _rig();
    rig.home.vaults = [
      _vault([_entry(_homeId, 'https://kem.example.com', 'home'), _entry(_replicaId, _replicaUrl, 'replica')]),
    ];
    // With only the home known, a home that is down leaves nowhere to go
    await rig.sync();
    expect(rig.home.requests.any((r) => r.url.queryParametersAll['vault']?.contains('user:${_target.accountId}') ?? false), isTrue);
    expect(rig.kept.single.servers.map((server) => server.url), ['https://kem.example.com', _replicaUrl]);
    expect(rig.kept.single.homeEpoch, 1);

    rig.home.respond = (request) async => _down(request);
    await rig.sync();

    expect(rig.replica.events, contains('sync'));
    expect(rig.replica.requests.map((r) => r.url.path), contains('/kem/v1/auth/device-key/verify'));
  });

  test('without the list the home is all the phone knows, and a home that is down is unreachable', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => _down(request);

    await expectLater(rig.sync(), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network)));

    expect(rig.replica.requests, isEmpty);
  });

  test('a list of strangers is refused and nothing is kept', () async {
    final rig = await _rig();
    rig.home.vaults = [
      _vault([_entry(_homeId, 'https://evil.example.net', 'home'), _entry(_replicaId, 'https://evil2.example.net', 'replica')]),
    ];

    await rig.sync();

    expect(rig.kept, isEmpty);
    rig.home.respond = (request) async => _down(request);
    await expectLater(rig.sync(), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network)));
  });

  test('a list for another vault is not the account\'s and is left alone', () async {
    final rig = await _rig();
    rig.home.vaults = [
      _vault([
        _entry(_homeId, 'https://kem.example.com', 'home'),
        _entry(_replicaId, _replicaUrl, 'replica'),
      ], owner: 'user:00000000-0000-4000-8000-000000000002'),
    ];

    await rig.sync();

    expect(rig.kept, isEmpty);
  });

  test('a list that moves the home with no promotion record is refused, and the old list is kept', () async {
    final rig = await _rig();
    rig.home.vaults = [
      _vault([_entry(_homeId, 'https://kem.example.com', 'home'), _entry(_replicaId, _replicaUrl, 'replica')]),
    ];
    await rig.sync();
    expect(rig.kept, hasLength(1));

    // The replica is named the home at a later epoch, with nothing signed
    rig.home.vaults = [
      _vault([_entry(_replicaId, _replicaUrl, 'home'), _entry(_homeId, 'https://kem.example.com', 'replica')], epoch: 2),
    ];
    await rig.sync();

    expect(rig.kept, hasLength(1), reason: 'the refused list was not handed on');
    // The old list still stands: the home first, the replica to fail over to
    rig.home.respond = (request) async => _down(request);
    await rig.sync();
    expect(rig.replica.events, contains('sync'));
  });

  test('a config that cannot be read changes nothing and fails no run', () async {
    final rig = await _rig();
    final answer = rig.home.handle;
    rig.home.respond = (request) async => request.url.path.endsWith('/kem/v1/config') ? http.Response('not json', 200) : answer(request);

    await rig.sync();

    expect(rig.home.events, contains('sync'));
    expect(rig.kept, isEmpty);
  });
}
