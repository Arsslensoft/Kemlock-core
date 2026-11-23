@TestOn('vm')
library;

// Failover in a live session (add-kemlock-server-sync, task 10.2's wiring): the
// host switches servers by the plan's rule, signs in to a replica with the
// device key and no password, reports where it is, and returns home after five
// healthy minutes. Two fake servers stand for the home and a replica, told
// apart by the certificate pin their client is asked for.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_backend.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_failover.dart';
import 'package:kemlock_core/features/sync/kemlock/km_host.dart';
import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

class _Values implements KmVaultValues {
  final values = <String, Object?>{};

  @override
  Future<Object?> load(String key) async => values[key] == null ? null : jsonDecode(jsonEncode(values[key]));

  @override
  Future<void> save(String key, Object? value) async => values[key] = jsonDecode(jsonEncode(value));

  @override
  void remove(String key) => values.remove(key);
}

class _Clock {
  DateTime now = DateTime.now();

  DateTime call() => now;

  void pass(Duration duration) => now = now.add(duration);
}

const _target = KemlockTarget(
  accountId: '00000000-0000-4000-8000-000000000001',
  email: 'me@example.com',
  servers: [
    KemlockServer(url: 'https://kem.example.com', pin: 'home'),
    KemlockServer(url: 'https://replica.example.com', role: KemlockServer.replica, pin: 'replica'),
  ],
  deviceId: FakeKemlockServer.deviceId,
);

late KmTestAccount _test;

class _Rig {
  _Rig({required this.home, required this.replica, required this.values, required this.host, required this.clock, required this.away});

  final FakeKemlockAccountServer home;
  final FakeKemlockAccountServer replica;
  final _Values values;
  final KmHost host;
  final _Clock clock;

  /// What the host reported after each run.
  final List<KmAway?> away;

  Future<KmSyncResult> sync() =>
      host.sync(_target, const Lists(), const ScopeState(known: []), now: DateTime.utc(2026, 11, 22).millisecondsSinceEpoch);
}

/// A signed-in phone whose vault names a home and one replica; the replica knows the device unless [known] is false.
Future<_Rig> _rig({bool known = true}) async {
  final home = FakeKemlockAccountServer(userId: _test.userId);
  final replica = FakeKemlockAccountServer(userId: _test.userId);
  if (known) replica.knownDevices.add(FakeKemlockServer.deviceId);
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
  final clock = _Clock();
  final away = <KmAway?>[];
  final host = KmHost(
    values: values,
    clientFor: (pin) => pin == 'replica' ? replica.client : home.client,
    proofsFor: (session) async => KmDpop(key),
    clock: clock.call,
    onAway: away.add,
  );
  return _Rig(home: home, replica: replica, values: values, host: host, clock: clock, away: away);
}

http.Response _down(http.Request request) => throw http.ClientException('the server is down');

void main() {
  setUpAll(() async {
    _test = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  test('on the home, nothing is signed in elsewhere and nothing is reported as away', () async {
    final rig = await _rig();
    await rig.sync();
    expect(rig.away, [null]);
    expect(rig.replica.requests, isEmpty);
  });

  test('the home goes down: the phone signs in to the replica by its key, with no password, and the run goes on', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => _down(request);

    final result = await rig.sync();

    expect(result.skipped, 0);
    expect(
      rig.replica.requests.map((r) => r.url.path),
      containsAll(['/kem/v1/auth/device-key/challenge', '/kem/v1/auth/device-key/verify']),
    );
    expect(rig.replica.events, contains('sync'));
    for (final request in rig.replica.requests) {
      expect(request.body, isNot(contains('password')));
    }
    expect(rig.away.single?.using.url, 'https://replica.example.com');
    // The home's stored session is as it was
    expect(KmSession.fromJson(rig.values.values[keyKemlockSession]! as Map<String, Object?>).tokens.accessExpiresAt, 1 << 50);
  });

  test('later runs stay on the replica without signing in again', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => _down(request);
    await rig.sync();
    rig.replica.requests.clear();

    await rig.sync();

    expect(rig.replica.requests.map((r) => r.url.path), isNot(contains('/kem/v1/auth/device-key/challenge')));
    expect(rig.replica.events.where((event) => event == 'sync').length, 2);
  });

  test('a server that answers with an error is reached: no switch', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => http.Response('{"type":"urn:kemlock:problem:internal"}', 500);

    await expectLater(rig.sync(), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server)));

    expect(rig.away.single, isNull);
    expect(rig.replica.requests, isEmpty);
  });

  test('a replica that does not know the device is not used, and the run says the servers are unreachable', () async {
    final rig = await _rig(known: false);
    rig.home.respond = (request) async => _down(request);

    await expectLater(rig.sync(), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network)));

    expect(rig.replica.events, isNot(contains('sync')));
  });

  test('the phone returns to the home after five healthy minutes, and one miss starts the count again', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => _down(request);
    await rig.sync();
    expect(rig.away.last, isNotNull);

    // The home answers again: the first check starts the clock
    rig.home.respond = null;
    await rig.sync();
    rig.clock.pass(const Duration(minutes: 3));
    await rig.sync();
    expect(rig.away.last, isNotNull, reason: 'three minutes is not five');

    // One miss, then up again
    rig.home.respond = (request) async => _down(request);
    rig.clock.pass(const Duration(minutes: 1));
    await rig.sync();
    rig.home.respond = null;
    rig.clock.pass(const Duration(minutes: 1));
    await rig.sync();
    rig.clock.pass(const Duration(minutes: 4));
    await rig.sync();
    expect(rig.away.last, isNotNull, reason: 'the miss restarted the count');

    rig.clock.pass(const Duration(minutes: 2));
    final homeSyncs = rig.home.events.where((event) => event == 'sync').length;
    await rig.sync();
    expect(rig.away.last, isNull);
    expect(rig.home.events.where((event) => event == 'sync').length, homeSyncs + 1, reason: 'the run was on the home');
  });

  test('a change only the home may accept is refused while on a replica, naming where and since when', () async {
    final rig = await _rig();
    rig.home.respond = (request) async => _down(request);
    await rig.sync();
    rig.clock.pass(const Duration(minutes: 2));

    try {
      rig.host.requireHome(_target);
      fail('a home-only change went through');
    } on KmHomeAway catch (away) {
      expect(away.using.url, 'https://replica.example.com');
      expect(rig.clock.now.difference(away.since), const Duration(minutes: 2));
    }
  });
}
