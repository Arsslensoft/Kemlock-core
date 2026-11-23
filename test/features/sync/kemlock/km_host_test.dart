@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_backend.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_host.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:kemlock_core/features/sync/kemlock/km_signin.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

/// The vault's sealed values, in memory as JSON, as the vault keeps them.
class _Values implements KmVaultValues {
  final values = <String, Object?>{};

  @override
  Future<Object?> load(String key) async => values[key] == null ? null : jsonDecode(jsonEncode(values[key]));

  @override
  Future<void> save(String key, Object? value) async => values[key] = jsonDecode(jsonEncode(value));

  @override
  void remove(String key) => values.remove(key);
}

late KmTestAccount _test;

KmAccount _account() => KmAccount(
  accountId: _test.userId,
  keyVersion: 1,
  rootKey: _test.root,
  kx1PrivateKey: _test.kx1.privateKey,
  sig1PrivateKey: _test.sig1.privateKey,
  kx1PublicKey: _test.kx1.publicKey,
  sig1PublicKey: _test.sig1.publicKey,
  opaqueEnrolled: true,
);

class _Rig {
  _Rig(this.server, this.key, this.values, this.host);

  final FakeKemlockAccountServer server;
  final SoftwareDeviceKey key;
  final _Values values;
  final KmHost host;

  KmSession get session => KmSession.fromJson(values.values[keyKemlockSession]! as Map<String, Object?>);
}

/// A signed-in phone: sealed session bound to a software key, sealed account, and a host over the fake server.
Future<_Rig> _rig({int accessExpiresAt = 1 << 50, bool keyLost = false}) async {
  final server = FakeKemlockAccountServer(userId: _test.userId);
  final key = SoftwareDeviceKey.generate();
  final tokens = server.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk));
  final values = _Values();
  await values.save(
    keyKemlockSession,
    KmSession(
      userId: _test.userId,
      deviceId: FakeKemlockServer.deviceId,
      tokens: KmTokens(
        access: tokens['accessToken']! as String,
        refresh: tokens['refreshToken']! as String,
        accessExpiresAt: accessExpiresAt,
        refreshExpiresAt: 1 << 50,
      ),
      deviceKey: const {'protection': 'software'},
    ).toJson(),
  );
  await values.save(keyKemlockAccount, _account().toJson());
  final host = KmHost(values: values, clientFor: (pin) => server.client, proofsFor: (session) async => keyLost ? null : KmDpop(key));
  return _Rig(server, key, values, host);
}

Future<KmSyncResult> _sync(_Rig rig) =>
    rig.host.sync(kmTarget, const Lists(), const ScopeState(known: []), now: DateTime.utc(2026, 11, 22).millisecondsSinceEpoch);

void main() {
  setUpAll(() async {
    _test = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  group('a run', () {
    test('opens the sealed session and account and syncs, storing the cache', () async {
      final rig = await _rig();
      final result = await _sync(rig);
      expect(result.skipped, 0);
      expect(rig.server.events, contains('sync'));
      expect(rig.values.values.containsKey(keyKemlockCache), isTrue);
    });

    test('an access token that ended is renewed, and the new session is sealed', () async {
      final rig = await _rig(accessExpiresAt: 0);
      final before = rig.session.tokens.refresh;
      await _sync(rig);
      expect(rig.session.tokens.refresh, isNot(before), reason: 'the refresh token rotates');
      expect(rig.session.tokens.accessExpiresAt, greaterThan(0));
    });

    test('with no session sealed, the phone says it is signed out', () async {
      final rig = await _rig();
      rig.values.remove(keyKemlockSession);
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'signed-out')));
      expect(rig.server.requests, isEmpty);
    });

    test('an account holding only the OPAQUE mark is signed out too', () async {
      final rig = await _rig();
      await rig.values.save(keyKemlockAccount, {'opaqueEnrolled': true});
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.sessionEnded)));
    });

    test('a device key the phone lost ends the session without a request', () async {
      final rig = await _rig(keyLost: true);
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'device-key-lost')));
      expect(rig.server.requests, isEmpty);
    });
  });

  group('a session the server ends', () {
    test('is kept marked with why, and every later run says so without asking the server', () async {
      final rig = await _rig(accessExpiresAt: 0);
      rig.server.endSession = 'signed-out';
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'signed-out')));
      expect(rig.session.extra[endedKey], 'signed-out');
      rig.server.requests.clear();
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'signed-out')));
      expect(rig.server.requests, isEmpty);
    });

    test('a refresh token used twice ends it for safety, and the entries are not touched', () async {
      final rig = await _rig(accessExpiresAt: 0);
      // Someone else used the phone's refresh token first
      final stolen = rig.session.tokens.refresh;
      await rig.host.sync(kmTarget, const Lists(), const ScopeState(known: []), now: 1);
      final replay = KmSession.fromJson(rig.values.values[keyKemlockSession]! as Map<String, Object?>);
      await rig.values.save(
        keyKemlockSession,
        KmSession(
          userId: replay.userId,
          deviceId: replay.deviceId,
          tokens: KmTokens(access: 'old', refresh: stolen, accessExpiresAt: 0, refreshExpiresAt: 1 << 50),
          deviceKey: replay.deviceKey,
        ).toJson(),
      );
      await expectLater(_sync(rig), throwsA(isA<KmError>().having((e) => e.reason, 'reason', 'refresh-reuse')));
      expect(rig.session.extra[endedKey], 'refresh-reuse');
    });
  });

  group('keeping a sign-in', () {
    test('seals the session and the account', () async {
      final values = _Values();
      final signedIn = KmSignedIn(
        session: KmSession(
          userId: _test.userId,
          deviceId: 'd',
          tokens: const KmTokens(access: 'a', refresh: 'r', accessExpiresAt: 1, refreshExpiresAt: 2),
        ),
        account: _account(),
      );
      await kmKeepSignIn(values, signedIn);
      expect(KmSession.fromJson(values.values[keyKemlockSession]! as Map<String, Object?>).tokens.refresh, 'r');
      expect(KmAccount.fromJson(values.values[keyKemlockAccount]! as Map<String, Object?>).accountId, _test.userId);
    });

    test('a different account drops the old account\'s cache', () async {
      final values = _Values();
      await values.save(keyKemlockAccount, {'accountId': '00000000-0000-4000-8000-0000000000ff'});
      await values.save(keyKemlockCache, {'cursor': 'x'});
      final signedIn = KmSignedIn(
        session: KmSession(
          userId: _test.userId,
          deviceId: 'd',
          tokens: const KmTokens(access: 'a', refresh: 'r', accessExpiresAt: 1, refreshExpiresAt: 2),
        ),
      );
      await kmKeepSignIn(values, signedIn);
      expect(values.values.containsKey(keyKemlockCache), isFalse);
    });

    test('the OPAQUE mark is kept apart from keys, and beside them once there are some', () async {
      final values = _Values();
      expect(await kmOpaqueSeen(values), isFalse);
      await kmRememberOpaque(values);
      expect(await kmOpaqueSeen(values), isTrue);
      await kmKeepAccount(values, _account().withOpaqueEnrolled());
      await kmRememberOpaque(values);
      final stored = KmAccount.fromJson(values.values[keyKemlockAccount]! as Map<String, Object?>);
      expect(stored.opaqueEnrolled, isTrue);
      expect(stored.rootKey, _test.root);
    });
  });

  group('signing out', () {
    test('asks the server to end this device\'s session', () async {
      final rig = await _rig();
      await rig.host.signOut(kmTarget);
      expect(rig.server.signedOut, [FakeKemlockServer.deviceId]);
    });

    test('with nothing signed in sends nothing', () async {
      final rig = await _rig();
      rig.values.remove(keyKemlockSession);
      await rig.host.signOut(kmTarget);
      expect(rig.server.requests, isEmpty);
    });
  });
}
