@TestOn('vm')
library;

// The push token and the server (add-kemlock-server-sync, design 13). The server's `DeviceDto` refuses a member it
// doesn't list, so the token is not in the device body of a sign-in; it goes to `POST /kem/v1/devices/push-token`
// once signed in, again when it changes, and `DELETE` takes it back. The fake server refuses unknown device fields,
// as the real one does.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
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

const _password = 'correct horse battery staple';
const _email = 'me@example.com';

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
  _Rig(this.server);

  final FakeKemlockAccountServer server;
  late final KmHost host;

  /// The token the phone's push channel gives now, or null for none.
  KmPushToken? token = (kind: 'fcm', token: 'fcm-token-1');

  Future<void> sync({bool push = true}) async {
    await host.sync(
      kmTarget.copyWith(push: push),
      const Lists(),
      const ScopeState(known: []),
      now: DateTime.utc(2026, 11, 22).millisecondsSinceEpoch,
    );
    await host.pushIdle;
  }
}

Future<_Rig> _rig() async {
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
  final rig = _Rig(server);
  rig.host = KmHost(
    values: values,
    clientFor: (pin) => server.client,
    proofsFor: (session) async => KmDpop(key),
    pushToken: () async => rig.token,
  );
  return rig;
}

void main() {
  setUpAll(() async {
    _test = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  group('the device body', () {
    test('carries no push token, so a server that refuses unknown device fields signs the phone in', () async {
      final server = FakeKemlockAccountServer(userId: _test.userId);
      await server.registerOpaque(_password, _test);
      final key = SoftwareDeviceKey.generate();
      final signIn = KmSignIn(
        api: KmApi(server.client, proofs: KmDpop(key)),
        server: FakeKemlockServer.url,
        device: const KmDeviceInfo(name: 'Kemlock on Pixel 9', kind: 'kemlock-android', bitwardenDeviceId: 'bw-device-1'),
        opaque: FakeKmOpaque(),
        deviceKey: const {'protection': 'software'},
        opaqueSeen: false,
        argon2: cheapArgon2,
      );

      final step = await signIn.password(_email, _password);

      expect(step, isA<KmSignedIn>());
      expect(server.devicesSeen.single.keys, unorderedEquals(['name', 'kind', 'bitwardenDeviceIdentifier']));
    });

    test('is refused by the fake with a member the server does not list, as the real server does', () async {
      final server = FakeKemlockAccountServer(userId: _test.userId);
      final api = KmApi(server.client, proofs: KmDpop(SoftwareDeviceKey.generate()));

      await expectLater(
        api.call(
          'POST',
          FakeKemlockServer.url,
          '/auth/sso/finish',
          body: {
            'code': 'code-1',
            'verifier': 'verifier-0123456789012345678901234567890123456',
            'device': {'name': 'Kemlock on Pixel 9', 'kind': 'kemlock-android', 'pushToken': 'fcm-token-1'},
          },
        ),
        throwsA(isA<KmError>().having((e) => e.status, 'status', 400)),
      );
    });
  });

  group('registering the token', () {
    test('a run that goes through sends the kind and the token, once', () async {
      final rig = await _rig();

      await rig.sync();
      await rig.sync();

      expect(rig.server.pushTokens, [(kind: 'fcm', token: 'fcm-token-1')]);
    });

    test('a token that changed is sent again', () async {
      final rig = await _rig();
      await rig.sync();

      rig.token = (kind: 'fcm', token: 'fcm-token-2');
      await rig.sync();

      expect(rig.server.pushTokens, [(kind: 'fcm', token: 'fcm-token-1'), (kind: 'fcm', token: 'fcm-token-2')]);
    });

    test('a phone with no token sends nothing', () async {
      final rig = await _rig();
      rig.token = null;

      await rig.sync();

      expect(rig.server.pushTokens, isEmpty);
    });

    test('with the push switch off nothing is sent, and turning it on sends the token', () async {
      final rig = await _rig();

      await rig.sync(push: false);
      expect(rig.server.pushTokens, isEmpty);

      await rig.sync();
      expect(rig.server.pushTokens, [(kind: 'fcm', token: 'fcm-token-1')]);
    });

    test('a server that refuses it does not fail the run, and the next run tries again', () async {
      final rig = await _rig();
      final answer = rig.server.handle;
      rig.server.respond = (request) async => request.url.path.endsWith('/devices/push-token')
          ? http.Response('{"type":"urn:kemlock:problem:internal"}', 500)
          : answer(request);

      await rig.sync();
      expect(rig.server.pushTokens, isEmpty);
      expect(rig.server.events, contains('sync'));

      rig.server.respond = null;
      await rig.sync();
      expect(rig.server.pushTokens, [(kind: 'fcm', token: 'fcm-token-1')]);
    });

    test('turning the switch off takes the token back from the server, and the next run asks for it again', () async {
      final rig = await _rig();
      await rig.sync();

      await rig.host.unregisterPush(kmTarget.copyWith(push: false));
      expect(rig.server.pushTokens.last, isNull);

      await rig.sync();
      expect(rig.server.pushTokens.last, (kind: 'fcm', token: 'fcm-token-1'));
    });
  });
}
