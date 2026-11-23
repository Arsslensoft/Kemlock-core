@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_signin.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sso.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

const _device = KmDeviceInfo(name: 'Kemlock on Pixel 9', kind: 'kemlock-android');

/// A browser sheet that records what it opened and answers as the test says.
class _Browser implements KmBrowserAuth {
  _Browser(this.answer);

  final Uri? Function(Uri url, String state) answer;
  final opened = <Uri>[];
  final states = <String>[];
  var cancels = 0;

  @override
  Future<Uri?> authenticate(Uri url, {required String state}) async {
    opened.add(url);
    states.add(state);
    return answer(url, state);
  }

  @override
  Future<void> cancel() async => cancels++;
}

({KmSignIn signIn, SoftwareDeviceKey key}) _signIn(FakeKemlockAccountServer server, {SoftwareDeviceKey? key}) {
  final deviceKey = key ?? SoftwareDeviceKey.generate();
  return (
    signIn: KmSignIn(
      api: KmApi(server.client, proofs: KmDpop(deviceKey)),
      server: FakeKemlockServer.url,
      device: _device,
      opaque: FakeKmOpaque(),
      deviceKey: const {'protection': 'software'},
      argon2: cheapArgon2,
    ),
    key: deviceKey,
  );
}

Uri _redirect(String state, {String code = 'code-1'}) => Uri.parse('kemlock://sso?code=$code&state=$state');

void main() {
  test('the PKCE challenge is RFC 7636\'s: the unpadded base64url SHA-256 of the verifier', () {
    expect(ssoChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  group('SSO through the system browser', () {
    test('signs in with the code and the verifier, and leaves the account to be opened', () async {
      final server = FakeKemlockAccountServer();
      final (:signIn, key: _) = _signIn(server);
      final browser = _Browser((url, state) => _redirect(state));
      final step = await kmSsoSignIn(signIn, browser, random: (n) => Uint8List.fromList(List.generate(n, (i) => i + n)));
      final done = step as KmSignedIn;
      expect(done.account, isNull);
      expect(done.session.userId, server.userId);
      expect(done.session.deviceKey, {'protection': 'software'});
      expect(browser.opened.single.host, 'idp.example.com');
      expect(browser.states.single, server.ssoStarts.single['state'], reason: 'the state the phone made is the one sent to start');
      expect(server.devicesSeen.single['name'], 'Kemlock on Pixel 9');
    });

    test('start carries a challenge but never the verifier, and finish carries the verifier but never the challenge', () async {
      final server = FakeKemlockAccountServer();
      final (:signIn, key: _) = _signIn(server);
      await kmSsoSignIn(signIn, _Browser((url, state) => _redirect(state)));
      final start = server.requests.firstWhere((r) => r.url.path.endsWith('/auth/sso/start'));
      final finish = server.requests.lastWhere((r) => r.url.path.endsWith('/auth/sso/finish'));
      final startBody = jsonDecode(start.body) as Map<String, Object?>;
      final finishBody = jsonDecode(finish.body) as Map<String, Object?>;
      expect(startBody.keys, unorderedEquals(['challenge', 'state']));
      expect(finishBody.keys, unorderedEquals(['code', 'verifier', 'device']));
      expect(ssoChallenge(finishBody['verifier']! as String), startBody['challenge']);
    });

    test('a cancel leaves the phone signed out: nothing is finished or kept', () async {
      final server = FakeKemlockAccountServer();
      final (:signIn, key: _) = _signIn(server);
      await expectLater(
        kmSsoSignIn(signIn, _Browser((url, state) => null)),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.cancelled)),
      );
      expect(server.requests.where((r) => r.url.path.endsWith('/auth/sso/finish')), isEmpty);
    });

    test('a redirect for another sign-in is refused before anything is sent to finish', () async {
      final server = FakeKemlockAccountServer();
      final (:signIn, key: _) = _signIn(server);
      await expectLater(
        kmSsoSignIn(signIn, _Browser((url, state) => _redirect('another-sign-in-state-0000000'))),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.ssoFailed)),
      );
      expect(server.requests.where((r) => r.url.path.endsWith('/auth/sso/finish')), isEmpty);
    });

    test('a redirect to another scheme or host, or carrying the provider\'s error, is refused', () async {
      for (final make in <Uri Function(String)>[
        (state) => Uri.parse('https://sso?code=code-1&state=$state'),
        (state) => Uri.parse('kemlock://other?code=code-1&state=$state'),
        (state) => Uri.parse('kemlock://sso?error=access_denied&state=$state'),
        (state) => Uri.parse('kemlock://sso?state=$state'),
      ]) {
        final server = FakeKemlockAccountServer();
        final (:signIn, key: _) = _signIn(server);
        await expectLater(
          kmSsoSignIn(signIn, _Browser((url, state) => make(state))),
          throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.ssoFailed)),
        );
      }
    });

    test('a provider address that is not https opens nothing', () async {
      final server = FakeKemlockAccountServer()..ssoUrl = 'http://idp.example.com/authorize';
      final (:signIn, key: _) = _signIn(server);
      final browser = _Browser((url, state) => _redirect(state));
      await expectLater(
        kmSsoSignIn(signIn, browser),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.unsupported)),
      );
      expect(browser.opened, isEmpty);
    });

    test('a browser that can\'t open is an SSO failure', () async {
      final server = FakeKemlockAccountServer();
      final (:signIn, key: _) = _signIn(server);
      await expectLater(
        kmSsoSignIn(signIn, _FailingBrowser()),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.ssoFailed)),
      );
    });
  });

  group('the server holds the flow to the verifier and the device key', () {
    Future<(FakeKemlockAccountServer, KmAuthApi, SoftwareDeviceKey)> started() async {
      final server = FakeKemlockAccountServer();
      final key = SoftwareDeviceKey.generate();
      final auth = KmAuthApi(KmApi(server.client, proofs: KmDpop(key)));
      await auth.ssoStart(FakeKemlockServer.url, ssoChallenge('verifier-0123456789012345678901234567890123456'), 'state-0123456789abcdef');
      return (server, auth, key);
    }

    test('the right code, verifier and key finish', () async {
      final (_, auth, _) = await started();
      final answer = await auth.ssoFinish(FakeKemlockServer.url, 'code-1', 'verifier-0123456789012345678901234567890123456', _device);
      expect(answer.grant, isNotNull);
    });

    test('a code without the verifier is refused', () async {
      final (_, auth, _) = await started();
      await expectLater(
        auth.ssoFinish(FakeKemlockServer.url, 'code-1', 'another-verifier-0000000000000000000000000000', _device),
        throwsA(isA<KmError>()),
      );
    });

    test('a code with another device key is refused, though the verifier is right', () async {
      final (server, _, _) = await started();
      final thief = KmAuthApi(KmApi(server.client, proofs: KmDpop(SoftwareDeviceKey.generate())));
      await expectLater(
        thief.ssoFinish(FakeKemlockServer.url, 'code-1', 'verifier-0123456789012345678901234567890123456', _device),
        throwsA(isA<KmError>()),
      );
    });
  });
}

class _FailingBrowser implements KmBrowserAuth {
  @override
  Future<Uri?> authenticate(Uri url, {required String state}) async => throw const KmBrowserFailure('no browser');

  @override
  Future<void> cancel() async {}
}
