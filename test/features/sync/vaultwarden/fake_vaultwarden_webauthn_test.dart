@TestOn('vm')
library;

// The fake server's security key step (provider 7): what it gives and what
// it refuses, as a real Vaultwarden was seen to
// (test/fixtures/vaultwarden/webauthn/README.md).
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_webauthn.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';

const _device = VwDevice(id: 'device', type: 0);

/// A software credential registered with the fake account.
class _Key {
  _Key(FakeVaultwarden server) {
    server.registerKey(id, pair.point);
  }

  final pair = newP256KeyPair();
  final id = Uint8List.fromList(List.filled(32, 0x51));
  int counter = 0;

  /// The token for [challenge], as a key and Kemlock would make it.
  String token(
    String challenge, {
    String origin = 'https://vault.example.com',
    String rpId = 'vault.example.com',
    int? count,
    int flags = 0x01,
    bool sign = true,
  }) {
    final clientData = vwKeyClientData(challenge: challenge, origin: origin);
    final n = count ?? ++counter;
    final authenticatorData = Uint8List.fromList([
      ...sha256.convert(utf8.encode(rpId)).bytes,
      flags,
      n >> 24 & 0xff,
      n >> 16 & 0xff,
      n >> 8 & 0xff,
      n & 0xff,
    ]);
    final signed = Uint8List.fromList([...authenticatorData, ...vwKeyClientDataHash(clientData)]);
    final signature = es256Sign(sign ? pair : newP256KeyPair(), signed);
    return vwKeyToken(credentialId: id, authenticatorData: authenticatorData, clientData: clientData, signature: signature);
  }
}

void main() {
  late FakeVaultwarden server;
  late VwApi api;
  late _Key key;
  late String hash;

  setUp(() async {
    server = FakeVaultwarden();
    await server.allowSignIn();
    api = fakeApi(server);
    key = _Key(server);
    const derive = CheapKeyDerivation();
    hash = await derive.passwordHash(await derive.masterKey(server.password, server.email, fakeKdf), server.password);
  });

  Future<VwLogin> signIn({String? token, bool remember = false, String? rememberToken}) => api.signIn(
    FakeVaultwarden.url,
    email: server.email,
    passwordHash: hash,
    device: _device,
    step: token == null ? null : VwSecondStep(provider: VwTwoFactor.webauthn, code: token, remember: remember),
    rememberToken: rememberToken,
  );

  /// Asks for the step and returns the challenge the server gave.
  Future<String> challenge() async {
    final needed = await signIn() as VwSecondStepNeeded;
    return VwKeyChallenge.parse(needed.details['7'], receivedAt: DateTime.utc(2026))!.challenge;
  }

  Matcher refused() =>
      throwsA(isA<VwError>().having((e) => e.problem, 'problem', VwProblem.code).having((e) => e.message, 'message', 'Webauthn'));

  test('gives a challenge shaped as the real server\'s', () async {
    final needed = await signIn() as VwSecondStepNeeded;

    expect(needed.providers, [VwTwoFactor.webauthn]);
    final options = needed.details['7']! as Map<String, Object?>;
    expect(options.keys, ['allowCredentials', 'challenge', 'extensions', 'rpId', 'timeout', 'userVerification']);
    expect(options['rpId'], 'vault.example.com');
    expect(options['timeout'], 60000);
    expect(options['userVerification'], 'discouraged');
    expect(options['extensions'], {'appid': 'https://vault.example.com/app-id.json'});
    expect(options['allowCredentials'], [
      {'id': b64url(key.id), 'type': 'public-key'},
    ]);
  });

  test('a correct token signs in', () async {
    final login = await signIn(token: key.token(await challenge()));

    expect(login, isA<VwSignedIn>());
    expect(server.webauthnRefusal, isNull);
    expect(server.webauthnKeys.single.counter, 1);
  });

  test('takes the origin\'s host in any case, as the real server', () async {
    expect(await signIn(token: key.token(await challenge(), origin: 'https://VAULT.example.com')), isA<VwSignedIn>());
  });

  test('refuses another origin', () async {
    await expectLater(signIn(token: key.token(await challenge(), origin: 'https://vault.example.org')), refused());
    expect(server.webauthnRefusal, 'another origin');
    await expectLater(signIn(token: key.token(await challenge(), origin: 'http://vault.example.com')), refused());
    expect(server.webauthnRefusal, 'another origin');
  });

  test('refuses another port', () async {
    await expectLater(signIn(token: key.token(await challenge(), origin: 'https://vault.example.com:8443')), refused());
    expect(server.webauthnRefusal, 'another origin');

    // And the other way round: a server on a port takes only that port
    server.domain = 'https://vault.example.com:8443';
    await expectLater(signIn(token: key.token(await challenge())), refused());
    expect(await signIn(token: key.token(await challenge(), origin: 'https://vault.example.com:8443')), isA<VwSignedIn>());
  });

  test('refuses an answer to an older challenge', () async {
    final stale = await challenge();
    await challenge();

    await expectLater(signIn(token: key.token(stale)), refused());
    expect(server.webauthnRefusal, 'another challenge');
  });

  test('refuses a challenge used twice', () async {
    final token = key.token(await challenge());
    await signIn(token: token);

    await expectLater(signIn(token: token), refused());
    expect(server.webauthnRefusal, "Can't recover login challenge");
  });

  test('a refused answer uses the challenge up', () async {
    final asked = await challenge();
    await expectLater(signIn(token: key.token(asked, origin: 'https://vault.example.org')), refused());

    await expectLater(signIn(token: key.token(asked)), refused());
    expect(server.webauthnRefusal, "Can't recover login challenge");
  });

  test('refuses a counter that did not grow', () async {
    await signIn(token: key.token(await challenge(), count: 5));

    await expectLater(signIn(token: key.token(await challenge(), count: 5)), refused());
    expect(server.webauthnRefusal, 'the counter did not grow');
    await expectLater(signIn(token: key.token(await challenge(), count: 4)), refused());
    expect(await signIn(token: key.token(await challenge(), count: 6)), isA<VwSignedIn>());
  });

  test('refuses a bad signature, another rpId and an absent user', () async {
    await expectLater(signIn(token: key.token(await challenge(), sign: false)), refused());
    expect(server.webauthnRefusal, 'bad signature');
    await expectLater(signIn(token: key.token(await challenge(), rpId: 'example.com')), refused());
    expect(server.webauthnRefusal, 'another rpId');
    await expectLater(signIn(token: key.token(await challenge(), flags: 0)), refused());
    expect(server.webauthnRefusal, 'the user was not present');
  });

  test('refuses a credential it does not know, and a token that is no JSON', () async {
    final other = _Key(FakeVaultwarden());
    final unknown = (jsonDecode(other.token(await challenge())) as Map<String, Object?>)..['rawId'] = b64url(List.filled(32, 9));
    await expectLater(signIn(token: jsonEncode(unknown)), refused());
    expect(server.webauthnRefusal, 'Credential not present');

    await challenge();
    await expectLater(signIn(token: '123456'), refused());
    expect(server.webauthnRefusal, startsWith('malformed token'));
  });

  test('without its own address asks about localhost, as the real server', () async {
    server.domain = null;

    final needed = await signIn() as VwSecondStepNeeded;

    final options = needed.details['7']! as Map<String, Object?>;
    expect(options['rpId'], 'localhost');
    expect(options['extensions'], {'appid': 'http://localhost/app-id.json'});
  });

  test('lists the method without a challenge when it has none to give', () async {
    server.webauthnChallenges = false;

    final needed = await signIn() as VwSecondStepNeeded;

    expect(needed.providers, [VwTwoFactor.webauthn]);
    expect(needed.details['7'], isNull);
    expect(server.webauthnChallenge, isNull);
  });

  test('remembers the device when asked, and then skips the step', () async {
    final login = await signIn(token: key.token(await challenge()), remember: true) as VwSignedIn;
    expect(login.rememberToken, isNotNull);

    expect(await signIn(rememberToken: login.rememberToken), isA<VwSignedIn>());
    // A token it never gave is answered as no step at all
    expect(await signIn(rememberToken: 'made up'), isA<VwSecondStepNeeded>());

    final forgetful = await signIn(token: key.token(await challenge())) as VwSignedIn;
    expect(forgetful.rememberToken, isNull);
  });
}
