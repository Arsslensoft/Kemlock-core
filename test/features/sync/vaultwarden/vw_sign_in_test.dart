@TestOn('vm')
library;

// When a security key is offered as a Vaultwarden account's second step,
// and asking the server for a new challenge without deriving keys again.
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_backend.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';

/// Counts how many times the master key is derived.
class _CountingDerivation extends CheapKeyDerivation {
  int masterKeys = 0;

  @override
  Future<Uint8List> masterKey(String password, String email, BwKdf kdf) {
    masterKeys++;
    return super.masterKey(password, email, kdf);
  }
}

void main() {
  late FakeVaultwarden server;
  late _CountingDerivation derive;
  late DateTime now;

  setUp(() async {
    server = FakeVaultwarden();
    await server.allowSignIn();
    derive = _CountingDerivation();
    now = DateTime.utc(2026, 11, 16, 9);
  });

  Future<VwAccountSetup> setup({bool canReachKey = true, String address = 'https://vault.example.com'}) async {
    final setup = VwAccountSetup(VwApi(server.newClient()), derive: derive, clock: () => now)..canReachKey = canReachKey;
    await setup.connect(address, server.email);
    return setup;
  }

  Future<VwSignInNeedsStep> needs(VwAccountSetup setup) async =>
      await setup.signIn(server.password, deviceId: 'device') as VwSignInNeedsStep;

  void registerKey() => server.registerKey(List.filled(32, 0x51), newP256KeyPair().point);

  test('offers a security key with a challenge and a phone that reaches one', () async {
    registerKey();

    final step = await needs(await setup());

    expect(step.keyOffer, VwKeyOffer.offered);
    expect(step.supported, [VwTwoFactor.webauthn]);
    expect(step.keyChallenge!.rpId, 'vault.example.com');
    expect(step.keyChallenge!.challenge, server.webauthnChallenge);
    expect(step.keyChallenge!.receivedAt, now);
  });

  test('does not offer it on a phone that reaches no key', () async {
    registerKey();

    final step = await needs(await setup(canReachKey: false));

    expect(step.keyOffer, VwKeyOffer.noReach);
    expect(step.supported, isEmpty);
  });

  test('does not offer it when the server gave no challenge', () async {
    registerKey();
    server.webauthnChallenges = false;

    final step = await needs(await setup());

    expect(step.keyOffer, VwKeyOffer.noChallenge);
    expect(step.keyChallenge, isNull);
    expect(step.supported, isEmpty);
  });

  test('takes a challenge for localhost, from a server without its own address, for none', () async {
    registerKey();
    server.domain = null;

    final step = await needs(await setup());

    expect(step.keyOffer, VwKeyOffer.noChallenge);
    expect(step.supported, isEmpty);
  });

  test('keeps a challenge for localhost when localhost is the address', () async {
    registerKey();
    server.domain = 'https://localhost:18443';

    final step = await needs(await setup(address: 'https://localhost:18443'));

    expect(step.keyOffer, VwKeyOffer.offered);
    expect(step.keyChallenge!.rpId, 'localhost');
  });

  test('keeps a challenge for another name, which the key step explains', () async {
    registerKey();

    final step = await needs(await setup(address: 'https://192.168.1.20'));

    expect(step.keyOffer, VwKeyOffer.offered);
    expect(step.keyChallenge!.rpId, 'vault.example.com');
  });

  test('says a security key is not a method of an account without one', () async {
    server.twoFactor = {VwTwoFactor.authenticator};

    final step = await needs(await setup());

    expect(step.keyOffer, VwKeyOffer.notAMethod);
    expect(step.supported, [VwTwoFactor.authenticator]);
  });

  test('offers the code methods first, then the key', () async {
    registerKey();
    server.twoFactor = {VwTwoFactor.webauthn, VwTwoFactor.yubikey, VwTwoFactor.email, VwTwoFactor.authenticator, VwTwoFactor.duo};

    final step = await needs(await setup());

    expect(step.supported, [VwTwoFactor.authenticator, VwTwoFactor.email, VwTwoFactor.yubikey, VwTwoFactor.webauthn]);
    expect(step.emailHint, 'm***@example.com');
  });

  test('a second try is one token request without a step, and no second key derivation', () async {
    registerKey();
    final account = await setup();
    final first = await needs(account);
    final requests = server.requests.length;
    now = now.add(const Duration(minutes: 2));

    final again = await account.askStepAgain(server.password, deviceId: 'device') as VwSignInNeedsStep;

    expect(derive.masterKeys, 1);
    final sent = server.requests.sublist(requests);
    expect(sent.map((request) => request.url.path), ['/identity/connect/token']);
    final form = Uri.splitQueryString(sent.single.body);
    expect(form.containsKey('twoFactorToken'), isFalse);
    expect(form.containsKey('twoFactorProvider'), isFalse);
    expect(again.keyChallenge!.challenge, isNot(first.keyChallenge!.challenge));
    expect(again.keyChallenge!.challenge, server.webauthnChallenge);
    expect(again.keyChallenge!.receivedAt, now);
    expect(first.keyChallenge!.isFresh(now), isFalse);
    expect(again.keyChallenge!.isFresh(now), isTrue);
  });
}
