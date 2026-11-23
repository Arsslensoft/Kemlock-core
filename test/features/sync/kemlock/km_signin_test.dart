@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/password_wrap.dart';
import 'package:kemlock_core/crypto/account/prf_wrap.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_signin.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

const _password = 'correct horse battery staple';
const _email = 'me@example.com';
const _device = KmDeviceInfo(name: 'Kemlock on Pixel 9', kind: 'kemlock-android');

/// Bitwarden's master key without its cost, as the sign-in's `bitwardenKey` takes.
Future<Uint8List> _cheapBitwardenKey(String password, String email, BwKdf kdf) async =>
    Uint8List.fromList(sha256.convert(utf8.encode('$password|$email|${kdf.iterations}')).bytes);

late KmTestAccount _account;

({KmSignIn signIn, SoftwareDeviceKey key}) _signIn(
  FakeKemlockAccountServer server, {
  bool opaqueSeen = false,
  Future<void> Function()? remember,
  KmDeviceInfo device = _device,
}) {
  final key = SoftwareDeviceKey.generate();
  final signIn = KmSignIn(
    api: KmApi(server.client, proofs: KmDpop(key)),
    server: FakeKemlockServer.url,
    device: device,
    opaque: FakeKmOpaque(),
    deviceKey: const {'protection': 'software'},
    opaqueSeen: opaqueSeen,
    rememberOpaque: remember,
    argon2: cheapArgon2,
    bitwardenKey: _cheapBitwardenKey,
  );
  return (signIn: signIn, key: key);
}

Future<FakeKemlockAccountServer> _opaqueServer() async {
  final server = FakeKemlockAccountServer(userId: _account.userId);
  await server.registerOpaque(_password, _account);
  return server;
}

/// A Compatible account that has not enrolled OPAQUE: Bitwarden's KDF, the hash it takes, and the user key it hands back.
Future<FakeKemlockAccountServer> _compatibleServer({Map<String, Object?>? material}) async {
  final server = FakeKemlockAccountServer(userId: _account.userId);
  const kdf = BwKdf(type: BwKdfType.pbkdf2, iterations: 600000);
  final master = await _cheapBitwardenKey(_password, _email, kdf);
  server
    ..bitwarden = kdf.toJson()
    ..bitwardenHashExpected = await bwMasterPasswordHash(master, _password)
    ..bitwardenUserKey = (await bwEncrypt(_account.root, bwStretch(master))).toString()
    ..material = material ?? {'keyVersion': 1};
  return server;
}

/// The paths the server was sent requests for, in order.
List<String> _paths(FakeKemlockServer server) => [for (final request in server.requests) request.url.path.replaceFirst('/kem/v1', '')];

KmSignedIn _signedIn(KmSignInStep step) => step as KmSignedIn;

void main() {
  setUpAll(() async {
    _account = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  group('the ways in', () {
    test('reads the server\'s config, then the email\'s ways', () async {
      final server = await _opaqueServer();
      final methods = await _signIn(server).signIn.ways(_email);
      expect(methods.password, isTrue);
      expect(methods.sso, isFalse);
      expect(_paths(server), ['/config', '/auth/methods']);
    });

    test('a server that is not a Kemlock Server is an address problem, and the email is never sent', () async {
      final server = await _opaqueServer();
      server.respond = (request) async => http.Response('{"hello":"world"}', 200, headers: {'content-type': 'application/json'});
      await expectLater(
        _signIn(server).signIn.ways(_email),
        throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.address)),
      );
      expect(server.requests.map((r) => r.url.path), ['/kem/v1/config']);
    });

    test('SSO and its provider come from the methods answer', () async {
      final server = await _opaqueServer();
      server.methods = {
        'methods': ['sso', 'password'],
        'sso': {'providerName': 'Example Co'},
        'ssoRequired': true,
      };
      final methods = await _signIn(server).signIn.ways(_email);
      expect(methods.sso, isTrue);
      expect(methods.ssoProvider, 'Example Co');
      expect(methods.ssoRequired, isTrue);
    });
  });

  group('the master password through OPAQUE', () {
    test('signs in, opens the root key, and no request carried the password or a hash', () async {
      final server = await _opaqueServer();
      final remembered = <int>[];
      final (:signIn, key: _) = _signIn(server, remember: () async => remembered.add(1));
      final done = _signedIn(await signIn.password(_email, _password));
      expect(done.account!.rootKey, _account.root);
      expect(done.account!.accountId, _account.userId);
      expect(done.account!.opaqueEnrolled, isTrue);
      expect(done.session.userId, _account.userId);
      expect(done.session.deviceKey, {'protection': 'software'});
      expect(done.bitwardenHashSent, isFalse);
      expect(remembered, [1], reason: 'the phone records that it saw OPAQUE work');
      // The salt and settings come first, so the master key exists before KE1
      expect(_paths(server).take(2), ['/auth/prelogin', '/auth/opaque/start']);
      expect(server.bitwardenHashes, isEmpty);
      for (final request in server.requests) {
        expect(request.body, isNot(contains(_password)));
        expect(request.url.path, isNot('/kem/v1/auth/bitwarden'));
      }
    });

    test('a wrong password is "wrong email or password", with no second try for the server to count', () async {
      final server = await _opaqueServer();
      await expectLater(
        _signIn(server).signIn.password(_email, 'not the password'),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.wrongPassword)),
      );
      expect(server.opaqueStarts, 1);
      expect(_paths(server), isNot(contains('/auth/opaque/finish')), reason: 'the phone stops at the server\'s proof');
    });

    test('a space that requires SSO is not a wrong password: the 403 comes after the proof, and says SSO', () async {
      final server = await _opaqueServer();
      server.ssoRequiredSpace = '5c9d0e1f-1111-4222-8333-444455556666';
      Object? caught;
      try {
        await _signIn(server).signIn.password(_email, _password);
      } on KmError catch (e) {
        caught = e;
      }

      expect(caught, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.ssoRequired));
      expect((caught! as KmError).spaceId, '5c9d0e1f-1111-4222-8333-444455556666');
      expect(_paths(server), contains('/auth/opaque/finish'), reason: 'only after the caller proved who they are');
      final failure = kmSignInFailure(caught);
      expect(failure, isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.ssoRequired));
      expect((failure as KmSignInError).detail, '5c9d0e1f-1111-4222-8333-444455556666');
    });

    test('any other failure is left as it is', () {
      const other = KmError(KmProblem.auth, status: 403);
      expect(kmSignInFailure(other), same(other));
    });

    test('an Argon2id memory of 2 GiB stops before any work, and before anything is sent to OPAQUE', () async {
      final server = await _opaqueServer();
      server.memoryKib = 2 * 1024 * 1024;
      await expectLater(
        _signIn(server).signIn.password(_email, _password),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.kdfBounds)),
      );
      expect(_paths(server), ['/auth/prelogin']);
    });

    test('a single pass or too many lanes is outside the bounds too', () async {
      for (final (passes, lanes) in [(1, 4), (11, 4), (3, 0), (3, 17)]) {
        final server = await _opaqueServer();
        server
          ..iterations = passes
          ..parallelism = lanes;
        await expectLater(
          _signIn(server).signIn.password(_email, _password),
          throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.kdfBounds)),
          reason: 'passes $passes, lanes $lanes',
        );
      }
    });

    test('the device the server registers carries the Vaultwarden device identifier when there is one', () async {
      final server = await _opaqueServer();
      const withId = KmDeviceInfo(
        name: 'Kemlock on Pixel 9',
        kind: 'kemlock-android',
        bitwardenDeviceId: '11111111-2222-4333-8444-555555555555',
      );
      await _signIn(server, device: withId).signIn.password(_email, _password);
      expect(server.devicesSeen.single['bitwardenDeviceIdentifier'], '11111111-2222-4333-8444-555555555555');
      expect(server.devicesSeen.single['name'], 'Kemlock on Pixel 9');

      final plain = await _opaqueServer();
      await _signIn(plain).signIn.password(_email, _password);
      expect(plain.devicesSeen.single.containsKey('bitwardenDeviceIdentifier'), isFalse);
    });
  });

  group('a second step', () {
    test('an authenticator code finishes the sign-in', () async {
      final server = await _opaqueServer();
      server.secondStep = ['totp'];
      final (:signIn, key: _) = _signIn(server);
      final step = await signIn.password(_email, _password);
      expect(step, isA<KmSecondStep>());
      expect((step as KmSecondStep).methods, ['totp']);
      final done = _signedIn(await signIn.secondStep('totp', '123456'));
      expect(done.account!.rootKey, _account.root);
    });

    test('a wrong code is refused by the server', () async {
      final server = await _opaqueServer();
      server.secondStep = ['totp'];
      final (:signIn, key: _) = _signIn(server);
      await signIn.password(_email, _password);
      await expectLater(signIn.secondStep('totp', '000000'), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.auth)));
    });

    test('methods the phone can\'t answer are named; only Duo sends the person to the web vault', () async {
      final server = await _opaqueServer();
      server.secondStep = ['totp', 'duo'];
      final step = await _signIn(server).signIn.password(_email, _password);
      expect((step as KmSecondStep).unsupported, ['duo']);

      final duoOnly = await _opaqueServer();
      duoOnly.secondStep = ['duo'];
      await expectLater(
        _signIn(duoOnly).signIn.password(_email, _password),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.webVaultOnly)),
      );
    });
  });

  group('a Compatible account', () {
    test('learns it has no OPAQUE record only when OPAQUE fails, then sends the Bitwarden hash once and enrols', () async {
      final server = await _compatibleServer();
      final remembered = <int>[];
      final (:signIn, key: _) = _signIn(server, remember: () async => remembered.add(1));
      final done = _signedIn(await signIn.password(_email, _password));
      expect(server.bitwardenHashes, hasLength(1));
      expect(done.bitwardenHashSent, isTrue);
      expect(done.enrolledOpaque, isTrue);
      expect(done.account!.opaqueEnrolled, isTrue);
      // The account stays Compatible: the root key is the Bitwarden user key, so it doesn't change
      expect(done.account!.rootKey, _account.root);
      expect(server.enrolments, hasLength(1));
      expect(server.opaqueStarts, 2, reason: 'one that failed, then one through OPAQUE after enrolment, with no second prompt');
      expect(remembered, [1]);
      expect(server.opaqueRecord, isNotNull);
      final paths = _paths(server);
      expect(paths.indexOf('/auth/opaque/start'), lessThan(paths.indexOf('/identity/accounts/prelogin')));
      expect(paths.indexOf('/identity/accounts/prelogin'), lessThan(paths.indexOf('/auth/bitwarden/start')));
    });

    test('the root key is wrapped under the new master key and the export key, with a signed bundle and sealed keys', () async {
      final server = await _compatibleServer();
      final done = _signedIn(await _signIn(server).signIn.password(_email, _password));
      final body = server.enrolments.single;
      expect(body['ticket'], 'ticket-1');
      expect(body.keys, containsAll(['upload', 'kdf', 'wrappedRootKey', 'publicBundle', 'bundleSignature', 'sealedPrivateKeys']));
      final kdf = body['kdf']! as Map<String, Object?>;
      final master = await deriveMasterKey(
        _password,
        b64urlDecode(kdf['salt']! as String),
        settings: Argon2idSettings(
          memoryKiB: kdf['memoryKib']! as int,
          iterations: kdf['iterations']! as int,
          parallelism: kdf['parallelism']! as int,
        ),
        runner: cheapArgon2,
      );
      final root = await unwrapRootWithPassword(
        masterKey: master,
        exportKey: FakeKmOpaque.exportKey(master),
        accountId: uuidBytes(_account.userId),
        keyVersion: 1,
        wrapped: b64urlDecode(body['wrappedRootKey']! as String),
      );
      expect(root, _account.root);
      expect(done.account!.accountId, _account.userId);
      expect(done.account!.kx1PublicKey, hasLength(1600));
    });

    test('a second step owed by the enrolment is answered, and its code goes with the last message', () async {
      final server = await _compatibleServer()
        ..enrolTwoFactor = ['totp'];
      final (:signIn, key: _) = _signIn(server);
      final step = await signIn.password(_email, _password);
      expect((step as KmSecondStep).methods, ['totp']);
      expect(server.enrolments, isEmpty, reason: 'nothing is finished before the code');
      final done = _signedIn(await signIn.secondStep('totp', '123456'));
      expect(server.enrolments.single['twoFactorCode'], '123456');
      expect(done.account!.rootKey, _account.root);
    });

    test('a PBKDF2 cost of 1 stops before anything derived from the password is sent', () async {
      final server = await _compatibleServer();
      server.bitwarden = {'kdf': 0, 'kdfIterations': 1};
      await expectLater(
        _signIn(server).signIn.password(_email, _password),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.kdfBounds)),
      );
      expect(_paths(server), isNot(contains('/auth/bitwarden/start')));
      expect(server.bitwardenHashes, isEmpty);
    });

    test('a wrong password is refused by the start route, once, and nothing is enrolled', () async {
      final server = await _compatibleServer();
      await expectLater(
        _signIn(server).signIn.password(_email, 'not it'),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.wrongPassword)),
      );
      expect(server.bitwardenHashes, hasLength(1));
      expect(server.enrolments, isEmpty);
    });

    test('a server without the bitwarden-enrol feature is never sent the hash', () async {
      final server = await _compatibleServer();
      server.features = ['opaque', 'dpop', 'sync'];
      final (:signIn, key: _) = _signIn(server);
      await signIn.ways(_email);
      await expectLater(
        signIn.password(_email, _password),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.wrongPassword)),
      );
      expect(server.bitwardenPrelogins, 0);
      expect(server.bitwardenHashes, isEmpty);
    });
  });

  group('no downgrade', () {
    test('a server that claims "not enrolled" after an OPAQUE sign-in gets no hash, and the phone says it may be impersonated', () async {
      final server = await _opaqueServer();
      var seen = false;
      await _signIn(server, remember: () async => seen = true).signIn.password(_email, _password);
      expect(seen, isTrue);

      // The server now behaves as if the account had no OPAQUE record, and offers the hash route
      const kdf = BwKdf(type: BwKdfType.pbkdf2, iterations: 600000);
      server
        ..opaqueRecord = null
        ..material = {'keyVersion': 1}
        ..bitwarden = kdf.toJson()
        ..bitwardenHashExpected = await bwMasterPasswordHash(await _cheapBitwardenKey(_password, _email, kdf), _password);
      server.requests.clear();
      await expectLater(
        _signIn(server, opaqueSeen: seen).signIn.password(_email, _password),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.downgrade)),
      );
      expect(server.bitwardenHashes, isEmpty);
      expect(server.bitwardenPrelogins, 0, reason: 'not even the Bitwarden cost was read, and nothing was derived');
      expect(_paths(server), isNot(contains('/auth/bitwarden/start')));
    });

    test('the same claim before the phone saw OPAQUE takes the hash route, which is the point of the record', () async {
      final server = await _compatibleServer();
      await _signIn(server).signIn.password(_email, _password);
      expect(server.bitwardenHashes, hasLength(1));
    });

    test('a record made in this very attempt counts too: enrolment closes the route', () async {
      final server = await _compatibleServer();
      final (:signIn, key: _) = _signIn(server);
      await signIn.password(_email, _password);
      expect(signIn.opaqueConfirmed, isTrue);
    });
  });

  group('opening an account that signed in without opening', () {
    Future<({KmSignIn signIn, KmSignedIn done, FakeKemlockAccountServer server})> external() async {
      final server = FakeKemlockAccountServer(userId: _account.userId)..material = _account.material();
      final (:signIn, :key) = _signIn(server);
      final answer = KmSignInAnswer.fromJson({
        'status': 'signed_in',
        'tokens': server.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk)),
      }, DateTime.now().millisecondsSinceEpoch);
      final done = _signedIn(await signIn.continueWith(answer, email: _email));
      return (signIn: signIn, done: done, server: server);
    }

    test('SSO and passkey sign-ins hold no account until it is opened', () async {
      final (:done, signIn: _, server: _) = await external();
      expect(done.account, isNull);
    });

    test('a passkey\'s PRF copy opens it, and another output, credential or key version does not', () async {
      final credential = Uint8List.fromList(List.generate(16, (i) => 200 - i));
      final prf = Uint8List.fromList(List.generate(32, (i) => i));
      final wrapped = await wrapRootWithPrf(
        prfOutput: prf,
        credentialId: credential,
        accountId: uuidBytes(_account.userId),
        keyVersion: 1,
        rootKey: _account.root,
      );
      final wrap = KmPrfWrap(wrapped: wrapped, keyVersion: 1);
      final (:signIn, :done, server: _) = await external();
      final opened = await signIn.openWithPrf(done.session, prf, credential, wrap);
      expect(opened!.rootKey, _account.root);
      await expectLater(
        signIn.openWithPrf(done.session, Uint8List(32), credential, wrap),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.unreadable)),
      );
      await expectLater(
        signIn.openWithPrf(done.session, prf, Uint8List.fromList([1, 2, 3]), wrap),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.unreadable)),
        reason: 'a copy opens only for the credential that made it',
      );
      expect(
        await signIn.openWithPrf(done.session, prf, credential, KmPrfWrap(wrapped: wrapped, keyVersion: 2)),
        isNull,
        reason: 'a copy for another key version is not the account\'s root',
      );
    });

    test('a root key from an approval opens it', () async {
      final (:signIn, :done, server: _) = await external();
      final opened = await signIn.openWithRoot(done.session, _account.root);
      expect(opened.accountId, _account.userId);
    });

    test('keys that aren\'t the account\'s own are refused: another root key, or a bundle with a changed signature', () async {
      final (:signIn, :done, :server) = await external();
      await expectLater(
        signIn.openWithRoot(done.session, Uint8List.fromList(List.filled(64, 9))),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.unreadable)),
      );
      final broken = Uint8List.fromList(_account.signature)..[10] ^= 1;
      server.material = {..._account.material(), 'bundleSignature': b64urlEncode(broken)};
      await expectLater(
        signIn.openWithRoot(done.session, _account.root),
        throwsA(isA<KmSignInError>().having((e) => e.issue, 'issue', KmSignInIssue.unreadable)),
      );
    });
  });

  group('KmAccount', () {
    test('round trips through its sealed JSON, keeping keys it does not know', () async {
      final server = await _opaqueServer();
      final done = _signedIn(await _signIn(server).signIn.password(_email, _password));
      final json = {...done.account!.toJson(), 'later': 1};
      final again = KmAccount.fromJson(jsonDecode(jsonEncode(json)) as Map<String, Object?>);
      expect(again.rootKey, _account.root);
      expect(again.opaqueEnrolled, isTrue);
      expect(again.toJson()['later'], 1);
      expect(storedOpaqueSeen(json), isTrue);
      expect(storedOpaqueSeen({'opaqueEnrolled': false}), isFalse);
      expect(storedOpaqueSeen(null), isFalse);
    });
  });
}
