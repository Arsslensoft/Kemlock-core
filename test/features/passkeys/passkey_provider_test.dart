// What a passkey provider does with a request: the relying party checked against the origin, a passkey made and the
// response a site gets for it, and a sign-in, checked against the fixture the phone's providers share.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/core/public_suffix_list.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/passkeys/passkey_bytes.dart';
import 'package:kemlock_core/features/passkeys/passkey_provider.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:test/test.dart';

const _list = '''
// ===BEGIN ICANN DOMAINS===
com
io
net
co.uk
*.ck
!www.ck
// ===BEGIN PRIVATE DOMAINS===
github.io
herokuapp.com
''';

Matcher _fails(PasskeyFailure failure) => throwsA(isA<PasskeyRequestError>().having((e) => e.failure, 'failure', failure));

void main() {
  final suffixes = PublicSuffixList.parse(_list);
  final fixture = jsonDecode(File('test/fixtures/passkeys/passkeys.json').readAsStringSync()) as Map<String, Object?>;
  final credential = fixture['credential']! as Map<String, Object?>;
  final registration = fixture['registration']! as Map<String, Object?>;
  final assertion = fixture['assertion']! as Map<String, Object?>;
  final key = P256KeyPair(unb64(credential['d']! as String), unb64(credential['point']! as String));
  final credentialId = unb64url(credential['credentialId']! as String);
  const challenge = 'a2VtbG9jay1maXh0dXJlLWNoYWxsZW5nZQ';
  const origin = 'https://webauthn.io';

  Map<String, Object?> creation({Map<String, Object?>? rp, Object? params, Object? exclude, Object? extensions, Object? userId}) => {
    'rp': rp ?? {'id': 'webauthn.io', 'name': 'WebAuthn.io'},
    'user': {'id': userId ?? 'dXNlci1maXh0dXJlLTE', 'name': 'fixture@example.org', 'displayName': 'Fixture User'},
    'challenge': challenge,
    'pubKeyCredParams':
        params ??
        [
          {'type': 'public-key', 'alg': -7},
          {'type': 'public-key', 'alg': -257},
        ],
    'excludeCredentials': ?exclude,
    'extensions': ?extensions,
  };

  group('the relying party', () {
    String check(String origin, [String? rpId]) => checkPasskeyRp(origin: origin, rpId: rpId, suffixes: suffixes);

    test('is the origin’s host when the request names none', () {
      expect(check('https://www.Example.com'), 'www.example.com');
      expect(check('https://example.com:8443', ''), 'example.com');
    });

    test('may be the host itself, or a registrable domain above it, by whole labels', () {
      expect(check('https://login.example.com', 'login.example.com'), 'login.example.com');
      expect(check('https://login.example.com', 'example.com'), 'example.com');
      expect(check('https://a.b.example.co.uk', 'EXAMPLE.co.uk'), 'example.co.uk');
      expect(check('https://example.com', 'example.com.'), 'example.com');
    });

    test('is never another site’s, or a name that only ends alike', () {
      expect(() => check('https://example.com', 'evil.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', 'ample.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://notexample.com', 'example.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', 'login.example.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com.evil.io', 'example.com'), _fails(PasskeyFailure.security));
    });

    test('is never a public suffix', () {
      expect(() => check('https://example.com', 'com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.co.uk', 'co.uk'), _fails(PasskeyFailure.security));
      expect(() => check('https://alice.github.io', 'github.io'), _fails(PasskeyFailure.security));
      expect(() => check('https://shop.foo.ck', 'foo.ck'), _fails(PasskeyFailure.security));
      // A tenant's own domain is its own
      expect(check('https://alice.github.io', 'alice.github.io'), 'alice.github.io');
    });

    test('accepts only its own host without the list', () {
      expect(checkPasskeyRp(origin: 'https://login.example.com', rpId: 'login.example.com'), 'login.example.com');
      expect(() => checkPasskeyRp(origin: 'https://login.example.com', rpId: 'example.com'), _fails(PasskeyFailure.security));
    });

    test('needs a secure origin: https, or http on localhost', () {
      expect(check('http://localhost:3000'), 'localhost');
      expect(check('http://localhost', 'localhost'), 'localhost');
      expect(check('http://app.localhost'), 'app.localhost');
      expect(() => check('http://localhost.evil.com'), _fails(PasskeyFailure.security));
      expect(() => check('http://example.com'), _fails(PasskeyFailure.security));
      expect(() => check('ftp://example.com'), _fails(PasskeyFailure.security));
      expect(() => check('null'), _fails(PasskeyFailure.security));
      expect(() => check('chrome-extension://abcdef'), _fails(PasskeyFailure.security));
      expect(() => check('http://app.localhost', 'localhost'), _fails(PasskeyFailure.security));
    });

    test('is never an address', () {
      expect(() => check('https://192.168.0.1'), _fails(PasskeyFailure.security));
      expect(() => check('https://[::1]'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', '1.2.3.4'), _fails(PasskeyFailure.security));
    });

    test('is a plain domain', () {
      expect(() => check('https://example.com', 'exa mple.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', '.example.com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', 'example..com'), _fails(PasskeyFailure.security));
      expect(() => check('https://example.com', 'example.com/x'), _fails(PasskeyFailure.security));
    });
  });

  group('a creation request', () {
    test('is read from the options JSON', () {
      final request = CreationRequest.parse(
        creation(
          extensions: {'credProps': true},
          exclude: [
            {'type': 'public-key', 'id': 'AAEC'},
          ],
        ),
      );
      expect(request.rpId, 'webauthn.io');
      expect(request.rpName, 'WebAuthn.io');
      expect(request.userName, 'fixture@example.org');
      expect(request.userDisplayName, 'Fixture User');
      expect(request.userHandle, utf8.encode('user-fixture-1'));
      expect(request.challenge, utf8.encode('kemlock-fixture-challenge'));
      expect(request.algorithms, [-7, -257]);
      expect(request.excluded, [
        Uint8List.fromList([0, 1, 2]),
      ]);
      expect(request.credProps, isTrue);
      expect(request.acceptsEs256, isTrue);
    });

    test('takes no list of algorithms as WebAuthn’s defaults, ES256 among them', () {
      expect(CreationRequest.parse(creation(params: [])).acceptsEs256, isTrue);
      expect(
        CreationRequest.parse(
          creation(
            params: [
              {'type': 'public-key', 'alg': -257},
            ],
          ),
        ).acceptsEs256,
        isFalse,
      );
      expect(
        CreationRequest.parse(
          creation(
            params: [
              {'type': 'public-key', 'alg': -8},
            ],
          ),
        ).acceptsEs256,
        isFalse,
      );
    });

    test('is refused when it can’t be read', () {
      expect(() => CreationRequest.parse({}), _fails(PasskeyFailure.encoding));
      expect(() => CreationRequest.parse({...creation(), 'user': null}), _fails(PasskeyFailure.encoding));
      expect(() => CreationRequest.parse({...creation(), 'challenge': ''}), _fails(PasskeyFailure.encoding));
      expect(() => CreationRequest.parse({...creation(), 'challenge': 'not base64!'}), _fails(PasskeyFailure.encoding));
      expect(
        () => CreationRequest.parse(creation(userId: base64Url.encode(Uint8List(65)).replaceAll('=', ''))),
        _fails(PasskeyFailure.encoding),
      );
      expect(
        () => CreationRequest.parse(
          creation(
            params: [
              {'type': 'other', 'alg': -7},
            ],
          ),
        ),
        _fails(PasskeyFailure.encoding),
      );
    });
  });

  group('a new passkey', () {
    CreatedPasskey make({Map<String, Object?>? options, Iterable<Passkey> held = const [], String? topOrigin}) => createPasskey(
      request: CreationRequest.parse(options ?? creation()),
      rpId: 'webauthn.io',
      origin: origin,
      topOrigin: topOrigin,
      now: 1763200000000,
      held: held,
      key: key,
      credentialId: credentialId,
      id: 'passkey-1',
    );

    test('is the record the phone keeps, ES256, with its key as PKCS#8 in base64', () async {
      final made = make().passkey;
      expect(made.id, 'passkey-1');
      expect(made.credentialId, credential['credentialId']);
      expect(made.rpId, 'webauthn.io');
      expect(made.rpName, 'WebAuthn.io');
      expect(made.userHandle, 'dXNlci1maXh0dXJlLTE');
      expect(made.userName, 'fixture@example.org');
      expect(made.userDisplayName, 'Fixture User');
      expect(made.algorithm, coseEs256);
      expect(made.addedAt, 1763200000000);
      expect(made.updatedAt, isNull);
      final pair = await P256KeyPair.fromPkcs8(unb64(made.privateKey));
      expect(pair.d, key.d);
      expect(pair.point, key.point);
      // The record round-trips through the vault's JSON
      expect(Passkey.fromJson(jsonDecode(jsonEncode(made.toJson())) as Map<String, Object?>), made);
    });

    test('answers with the fixture’s authenticator data and attestation object (format none)', () {
      final response = make().response;
      final inner = response['response']! as Map<String, Object?>;
      expect(response['id'], credential['credentialId']);
      expect(response['rawId'], credential['credentialId']);
      expect(response['type'], 'public-key');
      expect(response['authenticatorAttachment'], 'platform');
      expect(unb64url(inner['authenticatorData']! as String), unb64(registration['authData']! as String));
      expect(unb64url(inner['attestationObject']! as String), unb64(registration['attestationObject']! as String));
      expect(inner['transports'], ['internal']);
      expect(inner['publicKeyAlgorithm'], -7);
      expect(response['clientExtensionResults'], isEmpty);
    });

    test('gives the public key as SubjectPublicKeyInfo', () {
      final spki = unb64url((make().response['response']! as Map<String, Object?>)['publicKey']! as String);
      expect(spki, hasLength(91));
      expect(spki.sublist(0, 3), [0x30, 0x59, 0x30]);
      expect(spki.sublist(26), key.point);
      expect(p256Spki(key.point), spki);
    });

    test('writes the client data as the browser does, naming the origin and the challenge', () {
      final inner = make().response['response']! as Map<String, Object?>;
      final clientData = utf8.decode(unb64url(inner['clientDataJSON']! as String));
      expect(clientData, '{"type":"webauthn.create","challenge":"$challenge","origin":"https://webauthn.io","crossOrigin":false}');
    });

    test('names the top origin for a frame of another origin', () {
      final inner = make(topOrigin: 'https://embedder.example').response['response']! as Map<String, Object?>;
      expect(
        utf8.decode(unb64url(inner['clientDataJSON']! as String)),
        '{"type":"webauthn.create","challenge":"$challenge","origin":"https://webauthn.io","crossOrigin":true,"topOrigin":"https://embedder.example"}',
      );
      final same = make(topOrigin: origin).response['response']! as Map<String, Object?>;
      final text = utf8.decode(unb64url(same['clientDataJSON']! as String));
      expect(text, contains('"crossOrigin":false'));
      expect(text, isNot(contains('topOrigin')));
    });

    test('says the passkey is discoverable when the site asks', () {
      final response = make(options: creation(extensions: {'credProps': true})).response;
      expect(response['clientExtensionResults'], {
        'credProps': {'rk': true},
      });
    });

    test('is never made for a site that takes no ES256', () {
      expect(
        () => make(
          options: creation(
            params: [
              {'type': 'public-key', 'alg': -257},
            ],
          ),
        ),
        _fails(PasskeyFailure.notSupported),
      );
    });

    test('is refused when the site excludes a credential Kemlock holds for it', () {
      final held = make().passkey;
      final options = creation(
        exclude: [
          {'type': 'public-key', 'id': credential['credentialId']},
        ],
      );
      expect(() => make(options: options, held: [held]), _fails(PasskeyFailure.invalidState));
      // Another relying party's credential with that id is not the site's
      final elsewhere = Passkey.fromJson({...held.toJson(), 'rpId': 'example.com'});
      expect(make(options: options, held: [elsewhere]).passkey.rpId, 'webauthn.io');
    });

    test('has a random 16-byte credential id and a new key each time', () {
      CreatedPasskey fresh() => createPasskey(request: CreationRequest.parse(creation()), rpId: 'webauthn.io', origin: origin, now: 1);
      final a = fresh().passkey;
      final b = fresh().passkey;
      expect(unb64url(a.credentialId), hasLength(16));
      expect(a.credentialId, isNot(b.credentialId));
      expect(a.privateKey, isNot(b.privateKey));
      expect(a.id, isNot(b.id));
    });
  });

  group('a sign-in', () {
    final passkey = Passkey(
      id: 'passkey-1',
      credentialId: credential['credentialId']! as String,
      rpId: 'webauthn.io',
      rpName: 'WebAuthn.io',
      userHandle: 'dXNlci1maXh0dXJlLTE',
      userName: 'fixture@example.org',
      privateKey: credential['privateKey']! as String,
      addedAt: 1,
    );

    test('is the fixture’s client data, authenticator data and signature', () async {
      final response = await assertPasskey(passkey: passkey, challenge: unb64url(challenge), origin: origin);
      final inner = response['response']! as Map<String, Object?>;
      expect(utf8.decode(unb64url(inner['clientDataJSON']! as String)), assertion['clientDataJSON']);
      expect(unb64url(inner['authenticatorData']! as String), unb64(assertion['authData']! as String));
      expect(unb64url(inner['signature']! as String), unb64(assertion['signature']! as String));
      expect(unb64url(inner['userHandle']! as String), utf8.encode('user-fixture-1'));
      expect(response['id'], credential['credentialId']);
      expect(response['rawId'], credential['credentialId']);
      expect(response['type'], 'public-key');
      expect(response['authenticatorAttachment'], 'platform');
    });

    test('verifies with the credential’s public key, and the counter stays 0', () async {
      final response = await assertPasskey(passkey: passkey, challenge: Uint8List.fromList([1, 2, 3]), origin: 'https://login.webauthn.io');
      final inner = response['response']! as Map<String, Object?>;
      final authData = unb64url(inner['authenticatorData']! as String);
      expect(authData.sublist(33, 37), [0, 0, 0, 0]);
      expect(authData[32], 0x1D);
      final hash = sha256.convert(unb64url(inner['clientDataJSON']! as String)).bytes;
      final signed = Uint8List.fromList([...authData, ...hash]);
      expect(es256Verify(unb64(credential['point']! as String), signed, unb64url(inner['signature']! as String)), isTrue);
    });

    test('signs for the passkey’s relying party, not the origin’s host', () async {
      final response = await assertPasskey(passkey: passkey, challenge: Uint8List.fromList([9]), origin: 'https://sub.webauthn.io');
      final authData = unb64url((response['response']! as Map<String, Object?>)['authenticatorData']! as String);
      expect(authData.sublist(0, 32), rpIdHash('webauthn.io'));
    });
  });

  group('which passkeys answer a request', () {
    Passkey held(String id, String rpId, List<int> credential) =>
        Passkey(id: id, credentialId: b64url(credential), rpId: rpId, userHandle: 'dQ', userName: id, privateKey: 'k', addedAt: 1);
    final all = [
      held('a', 'example.com', [1]),
      held('b', 'example.com', [2]),
      held('c', 'login.example.com', [3]),
      held('d', 'Example.com.', [4]),
      held('e', 'other.org', [1]),
      held('dup', 'example.com', [1]),
    ];

    test('are the ones of exactly the relying party, each credential once', () {
      expect([for (final p in matchingPasskeys('example.com', const [], all)) p.id], ['a', 'b', 'd']);
      expect([for (final p in matchingPasskeys('login.example.com', const [], all)) p.id], ['c']);
      expect(matchingPasskeys('com', const [], all), isEmpty);
    });

    test('are narrowed by the credentials the site takes', () {
      final allowed = [
        Uint8List.fromList([2]),
        Uint8List.fromList([9]),
      ];
      expect([for (final p in matchingPasskeys('example.com', allowed, all)) p.id], ['b']);
      expect(
        matchingPasskeys('example.com', [
          Uint8List.fromList([9]),
        ], all),
        isEmpty,
      );
    });
  });

  group('an assertion request', () {
    test('is read from the options JSON', () {
      final request = AssertionRequest.parse({
        'rpId': 'Example.com',
        'challenge': challenge,
        'allowCredentials': [
          {'type': 'public-key', 'id': 'AAEC'},
          {'type': 'other', 'id': 'AwQ'},
          {'type': 'public-key', 'id': '!!'},
        ],
      });
      expect(request.rpId, 'example.com');
      expect(request.challenge, utf8.encode('kemlock-fixture-challenge'));
      expect(request.allowed, [
        Uint8List.fromList([0, 1, 2]),
      ]);
      expect(AssertionRequest.parse({'challenge': challenge}).rpId, isNull);
      expect(() => AssertionRequest.parse({}), _fails(PasskeyFailure.encoding));
    });
  });
}
