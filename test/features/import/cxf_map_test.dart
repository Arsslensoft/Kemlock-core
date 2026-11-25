@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/import/formats/cxf.dart';
import 'package:kemlock_core/features/import/formats/cxf_map.dart';
import 'package:kemlock_core/features/import/formats/cxf_passkey.dart';
import 'package:kemlock_core/features/import/formats/cxf_ssh_key.dart';
import 'package:kemlock_core/features/import/formats/import_extras.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/features/keys/key_bridge.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

// Written from the CXF 1.0 specification, as are the cases; see the README next to them.
final _example = File('test/fixtures/import/cxf/fido-example.json').readAsStringSync();
final _keys = {
  for (final key
      in ((jsonDecode(File('test/fixtures/import/cxf/keys.json').readAsStringSync()) as Json)['keys']! as List<Object?>).cast<Json>())
    key['name']! as String: key,
};

const _now = 1800000000000;

String Function() _ids() {
  var next = 0;
  return () => 'id-${next++}';
}

Future<ForeignImport> _map(Object? payload) => mapCxf(readCxf(payload), newId: _ids(), now: _now);

Json _field(String type, String value, [String? label]) => {'fieldType': type, 'value': value, 'label': ?label};

Json _item(
  String title,
  List<Object?> credentials, {
  List<String> urls = const [],
  List<String> tags = const [],
  String id = 'item',
  Json? extra,
}) => {
  'id': id,
  'title': title,
  'scope': {'urls': urls, 'androidApps': <Object?>[]},
  'credentials': credentials,
  'tags': tags,
  ...?extra,
};

Json _account(String id, String name, List<Object?> items, [List<Object?> collections = const []]) => {
  'id': id,
  'username': name,
  'email': '$name@example.com',
  'items': items,
  'collections': collections,
};

Json _doc(List<Object?> accounts) => {
  'version': {'major': 1, 'minor': 0},
  'exporterRpId': 'exporter.example.com',
  'exporterDisplayName': 'Exporter app',
  'timestamp': 1705228800,
  'accounts': accounts,
};

Future<ForeignImport> _one(
  List<Object?> credentials, {
  String title = 'Larkspur Mail',
  List<String> urls = const [],
  List<String> tags = const [],
}) => _map(
  _doc([
    _account('a', 'jane', [_item(title, credentials, urls: urls, tags: tags)]),
  ]),
);

final _basic = {'type': 'basic-auth', 'username': _field('string', 'ada'), 'password': _field('concealed-string', 'pw-1')};
final _totp = {'type': 'totp', 'secret': 'JBSWY3DPEHPK3PXP', 'period': 30, 'digits': 6, 'algorithm': 'sha1'};

void main() {
  group('the specification\'s example', () {
    late ForeignImport result;

    setUp(() async => result = await _map(jsonDecode(_example)));

    test('gives each kind its entries and lists what Kemlock doesn\'t keep', () {
      expect(result.source, ImportSource.cxf);
      expect(result.sourceName, 'Exporter app');
      expect(result.logins, hasLength(1));
      expect(result.accounts, hasLength(1));
      expect(result.passkeys, hasLength(1));
      expect(result.cards, hasLength(1));
      expect(result.identities.map((identity) => identity.name), ['Driver License', 'House Address', 'ID card', 'Passport', 'John Doe']);
      expect(result.notes, hasLength(1));
      expect(result.keys, hasLength(1));
      expect(result.skips, [
        const ImportSkip('Wifi', SkipReason.wifi),
        const ImportSkip('ID card', SkipReason.file, detail: 'example-file.txt'),
        const ImportSkip('API key', SkipReason.apiKey),
        const ImportSkip('Generated Password', SkipReason.generatedPassword),
      ]);
      expect(result.skipped, 4);
      expect(result.notices, [const ImportNotice('WebAuthn.io', NoticeReason.passkeyExtras)]);
      expect(result.units, [const ImportUnit(id: 'account:0', name: 'Jane Smith')]);
      expect(result.cuts!.any, isFalse);
    });

    test('makes a login with its website, tags and times, linked to its code', () {
      final login = result.logins.single;
      final code = result.accounts.single;

      expect(login.name, 'GitHub Login');
      expect(login.username, 'johndoe');
      expect(login.password, 'securepassword123');
      expect(login.uris, [const WebsiteRule('https://github.com')]);
      expect(login.websites, ['github.com']);
      expect(login.tags, ['Work Accounts', 'development', 'git', 'work']);
      expect(login.source, 'Exporter app');
      expect(login.addedAt, 1705142400000);
      expect(login.passwordChangedAt, 1705228800000);
      expect(login.accountId, code.id);
      expect(code.issuer, 'GitHub');
      expect(code.label, 'jane.smith@example.com');
      expect(code.secret, 'JBSWY3DPEHPK3PXP');
      expect(code.algorithm, 'SHA256');
      expect(code.digits, 6);
      expect(code.period, 30);
      expect(result.unitOf[login.id], 'account:0');
    });

    test('makes a card from year-month dates', () {
      final card = result.cards.single;

      expect(card.name, 'Visa Credit Card');
      expect(card.number, '4111111111111111');
      expect(card.cardholder, 'John Doe');
      expect(card.brand, 'Visa');
      expect(card.code, '123');
      expect(card.pin, '0000');
      expect((card.expMonth, card.expYear), (8, 2027));
      expect((card.validFromMonth, card.validFromYear), (2, 2024));
      expect(card.tags, ['finance', 'credit card', 'personal']);
    });

    test('makes a note, an SSH key and a passkey', () {
      expect(result.notes.single.title, 'Home alarm');
      expect(result.notes.single.text, 'some instructionts to enable/disable the alarm');

      final key = result.keys.single;
      expect(key.kind, 'ssh');
      expect(key.algorithm, 'rsa');
      expect(key.bits, 3072);
      expect(key.name, 'SSH Key');
      expect(key.note, 'Work SSH Key');
      expect(key.tags, ['Work Accounts']);

      final passkey = result.passkeys.single;
      expect(passkey.rpId, 'webauthn.io');
      expect(passkey.credentialId, 'Y3JlZGVudGlhbElkRXhhbXBsZQ');
      expect(passkey.userHandle, 'cnEzaNHWcYK3coWZjvoaV1Hj9gnI12mKe2dL2HZVFlY');
      expect(passkey.userName, 'johndoe');
      expect(passkey.userDisplayName, 'John Doe');
      expect(passkey.algorithm, -7);
      expect(unb64(passkey.privateKey), hasLength(138));
    });

    test('merges the name, address and document credentials into identities', () {
      final byName = {for (final identity in result.identities) identity.name: identity};

      final licence = result.identities.first;
      expect(licence.birthDate, '1990-05-15');
      expect(licence.documents!.single.type, 'driversLicence');
      expect(licence.documents!.single.number, 'D12345678');
      expect(licence.documents!.single.issuingCountry, 'US');
      expect(licence.documents!.single.issuingAuthority, 'Department of Motor Vehicles');
      expect((licence.documents!.single.issuedOn, licence.documents!.single.expiresOn), ('2020-06-01', '2030-06-01'));
      expect(licence.note, contains('License Class: C'));

      final home = byName['House Address']!;
      expect(home.address!.lines, ['123 Main Street']);
      expect(
        (home.address!.city, home.address!.region, home.address!.postalCode, home.address!.country),
        ('Springfield', 'US-CA', '12345', 'US'),
      );
      expect(home.phone, '+1-555-123-4567');
      expect(home.documents, isNull);

      expect(byName['ID card']!.documents!.single.type, 'idCard');
      expect(byName['ID card']!.documents!.single.number, '123456789');
      expect(byName['Passport']!.documents!.single.type, 'passport');
      expect(byName['Passport']!.documents!.single.number, 'A12345678');
      expect(byName['Passport']!.note, contains('Nationality: American'));

      final person = byName['John Doe']!;
      expect((person.title, person.givenName, person.middleName, person.familyName), ('Dr.', 'John', 'Michael', 'van Doe Smith'));
      expect(person.note, allOf(contains('Informal Given Name: Johnny'), contains('Credentials: PhD'), contains('Generation: III')));
    });
  });

  group('logins and codes', () {
    test('two basic-auth credentials in one item make two logins, each with the websites', () async {
      final result = await _one(
        [
          _basic,
          {..._basic, 'username': _field('string', 'grace')},
        ],
        urls: ['https://larkspur.example/login', 'https://mail.larkspur.example', 'https://larkspur.example/'],
      );

      expect(result.logins.map((login) => login.username), ['ada', 'grace']);
      for (final login in result.logins) {
        expect(login.uris, hasLength(3));
        expect(login.uris!.first, const WebsiteRule('https://larkspur.example/login'));
      }
    });

    test('a login and a code of one item are linked, and a code without an issuer takes the item\'s title', () async {
      final result = await _one([_basic, _totp], title: 'Fastmail');

      expect(result.accounts.single.issuer, 'Fastmail');
      expect(result.accounts.single.label, 'ada');
      expect(result.logins.single.accountId, result.accounts.single.id);
    });

    test('a code Kemlock can\'t generate is skipped and the login is still imported', () async {
      final result = await _one([
        _basic,
        {..._totp, 'algorithm': 'sha3-256'},
        {..._totp, 'digits': 7},
        {..._totp, 'secret': 'not base32 at all!'},
      ]);

      expect(result.logins, hasLength(1));
      expect(result.logins.single.accountId, isNull);
      expect(result.accounts, isEmpty);
      expect([for (final skip in result.skips) skip.reason], [SkipReason.totpAlgorithm, SkipReason.totpDigits, SkipReason.totpSecret]);
    });

    test('a note and custom fields join the login\'s note, a concealed field marked', () async {
      final result = await _one([
        _basic,
        {'type': 'note', 'content': _field('string', 'Back door code on the fridge')},
        {
          'type': 'custom-fields',
          'fields': [_field('string', '12345', 'Account number'), _field('concealed-string', 'x9', 'Recovery word')],
        },
      ]);

      expect(result.notes, isEmpty);
      expect(result.logins.single.note, 'Back door code on the fridge\n\nAccount number: 12345\nRecovery word (secret): x9');
    });

    test('an item of notes alone becomes a note', () async {
      final result = await _one(
        [
          {'type': 'note', 'content': _field('string', 'hello')},
        ],
        title: 'Alarm',
        tags: ['home'],
      );

      expect(result.notes.single.title, 'Alarm');
      expect(result.notes.single.text, 'hello');
      expect(result.notes.single.tags, ['home']);
    });
  });

  group('what is skipped', () {
    test('lists a file with its name, an item of a Wi-Fi network alone, and an unknown type, and still imports the rest', () async {
      final result = await _one([
        {'type': 'file', 'id': 'f', 'name': 'passport-scan.pdf', 'decryptedSize': 3, 'integrityHash': 'x'},
        {'type': 'loyalty-card', 'cardNumber': '1'},
        _basic,
      ]);
      final wifi = await _one([
        {'type': 'wifi', 'ssid': _field('string', 'Home')},
      ], title: 'Home Wi-Fi');
      final empty = await _one([], title: 'Hollow');

      expect(result.skips, [
        const ImportSkip('Larkspur Mail', SkipReason.file, detail: 'passport-scan.pdf'),
        const ImportSkip('Larkspur Mail', SkipReason.unknownType, detail: 'loyalty-card'),
      ]);
      expect(result.logins, hasLength(1));
      expect(wifi.skips, [const ImportSkip('Home Wi-Fi', SkipReason.wifi)]);
      expect(wifi.logins.length + wifi.notes.length + wifi.cards.length + wifi.identities.length, 0);
      expect(empty.skips, [const ImportSkip('Hollow', SkipReason.nothingKept)]);
    });

    test('puts no value of a payload into a skip or a notice', () async {
      final result = await _one([
        {'type': 'wifi', 'ssid': _field('string', 'secret-ssid'), 'passphrase': _field('concealed-string', 'secret-pass')},
        {'type': 'api-key', 'key': _field('concealed-string', 'secret-key')},
      ]);

      expect(result.skips.toString(), isNot(contains('secret')));
    });
  });

  group('collections and places', () {
    test('become tags, nested ones joined by " / ", with the item\'s own tags', () async {
      final result = await _map(
        _doc([
          _account(
            'a',
            'jane',
            [
              _item('Rent', [_basic], tags: ['personal'], id: 'r1'),
            ],
            [
              {
                'id': 'f',
                'title': 'Finance',
                'items': <Object?>[],
                'subCollections': [
                  {
                    'id': 'b',
                    'title': 'Banking',
                    'items': [
                      {'item': 'r1'},
                    ],
                  },
                ],
              },
            ],
          ),
        ]),
      );

      expect(result.logins.single.tags, ['Finance / Banking', 'personal']);
    });

    test('ask where each account goes, and where a collection shared with others goes', () async {
      Json shared(String owner) => {
        'name': 'shared',
        'accessors': [
          {
            'type': 'user',
            'accountId': owner,
            'name': 'owner',
            'permissions': ['manage'],
          },
          {
            'type': 'user',
            'accountId': 'u2',
            'name': 'bob',
            'permissions': ['read'],
          },
        ],
      };
      final result = await _map(
        _doc([
          _account('p', 'Personal', [
            _item('Mail', [_basic], id: 'm1'),
          ]),
          _account(
            'f',
            'Family',
            [
              _item('Wi-Fi router', [_basic], id: 'w1'),
              _item('Streaming', [_basic], id: 's1'),
            ],
            [
              {
                'id': 'c1',
                'title': 'Household',
                'items': [
                  {'item': 'w1'},
                ],
                'extensions': [shared('f')],
              },
              {
                'id': 'c2',
                'title': 'Mine',
                'items': [
                  {'item': 's1'},
                ],
              },
            ],
          ),
        ]),
      );

      expect(result.units, [
        const ImportUnit(id: 'account:0', name: 'Personal'),
        const ImportUnit(id: 'account:1', name: 'Family'),
        const ImportUnit(id: 'account:1/collection:0', name: 'Household', shared: true),
      ]);
      final unitByName = {for (final login in result.logins) login.name: result.unitOf[login.id]};
      expect(unitByName, {'Mail': 'account:0', 'Wi-Fi router': 'account:1/collection:0', 'Streaming': 'account:1'});
    });
  });

  group('passkeys', () {
    CxfPasskey passkeyOf(Json key) => CxfPasskey(
      credentialId: b64url([1, 2, 3, 4]),
      rpId: 'Larkspur.Example',
      username: 'ada',
      userDisplayName: '',
      userHandle: b64url([9, 9]),
      key: key['privateKey']! as String,
    );

    test('keep a P-256 key, which signs a challenge that verifies under its public key', () async {
      final made = await readCxfPasskey(passkeyOf(_keys['ecdsa-p256']!), id: 'p1', addedAt: 7);
      final passkey = made.passkey!;

      expect(passkey.rpId, 'larkspur.example');
      expect(passkey.credentialId, b64url([1, 2, 3, 4]));
      expect(passkey.userDisplayName, isNull);
      expect(passkey.addedAt, 7);
      final pair = await P256KeyPair.fromPkcs8(unb64(passkey.privateKey));
      final challenge = Uint8List.fromList(utf8.encode('a test challenge'));
      expect(es256Verify(pair.point, challenge, es256Sign(pair, challenge)), isTrue);
    });

    test('skip Ed25519, RSA and P-384 keys by name', () async {
      for (final (name, detail) in [('ed25519', 'ed25519'), ('ecdsa-p384', 'p384'), ('rsa', 'rsa')]) {
        final made = await readCxfPasskey(passkeyOf(_keys[name]!), id: 'p1', addedAt: 7);

        expect(made.passkey, isNull, reason: name);
        expect(made.skip, SkipReason.passkeyAlgorithm, reason: name);
        expect(made.detail, detail, reason: name);
      }
    });

    test('skip a key over 2 KiB or that can\'t be read, and ids that are empty', () async {
      final big = CxfPasskey(
        credentialId: 'AQID',
        rpId: 'a.example',
        username: 'u',
        userDisplayName: 'U',
        userHandle: 'AQ',
        key: b64url(Uint8List(2049)),
      );
      final damaged = CxfPasskey(
        credentialId: 'AQID',
        rpId: 'a.example',
        username: 'u',
        userDisplayName: 'U',
        userHandle: 'AQ',
        key: b64url([1, 2, 3]),
      );
      final noHandle = CxfPasskey(
        credentialId: 'AQID',
        rpId: 'a.example',
        username: 'u',
        userDisplayName: 'U',
        userHandle: '',
        key: _keys['ecdsa-p256']!['privateKey']! as String,
      );

      expect((await readCxfPasskey(big, id: 'p', addedAt: 1)).skip, SkipReason.passkeyKey);
      expect((await readCxfPasskey(damaged, id: 'p', addedAt: 1)).skip, SkipReason.passkeyKey);
      expect((await readCxfPasskey(noHandle, id: 'p', addedAt: 1)).skip, SkipReason.unreadable);
    });

    test('keep a passkey that came with extra secrets, flagged, and name the Ed25519 one when skipping', () async {
      final result = await _one([
        {
          'type': 'passkey',
          'credentialId': 'AQID',
          'rpId': 'a.example',
          'username': 'u',
          'userDisplayName': 'U',
          'userHandle': 'AQ',
          'key': _keys['ecdsa-p256']!['privateKey'],
          'fido2Extensions': {
            'hmacCredentials': {'algorithm': 'hmac-sha256', 'credWithUV': 'a', 'credWithoutUV': 'b'},
          },
        },
        {
          'type': 'passkey',
          'credentialId': 'AQID',
          'rpId': 'b.example',
          'username': 'u',
          'userDisplayName': 'U',
          'userHandle': 'AQ',
          'key': _keys['ed25519']!['privateKey'],
        },
      ], title: 'Larkspur');

      expect(result.passkeys.map((passkey) => passkey.rpId), ['a.example']);
      expect(result.notices, [const ImportNotice('Larkspur', NoticeReason.passkeyExtras)]);
      expect(result.skips, [const ImportSkip('Larkspur', SkipReason.passkeyAlgorithm, detail: 'ed25519')]);
    });
  });

  group('SSH keys', () {
    for (final name in ['ed25519', 'ecdsa-p256', 'ecdsa-p384', 'rsa']) {
      test('$name: the public half equals the one ssh-keygen -y printed', () async {
        final recorded = _keys[name]!;
        final made = await readCxfSshKey(
          CxfSshKey(keyType: recorded['keyType']! as String, privateKey: recorded['privateKey']! as String),
          id: 'k1',
          name: 'Work',
          addedAt: 5,
        );

        expect(made.key, isNotNull);
        expect(made.key!.kind, 'ssh');
        expect(made.key!.name, 'Work');
        expect(made.key!.addedAt, 5);
        expect(crypto.sshPublicKeyLine(parsedKeyOf(made.key!)), startsWith(recorded['publicKeyLine']! as String));
      });
    }

    test('a key over 16 KiB, damaged bytes and a key that is not SSH are skipped', () async {
      final big = CxfSshKey(keyType: 'ssh-rsa', privateKey: b64url(Uint8List(16 * 1024 + 1)));
      final damaged = CxfSshKey(keyType: 'ssh-rsa', privateKey: b64url([0x30, 0x03, 1, 2, 3]));

      for (final source in [big, damaged]) {
        final made = await readCxfSshKey(source, id: 'k', name: 'x', addedAt: 1);
        expect(made.key, isNull);
        expect(made.skip, SkipReason.sshKey);
      }
    });
  });

  group('parseForeignExport', () {
    test('reads a CXF file with the clock and the id maker it is given, and finds it from its content', () async {
      expect(detectFormat(_example), (source: ImportSource.cxf, encrypted: false));

      final result = await parseForeignExport(_example, newId: _ids(), now: _now);

      expect(result.source, ImportSource.cxf);
      expect(result.logins.single.id, startsWith('id-'));
      expect(result.sourceName, 'Exporter app');
    });

    test('refuses version 2.0 naming it, and reports a file without an entry as empty', () async {
      final v2 = jsonEncode({
        ..._doc([]),
        'version': {'major': 2, 'minor': 0},
      });

      await expectLater(
        parseForeignExport(v2),
        throwsA(
          isA<CxfException>().having((e) => e.problem, 'problem', CxfProblem.unsupportedVersion).having((e) => e.version, 'version', '2.0'),
        ),
      );
      await expectLater(
        parseForeignExport(jsonEncode(_doc([_account('a', 'jane', [])]))),
        throwsA(isA<ImportError>().having((e) => e.code, 'code', ImportErrorCode.empty)),
      );
    });
  });
}
