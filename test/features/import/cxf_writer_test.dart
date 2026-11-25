@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/import/formats/cxf.dart';
import 'package:kemlock_core/features/import/formats/cxf_map.dart';
import 'package:kemlock_core/features/import/formats/cxf_ssh_key.dart';
import 'package:kemlock_core/features/import/formats/cxf_writer.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

typedef Json = Map<String, Object?>;

// Throwaway keys made for the import tests; see the README next to them.
final _keys = {
  for (final key
      in ((jsonDecode(File('test/fixtures/import/cxf/keys.json').readAsStringSync()) as Json)['keys']! as List<Object?>).cast<Json>())
    key['name']! as String: key,
};

const _now = 1800000000000;
const _added = 1700000000000;

String Function() _ids() {
  var next = 0;
  return () => 'new-${next++}';
}

const _code = OtpAccount(
  id: 'code-1',
  type: OtpType.totp,
  issuer: 'Larkspur',
  label: 'ada',
  secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA256',
  digits: 8,
  period: 60,
  addedAt: _added,
);

const _lonelyCode = OtpAccount(
  id: 'code-2',
  type: OtpType.totp,
  issuer: 'GitLab',
  label: 'me',
  secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  addedAt: _added,
);

const _login = Login(
  id: 'login-1',
  name: 'Larkspur Mail',
  username: 'ada',
  password: 'correct horse',
  websites: ['mail.larkspur.example'],
  uris: [WebsiteRule('https://mail.larkspur.example'), WebsiteRule('https://larkspur.example/login')],
  note: 'Recovery e-mail is on the back.',
  tags: ['Finance / Banking', 'personal'],
  pinned: true,
  accountId: 'code-1',
  passwordChangedAt: 1750000000000,
  addedAt: _added,
);

Future<CxfWritten> _write({List<VaultKey> keys = const []}) async {
  final p256 = _keys['ecdsa-p256']!;
  return writeCxf(
    CxfExportItems(
      logins: [_login],
      codes: [_code, _lonelyCode],
      passkeys: [
        Passkey(
          id: 'passkey-1',
          credentialId: b64url([1, 2, 3, 4, 5, 6, 7, 8]),
          rpId: 'larkspur.example',
          userHandle: b64url([9, 8, 7]),
          userName: 'ada@larkspur.example',
          userDisplayName: 'Ada',
          privateKey: b64(unb64url(p256['privateKey']! as String)),
          addedAt: _added,
          tags: const ['personal'],
        ),
      ],
      notes: [const SecureNote(id: 'note-1', title: 'Alarm', text: 'Code 4711', addedAt: _added)],
      cards: [
        const PaymentCard(
          id: 'card-1',
          name: 'Visa',
          cardholder: 'Ada Lovelace',
          number: '4111111111111111',
          brand: 'Visa',
          expMonth: 4,
          expYear: 2029,
          code: '123',
          pin: '0000',
          validFromMonth: 5,
          validFromYear: 2024,
          addedAt: _added,
        ),
      ],
      identities: [
        const Identity(
          id: 'identity-1',
          name: 'Ada',
          title: 'Countess',
          givenName: 'Ada',
          middleName: 'Augusta',
          familyName: 'Lovelace',
          phone: '+44 20 7946 0000',
          birthDate: '1815-12-10',
          address: IdentityAddress(
            lines: ['1 Main Street', 'Flat 2'],
            city: 'London',
            region: 'Greater London',
            postalCode: 'N1 1AA',
            country: 'GB',
          ),
          documents: [IdentityDocument(id: 'doc-1', type: 'passport', number: 'P1234567', issuingCountry: 'GB', expiresOn: '2030-01-01')],
          addedAt: _added,
        ),
      ],
      keys: keys,
    ),
    now: _now,
  );
}

Future<VaultKey> _sshKey() async => (await readCxfSshKey(
  CxfSshKey(keyType: 'ssh-ed25519', privateKey: _keys['ed25519']!['privateKey']! as String),
  id: 'key-1',
  name: 'Deploy key',
  addedAt: _added,
)).key!;

void main() {
  late CxfWritten written;
  late ForeignImport back;

  setUp(() async {
    written = await _write(keys: [await _sshKey()]);
    back = await mapCxf(readCxf(jsonDecode(written.json)), newId: _ids(), now: _now);
  });

  test('writes a CXF 1.0 header with one account, and what it holds is read back without a skip or a cut', () {
    final document = parseCxf(written.json);

    expect(document.major, 1);
    expect(document.minor, 0);
    expect(document.exporterRpId, cxfExporterRpId);
    expect(document.exporterDisplayName, 'Kemlock');
    expect(document.timestamp, _now ~/ 1000);
    expect(document.accounts, hasLength(1));
    expect(document.accounts.single.items, hasLength(written.items));
    expect(written.leftOut, isEmpty);
    expect(back.skips, isEmpty);
    expect(back.notices, isEmpty);
    expect(document.cuts.itemsLeftOut + document.cuts.credentialsLeftOut + document.cuts.valuesTooLong, 0);
  });

  test('puts a login and its linked code in one item, the websites as the scope', () {
    final item = parseCxf(written.json).accounts.single.items.firstWhere((item) => item.id == cxfId('login-1'));

    expect(item.title, 'Larkspur Mail');
    expect([for (final credential in item.credentials) credential.type], ['basic-auth', 'totp', 'note']);
    expect(item.urls, ['https://mail.larkspur.example', 'https://larkspur.example/login']);
    expect(item.favorite, isTrue);
    expect(item.createdAt, _added ~/ 1000);
    expect(item.modifiedAt, 1750000000);
    // The linked code is not an item of its own, and the one nothing links to is
    expect(parseCxf(written.json).accounts.single.items.map((item) => item.id), isNot(contains(cxfId('code-1'))));
    expect(parseCxf(written.json).accounts.single.items.map((item) => item.id), contains(cxfId('code-2')));
  });

  test('gives back the login with its websites, tags, note and link to its code', () {
    final login = back.logins.single;
    final code = back.accounts.firstWhere((account) => account.issuer == 'Larkspur');

    expect(login.name, 'Larkspur Mail');
    expect(login.username, 'ada');
    expect(login.password, 'correct horse');
    expect([for (final rule in login.uris!) rule.uri], ['https://mail.larkspur.example', 'https://larkspur.example/login']);
    expect(login.note, 'Recovery e-mail is on the back.');
    expect(login.tags, unorderedEquals(['Finance / Banking', 'personal']));
    expect(login.pinned, isTrue);
    expect(login.accountId, code.id);
    expect(login.passwordChangedAt, 1750000000000);
  });

  test('gives back the codes with their secret, algorithm, digits and period', () {
    expect(back.accounts, hasLength(2));
    final code = back.accounts.firstWhere((account) => account.issuer == 'Larkspur');

    expect(code.secret, 'JBSWY3DPEHPK3PXP');
    expect(code.algorithm, 'SHA256');
    expect(code.digits, 8);
    expect(code.period, 60);
    expect(code.label, 'ada');
    expect(back.accounts.map((account) => account.secret), contains('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'));
  });

  test('gives back the passkey with its credential, user and key, and it still carries the P-256 key', () {
    final passkey = back.passkeys.single;

    expect(passkey.credentialId, b64url([1, 2, 3, 4, 5, 6, 7, 8]));
    expect(passkey.rpId, 'larkspur.example');
    expect(passkey.userHandle, b64url([9, 8, 7]));
    expect(passkey.userName, 'ada@larkspur.example');
    expect(passkey.userDisplayName, 'Ada');
    expect(passkey.privateKey, b64(unb64url(_keys['ecdsa-p256']!['privateKey']! as String)));
    expect(passkey.tags, ['personal']);
  });

  test('gives back the note, the card, the identity and the SSH key', () async {
    expect(back.notes.single.title, 'Alarm');
    expect(back.notes.single.text, 'Code 4711');

    final card = back.cards.single;
    expect(
      [card.name, card.cardholder, card.number, card.brand, card.expMonth, card.expYear],
      ['Visa', 'Ada Lovelace', '4111111111111111', 'Visa', 4, 2029],
    );
    expect([card.code, card.pin, card.validFromMonth, card.validFromYear], ['123', '0000', 5, 2024]);

    final identity = back.identities.single;
    expect([identity.title, identity.givenName, identity.middleName, identity.familyName], ['Countess', 'Ada', 'Augusta', 'Lovelace']);
    expect(identity.phone, '+44 20 7946 0000');
    expect(identity.birthDate, '1815-12-10');
    expect(identity.address!.lines, ['1 Main Street', 'Flat 2']);
    expect(
      [identity.address!.city, identity.address!.region, identity.address!.postalCode, identity.address!.country],
      ['London', 'Greater London', 'N1 1AA', 'GB'],
    );
    final document = identity.documents!.single;
    expect([document.type, document.number, document.issuingCountry, document.expiresOn], ['passport', 'P1234567', 'GB', '2030-01-01']);

    final key = back.keys.single;
    expect(key.name, 'Deploy key');
    expect(key.kind, KeyKind.ssh);
    expect(key.privateKey, (await _sshKey()).privateKey);
  });

  test('makes collections of the tags, a nested one for "Parent / Child", and links each item from its own', () {
    final collections = parseCxf(written.json).accounts.single.collections;

    expect(
      {
        for (final collection in collections) collection.tag: [for (final link in collection.links) link.item],
      },
      {
        'Finance': <String>[],
        'Finance / Banking': [cxfId('login-1')],
        'personal': [cxfId('login-1'), cxfId('passkey-1')],
      },
    );
  });

  test('leaves out what CXF has no type for, and says why', () async {
    const pgp = VaultKey(
      id: 'pgp-1',
      name: 'Mail key',
      kind: KeyKind.pgp,
      algorithm: 'pgp',
      privateKey: 'AAAA',
      origin: KeyOrigin.imported,
      addedAt: _added,
    );
    const protected = VaultKey(
      id: 'key-2',
      name: 'Locked key',
      kind: KeyKind.ssh,
      algorithm: 'ed25519',
      privateKey: 'AAAA',
      origin: KeyOrigin.imported,
      protected: true,
      addedAt: _added,
    );
    final result = writeCxf(
      const CxfExportItems(
        codes: [
          OtpAccount(
            id: 'hotp-1',
            type: OtpType.hotp,
            issuer: 'Bank',
            label: 'me',
            secret: 'JBSWY3DPEHPK3PXP',
            counter: 1,
            addedAt: _added,
          ),
        ],
        keys: [pgp, protected],
      ),
      now: _now,
    );

    expect(result.items, 0);
    expect(
      [for (final left in result.leftOut) (left.title, left.reason)],
      [('Bank', CxfLeftOutReason.notTotp), ('Mail key', CxfLeftOutReason.notSshKey), ('Locked key', CxfLeftOutReason.protectedKey)],
    );
  });

  test('writes a code saved with no type as time-based, which is what it is', () {
    const untyped = OtpAccount(id: 'old-1', issuer: 'GitHub', label: 'octocat', secret: 'JBSWY3DPEHPK3PXP', addedAt: _added);
    const login = Login(id: 'login-9', name: 'GitHub', username: 'octocat', password: 'pw', accountId: 'old-1', addedAt: _added);

    final alone = writeCxf(const CxfExportItems(codes: [untyped]), now: _now);
    final linked = writeCxf(
      const CxfExportItems(logins: [login], codes: [untyped]),
      now: _now,
    );

    expect(alone.leftOut, isEmpty);
    expect(alone.items, 1);
    expect(linked.leftOut, isEmpty);
    expect(linked.items, 1, reason: 'the code goes into its login’s item');
    expect(cxfLeftOut(const CxfExportItems(codes: [untyped])), isEmpty);
  });

  test('writes nothing to the log or to the description of what it made', () {
    expect(written.toString(), isNot(contains('correct horse')));
    expect(written.toString(), isNot(contains('JBSWY3DPEHPK3PXP')));
  });

  group('passkeys of another algorithm', () {
    Passkey passkey(String id, {int algorithm = coseEs256}) => Passkey(
      id: id,
      credentialId: b64url([1, 2, 3]),
      rpId: 'larkspur.example',
      rpName: 'Larkspur $id',
      userHandle: b64url([9]),
      userName: 'ada',
      privateKey: b64(unb64url(_keys['ecdsa-p256']!['privateKey']! as String)),
      algorithm: algorithm,
      addedAt: _added,
    );

    test('are left out with the algorithm as the reason, and an ES256 one is written', () {
      final result = writeCxf(
        CxfExportItems(passkeys: [passkey('p-es256'), passkey('p-eddsa', algorithm: -8), passkey('p-rs256', algorithm: -257)]),
        now: _now,
      );

      expect(result.items, 1);
      expect(
        [for (final left in result.leftOut) (left.title, left.reason)],
        [('Larkspur p-eddsa', CxfLeftOutReason.algorithm), ('Larkspur p-rs256', CxfLeftOutReason.algorithm)],
      );
      expect(parseCxf(result.json).accounts.single.items.single.id, cxfId('p-es256'));
    });

    test('are found without writing anything, for the sheet to list before a secret is read', () {
      final left = cxfLeftOut(CxfExportItems(passkeys: [passkey('p-es256'), passkey('p-eddsa', algorithm: -8)]));

      expect([for (final item in left) (item.title, item.reason)], [('Larkspur p-eddsa', CxfLeftOutReason.algorithm)]);
    });

    test('leave no item at all when none is ES256', () {
      final result = writeCxf(CxfExportItems(passkeys: [passkey('p-eddsa', algorithm: -8)]), now: _now);

      expect(result.items, 0);
      expect(parseCxf(result.json).accounts.single.items, isEmpty);
    });
  });

  group('the account id', () {
    const note = SecureNote(id: 'note-9', title: 'Alarm', text: 'Code 4711', addedAt: _added);

    test('is the default one when the caller names none', () {
      final result = writeCxf(const CxfExportItems(notes: [note]), now: _now);

      expect(parseCxf(result.json).accounts.single.id, cxfId('kemlock'));
    });

    test("is the vault's own when the caller names it, so two vaults are two accounts", () {
      final first = writeCxf(
        const CxfExportItems(notes: [note]),
        now: _now,
        accountId: 'vault-1',
      );
      final second = writeCxf(
        const CxfExportItems(notes: [note]),
        now: _now,
        accountId: '4a000000-0000-4000-8000-0000000000a1',
      );

      expect(parseCxf(first.json).accounts.single.id, cxfId('vault-1'));
      expect(parseCxf(second.json).accounts.single.id, cxfId('4a000000-0000-4000-8000-0000000000a1'));
      expect(parseCxf(first.json).accounts.single.id, isNot(parseCxf(second.json).accounts.single.id));
    });

    test('is written as every id is: base64url of at most 64 bytes, hashed past that', () {
      final long = 'v' * 70;

      final result = writeCxf(
        const CxfExportItems(notes: [note]),
        now: _now,
        accountId: long,
      );

      expect(parseCxf(result.json).accounts.single.id, cxfId(long));
      expect(unb64url(parseCxf(result.json).accounts.single.id), hasLength(32));
    });
  });

  group('what the importer asked for', () {
    List<List<String>> typesOf(CxfWritten result) => [
      for (final item in parseCxf(result.json).accounts.single.items) [for (final credential in item.credentials) credential.type],
    ];

    const address = Identity(
      id: 'identity-2',
      name: 'Home',
      address: IdentityAddress(city: 'London'),
      addedAt: _added,
    );

    test('writes everything when it did not say', () {
      final result = writeCxf(
        const CxfExportItems(logins: [_login], codes: [_code]),
        now: _now,
      );

      expect(typesOf(result), [
        ['basic-auth', 'totp', 'note'],
      ]);
    });

    test('leaves out a login note, and the code linked to it, unless their types were asked for', () {
      const items = CxfExportItems(logins: [_login], codes: [_code]);

      expect(typesOf(writeCxf(items, now: _now, asked: const {'basic-auth'})), [
        ['basic-auth'],
      ]);
      expect(typesOf(writeCxf(items, now: _now, asked: const {'basic-auth', 'note'})), [
        ['basic-auth', 'note'],
      ]);
      expect(typesOf(writeCxf(items, now: _now, asked: const {'basic-auth', 'totp'})), [
        ['basic-auth', 'totp'],
      ]);
      final result = writeCxf(items, now: _now, asked: const {'basic-auth'});
      expect(result.json, isNot(contains('Recovery e-mail')));
      expect(result.json, isNot(contains('JBSWY3DPEHPK3PXP')));
    });

    test('leaves out the note of every other kind as well', () {
      const card = PaymentCard(id: 'card-2', name: 'Visa', number: '4111111111111111', note: 'PIN is on the sleeve', addedAt: _added);
      const note = SecureNote(id: 'note-2', title: 'Alarm', text: 'Code 4711', addedAt: _added);

      final result = writeCxf(
        const CxfExportItems(cards: [card], notes: [note]),
        now: _now,
        asked: const {'credit-card'},
      );

      expect(typesOf(result), [
        ['credit-card'],
      ]);
      expect(result.json, isNot(contains('PIN is on the sleeve')));
      expect(result.json, isNot(contains('4711')));
    });

    test('writes no item that nothing it asked for is left in', () {
      final result = writeCxf(
        const CxfExportItems(identities: [address], logins: [_login]),
        now: _now,
        asked: const {'person-name'},
      );

      expect(result.items, 0);
      expect(typesOf(result), isEmpty);
    });

    test('writes only the credentials of an identity that were asked for', () {
      const full = Identity(
        id: 'identity-3',
        name: 'Ada',
        givenName: 'Ada',
        familyName: 'Lovelace',
        address: IdentityAddress(city: 'London'),
        addedAt: _added,
      );
      final everything = writeCxf(const CxfExportItems(identities: [full]), now: _now);
      final named = writeCxf(
        const CxfExportItems(identities: [full]),
        now: _now,
        asked: const {'person-name'},
      );

      expect(typesOf(everything).single, containsAll(['person-name', 'address']));
      expect(typesOf(named), [
        ['person-name'],
      ]);
    });

    test('keeps the collections of the items it wrote and no more', () {
      const tagged = SecureNote(id: 'note-3', title: 'Tagged', text: 'x', addedAt: _added, tags: ['t']);

      final result = writeCxf(
        const CxfExportItems(notes: [tagged]),
        now: _now,
        asked: const {'basic-auth'},
      );

      expect(parseCxf(result.json).accounts.single.collections, isEmpty);
    });
  });

  group('ids', () {
    // CXF 1.0 section 3.2: an id is base64url of opaque bytes, at most 64 of them
    final base64urlText = RegExp(r'^[A-Za-z0-9_-]+$');

    test('writes every id of the account, its items and its collections as base64url of its UTF-8 bytes', () {
      final account = ((jsonDecode(written.json) as Map<String, Object?>)['accounts']! as List<Object?>)[0]! as Map<String, Object?>;
      final ids = <String>[account['id'] as String, for (final item in account['items'] as List) (item as Map)['id'] as String];
      void collect(List<Object?> collections) {
        for (final collection in collections.cast<Map<String, Object?>>()) {
          ids.add(collection['id'] as String);
          ids.addAll([for (final link in collection['items'] as List) (link as Map)['item'] as String]);
          collect(collection['subCollections'] as List);
        }
      }

      collect(account['collections'] as List);

      expect(ids, isNotEmpty);
      for (final id in ids) {
        expect(id, matches(base64urlText), reason: id);
        expect(id, isNot(contains('=')));
        expect(unb64url(id), hasLength(inInclusiveRange(1, 64)));
      }
      expect(account['id'], 'a2VtbG9jaw');
      expect(utf8.decode(unb64url(cxfId('acc-1'))), 'acc-1');
      expect(cxfId('acc-1'), 'YWNjLTE');
    });

    test('links an item from its collection by the same id the item has', () {
      final account = ((jsonDecode(written.json) as Map<String, Object?>)['accounts']! as List<Object?>)[0]! as Map<String, Object?>;
      final itemIds = {for (final item in account['items'] as List) (item as Map)['id']};
      final linked = <Object?>[];
      void collect(List<Object?> collections) {
        for (final collection in collections.cast<Map<String, Object?>>()) {
          linked.addAll([for (final link in collection['items'] as List) (link as Map)['item']]);
          collect(collection['subCollections'] as List);
        }
      }

      collect(account['collections'] as List);

      expect(linked, isNotEmpty);
      expect(itemIds.containsAll(linked), isTrue);
    });

    test('keeps an id of 64 bytes and hashes one of more to its SHA-256 of 32 bytes, the same each time', () {
      final exact = 'a' * 64;
      final long = 'b' * 65;

      expect(unb64url(cxfId(exact)), utf8.encode(exact));
      expect(unb64url(cxfId(long)), hash.sha256.convert(utf8.encode(long)).bytes);
      expect(unb64url(cxfId(long)), hasLength(32));
      expect(cxfId(long), cxfId(long));
      // Multi-byte text counts in bytes, not characters
      expect(unb64url(cxfId('é' * 33)), hasLength(32));
    });

    test('writes the id of an item past the limit as the hash, and the collection links to it', () {
      final longId = 'x' * 100;
      final result = writeCxf(
        CxfExportItems(
          notes: [
            SecureNote(id: longId, title: 'Long', text: 'text', addedAt: _added, tags: const ['t']),
          ],
        ),
        now: _now,
      );

      final account = parseCxf(result.json).accounts.single;
      expect(account.items.single.id, cxfId(longId));
      expect(unb64url(account.items.single.id), hasLength(32));
      expect(account.collections.single.links.single.item, account.items.single.id);
    });
  });
}
