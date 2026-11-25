@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/core/storage/key_value_store.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/keys.dart' show readPrivateKey;
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:kemlock_core/features/keys/key_bridge.dart' show vaultKeyOf;
import 'package:kemlock_core/features/mail/mail_apps.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:kemlock_core/vault/sealed_value.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:kemlock_core/vault/vault_registry.dart';
import 'package:kemlock_core/vault/vault_store.dart';
import 'package:test/test.dart';

import '../compat/before_logins/export_payload.dart';
import 'contacts_fixture_inputs.dart';
import 'fast_kdf.dart';

const _secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const _accounts = [OtpAccount(id: 'a1', issuer: 'ACME', label: '', secret: _secret, addedAt: 0)];
const _services = [
  BackupService(
    id: 's1',
    serviceName: 'GitHub',
    codes: [BackupCode(code: 'abcd-1234')],
    addedAt: 0,
  ),
];

final _dealtWithAccount = OtpAccount.fromJson(const {
  'id': 'a2',
  'issuer': 'Adobe',
  'label': '',
  'secret': _secret,
  'addedAt': 1,
  'breachesDismissed': ['Adobe'],
});
final _dealtWithService = BackupService.fromJson(const {
  'id': 's2',
  'serviceName': 'Adobe',
  'codes': <Object?>[],
  'addedAt': 1,
  'breachesDismissed': ['Adobe'],
});

const _keys = [
  VaultKey(
    id: 'k1',
    name: 'laptop',
    kind: KeyKind.ssh,
    algorithm: 'ed25519',
    privateKey: 'MC4CAQAwBQYDK2VwBCIEIA==',
    publicKey: 'MCowBQYDK2VwAyEA',
    origin: KeyOrigin.generated,
    addedAt: 1,
  ),
  VaultKey(
    id: 'k2',
    name: 'odd',
    kind: KeyKind.other,
    algorithm: '1.3.101.999',
    privateKey: 'AAAA',
    origin: KeyOrigin.imported,
    addedAt: 2,
  ),
];
const _notes = [
  SecureNote(
    id: 'n1',
    title: 'Passport',
    text: 'In the drawer',
    tags: ['travel'],
    addedAt: 3,
    attachments: [
      NoteAttachment(
        id: 'f1',
        name: 'scan.pdf',
        size: 3,
        type: 'application/pdf',
        key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        addedAt: 3,
      ),
    ],
  ),
];
const _passkeys = [
  Passkey(
    id: 'p1',
    credentialId: 'AAECAwQFBgcICQoLDA0ODw',
    rpId: 'github.com',
    userHandle: 'dXNlcg',
    userName: 'octocat',
    privateKey: 'MIGHAgEAMBMGByqGSM49AgEG',
    addedAt: 4,
  ),
];

/// The accounts kept on a security key, as a version that knows them writes
/// the list (openspec: add-security-key-codes).
const _laterKeyAccounts = [
  {
    'id': 'ka1',
    'device': '0102030405060708',
    'keyName': 'YubiKey 5C NFC',
    'name': 'Example:alice@example.org',
    'issuer': 'Example',
    'label': 'alice@example.org',
    'period': 30,
    'type': 'totp',
    'algorithm': 'SHA1',
    'tags': ['work'],
    'addedAt': 5,
  },
];

/// A `contacts` list as a version that keeps other people's public keys writes it, and a list no version
/// writes, which keeps pinned that a list this version does not know is passed over.
const _laterContacts = [
  {
    'id': 'c1',
    'name': 'Grace Hopper',
    'public': 'mDMEavvBvhYJKwYBBAHaRw8BAQdA5u9VJy0bk117b67pa3OynrS90v96RwuEYCascWUiiLk=',
    'source': 'qr',
    'checkedAt': 1_799_000_000_000,
    'checkedFingerprint': '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495',
    'addedAt': 8,
  },
];
const _madeUpList = [
  {'id': 'h1', 'shape': 'cube', 'addedAt': 9},
];

Matcher throwsExportError(String message) => throwsA(isA<ExportFileError>().having((e) => e.message, 'message', contains(message)));

void main() {
  group('encrypted file export', () {
    late String exported;
    setUpAll(() async => exported = await exportVault(_accounts, _services, 'export password', deriveKey: fastKdf));

    test('round-trips accounts and backup services', () async {
      final payload = await importVault(exported, 'export password', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });

    test('carries the breaches an entry has marked dealt with', () async {
      final file = await exportVault([_dealtWithAccount], [_dealtWithService], 'pw', deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.accounts.single.toJson()['breachesDismissed'], ['Adobe']);
      expect(payload.backupServices.single.toJson()['breachesDismissed'], ['Adobe']);
    });

    test('writes self-describing metadata and no plaintext secrets', () {
      final parsed = jsonDecode(exported) as Map<String, Object?>;

      expect(parsed['version'], exportVersion);
      expect(parsed['app'], 'BackMyCodes');
      expect(parsed['scheme'], 'ML-KEM-1024 + AES-256-GCM + scrypt(N=131072,r=8,p=1)');
      expect(parsed.keys, ['version', 'app', 'exportedAt', 'scheme', 'config', 'vault']);
      expect(exported, isNot(contains(_secret)));
      expect(exported, isNot(contains('abcd-1234')));
    });

    test('is indented with two spaces, as JSON.stringify(_, null, 2) writes', () {
      expect(exported, startsWith('{\n  "version": 2,\n  "app": "BackMyCodes",\n  "exportedAt": "'));
    });

    test('dates the export as Date.toISOString does', () async {
      final file = await exportVault([], [], 'pw', deriveKey: fastKdf, now: DateTime.utc(2026, 10, 16, 9, 5, 3, 7, 999));

      expect((jsonDecode(file) as Map<String, Object?>)['exportedAt'], '2026-10-16T09:05:03.007Z');
    });

    test('rejects the wrong password', () async {
      await expectLater(importVault(exported, 'nope', deriveKey: fastKdf), throwsA(isA<AesGcmAuthError>()));
    });

    test("clears the password's key once it is used", () async {
      final derived = <Uint8List>[];
      Future<Uint8List> recording(String password, Uint8List salt) async {
        final key = await fastKdf(password, salt);
        derived.add(key);
        return key;
      }

      final file = await exportVault(_accounts, _services, 'pw', deriveKey: recording);
      expect((await importVault(file, 'pw', deriveKey: recording)).accounts, _accounts);
      await expectLater(importVault(file, 'nope', deriveKey: recording), throwsA(isA<AesGcmAuthError>()));

      expect(derived, hasLength(3));
      for (final key in derived) {
        expect(key, everyElement(0));
      }
    });

    test('rejects tampered data', () async {
      final parsed = jsonDecode(exported) as Map<String, Object?>;
      final vault = parsed['vault']! as Map<String, Object?>;
      final ct = vault['ct']! as String;
      final tampered = {
        ...parsed,
        'vault': {...vault, 'ct': (ct.startsWith('A') ? 'B' : 'A') + ct.substring(1)},
      };

      await expectLater(importVault(jsonEncode(tampered), 'export password', deriveKey: fastKdf), throwsA(isA<AesGcmAuthError>()));
    });

    for (final (input, message) in [
      ('not json', 'Invalid file — not valid JSON.'),
      (jsonEncode({'app': 'Other', 'version': 1}), 'not a Kemlock export'),
      (jsonEncode({'app': 'BackMyCodes'}), 'not a Kemlock export'),
      (jsonEncode({'app': 'BackMyCodes', 'version': exportVersion + 1}), 'Unsupported export version ${exportVersion + 1}'),
    ]) {
      test('rejects invalid input: $input', () async {
        await expectLater(importVault(input, 'pw', deriveKey: fastKdf), throwsExportError(message));
      });
    }

    test('reads a version 1 export, which holds the accounts alone', () async {
      // Built the way version 1 wrote it: the accounts array as the encrypted payload
      final file = await exportVault(_accounts, [], 'pw', deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final v1 = await _reseal(parsed, secretKey, jsonEncode([for (final a in _accounts) a.toJson()]));

      final payload = await importVault(jsonEncode({...parsed, 'version': 1, 'vault': v1}), 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, isEmpty);
    });

    test('reads the codes of a payload that holds lists a later version added', () async {
      // A later version puts keys, notes and passkeys in the same payload and
      // keeps the version at 2; this one must still import the codes.
      final file = await exportVault(_accounts, _services, 'pw', deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final later = await _reseal(
        parsed,
        secretKey,
        jsonEncode({
          'accounts': [for (final a in _accounts) a.toJson()],
          'backupServices': [for (final s in _services) s.toJson()],
          'keys': [
            {'id': 'k1', 'name': 'laptop', 'kind': 'ssh', 'algorithm': 'ed25519', 'private': 'AA==', 'addedAt': 1},
          ],
          'notes': [
            {'id': 'n1', 'title': 'Passport', 'text': '', 'addedAt': 1},
          ],
          'passkeys': [
            {
              'id': 'p1',
              'credentialId': 'AA',
              'rpId': 'example.com',
              'userHandle': 'AA',
              'userName': 'me',
              'privateKey': 'AA==',
              'addedAt': 1,
            },
          ],
        }),
      );

      final payload = await importVault(jsonEncode({...parsed, 'vault': later}), 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });

    test('reads the codes of a payload that holds a contacts list', () async {
      // A version that keeps other people's public keys puts them in the same payload, under `contacts`,
      // and keeps the version at 2. Written against the code from before contacts, which had to pass it over.
      final file = await exportVault(_accounts, _services, 'pw', deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final later = await _reseal(
        parsed,
        secretKey,
        jsonEncode({
          'accounts': [for (final a in _accounts) a.toJson()],
          'backupServices': [for (final s in _services) s.toJson()],
          'contacts': _laterContacts,
          'holograms': _madeUpList,
        }),
      );

      final payload = await importVault(jsonEncode({...parsed, 'vault': later}), 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });
  });

  group('keys, notes and passkeys', () {
    test('round-trip through an encrypted export, beside the codes', () async {
      final file = await exportVault(_accounts, _services, 'pw', keys: _keys, notes: _notes, passkeys: _passkeys, deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
      expect(payload.keys, _keys);
      expect(payload.notes, _notes);
      expect(payload.passkeys, _passkeys);
      expect(payload.fileCount, 1);
      // The file still says version 2, so older versions open it for its codes
      expect((jsonDecode(file) as Map<String, Object?>)['version'], 2);
    });

    // openspec: add-post-quantum-pgp, task 3.5
    test('post-quantum PGP keys of both formats round-trip byte for byte', () async {
      final pq = <VaultKey>[];
      for (final (i, path) in ['sequoia/pqc/standard.secret.asc', 'rfc9980/a2-secret.asc', 'gnupg/pqc/ky768-cv25519.secret.asc'].indexed) {
        final parsed = await readPrivateKey(File('test/fixtures/keys/$path').readAsStringSync());
        pq.add(vaultKeyOf(parsed, id: 'pq$i', name: path, origin: KeyOrigin.imported));
      }
      final file = await exportVault(_accounts, _services, 'pw', keys: [..._keys, ...pq], deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.keys, [..._keys, ...pq]);
      for (final (i, key) in pq.indexed) {
        expect(unb64(payload.keys[_keys.length + i].privateKey), unb64(key.privateKey));
        expect(unb64(payload.keys[_keys.length + i].publicKey!), unb64(key.publicKey!));
      }
    });

    test('open the same with the Recovery Kit', () async {
      final rk = RecoveryKey(kitId: 'KITID234', key: randomBytes(32), threshold: 2, shares: 3, createdAt: '2026-10-13T00:00:00.000Z');
      final file = await exportVault(
        _accounts,
        _services,
        'pw',
        keys: _keys,
        notes: _notes,
        passkeys: _passkeys,
        recoveryKey: rk,
        deriveKey: fastKdf,
      );

      final payload = await importVaultWithRecoveryKey(file, rk.key);

      expect(payload.keys, _keys);
      expect(payload.notes, _notes);
      expect(payload.passkeys, _passkeys);
    });

    test('are left out of the payload of a vault that has none', () async {
      final file = await exportVault(_accounts, _services, 'pw', deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final vault = parsed['vault']! as Map<String, Object?>;
      final sharedSecret = MlKem1024.decapsulate(unb64(vault['kemCT']! as String), secretKey);
      final payload = jsonDecode(
        utf8.decode(await aesGcmDecrypt(sharedSecret, unb64(vault['nonce']! as String), unb64(vault['ct']! as String))),
      );

      expect((payload as Map<String, Object?>).keys, ['accounts', 'backupServices']);
    });

    test('round-trip through a plain export', () {
      final payload = importVaultPlaintext(exportVaultPlaintext(_accounts, _services, keys: _keys, notes: _notes, passkeys: _passkeys));

      expect(payload.keys, _keys);
      expect(payload.notes, _notes);
      expect(payload.passkeys, _passkeys);
    });

    test('keep the card of a key on a security key through both exports and back', () async {
      // openspec: add-openpgp-card. The private half is GnuPG's stub, here a stand-in.
      final card = VaultKey.fromJson({
        ..._keys.first.toJson(),
        'id': 'k-card',
        'kind': 'pgp',
        'algorithm': 'pgp',
        'card': {
          'aid': 'D276000124010304FFFF123456780000',
          'slots': {'sig': '1FCDA135EE42400EC2B77CE677249ABE661CF8DB'},
        },
      });

      final encrypted = await importVault(
        await exportVault(_accounts, _services, 'pw', keys: [card], deriveKey: fastKdf),
        'pw',
        deriveKey: fastKdf,
      );
      final plain = importVaultPlaintext(exportVaultPlaintext(_accounts, _services, keys: [card]));

      for (final payload in [encrypted, plain]) {
        expect(payload.keys.single.toJson(), card.toJson());
        expect(payload.keys.single.isOnCard, isTrue);
      }
    });

    test('keep the management key of a security key that a note holds', () async {
      const note = SecureNote(
        id: 'n-piv',
        title: 'Management key – Example Key 12345678',
        text: 'A1B2 C3D4',
        addedAt: 0,
        piv: NotePivKey(key: '12345678', algorithm: 'aes256', managementKey: 'a1b2c3d4'),
      );
      final file = await exportVault(_accounts, _services, 'pw', notes: [note], deriveKey: fastKdf);
      final payload = await importVault(file, 'pw', deriveKey: fastKdf);
      expect(payload.notes.single.piv, note.piv);

      final plain = importVaultPlaintext(exportVaultPlaintext(_accounts, _services, notes: [note]));
      expect(plain.notes.single.piv, note.piv);
    });
  });

  // openspec: add-pgp-contacts, task 6.1
  group('contacts', () {
    final contacts = fixtureContacts();

    test('round-trip through an encrypted export, with their checks', () async {
      final file = await exportVault(_accounts, _services, 'pw', keys: _keys, contacts: contacts, deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.contacts, contacts);
      expect(
        (payload.contacts.first.checkedAt, payload.contacts.first.checkedFingerprint),
        (1793696400000, contacts.first.checkedFingerprint),
      );
      expect(payload.contacts.last.checkedAt, isNull);
      expect(payload.accounts, _accounts);
      expect(payload.keys, _keys);
      expect((jsonDecode(file) as Map<String, Object?>)['version'], 2);
      expect(file, isNot(contains('Grace Hopper')));
    });

    test('open the same with the Recovery Kit', () async {
      final rk = RecoveryKey(kitId: 'KITID234', key: randomBytes(32), threshold: 2, shares: 3, createdAt: '2026-10-13T00:00:00.000Z');
      final file = await exportVault(_accounts, _services, 'pw', contacts: contacts, recoveryKey: rk, deriveKey: fastKdf);

      expect((await importVaultWithRecoveryKey(file, rk.key)).contacts, contacts);
    });

    test('round-trip through a plain export', () {
      final file = exportVaultPlaintext(_accounts, _services, contacts: contacts);

      expect(importVaultPlaintext(file).contacts, contacts);
      expect(((jsonDecode(file) as Map<String, Object?>)['contacts']! as List<Object?>), hasLength(2));
    });

    test('a vault without contacts exports byte for byte what it did before contacts', () {
      final before = File('test/fixtures/vault-items/export-plain-before-contacts.json').readAsStringSync();

      final now = exportVaultPlaintext(
        fixtureAccounts,
        fixtureServices,
        keys: fixtureKeys,
        notes: fixtureNotes,
        passkeys: fixturePasskeys,
        now: fixtureWrittenAt,
      );

      expect(now, before);
      expect(now, isNot(contains('contacts')));
      expect(importVaultPlaintext(before).contacts, isEmpty);
    });

    test('are left out of the encrypted payload of a vault that has none', () async {
      final file = await exportVault(_accounts, _services, 'pw', keys: _keys, notes: _notes, passkeys: _passkeys, deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final vault = parsed['vault']! as Map<String, Object?>;
      final sharedSecret = MlKem1024.decapsulate(unb64(vault['kemCT']! as String), secretKey);
      final plain = await aesGcmDecrypt(sharedSecret, unb64(vault['nonce']! as String), unb64(vault['ct']! as String));

      expect((jsonDecode(utf8.decode(plain)) as Map<String, Object?>).keys, ['accounts', 'backupServices', 'keys', 'notes', 'passkeys']);
    });

    test('the export fixtures from before contacts open as before, and give no contact', () async {
      final plain = importVaultPlaintext(File('test/fixtures/vault-items/export-plain.json').readAsStringSync());

      expect(plain.contacts, isEmpty);
      expect(plain.keys, isNotEmpty);
    });

    // Task 6.4: the file a vault with contacts wrote the day they joined exports
    test('the export fixture holding contacts opens, with every kind and both checks', () {
      final text = File('test/fixtures/vault-items/export-with-contacts.json').readAsStringSync();

      final payload = importVaultPlaintext(text);

      expect(payload.contacts, contacts);
      expect(payload.accounts, fixtureAccounts);
      expect(payload.backupServices, fixtureServices);
      expect(payload.keys, fixtureKeys);
      expect(payload.notes, fixtureNotes);
      expect(payload.passkeys, fixturePasskeys);
      // And this version still writes that file, byte for byte
      expect(
        exportVaultPlaintext(
          fixtureAccounts,
          fixtureServices,
          keys: fixtureKeys,
          notes: fixtureNotes,
          passkeys: fixturePasskeys,
          contacts: contacts,
          now: fixtureWrittenAt,
        ),
        text,
      );
    });

    test('a list that is not one, or holds what is not a contact, reads as none', () {
      final base = jsonDecode(exportVaultPlaintext(_accounts, _services)) as Map<String, Object?>;

      expect(importVaultPlaintext(jsonEncode({...base, 'contacts': 'x'})).contacts, isEmpty);
      expect(
        importVaultPlaintext(
          jsonEncode({
            ...base,
            'contacts': [1, null, 'x'],
          }),
        ).contacts,
        isEmpty,
      );
    });
  });

  group('a keyAccounts list in a file', () {
    test('does not keep the rest of an encrypted export from being read', () async {
      final file = await exportVault(_accounts, _services, 'pw', keys: _keys, deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, 'pw');
      final later = await _reseal(
        parsed,
        secretKey,
        jsonEncode({
          'accounts': [for (final a in _accounts) a.toJson()],
          'backupServices': [for (final s in _services) s.toJson()],
          'keys': [for (final key in _keys) key.toJson()],
          'keyAccounts': _laterKeyAccounts,
        }),
      );

      final payload = await importVault(jsonEncode({...parsed, 'vault': later}), 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
      expect(payload.keys, _keys);
    });

    test('does not keep the rest of a plain export from being read', () {
      final later = {
        ...jsonDecode(exportVaultPlaintext(_accounts, _services, notes: _notes)) as Map<String, Object?>,
        'keyAccounts': _laterKeyAccounts,
      };

      final payload = importVaultPlaintext(jsonEncode(later));

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
      expect(payload.notes, _notes);
    });
  });

  // openspec: add-security-key-codes, task 8.1
  group('accounts on a security key', () {
    // Built from a file that wrongly carried a secret, a code and digits: none of them is kept.
    final onKey = [
      for (final json in _laterKeyAccounts) KeyAccount.fromJson({...json, 'secret': _secret, 'code': '287082', 'digits': 6}),
    ];

    Future<Map<String, Object?>> decrypted(String file, String password) async {
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final secretKey = await _openExport(parsed, password);
      final vault = parsed['vault']! as Map<String, Object?>;
      final sharedSecret = MlKem1024.decapsulate(unb64(vault['kemCT']! as String), secretKey);
      return jsonDecode(utf8.decode(await aesGcmDecrypt(sharedSecret, unb64(vault['nonce']! as String), unb64(vault['ct']! as String))))
          as Map<String, Object?>;
    }

    test('are left out of the files of a vault that has none, which stay what they were', () async {
      expect((await decrypted(await exportVault(_accounts, _services, 'pw', deriveKey: fastKdf), 'pw')).keys, [
        'accounts',
        'backupServices',
      ]);
      final plain = exportVaultPlaintext(_accounts, _services, keys: _keys, now: DateTime.utc(2026, 11, 16));
      expect((jsonDecode(plain) as Map<String, Object?>).keys, [
        'version',
        'app',
        'exportedAt',
        'scheme',
        'accounts',
        'backupServices',
        'keys',
      ]);
      expect(plain, exportVaultPlaintext(_accounts, _services, keys: _keys, keyAccounts: const [], now: DateTime.utc(2026, 11, 16)));
    });

    test('round-trip through an encrypted export, beside the rest', () async {
      final file = await exportVault(_accounts, _services, 'pw', keys: _keys, keyAccounts: onKey, deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.accounts, _accounts);
      expect(payload.keys, _keys);
      expect(payload.keyAccounts, onKey);
      expect(payload.keyAccounts.single.tags, ['work']);
      expect((jsonDecode(file) as Map<String, Object?>)['version'], 2);
    });

    test('round-trip through a plain export', () {
      final payload = importVaultPlaintext(exportVaultPlaintext(_accounts, _services, keyAccounts: onKey));

      expect(payload.accounts, _accounts);
      expect(payload.keyAccounts, onKey);
    });

    test('hold no secret, code or digits for them, decrypted or plain', () async {
      final sealed = await decrypted(await exportVault([], [], 'pw', keyAccounts: onKey, deriveKey: fastKdf), 'pw');
      final plain = jsonDecode(exportVaultPlaintext([], [], keyAccounts: onKey)) as Map<String, Object?>;

      for (final payload in [sealed, plain]) {
        final [entry] = payload['keyAccounts']! as List<Object?>;
        expect((entry! as Map<String, Object?>).keys, isNot(anyOf(contains('secret'), contains('code'), contains('digits'))));
        expect(jsonEncode(payload), isNot(contains(_secret)));
        expect(jsonEncode(payload), isNot(contains('287082')));
      }
    });
  });

  group('Recovery Kit exports', () {
    final rk = RecoveryKey(kitId: 'KITID234', key: randomBytes(32), threshold: 2, shares: 3, createdAt: '2026-10-13T00:00:00.000Z');

    test('also open with the kit', () async {
      final file = await exportVault(_accounts, _services, 'export pw', recoveryKey: rk, deriveKey: fastKdf);

      expect(exportRecoveryKit(file), (kitId: rk.kitId, threshold: 2));
      final payload = await importVaultWithRecoveryKey(file, rk.key);
      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
      // The export password still works as before
      expect((await importVault(file, 'export pw', deriveKey: fastKdf)).accounts, _accounts);
    });

    test('keeps exports without a kit as they were', () async {
      final file = await exportVault(_accounts, [], 'export pw', deriveKey: fastKdf);

      expect((jsonDecode(file) as Map<String, Object?>).containsKey('recovery'), isFalse);
      expect(exportRecoveryKit(file), isNull);
      await expectLater(importVaultWithRecoveryKey(file, Uint8List(32)), throwsExportError('without a Recovery Kit'));
    });

    test('reads no kit from a file that is not JSON', () {
      expect(exportRecoveryKit('nope'), isNull);
    });
  });

  // The payload is authenticated by the export's private key (sealed_value.dart)
  group('an authenticated payload', () {
    final rk = RecoveryKey(kitId: 'KITID234', key: randomBytes(32), threshold: 2, shares: 3, createdAt: '2026-10-13T00:00:00.000Z');

    /// What someone who can change the stored file, and has nothing else, puts in it: a payload of
    /// theirs sealed to the public key the file holds.
    Future<String> swapped(String file) async {
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final publicKey = unb64((parsed['config']! as Map<String, Object?>)['publicKey']! as String);
      final theirs = await sealValue(
        Uint8List.fromList(utf8.encode(jsonEncode({'accounts': <Object?>[], 'backupServices': <Object?>[]}))),
        publicKey,
        storageKey: exportSealKey,
      );
      return jsonEncode({...parsed, 'vault': theirs});
    }

    test('a new export says so in both wraps, in the shape every version reads', () async {
      final file = await exportVault(_accounts, _services, 'pw', recoveryKey: rk, deriveKey: fastKdf);
      final parsed = jsonDecode(file) as Map<String, Object?>;
      final config = parsed['config']! as Map<String, Object?>;
      final vault = parsed['vault']! as Map<String, Object?>;

      expect(parsed.keys, ['version', 'app', 'exportedAt', 'scheme', 'config', 'vault', 'recovery']);
      expect(config.keys, ['salt', 'skNonce', 'skEnc', 'publicKey', 'scrypt']);
      expect(vault.keys, ['kemCT', 'nonce', 'ct']);
      expect(isAuthenticatedWrapNonce(config['skNonce']), isTrue);
      expect(isAuthenticatedWrapNonce((parsed['recovery']! as Map<String, Object?>)['nonce']), isTrue);
      final secretKey = await _openExport(parsed, 'pw');
      expect((await openSealedValue(vault, secretKey, storageKey: exportSealKey)).verified, isTrue);
      // As a version from before authenticated payloads opens it
      final sharedSecret = MlKem1024.decapsulate(unb64(vault['kemCT']! as String), secretKey);
      final plain = await aesGcmDecrypt(sharedSecret, unb64(vault['nonce']! as String), unb64(vault['ct']! as String));
      expect(utf8.decode(plain), contains('ACME'));
      expect((await importVault(file, 'pw', deriveKey: fastKdf)).accounts, _accounts);
      expect((await importVaultWithRecoveryKey(file, rk.key)).accounts, _accounts);
    });

    test('a payload swapped by someone who has only the file is refused, by its password and by its kit', () async {
      final file = await swapped(await exportVault(_accounts, _services, 'pw', recoveryKey: rk, deriveKey: fastKdf));

      await expectLater(importVault(file, 'pw', deriveKey: fastKdf), throwsA(isA<AesGcmAuthError>()));
      await expectLater(importVaultWithRecoveryKey(file, rk.key), throwsA(isA<AesGcmAuthError>()));
    });

    test('a kit wrap from another export does not lower what the password wrap says', () async {
      final parsed = jsonDecode(await exportVault(_accounts, _services, 'pw', recoveryKey: rk, deriveKey: fastKdf)) as Map<String, Object?>;
      // An older export of the same kit: its own key pair, under a wrap that says nothing
      final older = MlKem1024.keygen();
      final theirs = await sealValue(
        Uint8List.fromList(utf8.encode(jsonEncode({'accounts': <Object?>[]}))),
        older.publicKey,
        storageKey: exportSealKey,
      );
      final file = jsonEncode({...parsed, 'recovery': await wrapForKit(rk, older.secretKey), 'vault': theirs});

      await expectLater(importVaultWithRecoveryKey(file, rk.key), throwsA(isA<AesGcmAuthError>()));
    });

    test('an export from before reads as it always did, its payload anyone could have sealed', () async {
      // Built as versions before wrote it: wraps with random nonces, a payload sealed to the public key alone
      final salt = randomBytes(32);
      final pair = MlKem1024.keygen();
      final wrapped = await aesGcmEncrypt(await fastKdf('pw', salt), pair.secretKey);
      final payload = await sealValue(
        Uint8List.fromList(
          utf8.encode(
            jsonEncode({
              'accounts': [for (final a in _accounts) a.toJson()],
              'backupServices': <Object?>[],
            }),
          ),
        ),
        pair.publicKey,
        storageKey: exportSealKey,
      );
      final file = jsonEncode({
        'version': 2,
        'app': 'BackMyCodes',
        'exportedAt': '2026-10-16T09:05:03.007Z',
        'scheme': 'ML-KEM-1024 + AES-256-GCM + scrypt(N=131072,r=8,p=1)',
        'config': {
          'salt': b64(salt),
          'skNonce': b64(wrapped.nonce),
          'skEnc': b64(wrapped.ct),
          'publicKey': b64(pair.publicKey),
          'scrypt': {'N': 131072, 'r': 8, 'p': 1},
        },
        'vault': payload,
        'recovery': await wrapForKit(rk, pair.secretKey),
      });

      expect((await importVault(file, 'pw', deriveKey: fastKdf)).accounts, _accounts);
      expect((await importVaultWithRecoveryKey(file, rk.key)).accounts, _accounts);
    });

    test('no export fixture has a wrap that happens to say so', () {
      for (final name in ['export-encrypted.json', 'export-with-key-accounts.json']) {
        final parsed = jsonDecode(File('test/fixtures/vault-items/$name').readAsStringSync()) as Map<String, Object?>;
        expect(isAuthenticatedWrapNonce((parsed['config']! as Map<String, Object?>)['skNonce']), isFalse, reason: name);
        final wrap = parsed['recovery'] as Map<String, Object?>?;
        expect(isAuthenticatedWrapNonce(wrap?['nonce']), isFalse, reason: name);
      }
      final legacy = jsonDecode(File('test/fixtures/legacy-v0.1.0.json').readAsStringSync()) as Map<String, Object?>;
      final fileExport = jsonDecode(legacy['fileExport']! as String) as Map<String, Object?>;
      expect(isAuthenticatedWrapNonce((fileExport['config']! as Map<String, Object?>)['skNonce']), isFalse);
    });
  });

  group('plaintext file export', () {
    test('round-trips accounts and backup services', () {
      final exported = exportVaultPlaintext(_accounts, _services);
      final parsed = jsonDecode(exported) as Map<String, Object?>;

      expect(parsed['app'], 'BackMyCodes');
      expect(parsed['scheme'], 'plaintext');
      final payload = importVaultPlaintext(exported);
      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });

    test('carries the breaches an entry has marked dealt with', () {
      final payload = importVaultPlaintext(exportVaultPlaintext([_dealtWithAccount], [_dealtWithService]));

      expect(payload.accounts.single.toJson()['breachesDismissed'], ['Adobe']);
      expect(payload.backupServices.single.toJson()['breachesDismissed'], ['Adobe']);
    });

    test('reads the codes of a plain export that holds lists a later version added', () {
      final later = {
        ...jsonDecode(exportVaultPlaintext(_accounts, _services)) as Map<String, Object?>,
        'keys': [
          {'id': 'k1', 'name': 'laptop', 'addedAt': 1},
        ],
        'notes': [
          {'id': 'n1', 'title': 'Passport', 'addedAt': 1},
        ],
        'passkeys': [
          {'id': 'p1', 'rpId': 'example.com', 'addedAt': 1},
        ],
      };

      final payload = importVaultPlaintext(jsonEncode(later));

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });

    test('reads the codes of a plain export that holds a contacts list', () {
      final later = {
        ...jsonDecode(exportVaultPlaintext(_accounts, _services)) as Map<String, Object?>,
        'contacts': _laterContacts,
        'holograms': _madeUpList,
      };

      final payload = importVaultPlaintext(jsonEncode(later));

      expect(payload.accounts, _accounts);
      expect(payload.backupServices, _services);
    });

    test('defaults missing sections to empty lists', () {
      final payload = importVaultPlaintext(jsonEncode({'app': 'BackMyCodes', 'scheme': 'plaintext'}));

      expect(payload.accounts, isEmpty);
      expect(payload.backupServices, isEmpty);
    });

    test('refuses encrypted files', () {
      expect(
        () => importVaultPlaintext(jsonEncode({'app': 'BackMyCodes', 'scheme': 'ML-KEM-1024'})),
        throwsExportError('File is encrypted'),
      );
    });

    test('refuses files that are not Kemlock exports', () {
      expect(() => importVaultPlaintext('{}'), throwsExportError('not a Kemlock export'));
      expect(() => importVaultPlaintext('nope'), throwsExportError('not valid JSON'));
    });
  });

  // openspec: add-pgp-mail-provider, task 3.2
  test('an export of a vault with approved mail apps names none of them', () async {
    final store = KeyValueStore.memory();
    final vaultStore = VaultStore(store, VaultRegistry(store), deriveKey: fastKdf);
    final session = await vaultStore.setupVault('pw');
    await vaultStore.saveAccounts(_accounts, session);
    await MailAppsStore(vaultStore)
        .save(const [MailApp(package: 'net.thunderbird.android', cert: 'aa11', name: 'Thunderbird', allowedAt: 1)], session);
    // What the export sheet hands the export: the open vault's lists
    final accounts = await vaultStore.loadAccounts(session);
    final services = await vaultStore.loadBackupServices(session);
    final keys = await vaultStore.loadKeys(session);
    final notes = await vaultStore.loadNotes(session);
    final contacts = await vaultStore.loadContacts(session);

    final plain = exportVaultPlaintext(accounts, services, keys: keys, notes: notes, contacts: contacts);
    expect(plain, isNot(contains('thunderbird')));
    final sealed = await exportVault(accounts, services, 'export pw', keys: keys, notes: notes, contacts: contacts, deriveKey: fastKdf);
    final secretKey = await _openExport(jsonDecode(sealed) as Map<String, Object?>, 'export pw');
    final vault = (jsonDecode(sealed) as Map<String, Object?>)['vault']! as Map<String, Object?>;
    final payload = await aesGcmDecrypt(
      MlKem1024.decapsulate(unb64(vault['kemCT']! as String), secretKey),
      unb64(vault['nonce']! as String),
      unb64(vault['ct']! as String),
    );
    expect(utf8.decode(payload), allOf(contains('ACME'), isNot(contains('thunderbird'))));
  });

  // openspec: add-passwords, task 7.5
  group('logins', () {
    const logins = [
      Login(
        id: 'l1',
        name: 'Larkspur Mail',
        username: 'ada@example.org',
        password: 'hunter2',
        websites: ['larkspur.example'],
        accountId: 'a1',
        previousPasswords: [PreviousPassword(password: 'first', until: 3)],
        addedAt: 2,
      ),
      Login(id: 'l2', name: 'Banking app', password: '1234', addedAt: 4),
    ];

    test('round-trip through an encrypted export, beside the codes', () async {
      final file = await exportVault(_accounts, _services, 'pw', logins: logins, deriveKey: fastKdf);

      final payload = await importVault(file, 'pw', deriveKey: fastKdf);

      expect(payload.logins, logins);
      expect(payload.accounts, _accounts);
      expect(file, isNot(contains('hunter2')));
    });

    test('round-trip through a plain export', () {
      final file = exportVaultPlaintext(_accounts, _services, logins: logins);

      expect(importVaultPlaintext(file).logins, logins);
      expect(file, contains('hunter2'), reason: 'a plain export is readable by anyone');
    });

    test('are left out of a vault that has none', () {
      expect((jsonDecode(exportVaultPlaintext(_accounts, _services)) as Map<String, Object?>).containsKey('logins'), isFalse);
    });

    test('pass over a phone from before logins, which still reads the codes', () {
      final json = jsonDecode(exportVaultPlaintext(_accounts, _services, logins: logins)) as Map<String, Object?>;

      final before = payloadBeforeLogins(json);

      expect(before.accounts, _accounts);
      expect(before.backupServices, _services);
    });
  });

  group('isEncryptedExport', () {
    test('tells encrypted from plaintext exports', () {
      expect(isEncryptedExport(exportVaultPlaintext([], [])), isFalse);
      expect(isEncryptedExport(jsonEncode({'app': 'BackMyCodes', 'scheme': 'ML-KEM'})), isTrue);
    });

    test('throws for files it does not recognise', () {
      expect(() => isEncryptedExport('nope'), throwsExportError('not valid JSON'));
      expect(() => isEncryptedExport('{"app":"x"}'), throwsExportError('not a Kemlock export'));
    });
  });
}

/// The export's ephemeral private key, opened with its password.
Future<Uint8List> _openExport(Map<String, Object?> parsed, String password) async {
  final config = parsed['config']! as Map<String, Object?>;
  final kek = await fastKdf(password, unb64(config['salt']! as String));
  return aesGcmDecrypt(kek, unb64(config['skNonce']! as String), unb64(config['skEnc']! as String));
}

/// The export's `vault` section with [json] in place of its payload, sealed
/// by its private key, as the version that wrote such a file seals it.
Future<Map<String, Object?>> _reseal(Map<String, Object?> parsed, Uint8List secretKey, String json) async {
  final sealed = await sealValue(
    Uint8List.fromList(utf8.encode(json)),
    MlKem1024.publicKeyOf(secretKey),
    storageKey: exportSealKey,
    authKey: sealAuthKey(secretKey),
  );
  return sealed;
}
