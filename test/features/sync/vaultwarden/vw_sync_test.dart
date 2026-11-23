@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/features/keys/key_bridge.dart' show vaultKeyOf;
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_items.dart' show tooLongForNotes;
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

const _secret = 'JBSWY3DPEHPK3PXP';
const _otherSecret = 'KRSXG5CTMVRXEZLU';

OtpAccount _account(String id, {String issuer = 'GitHub', String secret = _secret, int at = 1, OtpType? type, int? counter}) =>
    OtpAccount(id: id, type: type, issuer: issuer, label: 'me@example.com', secret: secret, counter: counter, addedAt: at);

BackupService _codes(String id, {int at = 1}) => BackupService(
  id: id,
  serviceName: 'GitHub',
  codes: const [
    BackupCode(code: 'aaaa-1111'),
    BackupCode(code: 'bbbb-2222'),
  ],
  addedAt: at,
);

/// [entry] as it is once a breach of its service was marked dealt with.
T _dealtWith<T>(T entry) => switch (entry) {
  OtpAccount() => OtpAccount.fromJson({
    ...entry.toJson(),
    'breachesDismissed': ['Adobe'],
  }),
  BackupService() => BackupService.fromJson({
    ...entry.toJson(),
    'breachesDismissed': ['Adobe'],
  }),
  _ => throw ArgumentError.value(entry),
} as T;

/// One phone syncing a vault's own entries with the home.
class _Phone {
  _Phone(this.server, this.target) : reader = VwReader(server.userKey);

  final FakeVaultwarden server;
  VaultwardenTarget target;
  final VwReader reader;
  Lists lists = const Lists();
  ScopeState state = const ScopeState(known: []);
  late VwCredentials credentials = server.credentials();
  var stored = 0;

  List<OtpAccount> get accounts => lists.accounts;

  VaultwardenScopeSync get _scope => VaultwardenScopeSync(
    connection: VwConnection(
      api: VwApi(server.client),
      server: FakeVaultwarden.url,
      credentials: credentials,
      onCredentials: (next) async {
        credentials = next;
        stored++;
      },
    ),
    reader: reader,
    target: target,
  );

  Future<VwSyncPreview> preview({bool newHome = false}) => _scope.preview(lists, now: server.revision + 500, newHome: newHome);

  Future<VwSyncResult> sync({RemovalChoice? choice, int? now}) async {
    final at = now ?? server.revision + 500;
    final result = await _scope.sync(lists, state, now: at, choice: choice);
    lists = applyScope(lists, null, result.doc);
    state = ScopeState(known: result.known, lastSyncAt: at, extra: result.state);
    return result;
  }
}

/// The live items of the home's folder, decrypted names first.
Future<List<(Map<String, Object?>, String)>> _items(FakeVaultwarden server, {bool trash = false}) async => [
  for (final cipher in server.ciphers.values)
    if ((cipher['deletedDate'] != null) == trash) (cipher, await bwDecryptString(cipher['name']! as String, server.userKey)),
];

Future<String?> _open(Object? value, BwKey key) async => value is String ? bwDecryptString(value, key) : null;

/// Every value of an item, decrypted, for checking what Bitwarden apps show.
Future<List<String>> _plainText(Map<String, Object?> cipher, BwKey key) async {
  final login = cipher['login'] as Map<String, Object?>? ?? const {};
  return [
    for (final value in [cipher['name'], cipher['notes'], login['username'], login['password'], login['totp']]) ?await _open(value, key),
    for (final field in (cipher['fields'] as List<Object?>? ?? const []).cast<Map<String, Object?>>()) ...[
      ?await _open(field['name'], key),
      ?await _open(field['value'], key),
    ],
  ];
}

/// A Bitwarden app's edit: [change] gets the item's values decrypted and
/// returns the ones to change, which are encrypted and saved.
Future<void> _editInBitwarden(FakeVaultwarden server, String id, Map<String, Object?> Function(Map<String, Object?> values) change) async {
  final cipher = server.ciphers[id]!;
  final key = server.userKey;
  final login = {...?(cipher['login'] as Map<String, Object?>?)};
  final values = <String, Object?>{
    'name': await _open(cipher['name'], key),
    'notes': await _open(cipher['notes'], key),
    'username': await _open(login['username'], key),
    'totp': await _open(login['totp'], key),
    'favorite': cipher['favorite'],
  };
  final next = change(values);
  final body = {...cipher};
  for (final MapEntry(key: name, :value) in next.entries) {
    final encrypted = value is String ? await bwEncryptString(value, key) : value;
    switch (name) {
      case 'username' || 'totp' || 'password':
        login[name] = encrypted;
      default:
        body[name] = encrypted;
    }
  }
  body['login'] = cipher['login'] == null ? null : login;
  server.put(body, id: id);
}

void main() {
  group('sealed storage', () {
    test('uploads the entries sealed, and a second phone gets them', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')], backupServices: [_codes('s1')]);

      await phone.sync();

      final items = await _items(server);
      expect(items.map((item) => item.$2), unorderedEquals(['Kemlock', sealedEntryName, sealedEntryName]));
      // Nothing of the entries shows in Vaultwarden
      for (final (cipher, _) in items) {
        final text = (await _plainText(cipher, server.userKey)).join(' ');
        expect(text, isNot(contains(_secret)));
        expect(text, isNot(contains('GitHub')));
        expect(text, isNot(contains('aaaa-1111')));
      }

      final other = _Phone(server, target);
      await other.sync();
      expect(other.accounts.single.secret, _secret);
      expect(other.lists.backupServices.single.codes.first.code, 'aaaa-1111');
    });

    test('carries the breaches an entry has marked dealt with', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)
        ..lists = Lists(accounts: [_dealtWith(_account('a1'))], backupServices: [_dealtWith(_codes('s1'))]);

      await phone.sync();
      final other = _Phone(server, target);
      await other.sync();

      expect(other.accounts.single.toJson()['breachesDismissed'], ['Adobe']);
      expect(other.lists.backupServices.single.toJson()['breachesDismissed'], ['Adobe']);
    });

    test('passes edits and deletions between phones', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final a = _Phone(server, target)
        ..lists = Lists(
          accounts: [
            _account('a1'),
            _account('a2', issuer: 'GitLab', secret: _otherSecret),
          ],
        );
      final b = _Phone(server, target);
      await a.sync();
      await b.sync();

      a.lists = Lists(
        accounts: [a.accounts.first.copyWith(issuer: 'GitHub work', updatedAt: server.revision + 100)],
      );
      await a.sync();
      await b.sync();

      expect(b.accounts.single.issuer, 'GitHub work');
      final trashed = await _items(server, trash: true);
      expect(trashed.single.$2, sealedEntryName);
    });

    test('stops with a key problem when the seal key does not open the home', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(
        server,
        target.copyWith(
          seal: VwSeal(key: b64(randomBytes(32)), kdf: target.seal!.kdf),
        ),
      )..lists = Lists(accounts: [_account('a1')]);

      await expectLater(phone.sync(), throwsA(isA<SyncFileError>().having((e) => e.problem, 'problem', SyncFileProblem.key)));
      expect(await _items(server), hasLength(1));
    });

    test('leaves an item it cannot open alone, and keeps the entry here', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final a = _Phone(server, target)
        ..lists = Lists(
          accounts: [
            _account('a1'),
            _account('a2', secret: _otherSecret),
          ],
        );
      await a.sync();

      // Another phone, with another key, wrote a2 again
      final (cipher, _) = (await _items(server)).firstWhere((item) => item.$2 == sealedEntryName && _fieldOf(item.$1) != null);
      final id = cipher['id']! as String;
      final value = await bwDecryptString(_fieldOf(cipher)!['value']! as String, server.userKey);
      final entryId = sealedHeader(value)!.id;
      final wrong = await sealEntry(_account(entryId, issuer: 'Changed'), target.home, randomBytes(32));
      final changed = jsonDecode(jsonEncode(cipher)) as Map<String, Object?>;
      (changed['fields']! as List<Object?>)[0] = {
        ...(changed['fields']! as List<Object?>)[0]! as Map<String, Object?>,
        'value': await bwEncryptString(wrong, server.userKey),
      };
      server.put(changed, id: id);
      final before = jsonEncode(server.ciphers[id]);

      final result = await a.sync();

      expect(result.skipped, 1);
      expect(a.accounts.map((account) => account.id), containsAll(['a1', 'a2']));
      expect(a.accounts.firstWhere((account) => account.id == entryId).issuer, 'GitHub');
      expect(jsonEncode(server.ciphers[id]), before);
      expect(a.state.known, contains(entryId));
    });
  });

  group('plain storage', () {
    test('writes logins Bitwarden apps show, with the code', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)
        ..lists = Lists(
          accounts: [_account('a1').copyWith(note: 'a note', pinned: true)],
          backupServices: [_codes('s1')],
        );

      await phone.sync();

      final login = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub').$1;
      final values = login['login']! as Map<String, Object?>;
      expect(await bwDecryptString(values['username']! as String, server.userKey), 'me@example.com');
      expect(
        await bwDecryptString(values['totp']! as String, server.userKey),
        allOf(startsWith('otpauth://totp/GitHub:me%40example.com?'), contains('secret=$_secret')),
      );
      expect(await bwDecryptString(login['notes']! as String, server.userKey), 'a note');
      expect(login['favorite'], isTrue);
      expect(login['folderId'], target.folderId);

      final note = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub backup codes').$1;
      expect(await bwDecryptString(note['notes']! as String, server.userKey), 'aaaa-1111\nbbbb-2222');
    });

    // openspec: add-post-quantum-pgp, task 8.6
    test('holds a standard post-quantum key back as too long, counts it, and writes a GnuPG-format one', () async {
      Future<VaultKey> key(String name, String id, String title) async => vaultKeyOf(
        await crypto.readPrivateKey(File('test/fixtures/keys/kemlock/$name.unprotected.asc').readAsStringSync()),
        id: id,
        name: title,
        origin: KeyOrigin.generated,
      );
      final standard = await key('pgp-pq-standard', 'k-standard', 'Ada, post-quantum');
      final gnupg = await key('pgp-pq-gnupg', 'k-gnupg', 'Ada, for GnuPG');
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain, plainKinds: agreedToAll);
      final phone = _Phone(server, target)..lists = Lists(keys: [standard, gnupg]);

      expect((await phone.preview()).tooLong, ['k-standard']);
      final result = await phone.sync();

      expect(result.state['tooLong'], ['k-standard']);
      expect(phone.lists.keys.map((key) => key.id), unorderedEquals(['k-standard', 'k-gnupg']));
      final items = await _items(server);
      expect([for (final (_, name) in items) name], unorderedEquals(['Kemlock', 'Ada, for GnuPG']));
      final item = items.singleWhere((item) => item.$2 == 'Ada, for GnuPG').$1;
      final notes = await bwDecryptString(item['notes']! as String, server.userKey);
      expect(notes, startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----'));
      expect(tooLongForNotes(notes), isFalse);
      // It isn't taken for a deletion later either, and another phone gets
      // the GnuPG-format key
      final again = await phone.sync();
      expect(again.state['tooLong'], ['k-standard']);
      expect(phone.lists.keys, hasLength(2));
      final other = _Phone(server, target);
      await other.sync();
      expect(other.lists.keys.single.publicKey, gnupg.publicKey);
    });

    test('carries the breaches an entry has marked dealt with', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)
        ..lists = Lists(accounts: [_dealtWith(_account('a1'))], backupServices: [_dealtWith(_codes('s1'))]);

      await phone.sync();
      final other = _Phone(server, target);
      await other.sync();

      expect(other.accounts.single.toJson()['breachesDismissed'], ['Adobe']);
      expect(other.lists.backupServices.single.toJson()['breachesDismissed'], ['Adobe']);
    });

    test('takes edits made in Bitwarden, as of the item revision', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')], backupServices: [_codes('s1')]);
      await phone.sync();

      final login = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub').$1;
      await _editInBitwarden(server, login['id']! as String, (values) => {'name': 'GitHub (work)', 'totp': _otherSecret});
      final note = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub backup codes').$1;
      await _editInBitwarden(server, note['id']! as String, (values) => {'notes': 'aaaa-1111\n✓ bbbb-2222\n\n---\nIn the drawer'});

      await phone.sync();

      final account = phone.accounts.single;
      expect((account.issuer, account.secret, account.algorithm, account.digits), ('GitHub (work)', _otherSecret, 'SHA1', 6));
      expect(account.updatedAt, DateTime.parse(server.ciphers[login['id']]!['revisionDate']! as String).millisecondsSinceEpoch);
      final service = phone.lists.backupServices.single;
      expect(service.codes.map((code) => code.used), [false, true]);
      expect(service.codes.last.usedAt, isNotNull);
      expect(service.note, 'In the drawer');
    });

    test('a code removed in Bitwarden deletes the account here', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      await phone.sync();
      final login = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub').$1;

      await _editInBitwarden(server, login['id']! as String, (values) => {'totp': null});
      await phone.sync();

      expect(phone.accounts, isEmpty);
      // The login itself stays, as the user left it
      expect(server.ciphers[login['id']]!['deletedDate'], isNull);
    });

    test("puts the code in the user's login with the same secret, and keeps everything else", () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain, pickUp: true);
      final key = server.userKey;
      final login = server.put({
        'type': 1,
        'name': await bwEncryptString('GitHub', key),
        'notes': await bwEncryptString('my notes', key),
        'fields': [
          {'type': 0, 'name': await bwEncryptString('PIN', key), 'value': await bwEncryptString('1234', key), 'linkedId': null},
        ],
        'login': {
          'username': await bwEncryptString('me@example.com', key),
          'password': await bwEncryptString('hunter2', key),
          'totp': await bwEncryptString(_secret, key),
          'uris': [
            {'uri': await bwEncryptString('https://github.com', key), 'match': null},
          ],
          'fido2Credentials': [
            {'credentialId': await bwEncryptString('passkey', key)},
          ],
        },
        'passwordHistory': [
          {'password': await bwEncryptString('old', key), 'lastUsedDate': '2026-01-01T00:00:00.000Z'},
        ],
      });
      final id = login['id']! as String;
      final phone = _Phone(server, target)
        ..lists = Lists(
          accounts: [_account('a1', at: server.revision + 100).copyWith(note: 'mine')],
        );

      await phone.sync();

      // One account, under the login's id, and no new item
      expect(phone.accounts.single.id, pickedUpId(id));
      expect((await _items(server)).where((item) => item.$2 == 'GitHub'), hasLength(1));
      final after = server.ciphers[id]!;
      final values = after['login']! as Map<String, Object?>;
      final valuesBefore = login['login']! as Map<String, Object?>;
      for (final name in ['username', 'password', 'uris', 'fido2Credentials']) {
        expect(values[name], valuesBefore[name], reason: name);
      }
      expect(after['name'], login['name']);
      expect(after['notes'], login['notes']);
      expect(after['passwordHistory'], login['passwordHistory']);
      expect((after['fields']! as List<Object?>).first, (login['fields']! as List<Object?>).first);
      final field = (after['fields']! as List<Object?>).last! as Map<String, Object?>;
      expect(await bwDecryptString(field['name']! as String, key), fieldName);

      // Deleting it here takes only the code off the login
      phone.lists = const Lists();
      await phone.sync();
      final unlinked = server.ciphers[id]!;
      expect(unlinked['deletedDate'], isNull);
      expect((unlinked['login']! as Map<String, Object?>)['totp'], isNull);
      expect((unlinked['login']! as Map<String, Object?>)['password'], valuesBefore['password']);
      expect(unlinked['fields'], login['fields']);
    });

    test('picks up logins with a code only when asked', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      server.put({
        'type': 1,
        'name': await bwEncryptString('Steam', server.userKey),
        'login': {
          'username': await bwEncryptString('gamer', server.userKey),
          'totp': await bwEncryptString('steam://$_secret', server.userKey),
        },
      });

      final off = _Phone(server, target);
      await off.sync();
      expect(off.accounts, isEmpty);

      final on = _Phone(server, target.copyWith(pickUp: true));
      await on.sync();
      final account = on.accounts.single;
      expect((account.issuer, account.label, account.kind), ('Steam', 'gamer', OtpType.steam));
      expect(account.id, startsWith('vw-'));
    });

    test('keeps HOTP out of the login code, in the field', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('h1', type: OtpType.hotp, counter: 4)]);
      await phone.sync();

      final login = (await _items(server)).singleWhere((item) => item.$2 == 'GitHub').$1;
      expect((login['login']! as Map<String, Object?>)['totp'], isNull);

      final other = _Phone(server, target);
      await other.sync();
      expect((other.accounts.single.kind, other.accounts.single.counter), (OtpType.hotp, 4));

      // Counters never go back
      phone.lists = Lists(accounts: [phone.accounts.single.copyWith(counter: 9, updatedAt: server.revision + 10)]);
      other.lists = Lists(accounts: [other.accounts.single.copyWith(counter: 6, updatedAt: server.revision + 20)]);
      await phone.sync();
      await other.sync();
      expect(other.accounts.single.counter, 9);
    });
  });

  group('either storage', () {
    for (final mode in VaultwardenMode.values) {
      test('${mode.name}: an item trashed or deleted for good in Vaultwarden is deleted here', () async {
        final server = FakeVaultwarden();
        final target = await makeHome(server, mode);
        final phone = _Phone(server, target)
          ..lists = Lists(
            accounts: [
              _account('a1'),
              _account('a2', secret: _otherSecret),
              _account('a3', secret: 'GEZDGNBVGY3TQOJQ'),
            ],
          );
        await phone.sync();
        final entries = [
          for (final item in await _items(server))
            if (item.$2 != 'Kemlock') item.$1['id']! as String,
        ];

        server.trash(entries[0]);
        server.purge(entries[1]);
        await phone.sync();

        expect(phone.accounts, hasLength(1));
      });

      test('${mode.name}: an edit made here after a deletion there wins', () async {
        final server = FakeVaultwarden();
        final target = await makeHome(server, mode);
        final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
        await phone.sync();
        final entry = [
          for (final item in await _items(server))
            if (item.$2 != 'Kemlock') item.$1['id']! as String,
        ].single;

        server.trash(entry);
        phone.lists = Lists(
          accounts: [phone.accounts.single.copyWith(issuer: 'Renamed', updatedAt: server.revision + 1000)],
        );
        await phone.sync(now: server.revision + 2000);

        expect(phone.accounts.single.issuer, 'Renamed');
        expect(server.ciphers[entry]!['deletedDate'], isNull, reason: 'restored from the trash');
      });

      test('${mode.name}: a deletion the server dates years ahead is taken as of this run', () async {
        final server = FakeVaultwarden();
        final target = await makeHome(server, mode);
        final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
        await phone.sync();
        final entry = [
          for (final item in await _items(server))
            if (item.$2 != 'Kemlock') item.$1['id']! as String,
        ].single;

        server.trash(entry);
        server.ciphers[entry] = {...server.ciphers[entry]!, 'deletedDate': '2099-01-01T00:00:00.000000Z'};
        final at = server.revision + 500;
        final result = await phone.sync(now: at);

        expect(phone.accounts, isEmpty);
        expect([for (final tombstone in result.doc.deleted) tombstone.at], [at]);
      });
    }

    test('merges again when another phone changes an item between the read and the write', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final a = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      final b = _Phone(server, target);
      await a.sync();
      await b.sync();

      a.lists = Lists(
        accounts: [a.accounts.single.copyWith(issuer: 'From A', updatedAt: server.revision + 10)],
      );
      b.lists = Lists(
        accounts: [b.accounts.single.copyWith(issuer: 'From B', updatedAt: server.revision + 20)],
      );
      // B writes after A has read the vault and before A writes
      var reads = 0;
      server.respond = (request) async {
        if (request.url.path == '/api/sync' && reads++ == 0) {
          final answer = await server.handle(request);
          server.respond = null;
          await b.sync();
          return answer;
        }
        return server.handle(request);
      };
      await a.sync();
      await b.sync();

      expect(a.accounts.single.issuer, 'From B');
      expect(b.accounts.single.issuer, 'From B');
      expect(server.requests.where((r) => r.url.path == '/api/sync').length, greaterThan(3));
    });

    test('stops and asks before removing many entries, then does as told', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..lists = Lists(accounts: [for (var i = 0; i < 8; i++) _account('a$i', secret: base32Of(i))]);
      await phone.sync();
      for (final (cipher, name) in await _items(server)) {
        if (name != 'Kemlock' && server.ciphers.length > 4) server.purge(cipher['id']! as String);
      }
      final left = server.ciphers.length;

      await expectLater(phone.sync(), throwsA(isA<VwSyncError>().having((e) => e.issue, 'issue', VwSyncIssue.removals)));
      expect(phone.accounts, hasLength(8));

      await phone.sync(choice: RemovalChoice.keep);
      expect(phone.accounts, hasLength(8));
      expect(server.ciphers.length, greaterThan(left), reason: 'what was missing there came back');

      for (final (cipher, name) in await _items(server)) {
        if (name != 'Kemlock' && server.ciphers.length > 4) server.trash(cipher['id']! as String);
      }
      await expectLater(phone.sync(), throwsA(isA<VwSyncError>()));
      await phone.sync(choice: RemovalChoice.remove);
      expect(phone.accounts.length, lessThan(8));
    });

    test('asks too when a few entries go after the last day’s runs took others', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..lists = Lists(accounts: [for (var i = 0; i < 20; i++) _account('a$i', secret: base32Of(i))]);
      await phone.sync();
      // The server no longer hands out three of the items, as one that means to empty the vault would
      Future<void> withholdThree() async {
        final entries = [
          for (final (cipher, name) in await _items(server))
            if (name != 'Kemlock') cipher['id']! as String,
        ];
        entries.take(3).forEach(server.purge);
      }

      final asks = throwsA(isA<VwSyncError>().having((e) => e.issue, 'issue', VwSyncIssue.removals).having((e) => e.count, 'count', 3));

      // Three of twenty: few enough for one run
      await withholdThree();
      await phone.sync();
      expect(phone.accounts, hasLength(17));

      // Three more the same day make six of twenty
      await withholdThree();
      await expectLater(phone.sync(), asks);
      expect(phone.accounts, hasLength(17));

      // Told to keep everything, the phone puts them back, and still counts the first three
      await phone.sync(choice: RemovalChoice.keep);
      expect(phone.accounts, hasLength(17));
      expect(await _items(server), hasLength(18));
      await withholdThree();
      await expectLater(phone.sync(), asks);

      // Told to remove them, it does, and counts from none
      await phone.sync(choice: RemovalChoice.remove);
      expect(phone.accounts, hasLength(14));
      await withholdThree();
      await phone.sync();
      expect(phone.accounts, hasLength(11));

      // Those three count for a day, and no longer
      await withholdThree();
      await expectLater(phone.sync(), asks);
      await phone.sync(now: server.revision + removalWindow.inMilliseconds);
      expect(phone.accounts, hasLength(8));
    });

    test('stops without changing anything when the home is gone or its storage changed', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      await phone.sync();
      final home = (await _items(server)).singleWhere((item) => item.$2 == 'Kemlock').$1;

      final other = _Phone(server, target.copyWith(mode: VaultwardenMode.sealed));
      await expectLater(other.sync(), throwsA(isA<VwSyncError>().having((e) => e.issue, 'issue', VwSyncIssue.modeChanged)));

      server.trash(home['id']! as String);
      final before = jsonEncode(server.ciphers);
      await expectLater(phone.sync(), throwsA(isA<VwSyncError>().having((e) => e.issue, 'issue', VwSyncIssue.homeMissing)));
      expect(jsonEncode(server.ciphers), before);
      expect(phone.accounts, hasLength(1));
    });

    test('only asks for the revision date when nothing changed', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      await phone.sync();
      await phone.sync(); // reads once more after its own writes
      server.requests.clear();

      await phone.sync();

      expect(server.requests.map((r) => r.url.path), ['/api/accounts/revision-date']);
    });

    test('renews the token, stores it, and reports a revoked session', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..credentials = server.credentials(expiresAt: 0);
      await phone.sync();
      expect(phone.stored, 1);
      expect(phone.credentials.expiresAt, greaterThan(0));

      server.revoked = true;
      phone.credentials = phone.credentials.withTokens(accessToken: 'x', refreshToken: 'y', expiresAt: 0);
      await expectLater(phone.sync(), throwsA(isA<VwError>().having((e) => e.problem, 'problem', VwProblem.signedOut)));
    });

    test("renews an API key's session by signing in with the key again", () async {
      final server = FakeVaultwarden();
      await server.allowSignIn();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)
        ..credentials = server.credentials(expiresAt: 0).withTokens(accessToken: 'expired', refreshToken: '', expiresAt: 0);
      phone.credentials = VwCredentials.fromJson({
        ...phone.credentials.toJson(),
        'clientId': FakeVaultwarden.apiKey.clientId,
        'clientSecret': FakeVaultwarden.apiKey.clientSecret,
      });

      await phone.sync();

      expect(server.apiKeySignIns, 1);
      expect(phone.stored, 1);
      expect(phone.credentials.clientSecret, FakeVaultwarden.apiKey.clientSecret);
      expect(phone.credentials.expiresAt, greaterThan(0));
    });

    test('moves entries kept the other way when the home changes how it keeps them', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      await phone.sync();

      // The home now keeps entries plain
      final (homeCipher, _) = (await _items(server)).singleWhere((item) => item.$2 == 'Kemlock');
      final reader = VwReader(server.userKey);
      final home = (await reader.read([VwCipher(homeCipher)])).homes.single;
      final writer = VwWriter(userKey: server.userKey, userId: FakeVaultwarden.userId);
      server.put(await writer.updateHome(home, home.home.copyWith(mode: VaultwardenMode.plain)), id: homeCipher['id']! as String);
      phone.target = target.copyWith(mode: VaultwardenMode.plain);

      await phone.sync();

      final names = [for (final item in await _items(server)) item.$2];
      expect(names, unorderedEquals(['Kemlock', 'GitHub']));
      expect((await _items(server, trash: true)).single.$2, sealedEntryName);
      expect(phone.accounts.single.id, 'a1');
    });
  });

  group('what a first sync would do', () {
    ({int to, int toLists, int from, int fromLists, int removedHere, int removedThere}) counts(VwSyncPreview preview) => (
      to: preview.toVaultAccounts,
      toLists: preview.toVaultServices,
      from: preview.fromVaultAccounts,
      fromLists: preview.fromVaultServices,
      removedHere: preview.removedHere,
      removedThere: preview.removedThere,
    );

    test('counts what goes each way when joining a home, and writes nothing', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final first = _Phone(server, target)
        ..lists = Lists(
          accounts: [
            _account('a1'),
            _account('a2', issuer: 'GitLab', secret: _otherSecret),
          ],
          backupServices: [_codes('s1')],
        );
      await first.sync();
      final before = (jsonEncode(server.ciphers), server.revision);

      final joining = _Phone(server, target)
        ..lists = Lists(
          accounts: [_account('a3', issuer: 'Proton', secret: base32Of(3))],
        );
      final preview = await joining.preview();

      expect(counts(preview), (to: 1, toLists: 0, from: 2, fromLists: 1, removedHere: 0, removedThere: 0));
      expect(preview.isEmpty, isFalse);
      expect((jsonEncode(server.ciphers), server.revision), before, reason: 'a preview writes nothing');
      // The sync itself does what the preview said
      await joining.sync();
      expect(joining.accounts.map((account) => account.id), unorderedEquals(['a1', 'a2', 'a3']));
      expect(joining.lists.backupServices.single.id, 's1');
    });

    test('counts every entry of a new home as going, and picked-up logins as coming', () async {
      final server = FakeVaultwarden();
      await putUserLogin(server, server.userKey, secret: _otherSecret);
      // The home isn't made yet: its id is in no item
      final target = VaultwardenTarget(
        server: FakeVaultwarden.url.toString(),
        email: server.email,
        home: newHomeId(),
        mode: VaultwardenMode.plain,
        folderId: '',
        pickUp: true,
      );
      final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')], backupServices: [_codes('s1')]);

      final preview = await phone.preview(newHome: true);

      expect(counts(preview), (to: 1, toLists: 1, from: 1, fromLists: 0, removedHere: 0, removedThere: 0));
      await expectLater(phone.preview(), throwsA(isA<VwSyncError>()), reason: 'a home that should be there still has to be');
    });

    test('counts entries deleted on another device as leaving this phone', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.sealed);
      final first = _Phone(server, target)
        ..lists = Lists(
          accounts: [
            _account('a1'),
            _account('a2', issuer: 'GitLab', secret: _otherSecret),
          ],
        );
      await first.sync();
      first.lists = Lists(accounts: [first.accounts.firstWhere((account) => account.id == 'a1')]);
      await first.sync();

      // A phone with an older copy of the vault, from before a2 was deleted
      final restored = _Phone(server, target)
        ..lists = Lists(
          accounts: [
            _account('a1'),
            _account('a2', issuer: 'GitLab', secret: _otherSecret),
          ],
        );
      final preview = await restored.preview();

      expect(counts(preview), (to: 0, toLists: 0, from: 0, fromLists: 0, removedHere: 1, removedThere: 0));
    });

    test('is empty when both sides hold the same entries', () async {
      final server = FakeVaultwarden();
      final target = await makeHome(server, VaultwardenMode.plain);
      final first = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
      await first.sync();

      final second = _Phone(server, target)..lists = first.lists;
      expect((await second.preview()).isEmpty, isTrue);
    });
  });
}

Map<String, Object?>? _fieldOf(Map<String, Object?> cipher) =>
    (cipher['fields'] as List<Object?>?)?.cast<Map<String, Object?>>().where((field) => field['type'] == 1).firstOrNull;

/// A distinct valid secret for each [i].
String base32Of(int i) => 'JBSWY3DPEHPK3P${'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[i]}Q';
