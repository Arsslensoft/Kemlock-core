@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

/// Items of kinds added after accounts and backup codes: keys, notes and
/// passkeys, which this build reads, and one no version has made, which it
/// must leave alone while it keeps syncing its own entries.
///
/// Before keys, notes and passkeys were built, these tests pinned that a
/// build which doesn't know a kind reads its items as unreadable, writes
/// nothing to them, and doesn't take their coming or going for a change to
/// its own entries (425d921, "pin that today's readers leave later vault
/// items alone"). Phones that stay on such a build still do exactly that;
/// the made-up kind keeps the guarantee pinned here for later kinds.
const _laterKinds = {
  'key': {'id': 'k1', 'name': 'laptop', 'kind': 'ssh', 'algorithm': 'ed25519', 'private': 'AA==', 'addedAt': 1},
  'note': {'id': 'n1', 'title': 'Passport', 'text': 'In the drawer', 'addedAt': 1},
  'passkey': {
    'id': 'p1',
    'credentialId': 'AA',
    'rpId': 'example.com',
    'userHandle': 'AA',
    'userName': 'me',
    'privateKey': 'AA==',
    'addedAt': 1,
  },
  // Someone's public key. Until this build kept contacts it read this item as unreadable and left it
  // alone (dfe3e73 pinned that); it reads it now, like the three kinds above
  'contact': {'id': 'c1', 'name': 'Grace Hopper', 'public': 'mDMEavvBvhYJ', 'source': 'qr', 'addedAt': 1},
  'hologram': {'id': 'h1', 'addedAt': 1},
};

/// The kind no version knows.
const _madeUp = 'hologram';

/// The kinds this build reads.
const _known = {'key', 'note', 'passkey', 'contact'};

/// [json] as the entry of [kind] it is.
Object _entryOf(String kind, Map<String, Object?> json) => switch (kind) {
  'key' => VaultKey.fromJson(json),
  'note' => SecureNote.fromJson(json),
  'contact' => Contact.fromJson(json),
  _ => Passkey.fromJson(json),
};

const _secret = 'JBSWY3DPEHPK3PXP';

OtpAccount _account(String id) => OtpAccount(id: id, issuer: 'GitHub', label: 'me@example.com', secret: _secret, addedAt: 1);

/// [entry] of [kind] sealed with [key], as a later version seals it.
Future<String> _sealLater(String kind, Map<String, Object?> entry, String home, Uint8List key) async {
  final sealed = await aesGcmEncrypt(key, utf8.encode(jsonEncode({'kind': kind, 'entry': entry})));
  return 'kemlock-sealed:1:$home:${entry['id']}:${b64(sealed.nonce)}:${b64(sealed.ct)}';
}

/// [entry] of [kind] as a later version's plain field.
String _plainLater(String kind, Map<String, Object?> entry, String home) =>
    jsonEncode({'v': 1, 'home': home, 'id': entry['id'], 'own': true, 'kind': kind, 'sum': 'AAAAAAAAAAAAAAAAAAAAAA==', 'entry': entry});

/// Puts an item in the home holding [field] in its `Kemlock` field, as a
/// secure note, the way a later version would write it.
Future<String> _putItem(FakeVaultwarden server, VaultwardenTarget target, String name, String field) async {
  final writer = VwWriter(userKey: server.userKey, userId: FakeVaultwarden.userId);
  final body = await writer.create(
    _account('placeholder'),
    form: VaultwardenMode.sealed,
    home: target.home,
    folderId: target.folderId,
    sealKey: Uint8List(32),
  );
  final item = server.put({
    ...body,
    'name': await bwEncryptString(name, server.userKey),
    'fields': [
      {
        'type': 1,
        'name': await bwEncryptString(fieldName, server.userKey),
        'value': await bwEncryptString(field, server.userKey),
        'linkedId': null,
      },
    ],
  });
  return item['id']! as String;
}

/// One phone of this build syncing a vault's own entries with the home.
class _Phone {
  _Phone(this.server, this.target) : reader = VwReader(server.userKey);

  final FakeVaultwarden server;
  final VaultwardenTarget target;
  final VwReader reader;
  Lists lists = const Lists();
  ScopeState state = const ScopeState(known: []);
  late VwCredentials credentials = server.credentials();

  Future<VwSyncResult> sync() async {
    final at = server.revision + 500;
    final result = await VaultwardenScopeSync(
      connection: VwConnection(
        api: VwApi(server.client),
        server: FakeVaultwarden.url,
        credentials: credentials,
        onCredentials: (next) async => credentials = next,
      ),
      reader: reader,
      target: target,
    ).sync(lists, state, now: at);
    lists = applyScope(lists, null, result.doc);
    state = ScopeState(known: result.known, lastSyncAt: at, extra: result.state);
    return result;
  }
}

void main() {
  for (final mode in VaultwardenMode.values) {
    // The kinds this build reads, sealed and plain
    const readable = _known;

    group('${mode.name} items of kinds added after codes', () {
      late FakeVaultwarden server;
      late VaultwardenTarget target;
      late Map<String, String> itemIds;

      setUp(() async {
        server = FakeVaultwarden();
        target = await makeHome(server, mode);
        itemIds = {};
        for (final MapEntry(key: kind, value: entry) in _laterKinds.entries) {
          if (mode == VaultwardenMode.plain && readable.contains(kind)) {
            // The kinds this build keeps plain, in the items it makes for them
            final writer = VwWriter(userKey: server.userKey, userId: FakeVaultwarden.userId);
            final body = await writer.create(_entryOf(kind, entry), form: mode, home: target.home, folderId: target.folderId);
            itemIds[kind] = server.put(body)['id']! as String;
            continue;
          }
          final field = mode == VaultwardenMode.sealed
              ? await _sealLater(kind, entry, target.home, unb64(target.seal!.key))
              : _plainLater(kind, entry, target.home);
          itemIds[kind] = await _putItem(server, target, 'A later $kind', field);
        }
      });

      test('read the kinds this build knows, and the made-up one as unreadable', () async {
        final ciphers = [for (final cipher in server.ciphers.values) VwCipher(cipher)];
        final sealKey = target.seal == null ? null : unb64(target.seal!.key);

        final read = await VwReader(server.userKey).read(ciphers, home: target.home, sealKey: sealKey);

        final claims = {for (final claim in read.entries) claim.id: claim};
        for (final MapEntry(key: kind, value: entry) in _laterKinds.entries) {
          final claim = claims[entry['id']]!;
          expect(claim.unreadable, !readable.contains(kind), reason: kind);
          expect(claim.entry == null, !readable.contains(kind), reason: kind);
        }
        if (readable.isNotEmpty) {
          expect(claims['k1']!.entry, isA<VaultKey>());
          expect((claims['n1']!.entry! as SecureNote).text, 'In the drawer');
          expect((claims['p1']!.entry! as Passkey).rpId, 'example.com');
        }
      });

      test('the made-up kind is left alone while this phone syncs', () async {
        final before = {for (final id in itemIds.values) id: jsonEncode(server.ciphers[id])};
        final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);

        final first = await phone.sync();
        final second = await phone.sync();

        // Nothing it read is written back, and nothing it can't read is touched
        for (final MapEntry(key: id, value: json) in before.entries) {
          expect(jsonEncode(server.ciphers[id]), json, reason: id);
        }
        expect(first.skipped, _laterKinds.length - readable.length);
        expect(second.skipped, _laterKinds.length - readable.length);
        // Its own entries still sync, and the kinds it reads come in
        expect(phone.lists.accounts.map((account) => account.id), ['a1']);
        expect(phone.lists.backupServices, isEmpty);
        expect(phone.lists.keys.map((key) => key.id), [if (readable.contains('key')) 'k1']);
        expect(phone.lists.notes.map((note) => note.id), [if (readable.contains('note')) 'n1']);
        expect(phone.lists.passkeys.map((passkey) => passkey.id), [if (readable.contains('passkey')) 'p1']);
        expect(phone.lists.contacts.map((contact) => contact.id), [if (readable.contains('contact')) 'c1']);
        final other = _Phone(server, target);
        await other.sync();
        expect(other.lists.accounts.single.secret, _secret);
      });

      test("the made-up kind going away is not taken for a change to this phone's entries", () async {
        final phone = _Phone(server, target)..lists = Lists(accounts: [_account('a1')]);
        await phone.sync();
        final keys = phone.lists.keys;

        // A later phone deletes its item for good
        server.purge(itemIds[_madeUp]!);
        final result = await phone.sync();

        expect(result.doc.accounts.map((account) => account.id), ['a1']);
        expect(result.skipped, _laterKinds.length - readable.length - 1);
        expect(phone.lists.accounts.map((account) => account.id), ['a1']);
        expect(phone.lists.keys, keys);
        for (final kind in ['key', 'note', 'passkey', 'contact']) {
          expect(server.ciphers[itemIds[kind]]!['deletedDate'], isNull, reason: kind);
        }
      });
    });
  }

  test("a sealed home carries this phone's keys, notes and passkeys to another phone", () async {
    final server = FakeVaultwarden();
    final target = await makeHome(server, VaultwardenMode.sealed);
    const key = VaultKey(
      id: 'k1',
      name: 'laptop',
      kind: KeyKind.ssh,
      algorithm: 'ed25519',
      privateKey: 'MC4CAQAwBQYDK2VwBCIEIA==',
      origin: KeyOrigin.generated,
      addedAt: 1,
    );
    const note = SecureNote(id: 'n1', title: 'Passport', addedAt: 1);
    const passkey = Passkey(
      id: 'p1',
      credentialId: 'cred',
      rpId: 'github.com',
      userHandle: 'aGFuZGxl',
      userName: 'me',
      privateKey: 'MIGH',
      addedAt: 1,
    );
    final phone = _Phone(server, target)
      ..lists = Lists(accounts: [_account('a1')], keys: const [key], notes: const [note], passkeys: const [passkey]);

    await phone.sync();
    await phone.sync();
    final other = _Phone(server, target);
    await other.sync();

    for (final lists in [phone.lists, other.lists]) {
      expect(lists.keys, [key]);
      expect(lists.notes, [note]);
      expect(lists.passkeys, [passkey]);
      expect(lists.accounts.single.id, 'a1');
    }
  });
}
