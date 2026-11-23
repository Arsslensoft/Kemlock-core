@TestOn('vm')
library;

// Consent per kind for plain homes: keys, notes and passkeys aren't written
// in the clear until the user agrees to their kind, the run says how many
// of each wait, and agreeing once covers every later item of that kind.
import 'dart:convert';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

class _Phone {
  _Phone(this.server, this.target) : reader = VwReader(server.userKey);

  final FakeVaultwarden server;
  VaultwardenTarget target;
  final VwReader reader;
  Lists lists = const Lists();
  ScopeState state = const ScopeState(known: []);
  late VwCredentials credentials = server.credentials();

  VaultwardenScopeSync get _scope => VaultwardenScopeSync(
    connection: VwConnection(
      api: VwApi(server.client),
      server: FakeVaultwarden.url,
      credentials: credentials,
      onCredentials: (next) async => credentials = next,
    ),
    reader: reader,
    target: target,
  );

  Future<VwSyncResult> sync() async {
    final at = server.revision + 500;
    final result = await _scope.sync(lists, state, now: at);
    lists = applyScope(lists, null, result.doc);
    state = ScopeState(known: result.known, lastSyncAt: at, extra: result.state);
    return result;
  }

  Future<VwSyncPreview> preview() => _scope.preview(lists, now: server.revision + 500);
}

const _account = OtpAccount(id: 'a1', issuer: 'GitHub', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
const _key = VaultKey(
  id: 'k1',
  name: 'laptop',
  kind: KeyKind.signing,
  algorithm: '1.2.3.4',
  privateKey: 'MAA=',
  origin: KeyOrigin.imported,
  addedAt: 1,
);
const _note = SecureNote(id: 'n1', title: 'Passport', text: 'In the drawer', addedAt: 1);
const _passkey = Passkey(
  id: 'p1',
  credentialId: 'AQIDBA',
  rpId: 'github.com',
  userHandle: 'dXNlcg',
  userName: 'me',
  privateKey: 'MAA=',
  addedAt: 1,
);

/// The kinds of the entries the home's items hold, decrypted from their fields.
Future<List<String>> _kindsThere(FakeVaultwarden server) async => [
  for (final cipher in server.ciphers.values)
    if (cipher['deletedDate'] == null)
      for (final field in (cipher['fields'] as List<Object?>? ?? const []).cast<Map<String, Object?>>())
        if (await bwDecryptString(field['name']! as String, server.userKey) == fieldName)
          if (PlainField.tryParse(await bwDecryptString(field['value']! as String, server.userKey)) case final plain?) plain.kind.name,
];

void main() {
  late FakeVaultwarden server;

  setUp(() => server = FakeVaultwarden());

  test('nothing of a kind is written before the user agrees, and the run says how many wait', () async {
    final target = await makeHome(server, VaultwardenMode.plain);
    final phone = _Phone(server, target)..lists = const Lists(accounts: [_account], keys: [_key], notes: [_note], passkeys: [_passkey]);

    final preview = await phone.preview();
    final result = await phone.sync();

    expect(preview.paused, {EntryKind.key: 1, EntryKind.note: 1, EntryKind.passkey: 1});
    expect(preview.toVaultAccounts, 1);
    expect(result.state['paused'], {'key': 1, 'note': 1, 'passkey': 1});
    expect(await _kindsThere(server), ['account'], reason: 'the codes still sync');
    // They stay here, and their absence there is never taken for a deletion
    final again = await phone.sync();
    expect(again.state['paused'], {'key': 1, 'note': 1, 'passkey': 1});
    expect(phone.lists.keys, [_key]);
    expect(phone.lists.notes, [_note]);
    expect(phone.lists.passkeys, [_passkey]);
    expect(phone.state.known, ['a1']);
  });

  test('agreeing writes that kind, and covers later items of it', () async {
    final target = await makeHome(server, VaultwardenMode.plain);
    final phone = _Phone(server, target)..lists = const Lists(keys: [_key], notes: [_note], passkeys: [_passkey]);
    await phone.sync();

    phone.target = target.copyWith(plainKinds: {'note'});
    final agreed = await phone.sync();

    expect(await _kindsThere(server), ['note']);
    expect(agreed.state['paused'], {'key': 1, 'passkey': 1});

    // A second note later goes without asking again
    const later = SecureNote(id: 'n2', title: 'Visa', addedAt: 2);
    phone.lists = Lists(keys: const [_key], notes: [...phone.lists.notes, later], passkeys: const [_passkey]);
    await phone.sync();
    expect(await _kindsThere(server), unorderedEquals(['note', 'note']));

    phone.target = phone.target.copyWith(plainKinds: {...agreedToAll});
    final all = await phone.sync();
    expect(await _kindsThere(server), unorderedEquals(['note', 'note', 'key', 'passkey']));
    expect(all.state['paused'], isNull);
  });

  test("taking what another phone wrote needs no agreement, but this phone's edits wait for it", () async {
    final writer = _Phone(server, await makeHome(server, VaultwardenMode.plain, plainKinds: agreedToAll))
      ..lists = const Lists(notes: [_note]);
    await writer.sync();
    final reader = _Phone(server, writer.target.copyWith(plainKinds: const {}));

    await reader.sync();
    expect(reader.lists.notes, [_note]);

    final before = jsonEncode(server.ciphers);
    reader.lists = Lists(
      notes: [_note.copyWith(text: 'Moved to the safe', updatedAt: server.revision + 100)],
    );
    final result = await reader.sync();

    expect(jsonEncode(server.ciphers), before, reason: 'nothing written in the clear');
    expect(result.state['paused'], {'note': 1});
    expect(reader.lists.notes.single.text, 'Moved to the safe');
  });

  test('a sealed home needs no agreement', () async {
    final phone = _Phone(server, await makeHome(server, VaultwardenMode.sealed))
      ..lists = const Lists(keys: [_key], notes: [_note], passkeys: [_passkey]);

    final result = await phone.sync();

    expect(result.state['paused'], isNull);
    expect(_Phone(server, phone.target).sync().then((r) => r.doc.ids.toSet()), completion({'k1', 'n1', 'p1'}));
  });

  test('the kinds agreed to are kept in the settings, which stay as they were without them', () {
    const target = VaultwardenTarget(
      server: 'https://vault.example.com',
      email: 'me',
      home: 'h',
      mode: VaultwardenMode.plain,
      folderId: 'f',
    );

    expect(target.toJson().containsKey('plainKinds'), isFalse);
    final agreed = target.copyWith(plainKinds: {'passkey', 'key'});
    expect(agreed.toJson()['plainKinds'], ['key', 'passkey']);
    expect(VaultwardenTarget.fromJson(jsonDecode(jsonEncode(agreed.toJson())) as Map<String, Object?>).plainKinds, {'key', 'passkey'});
    expect(VaultwardenTarget.fromJson(agreed.toJson()), agreed);
  });
}
