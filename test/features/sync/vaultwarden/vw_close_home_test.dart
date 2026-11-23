@TestOn('vm')
library;

// Closing a sealed home after a move (move-off-vaultwarden-sync, tasks 4.1 and 4.2): the home note goes to the
// trash first, so a phone still on Vaultwarden sync stops at home-missing and changes nothing; a home that
// holds an item this build can't read, or an entry the move didn't confirm, is left open and untouched; and
// what was closed can be taken out of the trash again.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_backend.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

OtpAccount _account(String id) => OtpAccount(id: id, issuer: id, label: 'me@example.com', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);

/// One phone syncing the home.
class _Phone {
  _Phone(this.server, this.target);

  final FakeVaultwarden server;
  final VaultwardenTarget target;
  Lists lists = const Lists();
  ScopeState state = const ScopeState(known: []);
  late final reader = VwReader(server.userKey);

  VwConnection get connection =>
      VwConnection(api: VwApi(server.client), server: FakeVaultwarden.url, credentials: server.credentials(), onCredentials: (_) async {});

  Future<void> sync() async {
    final now = server.revision + 500;
    final result = await VaultwardenScopeSync(connection: connection, reader: reader, target: target).sync(lists, state, now: now);
    lists = applyScope(lists, null, result.doc);
    state = ScopeState(known: result.known, lastSyncAt: now, extra: result.state);
  }
}

/// A sealed home with [ids] synced into it.
Future<({FakeVaultwarden server, VaultwardenTarget target, _Phone phone})> _home(List<String> ids) async {
  final server = FakeVaultwarden();
  final target = await makeHome(server, VaultwardenMode.sealed);
  final phone = _Phone(server, target)..lists = Lists(accounts: [for (final id in ids) _account(id)]);
  await phone.sync();
  return (server: server, target: target, phone: phone);
}

/// The ids of the requests that sent an item to the trash, in order.
List<String> _trashed(FakeVaultwarden server) => [
  for (final request in server.requests)
    if (RegExp(r'^/api/ciphers/([^/]+)/delete$').firstMatch(request.url.path) case final match?) match[1]!,
];

Future<String> _homeId(_Phone phone) async {
  final read = await phone.reader.read(await phone.connection.ciphers(), home: phone.target.home);
  return read.homes.single.cipher.id;
}

/// Puts an item in the home that a later version of Kemlock wrote: a kind this build doesn't know.
Future<void> _putHologram(FakeVaultwarden server, VaultwardenTarget target) async {
  final writer = VwWriter(userKey: server.userKey, userId: FakeVaultwarden.userId);
  final body = await writer.create(
    _account('placeholder'),
    form: VaultwardenMode.sealed,
    home: target.home,
    folderId: target.folderId,
    sealKey: Uint8List(32),
  );
  final entry = {'id': 'h1', 'addedAt': 1};
  final sealed = await aesGcmEncrypt(unb64(target.seal!.key), utf8.encode(jsonEncode({'kind': 'hologram', 'entry': entry})));
  final field = 'kemlock-sealed:1:${target.home}:h1:${b64(sealed.nonce)}:${b64(sealed.ct)}';
  server.put({
    ...body,
    'name': await bwEncryptString('Hologram', server.userKey),
    'fields': [
      {
        'type': 1,
        'name': await bwEncryptString(fieldName, server.userKey),
        'value': await bwEncryptString(field, server.userKey),
        'linkedId': null,
      },
    ],
  });
}

void main() {
  test('trashes the home note first, then each sealed item, and a phone still on the home stops and changes nothing', () async {
    final world = await _home(['a1', 'a2', 'a3']);
    final second = _Phone(world.server, world.target);
    await second.sync();
    final home = await _homeId(world.phone);

    final result = await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1', 'a2', 'a3'});

    expect(result.outcome, VwCloseOutcome.closed);
    expect(result.changed, 3);
    final order = _trashed(world.server);
    expect(order, hasLength(4));
    expect(order.first, home, reason: 'the home note goes first');
    expect(
      world.server.ciphers.values.where((cipher) => cipher['deletedDate'] == null),
      isEmpty,
      reason: 'everything is in the trash, nothing deleted',
    );
    expect(world.server.ciphers, hasLength(4));

    final snapshot = jsonEncode(world.server.ciphers);
    await expectLater(second.sync(), throwsA(isA<VwSyncError>().having((e) => e.issue, 'issue', VwSyncIssue.homeMissing)));
    expect(second.lists.accounts.map((a) => a.id), unorderedEquals(['a1', 'a2', 'a3']), reason: 'its entries stay');
    expect(jsonEncode(world.server.ciphers), snapshot, reason: 'it wrote nothing');
  });

  test('leaves a home open and untouched when it holds an item of a kind this build can’t read', () async {
    final world = await _home(['a1', 'a2']);
    await _putHologram(world.server, world.target);
    final before = world.server.requests.length;

    final result = await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1', 'a2'});

    expect(result.outcome, VwCloseOutcome.blocked);
    expect(result.unreadable, 1);
    expect(_trashed(world.server), isEmpty, reason: 'no item is trashed');
    expect(world.server.ciphers.values.where((cipher) => cipher['deletedDate'] != null), isEmpty);
    expect(world.server.requests.skip(before).where((request) => request.method != 'GET'), isEmpty);
    // The home keeps syncing beside the Kemlock API
    await world.phone.sync();
  });

  test('leaves a home open when an entry in it was never confirmed by the move’s check', () async {
    final world = await _home(['a1', 'a2']);
    // Another phone adds an entry after this phone's last sync
    final other = _Phone(world.server, world.target)..lists = Lists(accounts: [_account('a3')]);
    await other.sync();

    final result = await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1', 'a2'});

    expect(result.outcome, VwCloseOutcome.blocked);
    expect(result.unconfirmed, 1);
    expect(_trashed(world.server), isEmpty);
  });

  test('reports a home that is already in the trash as gone, and trashes nothing more', () async {
    final world = await _home(['a1']);
    await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1'});
    final trashed = _trashed(world.server).length;

    final again = await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1'});

    expect(again.outcome, VwCloseOutcome.alreadyGone);
    expect(_trashed(world.server), hasLength(trashed));
  });

  test('removeFromVault takes the same order: the home note first', () async {
    final world = await _home(['a1', 'a2']);
    final home = await _homeId(world.phone);

    final changed = await VwAccountSetup.removeFromVault(world.phone.connection, world.target);

    expect(changed, 2);
    expect(_trashed(world.server).first, home);
    expect(_trashed(world.server), hasLength(3));
  });

  test('takes the home and the items trashed with it out of the trash, and leaves an entry deleted before the close', () async {
    final world = await _home(['a1', 'a2', 'a3']);
    // The person deleted a3 before the move
    world.phone.lists = Lists(accounts: [_account('a1'), _account('a2')]);
    await world.phone.sync();
    final deletedBefore = world.server.ciphers.entries
        .where((entry) => entry.value['deletedDate'] != null)
        .map((entry) => entry.key)
        .toSet();
    expect(deletedBefore, hasLength(1));
    await VwAccountSetup.closeHome(world.phone.connection, world.target, confirmed: {'a1', 'a2'});

    final restored = await VwAccountSetup.restoreHome(world.phone.connection, world.target);

    expect(restored, 2);
    final stillTrashed = world.server.ciphers.entries
        .where((entry) => entry.value['deletedDate'] != null)
        .map((entry) => entry.key)
        .toSet();
    expect(stillTrashed, deletedBefore);
    // The restored home syncs again as it did
    await world.phone.sync();
    expect(world.phone.lists.accounts.map((a) => a.id), unorderedEquals(['a1', 'a2']));
  });
}
