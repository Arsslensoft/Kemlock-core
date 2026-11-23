@TestOn('vm')
library;

import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_end.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_old_store.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_record.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/webdav.dart';
import 'package:test/test.dart';

const _kemlock = KemlockTarget(
  accountId: '3f2c9a71-e4b0-4856-8a00-000000000001',
  email: 'me@example.com',
  servers: [KemlockServer(url: 'https://vault.example.com', role: KemlockServer.home)],
  deviceId: 'device-1',
);

const _vaultwarden = VaultwardenTarget(
  server: 'https://vault.example.com',
  email: 'me@example.com',
  home: 'home-1',
  mode: VaultwardenMode.plain,
  folderId: 'folder-1',
);

final _personal = SyncTarget(
  dav: const DavAccount(url: 'https://dav.example.com/f', username: 'u', password: 'p'),
  file: syncFile,
  key: 'a2V5',
);

void main() {
  test('a plain home stays beside the Kemlock target, marked as a copy, and the Kemlock scope starts from the checked ids', () {
    final end = kmEndOfMove(
      settings: const SyncSettings(vaultwarden: _vaultwarden, kemlock: _kemlock),
      states: {
        vaultwardenScope: const ScopeState(known: ['a', 'b'], lastSyncAt: 5, extra: {'seq': 3}),
      },
      result: const KmOldStoreResult(KmOldStore.copyKept),
      confirmed: ['a', 'b', 'c'],
      now: 9,
    );
    expect(end.settings.vaultwarden, isNotNull);
    expect(end.settings.kemlock, isNotNull);
    expect(end.settings.personal, isNull);
    expect(end.settings.ownEntriesClash, isFalse);
    final copy = end.states[vaultwardenScope]!;
    expect(isCopyScope(copy), isTrue);
    expect(copy.known, ['a', 'b']);
    expect(copy.extra['seq'], 3);
    expect(end.states[kemlockScope]!.known, ['a', 'b', 'c']);
  });

  test('a closed sealed home is no longer synced', () {
    final end = kmEndOfMove(
      settings: const SyncSettings(vaultwarden: _vaultwarden, kemlock: _kemlock),
      states: {
        vaultwardenScope: const ScopeState(known: ['a']),
      },
      result: const KmOldStoreResult(KmOldStore.closed, changed: 3),
      confirmed: ['a'],
      now: 9,
    );
    expect(end.settings.vaultwarden, isNull);
    expect(end.settings.kemlock, isNotNull);
    expect(end.states.containsKey(vaultwardenScope), isFalse);
  });

  test('a sealed home left open keeps syncing as a copy', () {
    final end = kmEndOfMove(
      settings: const SyncSettings(vaultwarden: _vaultwarden, kemlock: _kemlock),
      states: const {},
      result: const KmOldStoreResult(KmOldStore.blocked, unreadable: 1),
      confirmed: ['a'],
      now: 9,
    );
    expect(end.settings.vaultwarden, isNotNull);
    expect(isCopyScope(end.states[vaultwardenScope]!), isTrue);
  });

  test('a WebDAV file is left alone: personal is null and spaces stay', () {
    final space = Space(id: 'space-1', name: 'Family', target: _personal, joinedAt: 1);
    final end = kmEndOfMove(
      settings: SyncSettings(personal: _personal, spaces: [space], kemlock: _kemlock),
      states: {
        personalScope: const ScopeState(known: ['a']),
        'space-1': const ScopeState(known: ['s']),
      },
      result: const KmOldStoreResult(KmOldStore.fileLeft),
      confirmed: ['a'],
      now: 9,
    );
    expect(end.settings.personal, isNull);
    expect(end.settings.spaces, [space]);
    expect(end.states.containsKey(personalScope), isFalse);
    expect(end.states['space-1']!.known, ['s']);
  });
  test('a Vaultwarden home on the server is the source, a Vaultwarden elsewhere is not, WebDAV is', () {
    final home = kmMoveSourceOf(const SyncSettings(vaultwarden: _vaultwarden), _kemlock);
    expect(home?.name, vaultwardenSource);
    expect(home?.mode, 'plain');
    const other = VaultwardenTarget(
      server: 'https://elsewhere.example.org',
      email: 'me@example.com',
      home: 'home-2',
      mode: VaultwardenMode.sealed,
      folderId: 'f',
    );
    expect(kmMoveSourceOf(const SyncSettings(vaultwarden: other), _kemlock), isNull);
    expect(kmMoveSourceOf(SyncSettings(personal: _personal), _kemlock)?.name, webdavSource);
    expect(kmMoveSourceOf(const SyncSettings(), _kemlock), isNull);
  });

  test('a trimmed record drops the kept Vaultwarden target and keeps the rest', () {
    final record = KmMoveRecord(
      source: vaultwardenSource,
      server: 'https://vault.example.com',
      startedAt: 1,
      finishedAt: 2,
      step: KmMoveStep.done,
      extra: {kmGoBackTargetKey: _vaultwarden.toJson(), 'future': 1},
    );
    expect(record.trimmed().toJson(), {'v': 1, 'source': 'vaultwarden', 'done': true, 'finishedAt': 2, 'future': 1});
  });
}
