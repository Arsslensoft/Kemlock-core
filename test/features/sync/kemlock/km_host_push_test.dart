@TestOn('vm')
library;

// KmHost.pushEntry writes one item with its files now, over the host's own cache and manifest.
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:kemlock_core/vault/attachment_seal.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'km_host_kit.dart';
import 'km_sync_kit.dart';

const _item = '3f2c9a71-e4b0-4856-8a00-0000000000a1';
const _note = '3f2c9a71-e4b0-4856-8a00-0000000000a2';

final _now = DateTime.utc(2026, 11, 25).millisecondsSinceEpoch;

Future<({KmEntry entry, SealedAttachment made})> _fileEntry(HostPhone phone) async {
  final made = await sealAttachment(randomBytes(2000), name: 'Lease.pdf', now: 1);
  phone.store.files[made.entry.id] = made.sealed;
  final item = VaultFile(id: _item, name: 'Lease.pdf', file: made.entry, addedAt: 1);
  return (entry: (kind: KmKind.file, json: item.toJson()), made: made);
}

void main() {
  setUpAll(() async {
    hostAccount = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  test('writes the item and its file at once, lists them in the signed manifest, and leaves the next sync nothing to write', () async {
    final server = FakeKemlockAccountServer(userId: hostAccount.userId);
    final one = await hostPhone(server);
    final file = await _fileEntry(one);

    final pushed = await one.host.pushEntry(kmTarget, file.entry, now: _now);

    expect(pushed.unsent, isEmpty);
    expect(kmServerFileId(kmAttachmentsOf(pushed.entry).single), server.files.keys.single);
    expect(server.items[_item]!.revision, 2, reason: 'the item, then the item naming its file');
    expect(server.manifest, isNotNull);

    server.events.clear();
    final run = await one.sync(_now + 60000, Lists(files: [VaultFile.fromJson(pushed.entry.json)]));

    expect(server.events, isNot(contains('batch')), reason: 'the cache already holds the item as the push left it');
    expect(run.doc.files.single.id, _item);
    expect(server.items[_item]!.revision, 2);
  });

  test('a second phone reads what was pushed, and fetches the file', () async {
    final server = FakeKemlockAccountServer(userId: hostAccount.userId);
    final one = await hostPhone(server);
    final file = await _fileEntry(one);
    await one.host.pushEntry(kmTarget, file.entry, now: _now);
    final two = await hostPhone(server);

    final run = await two.sync(_now + 60000);

    expect(run.doc.files.single.id, _item, reason: 'the manifest the push signed lists the item');
    expect(two.store.files.keys, [file.made.entry.id]);
  });

  test('merges the entry with the copy another device wrote since the host last read, and writes the merge', () async {
    final server = FakeKemlockAccountServer(userId: hostAccount.userId);
    final one = await hostPhone(server);
    final two = await hostPhone(server);
    KmEntry note(String title, int at) => (kind: KmKind.note, json: SecureNote(id: _note, title: title, addedAt: 1, updatedAt: at).toJson());

    await one.host.pushEntry(kmTarget, note('From one', 5), now: _now);
    final pushed = await two.host.pushEntry(kmTarget, note('From two', 9), now: _now + 1);

    expect(SecureNote.fromJson(pushed.entry.json).title, 'From two', reason: 'the newer edit wins the merge');
    expect(server.items[_note]!.revision, 2, reason: 'written over the revision it read, never as a new item');
  });
}
