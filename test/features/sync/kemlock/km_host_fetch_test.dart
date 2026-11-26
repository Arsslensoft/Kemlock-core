@TestOn('vm')
library;

// `KmHost.fetchMissing` is passed to the files the host builds: a host that keeps no file bytes downloads none at a sync.
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:kemlock_core/vault/attachment_seal.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'km_host_kit.dart';

const _item = '3f2c9a71-e4b0-4856-8a00-0000000000a1';

final _now = DateTime.utc(2026, 11, 25).millisecondsSinceEpoch;

void main() {
  setUpAll(() async {
    hostAccount = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  test('a host with fetchMissing off downloads no file at a sync, and one that leaves it on does', () async {
    final server = FakeKemlockAccountServer(userId: hostAccount.userId);
    final one = await hostPhone(server);
    final made = await sealAttachment(randomBytes(2000), name: 'Lease.pdf', now: 1);
    one.store.files[made.entry.id] = made.sealed;
    await one.sync(
      _now,
      Lists(
        files: [VaultFile(id: _item, name: 'Lease.pdf', file: made.entry, addedAt: 1)],
      ),
    );
    expect(server.files, hasLength(1), reason: 'the first phone sent the file');
    final fetching = await hostPhone(server);
    final lazy = await hostPhone(server, fetchMissing: false);

    final a = await fetching.sync(_now + 60000);
    final b = await lazy.sync(_now + 60000);

    expect(a.doc.files.single.id, _item);
    expect(b.doc.files.single.id, _item, reason: 'the item is read either way');
    expect(fetching.store.files.keys, [made.entry.id]);
    expect(lazy.store.files, isEmpty);
  });
}
