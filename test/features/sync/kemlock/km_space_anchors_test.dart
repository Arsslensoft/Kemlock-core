@TestOn('vm')
library;

// The anchors of the account's server spaces on Kemlock Server (docs/plans/add-server-spaces.md, design 2 point 1): one
// item of the kind `space-anchors`, owned by the user, that the account's devices merge with `SpaceAnchors.mergedWith`.
import 'dart:typed_data';

import 'package:kemlock_core/features/spaces/space_head_store.dart';
import 'package:kemlock_core/features/spaces/space_verify.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import '../../spaces/chain_kit.dart';
import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

ChainAnchor _anchor(int seq, int fill, {int epoch = 1}) =>
    ChainAnchor(epoch: epoch, links: [for (var i = 0; i <= seq; i++) Uint8List(32)..fillRange(0, 32, fill + i)]);

/// What one phone's vault holds of the anchors, as `KmAnchors` reads and writes it.
class _Vault {
  _Vault([SpaceAnchors? held]) : anchors = held ?? SpaceAnchors();

  SpaceAnchors anchors;
  var saves = 0;

  KmAnchors get hook => KmAnchors(
    load: () async => anchors.length == 0 ? null : anchors.toJson(),
    save: (json) async {
      anchors = SpaceAnchors.fromJson(json);
      saves++;
    },
  );
}

void main() {
  late FakeKemlockServer server;
  late KmClock clock;

  setUp(() {
    server = FakeKemlockServer()..checkTokens = false;
    clock = KmClock();
  });

  String itemId(KmPhone phone) => kmItemId(kmSpaceAnchorsEntryId, phone.crypto.owner);

  test('a phone puts its anchors up as one item of the user, and another phone of the account takes them', () async {
    final first = _Vault(SpaceAnchors({uuid(1): _anchor(3, 1)}));
    final second = _Vault();
    final a = KmPhone(server, clock: clock, anchors: first.hook);
    await a.run();
    final item = server.items[itemId(a)]!;
    expect(item.kind, KmKind.spaceAnchors);
    expect(item.owner, 'user:${server.userId}');
    expect(item.revision, 1);

    final other = KmPhone(server, clock: clock, crypto: a.crypto.alike(), anchors: second.hook);
    await other.run();
    expect(second.anchors.of(uuid(1)), _anchor(3, 1));
  });

  test('two phones that met different lengths of one chain both end on the longer', () async {
    final first = _Vault(SpaceAnchors({uuid(1): _anchor(2, 1)}));
    final second = _Vault(SpaceAnchors({uuid(1): _anchor(5, 1), uuid(2): _anchor(0, 7)}));
    final a = KmPhone(server, clock: clock, anchors: first.hook);
    final b = KmPhone(server, clock: clock, crypto: a.crypto.alike(), anchors: second.hook);

    await a.run();
    await b.run();
    await a.run();

    expect(first.anchors.of(uuid(1)), _anchor(5, 1));
    expect(first.anchors.of(uuid(2)), _anchor(0, 7));
    expect(server.items[itemId(a)]!.revision, 2);
  });

  test('a run that has nothing to add writes nothing more', () async {
    final vault = _Vault(SpaceAnchors({uuid(1): _anchor(1, 1)}));
    final phone = KmPhone(server, clock: clock, anchors: vault.hook);

    await phone.run();
    final revision = server.items[itemId(phone)]!.revision;
    await phone.run();

    expect(server.items[itemId(phone)]!.revision, revision);
    expect(vault.saves, 0);
  });

  test('the item is no entry: it is not counted as skipped, and no entry is made of it', () async {
    final vault = _Vault(SpaceAnchors({uuid(1): _anchor(1, 1)}));
    final phone = KmPhone(
      server,
      clock: clock,
      lists: Lists(accounts: [acct('3f2c9a71-e4b0-4856-8a00-0000000000a1')]),
      anchors: vault.hook,
    );

    final result = await phone.run();
    final again = await phone.run();

    expect(result.skipped, 0);
    expect(again.skipped, 0);
    expect(again.doc.accounts, hasLength(1));
    expect(again.known, ['3f2c9a71-e4b0-4856-8a00-0000000000a1']);
  });

  test('a phone with no anchors to carry writes no such item', () async {
    final phone = KmPhone(server, clock: clock, anchors: _Vault().hook);

    await phone.run();

    expect(server.items.containsKey(itemId(phone)), isFalse);
  });

  test('a phone with no hook leaves the item as the server has it', () async {
    final carrier = KmPhone(server, clock: clock, anchors: _Vault(SpaceAnchors({uuid(1): _anchor(1, 1)})).hook);
    await carrier.run();
    final plain = KmPhone(server, clock: clock, crypto: carrier.crypto.alike());

    await plain.run();

    expect(server.items[itemId(carrier)]!.revision, 1);
  });

  test('a vault whose anchors can’t be read is left alone, and writes nothing over the server', () async {
    final carrier = _Vault(SpaceAnchors({uuid(1): _anchor(1, 1)}));
    final a = KmPhone(server, clock: clock, anchors: carrier.hook);
    await a.run();
    final broken = KmPhone(
      server,
      clock: clock,
      crypto: a.crypto.alike(),
      anchors: KmAnchors(load: () async => throw StateError('sealed value will not open'), save: (_) async => fail('saved over it')),
    );

    await broken.run();

    expect(server.items[itemId(a)]!.revision, 1);
  });
}
