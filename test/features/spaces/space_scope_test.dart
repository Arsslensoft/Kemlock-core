@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:kemlock_core/features/spaces/space_scope.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:test/test.dart';

import '../../crypto/account/server_vectors.dart';
import 'chain_kit.dart';

// A server space as one more scope: its ids, held to the server's legacy-id vectors, and where an item's collection
// lives. The merge's own code is untouched, and these tests show it still places a server space's entries.
void main() {
  group('the ids a server may list a space under', () {
    test('are UUIDs, and not the names the vault’s own entries sync under', () {
      expect(isServerSpaceId(uuid(0x5a)), isTrue);
      for (final id in ['personal', 'vaultwarden', 'fam-01', '', uuid(0xab).toUpperCase()]) {
        expect(isServerSpaceId(id), isFalse, reason: id);
      }
    });
  });

  group("the legacy ids of the server's vectors", () {
    final cases = readServerCases('legacy-ids.json');

    test('a WebDAV space id gives the recorded UUID, and two members compute the same one', () {
      final spaces = cases.where((c) => c['type'] == 'space');
      expect(spaces, isNotEmpty);
      for (final c in spaces) {
        final mine = serverSpaceUuid(c['old']! as String);
        final theirs = serverSpaceUuid(c['old']! as String);
        expect(mine, c['uuid_text'], reason: '${c['old']}');
        expect(theirs, mine);
      }
    });

    test('an entry id gives the recorded UUID under the owner of the mapped space', () {
      final space = serverSpaceUuid('team_Alpha-01');
      final items = cases.where((c) => c['type'] == 'item' && c['owner_label'] == 'mapped-space');
      expect(items, isNotEmpty);
      for (final c in items) {
        expect(serverItemUuid(c['old']! as String, space), c['uuid_text'], reason: '${c['old']}');
      }
    });

    test('a UUID is never mapped, and the same entry id in two spaces has two UUIDs', () {
      expect(serverSpaceUuid(uuid(0x5a)), uuid(0x5a));
      expect(serverItemUuid(uuid(0x11), uuid(0x5a)), uuid(0x11));
      final a = serverItemUuid('acc-1', serverSpaceUuid('fam-01'));
      final b = serverItemUuid('acc-1', serverSpaceUuid('team'));
      expect(a, isNot(b));
      expect(itemUuid('acc-1', Owner.space(serverSpaceUuid('fam-01'))), a);
    });
  });

  group('the collection of each entry', () {
    test('is kept in the scope state beside whatever else it holds, and reads back', () {
      final state = ScopeState(known: const ['a'], extra: withSpaceCollections({'seq': 4}, {'a': uuid(0xe0), 'b': uuid(0xf1)}));
      final read = ScopeState.fromJson(state.toJson());
      expect(spaceCollectionsOf(read.extra), {'a': uuid(0xe0), 'b': uuid(0xf1)});
      expect(read.extra['seq'], 4);
    });

    test('reads as none when it is missing or damaged, and drops a value that is not a collection id', () {
      expect(spaceCollectionsOf(const {}), isEmpty);
      expect(spaceCollectionsOf({spaceCollectionsKey: 'x'}), isEmpty);
      expect(
        spaceCollectionsOf({
          spaceCollectionsKey: {'a': uuid(0xe0), 'b': 'nope', 'c': 3},
        }),
        {'a': uuid(0xe0)},
      );
    });

    test('never enters the entry’s JSON, so a server space’s entries and a WebDAV file have the same bytes', () {
      const login = Login(id: 'l1', name: 'Site', username: 'me', password: 'pw', addedAt: 1);
      final inSpace = login.inSpace(uuid(0x5a));
      final entry = kmEntriesOf(Lists(logins: [inSpace])).single;
      expect(entry.json.containsKey('collectionId'), isFalse);
      expect(entry.json['spaceId'], uuid(0x5a));
      expect(canonical(entry.json), canonical(inSpace.toJson()));
      // The state that holds the collection is not what a sync file holds
      expect(canonical(Lists(logins: [inSpace]).toJson()), isNot(contains('collection')));
    });
  });

  group('the merge places a server space like any other scope', () {
    const login = Login(id: 'l1', name: 'Site', username: 'me', password: 'pw', addedAt: 1, updatedAt: 5);
    final space = uuid(0x5a);

    test('an entry moved into it, changed only in its space and its time, is taken, and is not held elsewhere', () {
      final here = Lists(logins: [login]);
      final moved = Lists(logins: [login.inSpace(space).stamped(20)]);

      final applied = applyScope(here, space, moved);

      expect(applied.logins.single.spaceId, space);
      expect(heldElsewhere(here, space, moved), isEmpty);
    });

    test('an entry under the id of the vault’s own login, with other contents and a later time, stays out and is reported', () {
      final here = Lists(logins: [login]);
      final other = Lists(logins: [login.copyWith(password: 'taken').inSpace(space).stamped(20)]);

      final applied = applyScope(here, space, other);

      expect(applied.logins.single.password, 'pw');
      expect(applied.logins.single.spaceId, isNull);
      expect(heldElsewhere(here, space, other), {'l1'});
    });
  });
}
