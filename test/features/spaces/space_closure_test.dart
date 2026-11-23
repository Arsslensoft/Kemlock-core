@TestOn('vm')
library;

// What closes the WebDAV copy of a moved space (docs/plans/add-server-spaces.md, design 7 and task 8.4), read from the verified
// chain and the space's items, which every member's app derives the same: a removal that marked keys, a key replacement, and the
// marker the Owner writes. An invitation that never held a key is none of them.
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/features/spaces/space_bridge.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:kemlock_core/features/sync/kemlock/km_cache.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

void main() {
  final space = uuid(0x5a);
  final everyone = uuid(0xe0);
  final alice = Person(1);
  final bob = Person(2);
  final carol = Person(3);
  const spaceRef = KeyRef.space();
  final everyoneRef = KeyRef.collection(everyone);

  // Alice makes the space, invites Bob with edit on "Everyone", confirms him and seals him the keys he awaits
  ChainBuilder twoMembers() => ChainBuilder(space)
    ..create(alice, collection: everyone)
    ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
    ..confirm(alice, bob)
    ..seal(alice, [spaceRef, everyoneRef]);

  KmCachedItem marker(String kind, {bool deleted = false}) =>
      KmCachedItem(revision: 1, kind: kind, keyVersion: 1, hash: deleted ? '' : 'aGFzaA', opaque: true);

  Map<String, KmCachedItem> items({KmCachedItem? open, KmCachedItem? closed}) => {
    kmItemId(kmBridgeOpenId, Owner.space(space)): ?open,
    kmItemId(kmBridgeClosedId, Owner.space(space)): ?closed,
  };

  group('the chain closes the copy', () {
    test('a space nobody was removed from, whose keys were never replaced, leaves it open', () {
      expect(chainClosure(twoMembers().state), isNull);
    });

    test('a removal of a member who held keys marks them, which closes it', () {
      final chain = twoMembers()..remove(alice, bob, replace: [spaceRef, everyoneRef]);

      expect(chain.state.keysNeedReplacing, isTrue);
      expect(chainClosure(chain.state), SpaceCopyClosed.removal);
    });

    test('the replacement of the keys that follows keeps it closed', () {
      final chain = twoMembers()
        ..remove(alice, bob, replace: [spaceRef, everyoneRef])
        ..keys(alice, [spaceRef, everyoneRef]);

      expect(chain.state.keysNeedReplacing, isFalse, reason: 'the replacement is done');
      expect(chainClosure(chain.state), SpaceCopyClosed.keys, reason: 'the keys are at a later version than the file’s key was');
    });

    test('a second collection closes it: the file can’t keep a collection’s restriction', () {
      final chain = twoMembers()..collection(alice, uuid(0xf1));

      expect(chain.state.collections, hasLength(2));
      expect(chainClosure(chain.state), SpaceCopyClosed.restricted);
    });

    test('a grant that hides passwords closes it, and one that doesn’t leaves it open', () {
      final shown = twoMembers()..invite(alice, carol, grants: {everyone: CollectionPermission.editHidePasswords});
      expect(chainClosure(shown.state), SpaceCopyClosed.restricted, reason: 'edit-hide-passwords hides them');

      final open = twoMembers()..invite(alice, carol, grants: {everyone: CollectionPermission.view});
      expect(chainClosure(open.state), isNull, reason: 'a plain view grant in "Everyone" crosses as it always has');
    });

    test('a removal of a member who held no key seal marks nothing and still closes it', () {
      final chain = ChainBuilder(space)
        ..create(alice, collection: everyone)
        ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
        ..confirm(alice, bob)
        ..remove(alice, bob);

      expect(chain.state.keysNeedReplacing, isFalse, reason: 'nothing was sealed to Bob, so no key is marked');
      expect(chain.state.member(bob.id)!.status, MemberStatus.removed);
      expect(chainClosure(chain.state), SpaceCopyClosed.removal, reason: 'Bob holds the file’s key all the same');
    });

    test('a member who left closes it as a removal does', () {
      final chain = twoMembers()..remove(bob, bob, replace: [spaceRef, everyoneRef]);

      expect(chainClosure(chain.state), SpaceCopyClosed.removal);
    });

    test('an invitation that is revoked is a removal too, which closes it: the invite carried the file’s key', () {
      final chain = twoMembers()
        ..invite(alice, carol)
        ..remove(alice, carol);

      expect(chain.state.member(carol.id)!.inSpace, isFalse);
      expect(chainClosure(chain.state), SpaceCopyClosed.removal);
    });
  });

  group('what a run of the space says of its WebDAV copy', () {
    test('says nothing while there is no marker and the chain closes nothing', () {
      expect(bridgeSignalOf(twoMembers().state, items(), Owner.space(space)), isNull);
    });

    test('says the move is whole once its marker is there, and a tombstone of it says nothing', () {
      final owner = Owner.space(space);
      final open = bridgeSignalOf(twoMembers().state, items(open: marker(KmKind.bridgeOpen)), owner);
      expect(open?.signal, BridgeSignal.open);
      expect(bridgeSignalOf(twoMembers().state, items(open: marker(KmKind.bridgeOpen, deleted: true)), owner), isNull);
    });

    test('keeps saying the Owner closed it once the marker is deleted: a copy that was closed is not opened again', () {
      final owner = Owner.space(space);
      final deleted = items(open: marker(KmKind.bridgeOpen), closed: marker(KmKind.bridgeClosed, deleted: true));
      expect(bridgeSignalOf(twoMembers().state, deleted, owner)?.signal, BridgeSignal.closed);
      expect(bridgeSignalOf(twoMembers().state, deleted, owner)?.reason, SpaceCopyClosed.owner);

      // A tombstone this phone saw whose kind it holds as nothing still counts
      final bare = items(
        closed: KmCachedItem(revision: 2, kind: '', keyVersion: 1, hash: ''),
      );
      expect(bridgeSignalOf(twoMembers().state, bare, owner)?.signal, BridgeSignal.closed);
    });

    test('tells a marker by its kind: an entry that carries a marker’s id is none', () {
      final owner = Owner.space(space);
      final entry = KmCachedItem(revision: 1, kind: KmKind.login, keyVersion: 1, hash: 'aGFzaA');

      expect(bridgeSignalOf(twoMembers().state, items(open: entry), owner), isNull, reason: 'a login with the open marker’s id');
      expect(bridgeSignalOf(twoMembers().state, items(closed: entry), owner), isNull, reason: 'a login with the closed marker’s id');
    });

    test('says the Owner closed it from the closed marker, whatever the open one says', () {
      final seen = bridgeSignalOf(
        twoMembers().state,
        items(open: marker(KmKind.bridgeOpen), closed: marker(KmKind.bridgeClosed)),
        Owner.space(space),
      );

      expect(seen?.signal, BridgeSignal.closed);
      expect(seen?.reason, SpaceCopyClosed.owner);
    });

    test('says the chain closed it before the Owner did: the chain can’t be forged', () {
      final chain = twoMembers()..remove(alice, bob, replace: [spaceRef, everyoneRef]);

      final seen = bridgeSignalOf(
        chain.state,
        items(open: marker(KmKind.bridgeOpen), closed: marker(KmKind.bridgeClosed)),
        Owner.space(space),
      );

      expect(seen?.signal, BridgeSignal.closed);
      expect(seen?.reason, SpaceCopyClosed.removal);
    });

    test('carries a signal in a state and takes it out again, with every other key as it was', () {
      final state = withBridgeSignal({'collections': <String, Object?>{}, 'seq': 4}, BridgeSignal.closed, SpaceCopyClosed.keys);

      expect(state[bridgeStateKey], 'closed');
      final taken = takeBridgeSignal(state);
      expect(taken.signal, BridgeSignal.closed);
      expect(taken.reason, SpaceCopyClosed.keys);
      expect(taken.state, {'collections': <String, Object?>{}, 'seq': 4});
      expect(takeBridgeSignal({'seq': 1}).signal, isNull);
    });
  });
}
