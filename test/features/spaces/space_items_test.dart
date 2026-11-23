@TestOn('vm')
library;

import 'package:kemlock_core/features/spaces/server_spaces.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

// Which item revisions a device accepts (the space chain section, "Using the state", Items, and its test case 7):
// only under the collection's current key version, and nothing newer than what it accepted while the key is marked.
void main() {
  final space = uuid(0x5a);
  final alice = Person(1);
  final bob = Person(2);
  final everyone = uuid(0xe0);
  final finance = uuid(0xf1);
  final team = uuid(0x91);
  final spaceKey = const KeyRef.space();
  final everyoneKey = KeyRef.collection(everyone);
  final financeKey = KeyRef.collection(finance);

  /// bob holds the space key, "Everyone" and "Finance", the last through the group "Team".
  ChainBuilder withFinance() => ChainBuilder(space)
    ..create(alice)
    ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
    ..confirm(alice, bob)
    ..seal(alice, [spaceKey, everyoneKey])
    ..collection(alice, finance)
    ..group(alice, team)
    ..groupMembers(alice, team, add: [bob])
    ..grant(alice, finance, 'group:$team', CollectionPermission.edit)
    ..seal(alice, [financeKey]);

  String? refusal(SpaceState chain, String? collection, int keyVersion, int revision, {int? accepted}) =>
      itemRefusal(chain: chain, collection: collection, keyVersion: keyVersion, revision: revision, acceptedRevision: accepted);

  test('a revision under the collection\'s current key version is accepted', () {
    final state = withFinance().state;
    expect(refusal(state, finance, 1, 1), isNull);
    expect(refusal(state, finance, 1, 7, accepted: 6), isNull);
    expect(refusal(state, everyone, 1, 3), isNull);
  });

  test('an item of a collection that is deleted or the chain doesn\'t know is refused', () {
    final state = (withFinance()..collectionDelete(alice, finance)).state;
    expect(refusal(state, finance, 1, 1), contains('deleted or unknown'));
    expect(refusal(state, uuid(0xdd), 1, 1), contains('deleted or unknown'));
    expect(refusal(state, null, 1, 1), contains('deleted or unknown'));
  });

  test('7: after Finance\'s key moves to version 2, a revision under version 1 is held, and one under version 2 is not', () {
    final removed = withFinance()..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey]);
    final state = (removed..keys(alice, [spaceKey, everyoneKey, financeKey])).state;
    expect(state.collections[finance]!.keyVersion, 2);
    expect(refusal(state, finance, 1, 4, accepted: 3), contains('key version 1'));
    expect(refusal(state, finance, 2, 4, accepted: 3), isNull);
    // A version the chain doesn't have yet is no better
    expect(refusal(state, finance, 3, 4, accepted: 3), contains('key version 3'));
  });

  test('7: a revision that arrives between the remove and the keys record is held, and what was accepted stays', () {
    final state = (withFinance()..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey])).state;
    expect(state.spaceKeyMarked, isTrue);
    // Newer than the one accepted, or a new item: refused, whatever its key version
    expect(refusal(state, finance, 1, 5, accepted: 4), contains('marked'));
    expect(refusal(state, finance, 1, 1), contains('marked'));
    expect(refusal(state, everyone, 1, 9, accepted: 2), contains('marked'));
    // The revision already accepted is not a newer one
    expect(refusal(state, finance, 1, 4, accepted: 4), isNull);
    expect(refusal(state, finance, 1, 3, accepted: 4), isNull);
  });

  test('a marked collection key holds only its own collection, until its keys record', () {
    final marked = withFinance()..ungrant(alice, finance, 'group:$team', replace: [financeKey]);
    final state = marked.state;
    expect(state.spaceKeyMarked, isFalse);
    expect(refusal(state, finance, 1, 5, accepted: 4), contains('marked'));
    expect(refusal(state, everyone, 1, 5, accepted: 4), isNull);
    final replaced = (marked..keys(alice, [financeKey])).state;
    expect(refusal(replaced, finance, 2, 5, accepted: 4), isNull);
    expect(refusal(replaced, finance, 1, 5, accepted: 4), contains('key version 1'));
  });
}
