@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

// What a space's chain derives (the space chain section of docs/crypto.md, "State" and "Kinds"): one valid chain
// with a record of every kind, and the records the state refuses because they make no sense where they land. Who may
// sign each, and the signatures, are space_verify_test.dart's.
void main() {
  final space = uuid(0x5a);
  final alice = Person(1);
  final bob = Person(2);
  final carol = Person(3);
  final dan = Person(4);
  final everyone = uuid(0xe0);
  final finance = uuid(0xf1);
  final team = uuid(0x91);
  final spaceKey = const KeyRef.space();
  final everyoneKey = KeyRef.collection(everyone);
  final financeKey = KeyRef.collection(finance);

  ChainBuilder started() => ChainBuilder(space)..create(alice);

  /// A space with alice as Owner and bob confirmed as a Member with edit on "Everyone", who holds both keys.
  ChainBuilder withBob() => started()
    ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
    ..confirm(alice, bob)
    ..seal(alice, [spaceKey, everyoneKey]);

  /// [withBob] and a collection "Finance" bob holds through the group "Team".
  ChainBuilder withFinance() => withBob()
    ..collection(alice, finance)
    ..group(alice, team)
    ..groupMembers(alice, team, add: [bob])
    ..grant(alice, finance, 'group:$team', CollectionPermission.view)
    ..seal(alice, [financeKey]);

  ChainRefusal refusal(void Function() apply) {
    try {
      apply();
    } on ChainRefusal catch (e) {
      return e;
    }
    fail('expected a ChainRefusal');
  }

  void expectRefused(ChainBuilder chain, ChainProblem problem) => expect(refusal(() => chain.state).problem, problem);

  group('a valid chain with a record of every kind', () {
    late ChainBuilder chain;

    setUp(() {
      chain = withBob()
        ..invite(alice, carol, role: SpaceRole.custom, custom: [CustomPermission.manageUsers, CustomPermission.createCollections])
        ..confirm(alice, carol)
        ..seal(alice, [spaceKey])
        ..collection(carol, finance, grants: {'user:${bob.id}': CollectionPermission.view})
        ..group(alice, team)
        ..groupMembers(alice, team, add: [bob, carol])
        ..grant(alice, finance, 'group:$team', CollectionPermission.viewHidePasswords)
        ..role(alice, bob, SpaceRole.custom, custom: [CustomPermission.manageGroups])
        ..role(alice, carol, SpaceRole.owner)
        ..rename(alice, NameTarget.collection(finance))
        ..move(alice, finance, parent: everyone)
        ..policies(alice, {'requireSso': true})
        ..recoveryKey(alice)
        ..policies(alice, {'accountRecovery': true})
        ..keys(alice, [spaceKey, everyoneKey])
        ..ungrant(alice, finance, 'group:$team')
        ..groupDelete(alice, team)
        ..collectionDelete(alice, finance)
        ..rekey(bob, bob.withNewKeys())
        ..fence(alice);
    });

    test('the maker is the Owner, confirmed with their own bundle, and the space starts with one collection', () {
      final state = started().state;
      expect(state.member(alice.id)!.role, SpaceRole.owner);
      expect(state.member(alice.id)!.isConfirmed, isTrue);
      expect(state.member(alice.id)!.bundle!.fingerprint, alice.bundle.fingerprint);
      expect(state.member(alice.id)!.confirmation, isNull);
      expect(state.spaceKeyVersion, 1);
      expect(state.nameOf(const NameTarget.space())!.hash, hash32(7));
      expect(state.nameOf(const NameTarget.space())!.version, 1);
      expect(state.collections.keys, [everyone]);
      expect(state.collections[everyone]!.keyVersion, 1);
      expect(state.collections[everyone]!.nameHash, hash32(8));
      expect(state.accessOf(alice.id, everyone)!.manage, isTrue);
      expect(state.epoch, 1);
      expect(state.keyVersionOf(spaceKey), 1);
      expect(state.keyCheck(spaceKey), hash32(2));
      expect(state.holds(spaceKey, alice.id), isTrue);
      expect(state.covered(everyoneKey, alice.id), isTrue);
      expect(state.commitmentsOf(spaceKey).single.seq, 0);
      expect(state.markedKeys, isEmpty);
    });

    test('an invitation grants at once and holds no key, until the member is confirmed and sealed to', () {
      final invited = (started()..invite(alice, bob, grants: {everyone: CollectionPermission.edit})).state;
      expect(invited.member(bob.id)!.status, MemberStatus.invited);
      expect(invited.member(bob.id)!.invitedBy, alice.id);
      expect(invited.member(bob.id)!.bundle, isNull);
      expect(invited.accessOf(bob.id, everyone)!.edit, isTrue);
      expect(invited.entitled(spaceKey), {alice.id});
      expect(invited.awaiting(spaceKey), isEmpty);

      final confirmed =
          (started()
                ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
                ..confirm(alice, bob))
              .state;
      expect(confirmed.entitled(spaceKey), {alice.id, bob.id});
      expect(confirmed.awaiting(spaceKey), [bob.id]);
      expect(confirmed.awaiting(everyoneKey), [bob.id]);
      expect(confirmed.holds(spaceKey, bob.id), isFalse);

      final sealed = withBob().state;
      expect(sealed.awaiting(spaceKey), isEmpty);
      expect(sealed.awaiting(everyoneKey), isEmpty);
      expect(sealed.sealOf(spaceKey, bob.id)!.bundleVersion, 1);
      expect(sealed.sealOf(spaceKey, bob.id)!.seq, 3);
      expect(sealed.commitmentsOf(spaceKey).map((c) => (c.seq, c.count)), [(0, 1), (3, 1)]);
    });

    test('confirming records the member\'s bundle and confirmation', () {
      final bobState = withBob().state.member(bob.id)!;
      expect(bobState.isConfirmed, isTrue);
      expect(bobState.bundle!.bytes, bob.bundle.bytes);
      expect(bobState.confirmation!.by, alice.id);
      expect(bobState.confirmation!.seq, 2);
      expect(bobState.confirmation!.statement, hasLength(134));
      expect(bobState.bundleSignature, bob.bundleSignature);
    });

    test('derives the members, roles, groups, collections and policies of the end of the chain', () {
      final state = chain.state;
      expect(state.member(carol.id)!.role, SpaceRole.owner);
      expect(state.member(carol.id)!.custom, isEmpty);
      expect(state.member(bob.id)!.role, SpaceRole.custom);
      expect(state.member(bob.id)!.custom, {CustomPermission.manageGroups});
      expect(state.confirmedOwners, 2);
      expect(state.groups, isEmpty);
      expect(state.collections.keys, [everyone]);
      expect(state.retired, {finance, team});
      expect(state.policies['requireSso'], isTrue);
      expect(state.policies['accountRecovery'], isTrue);
      expect(state.recoveryKey, hasLength(1600));
      expect(state.epoch, 2);
      expect(state.home, uuid(0xf2));
      expect(state.promotion, hash32(33));
      expect(state.headSeq, chain.entries.length - 1);
      expect(state.headHash, chain.entries.last.entry.hashed);
    });

    test('a keys record replaces the keys, their seals and checks, and the names it commits again', () {
      final state = chain.state;
      expect(state.spaceKeyVersion, 2);
      expect(state.collections[everyone]!.keyVersion, 2);
      expect(state.keyCheck(spaceKey), hash32(3));
      expect(state.commitmentsOf(spaceKey).single.count, 3);
      expect(state.nameOf(const NameTarget.space())!.version, 2);
      expect(state.nameOf(const NameTarget.space())!.hash, hash32(41));
      expect(state.nameOf(NameTarget.collection(everyone))!.version, 2);
    });

    test('a rekey replaces the bundle, keeps a seq in place of a confirmation, and leaves the member awaiting seals', () {
      final state = chain.state;
      final member = state.member(bob.id)!;
      expect(member.bundle!.keyVersion, 2);
      expect(member.confirmation, isNull);
      expect(member.rekeySeq, chain.entries.length - 2);
      expect(state.holds(spaceKey, bob.id), isTrue);
      expect(state.covered(spaceKey, bob.id), isFalse);
      expect(state.awaiting(spaceKey), [bob.id]);
    });

    test('a combined access hides passwords only when every grant hides them', () {
      final state =
          (withBob()
                ..group(alice, team)
                ..groupMembers(alice, team, add: [bob])
                ..grant(alice, everyone, 'group:$team', CollectionPermission.viewHidePasswords))
              .state;
      final access = state.accessOf(bob.id, everyone)!;
      expect(access.edit, isTrue);
      expect(access.hidePasswords, isFalse);
      expect(access.manage, isFalse);
    });

    test('names take the space key version they are committed under', () {
      final state =
          (withBob()
                ..rename(alice, const NameTarget.space())
                ..keys(alice, [spaceKey])
                ..rename(alice, NameTarget.collection(everyone)))
              .state;
      expect(state.nameOf(NameTarget.collection(everyone))!.version, 2);
      expect(state.nameOf(NameTarget.collection(everyone))!.hash, hash32(21));
      expect(state.nameOf(const NameTarget.space())!.version, 2);
    });
  });

  group('removal ends access and names what must be replaced', () {
    test('removing a member who holds keys through a group needs exactly the keys they held in replace', () {
      final state = (withFinance()..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey])).state;
      expect(state.member(bob.id)!.status, MemberStatus.removed);
      expect(state.markedKeys, {spaceKey, everyoneKey, financeKey});
      expect(state.spaceKeyMarked, isTrue);
      expect(state.markedCollections, {everyone, finance});
      expect(state.accessOf(bob.id, everyone), isNull);
      expect(state.accessOf(bob.id, finance), isNull);
      expect(state.groups[team]!.members, isEmpty);
      expect(state.sealOf(spaceKey, bob.id), isNull);
      // Inviting them again gives them nothing
      final again =
          (withFinance()
                ..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey])
                ..invite(alice, bob))
              .state;
      expect(again.member(bob.id)!.status, MemberStatus.invited);
      expect(again.accessOf(bob.id, everyone), isNull);
      expect(again.accessOf(bob.id, finance), isNull);
      expect(again.groups[team]!.members, isEmpty);
    });

    test('an empty replace, or one that names too few or too many keys, is invalid', () {
      expectRefused(withFinance()..remove(alice, bob), ChainProblem.invalid);
      expectRefused(withFinance()..remove(alice, bob, replace: [spaceKey]), ChainProblem.invalid);
      expectRefused(withFinance()..remove(alice, bob, replace: [everyoneKey, spaceKey]), ChainProblem.invalid);
      expectRefused(withBob()..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey]), ChainProblem.invalid);
    });

    test('someone who was only invited, or confirmed and never sealed to, leaves nothing to replace', () {
      final invited =
          (started()
                ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
                ..remove(alice, bob))
              .state;
      expect(invited.markedKeys, isEmpty);
      final unsealed =
          (started()
                ..invite(alice, bob)
                ..confirm(alice, bob)
                ..remove(alice, bob))
              .state;
      expect(unsealed.markedKeys, isEmpty);
    });

    test('taking a grant away marks that collection\'s key, and only when the member held it', () {
      final state = (withFinance()..ungrant(alice, finance, 'group:$team', replace: [financeKey])).state;
      expect(state.markedKeys, {financeKey});
      expect(state.spaceKeyMarked, isFalse);
      expectRefused(withFinance()..ungrant(alice, finance, 'group:$team'), ChainProblem.invalid);
      // A grant nobody held through is nothing to replace
      final unheld =
          (withBob()
                ..collection(alice, finance)
                ..grant(alice, finance, 'user:${bob.id}', CollectionPermission.view)
                ..ungrant(alice, finance, 'user:${bob.id}'))
              .state;
      expect(unheld.markedKeys, isEmpty);
    });

    test('leaving a group, and deleting one, name the keys the group gave', () {
      expectRefused(withFinance()..groupMembers(alice, team, remove: [bob]), ChainProblem.invalid);
      expect((withFinance()..groupMembers(alice, team, remove: [bob], replace: [financeKey])).state.markedKeys, {financeKey});
      expectRefused(withFinance()..groupDelete(alice, team), ChainProblem.invalid);
      final deleted = (withFinance()..groupDelete(alice, team, replace: [financeKey])).state;
      expect(deleted.markedKeys, {financeKey});
      expect(deleted.groups, isEmpty);
      expect(deleted.grants[finance]!.keys, [Grantee.user(alice.id).wire]);
    });
  });

  group('a marked key waits for its replacement', () {
    ChainBuilder removedBob() => withFinance()
      ..invite(alice, carol)
      ..confirm(alice, carol)
      ..remove(alice, bob, replace: [everyoneKey, financeKey, spaceKey]);

    test('while the space key is marked: no seal, no confirmation, no new collection, group or name, no new access', () {
      expect(removedBob().state.spaceKeyMarked, isTrue);
      expectRefused(removedBob()..seal(alice, [spaceKey]), ChainProblem.invalid);
      expectRefused(
        removedBob()
          ..invite(alice, dan)
          ..confirm(alice, dan),
        ChainProblem.invalid,
      );
      expectRefused(removedBob()..collection(alice, uuid(0xc1)), ChainProblem.invalid);
      expectRefused(removedBob()..group(alice, uuid(0x92)), ChainProblem.invalid);
      expectRefused(removedBob()..rename(alice, const NameTarget.space()), ChainProblem.invalid);
      expectRefused(removedBob()..grant(alice, finance, 'user:${carol.id}', CollectionPermission.view), ChainProblem.invalid);
      expectRefused(removedBob()..invite(alice, dan, grants: {everyone: CollectionPermission.view}), ChainProblem.invalid);
      // An invitation without access is allowed, and so is taking access away
      expect((removedBob()..invite(alice, dan)).state.member(dan.id)!.status, MemberStatus.invited);
    });

    test('a keys record that replaces the space key and the collection keys with every name clears the marks', () {
      final state = (removedBob()..keys(alice, [spaceKey, everyoneKey, financeKey])).state;
      expect(state.markedKeys, isEmpty);
      expect(state.spaceKeyVersion, 2);
      expect(state.collections[finance]!.keyVersion, 2);
      expect(state.entitled(spaceKey), {alice.id, carol.id});
      expect(state.holds(spaceKey, bob.id), isFalse);
    });

    test('a keys record that replaces the space key without names, or with a collection missing, is invalid', () {
      expectRefused(removedBob()..keys(alice, [spaceKey, everyoneKey, financeKey], noNames: true), ChainProblem.invalid);
      final full = packedNames(removedBob().state);
      final missing = Uint8List.fromList([...full.sublist(0, 49 * 2), ...full.sublist(49 * 3)]);
      expectRefused(removedBob()..keys(alice, [spaceKey, everyoneKey, financeKey], names: missing), ChainProblem.invalid);
      final extra = Uint8List.fromList([...full, 3, ...uuidBytes(uuid(0x99)), ...hash32()]);
      expectRefused(removedBob()..keys(alice, [spaceKey], names: extra), ChainProblem.invalid);
      expectRefused(removedBob()..keys(alice, [everyoneKey], names: full), ChainProblem.invalid);
    });

    test('a collection key that is marked alone blocks only its own seal and access', () {
      final marked = withFinance()
        ..invite(alice, carol)
        ..confirm(alice, carol)
        ..ungrant(alice, finance, 'group:$team', replace: [financeKey]);
      expect(marked.state.markedKeys, {financeKey});
      expectRefused(marked.fork()..grant(alice, finance, 'user:${carol.id}', CollectionPermission.view), ChainProblem.invalid);
      expect(
        (marked.fork()..grant(alice, everyone, 'user:${carol.id}', CollectionPermission.view)).state.accessOf(carol.id, everyone),
        isNotNull,
      );
      expect((marked.fork()..keys(alice, [financeKey])).state.markedKeys, isEmpty);
    });

    test('a key that isn\'t marked may be replaced too, and a version that doesn\'t follow is invalid', () {
      expect((withBob()..keys(alice, [everyoneKey])).state.collections[everyone]!.keyVersion, 2);
      final chain = withBob();
      final before = chain.state;
      chain.add(alice, ChainKind.keys, {
        'rotate': [commitment(everyoneKey, before.keyVersionOf(everyoneKey)! + 2, 2, makes: true)],
      });
      expectRefused(chain, ChainProblem.invalid);
    });
  });

  group('seals', () {
    test('a seal shares a key with the members awaiting it, and only with them', () {
      // Nobody awaits the space key: a commitment of no recipients is malformed, of one is invalid
      expectRefused(withBob()..seal(alice, [spaceKey]), ChainProblem.malformed);
      final nobody = withBob();
      nobody.add(alice, ChainKind.seal, {
        'seals': [commitment(spaceKey, 1, 1)],
      });
      expectRefused(nobody, ChainProblem.invalid);
      final miscounted = started()
        ..invite(alice, bob)
        ..confirm(alice, bob);
      miscounted.add(alice, ChainKind.seal, {
        'seals': [commitment(spaceKey, 1, 2)],
      });
      expectRefused(miscounted, ChainProblem.invalid);
    });

    test('a seal of a key version that isn\'t current, or of a key that isn\'t there, is invalid', () {
      final stale = started()
        ..invite(alice, bob)
        ..confirm(alice, bob);
      stale.add(alice, ChainKind.seal, {
        'seals': [commitment(spaceKey, 2, 1)],
      });
      expectRefused(stale, ChainProblem.invalid);
      final missing = started()
        ..invite(alice, bob)
        ..confirm(alice, bob);
      missing.add(alice, ChainKind.seal, {
        'seals': [commitment(KeyRef.collection(finance), 1, 1)],
      });
      expectRefused(missing, ChainProblem.invalid);
    });

    test('a collection or a create that commits the wrong number of recipients is invalid', () {
      expectRefused(withBob()..collection(alice, finance, recipients: 2), ChainProblem.invalid);
      expect(
        (withBob()..collection(alice, finance, grants: {'user:${bob.id}': CollectionPermission.view})).state.awaiting(financeKey),
        isEmpty,
      );
    });
  });

  group('refuses a record that makes no sense where it lands', () {
    test('a sequence number that isn\'t next, or a link that doesn\'t follow', () {
      expectRefused(
        started()
          ..invite(alice, bob, grants: {})
          ..add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()}, seqOverride: 5),
        ChainProblem.badSequence,
      );
      expectRefused(
        started()..add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()}, prevOverride: Uint8List(32)),
        ChainProblem.badLink,
      );
    });

    test('a record of another space', () {
      final chain = started();
      final other = SpaceChainEntry(
        space: uuid(0x99),
        seq: 1,
        prev: chain.prev,
        epoch: 1,
        at: 5,
        by: alice.id,
        kind: ChainKind.group,
        body: {'group': team, 'nameHash': hash64()},
      );
      expect(refusal(() => chain.state.apply(other)).problem, ChainProblem.wrongSpace);
    });

    test('a chain that starts with anything but create, or creates twice', () {
      final first = ChainBuilder(space)..add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()});
      expectRefused(first, ChainProblem.invalid);
      expectRefused(started()..create(alice), ChainProblem.invalid);
    });

    test('a first record signed by someone other than the account that made the space', () {
      final chain = ChainBuilder(space);
      chain.add(bob, ChainKind.create, {
        'bundle': b64urlEncode(alice.bundle.bytes),
        'bundleSignature': b64urlEncode(alice.bundleSignature),
        'collection': {'id': everyone, 'nameHash': hash64()},
        'member': alice.id,
        'nameHash': hash64(),
        'seals': [commitment(everyoneKey, 1, 1, makes: true), commitment(spaceKey, 1, 1, makes: true)],
      });
      expectRefused(chain, ChainProblem.invalid);
    });

    test('a create whose bundle is another account\'s, or whose seals aren\'t the two first versions', () {
      final chain = ChainBuilder(space);
      chain.add(alice, ChainKind.create, {
        'bundle': b64urlEncode(bob.bundle.bytes),
        'bundleSignature': b64urlEncode(bob.bundleSignature),
        'collection': {'id': everyone, 'nameHash': hash64()},
        'member': alice.id,
        'nameHash': hash64(),
        'seals': [commitment(everyoneKey, 1, 1, makes: true), commitment(spaceKey, 1, 1, makes: true)],
      });
      expectRefused(chain, ChainProblem.badBundle);
      final seals = ChainBuilder(space);
      seals.add(alice, ChainKind.create, {
        'bundle': b64urlEncode(alice.bundle.bytes),
        'bundleSignature': b64urlEncode(alice.bundleSignature),
        'collection': {'id': everyone, 'nameHash': hash64()},
        'member': alice.id,
        'nameHash': hash64(),
        'seals': [commitment(everyoneKey, 1, 1, makes: true), commitment(spaceKey, 2, 1, makes: true)],
      });
      expectRefused(seals, ChainProblem.invalid);
    });

    test('an invitation for a member who is in already, as an owner, with custom permissions on another role, or for nothing', () {
      expectRefused(withBob()..invite(alice, bob), ChainProblem.invalid);
      expectRefused(started()..invite(alice, bob, role: SpaceRole.owner), ChainProblem.invalid);
      expectRefused(started()..invite(alice, bob, custom: [CustomPermission.manageUsers]), ChainProblem.invalid);
      expectRefused(started()..invite(alice, bob, grants: {uuid(0xdd): CollectionPermission.view}), ChainProblem.invalid);
    });

    test('a confirmation of someone not invited, of oneself, or of a member already confirmed with the same keys', () {
      expectRefused(started()..confirm(alice, bob), ChainProblem.invalid);
      expectRefused(started()..confirm(alice, alice), ChainProblem.invalid);
      expectRefused(withBob()..confirm(alice, bob), ChainProblem.invalid);
    });

    test('a confirmation whose statement is for another member, key version or confirmer, and a bundle of another account', () {
      ChainBuilder invited() => started()..invite(alice, bob);
      expectRefused(invited()..confirm(alice, bob, statementFor: carol), ChainProblem.badConfirmation);
      expectRefused(invited()..confirm(alice, bob, statementFor: bob.withNewKeys()), ChainProblem.badConfirmation);
      expectRefused(invited()..confirm(alice, bob, statementConfirmer: carol), ChainProblem.badConfirmation);
      expectRefused(invited()..confirm(alice, bob, bundleFrom: carol), ChainProblem.badBundle);
    });

    test('a member confirmed again with a newer key version has the new bundle, and an older one is refused', () {
      final newer = bob.withNewKeys();
      final state = (withBob()..confirm(alice, newer)).state;
      expect(state.member(bob.id)!.bundle!.keyVersion, 2);
      expect(state.confirmedMembers.length, 2);
      expectRefused(
        withBob()
          ..confirm(alice, bob.withNewKeys().withNewKeys())
          ..confirm(alice, newer),
        ChainProblem.invalid,
      );
    });

    test('a rekey to a bundle of the same or an older key version, or of another account', () {
      expectRefused(withBob()..rekey(bob, bob), ChainProblem.invalid);
      expectRefused(withBob()..rekey(bob, carol.withNewKeys()), ChainProblem.badBundle);
      expect((withBob()..rekey(bob, bob.withNewKeys())).state.member(bob.id)!.bundle!.keyVersion, 2);
    });

    test('a role that changes nothing, an owner who isn\'t confirmed, and custom permissions on another role', () {
      expectRefused(withBob()..role(alice, bob, SpaceRole.member), ChainProblem.invalid);
      expectRefused(
        started()
          ..invite(alice, bob)
          ..role(alice, bob, SpaceRole.owner),
        ChainProblem.invalid,
      );
      expectRefused(withBob()..role(alice, bob, SpaceRole.admin, custom: [CustomPermission.manageUsers]), ChainProblem.invalid);
    });

    test('a collection that exists, was deleted, whose parent is missing, or that nests too deep', () {
      expectRefused(started()..collection(alice, everyone), ChainProblem.invalid);
      expectRefused(started()..collection(alice, finance, parent: uuid(0xdd)), ChainProblem.invalid);
      expectRefused(
        started()
          ..collectionDelete(alice, everyone)
          ..collection(alice, everyone),
        ChainProblem.invalid,
      );
      final chain = started();
      var parent = everyone;
      for (var depth = 2; depth <= 16; depth++) {
        final id = uuid(0x1000 + depth);
        chain.collection(alice, id, parent: parent, recipients: 1);
        parent = id;
      }
      expect(chain.state.collections, hasLength(16));
      expectRefused(chain..collection(alice, uuid(0x2000), parent: parent, recipients: 1), ChainProblem.invalid);
    });

    test('a collection whose maker isn\'t among its grants', () {
      final chain = started();
      chain.add(alice, ChainKind.collection, {
        'collection': finance,
        'grants': [
          {'grantee': 'user:${bob.id}', 'permission': 'view'},
        ],
        'nameHash': hash64(),
        'seals': [commitment(financeKey, 1, 1, makes: true)],
      });
      expectRefused(chain, ChainProblem.invalid);
    });

    test('a grant of a collection or to a grantee that isn\'t there, one that changes nothing, and an ungrant that isn\'t', () {
      expectRefused(started()..grant(alice, uuid(0xdd), 'user:${alice.id}', CollectionPermission.view), ChainProblem.invalid);
      expectRefused(started()..grant(alice, everyone, 'user:${bob.id}', CollectionPermission.view), ChainProblem.invalid);
      expectRefused(started()..grant(alice, everyone, 'group:$team', CollectionPermission.view), ChainProblem.invalid);
      expectRefused(started()..grant(alice, everyone, 'user:${alice.id}', CollectionPermission.manage), ChainProblem.invalid);
      expectRefused(started()..ungrant(alice, everyone, 'user:${bob.id}'), ChainProblem.invalid);
    });

    test('moving a collection below itself, to its own parent, or to one that isn\'t there', () {
      ChainBuilder nested() => started()..collection(alice, finance, parent: everyone, recipients: 1);
      expectRefused(nested()..move(alice, everyone, parent: finance), ChainProblem.invalid);
      expectRefused(nested()..move(alice, finance, parent: everyone), ChainProblem.invalid);
      expectRefused(nested()..move(alice, finance, parent: finance), ChainProblem.invalid);
      expectRefused(nested()..move(alice, finance, parent: uuid(0xdd)), ChainProblem.invalid);
      expect((nested()..move(alice, finance)).state.collections[finance]!.parent, isNull);
    });

    test('deleting a collection that has children, and reusing the id of a deleted collection or group', () {
      expectRefused(
        started()
          ..collection(alice, finance, parent: everyone, recipients: 1)
          ..collectionDelete(alice, everyone),
        ChainProblem.invalid,
      );
      expectRefused(
        withBob()
          ..group(alice, team)
          ..groupDelete(alice, team)
          ..group(alice, team),
        ChainProblem.invalid,
      );
    });

    test('a group member who isn\'t in the space or is in the group already, and a removal of one who isn\'t', () {
      expectRefused(
        started()
          ..group(alice, team)
          ..groupMembers(alice, team, add: [bob]),
        ChainProblem.invalid,
      );
      expectRefused(
        withBob()
          ..group(alice, team)
          ..groupMembers(alice, team, add: [bob])
          ..groupMembers(alice, team, add: [bob]),
        ChainProblem.invalid,
      );
      expectRefused(
        withBob()
          ..group(alice, team)
          ..groupMembers(alice, team, remove: [bob]),
        ChainProblem.invalid,
      );
    });

    test('a rename of nothing, or to the name it has', () {
      expectRefused(started()..rename(alice, NameTarget.collection(finance)), ChainProblem.invalid);
      expectRefused(started()..rename(alice, NameTarget.group(team)), ChainProblem.invalid);
      expectRefused(started()..rename(alice, const NameTarget.space(), seed: 7), ChainProblem.invalid);
    });

    test('removing or demoting the last confirmed owner, and an owner who isn\'t confirmed', () {
      expectRefused(started()..remove(alice, alice, replace: [spaceKey, everyoneKey]), ChainProblem.invalid);
      expectRefused(started()..role(alice, alice, SpaceRole.admin), ChainProblem.invalid);
      expect(
        (withBob()
              ..role(alice, bob, SpaceRole.owner)
              ..role(alice, alice, SpaceRole.admin))
            .state
            .confirmedOwners,
        1,
      );
    });

    test('the policies: account recovery with no recovery key, a timeout that contradicts itself, or no change', () {
      expectRefused(started()..policies(alice, {'accountRecovery': true}), ChainProblem.invalid);
      expectRefused(
        started()..policies(alice, {
          'sessionTimeout': {'action': 'lock', 'minutes': 0},
        }),
        ChainProblem.invalid,
      );
      expectRefused(
        started()..policies(alice, {
          'sessionTimeout': {'action': 'none', 'minutes': 5},
        }),
        ChainProblem.invalid,
      );
      expectRefused(started()..policies(alice, {'twoStep': false}), ChainProblem.invalid);
      expect(
        (started()..policies(alice, {
              'sessionTimeout': {'action': 'lock', 'minutes': 15},
            }))
            .state
            .policies['sessionTimeout'],
        {'action': 'lock', 'minutes': 15},
      );
    });

    test('a recovery key that is set already, a clear with none, and a clear while account recovery is on', () {
      expectRefused(
        started()
          ..recoveryKey(alice)
          ..recoveryKey(alice),
        ChainProblem.invalid,
      );
      expectRefused(started()..recoveryKeyClear(alice), ChainProblem.invalid);
      expectRefused(
        started()
          ..recoveryKey(alice)
          ..policies(alice, {'accountRecovery': true})
          ..recoveryKeyClear(alice),
        ChainProblem.invalid,
      );
      final cleared =
          (started()
                ..recoveryKey(alice)
                ..recoveryKeyClear(alice))
              .state;
      expect(cleared.recoveryKey, isNull);
    });

    test('a body with a member it doesn\'t have, or one that isn\'t a UUID, is refused as malformed', () {
      final chain = started();
      chain.add(alice, ChainKind.group, {'group': 'not-a-uuid', 'nameHash': hash64()});
      expectRefused(chain, ChainProblem.malformed);
    });
  });

  group('epochs', () {
    test('a record of the next epoch that isn\'t a fence, a fence that doesn\'t raise it by one, and a lower epoch', () {
      final early = withBob();
      early.add(alice, ChainKind.role, {'custom': <String>[], 'member': bob.id, 'role': 'admin'}, epochOverride: 2);
      expectRefused(early, ChainProblem.badEpoch);
      expectRefused(withBob()..fence(alice, epochOverride: 3), ChainProblem.badEpoch);
      expectRefused(withBob()..fence(alice, epochOverride: 1), ChainProblem.badEpoch);
      final fenced = withBob()..fence(alice);
      expect(fenced.state.epoch, 2);
      final lower = fenced.fork();
      lower.add(alice, ChainKind.role, {'custom': <String>[], 'member': bob.id, 'role': 'admin'}, epochOverride: 1);
      expectRefused(lower, ChainProblem.badEpoch);
      expect((fenced..role(alice, bob, SpaceRole.admin)).state.epoch, 2);
    });

    test('the first record is of epoch 1', () {
      final chain = ChainBuilder(space, epoch: 2)..create(alice);
      expectRefused(chain, ChainProblem.badEpoch);
    });
  });

  group('limits', () {
    test('the 1,001st collection is invalid, and the 1,000th is not', () {
      final chain = started();
      var state = chain.state;
      for (var i = 1; i < 1000; i++) {
        state = state.apply(chain.collection(alice, uuid(0x10000 + i), recipients: 1).entry);
      }
      expect(state.collections, hasLength(1000));
      final next = chain.collection(alice, uuid(0x20000), recipients: 1).entry;
      expect(refusal(() => state.apply(next)).problem, ChainProblem.invalid);
    });

    test('the 10,001st member is invalid, and the 10,000th is not', () {
      final chain = started();
      var state = chain.state;
      SpaceChainEntry invite(int n) => chain.add(alice, ChainKind.invite, {
        'custom': <String>[],
        'grants': <Object?>[],
        'member': uuid(0x100000 + n),
        'role': 'member',
      }).entry;
      for (var i = 1; i < 10000; i++) {
        state = state.apply(invite(i));
      }
      expect(state.members, hasLength(10000));
      final next = invite(10000);
      expect(refusal(() => state.apply(next)).problem, ChainProblem.invalid);
    }, timeout: const Timeout(Duration(minutes: 5)));
  });
}
