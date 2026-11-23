@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_head_store.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:kemlock_core/features/spaces/space_verify.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

// Checking a chain: the order of the checks, the signatures, and who may make each record (the space chain
// section of docs/crypto.md, "Verification", "Authority" and its test cases). Every chain, valid or not, is built in
// code, with cheap fake signatures except in the last group.
void main() {
  final space = uuid(0x5a);
  final alice = Person(1); // the Owner
  final bob = Person(2); // an Admin
  final carol = Person(3); // a Member with edit on "Everyone"
  final dan = Person(4);
  final erin = Person(5);
  final gus = Person(6);
  final everyone = uuid(0xe0);
  final finance = uuid(0xf1);
  final team = uuid(0x91);
  final spaceKey = const KeyRef.space();
  final financeKey = KeyRef.collection(finance);
  const crypto = FakeChainCrypto();

  /// alice (Owner) makes the space and confirms bob as an Admin and carol as a Member with edit on "Everyone".
  ChainBuilder base() => ChainBuilder(space)
    ..create(alice)
    ..invite(alice, bob, role: SpaceRole.admin)
    ..confirm(alice, bob)
    ..invite(alice, carol, grants: {everyone: CollectionPermission.edit})
    ..confirm(alice, carol);

  Future<ChainResult> verify(ChainBuilder chain) => verifyChain(space: space, entries: chain.entries, crypto: crypto);

  /// Verifies [chain] plus the one record [add] makes, and expects the result to stop at it for [problem].
  Future<ChainResult> refused(ChainBuilder chain, void Function(ChainBuilder) add, ChainProblem problem) async {
    final next = chain.fork();
    add(next);
    final result = await verify(next);
    expect(result.problem, problem, reason: result.detail);
    expect(result.problemSeq, chain.seq, reason: 'it stops at the record that was refused');
    expect(result.accepted, hasLength(chain.entries.length), reason: 'what came before is accepted');
    expect(result.state.headSeq, chain.seq - 1, reason: 'the state is the one before the refused record');
    return result;
  }

  /// Verifies [chain] plus the record [add] makes, and expects every record to be accepted.
  Future<ChainResult> accepted(ChainBuilder chain, void Function(ChainBuilder) add) async {
    final next = chain.fork();
    add(next);
    final result = await verify(next);
    expect(result.problem, isNull, reason: result.detail);
    expect(result.accepted, hasLength(next.entries.length));
    return result;
  }

  Future<void> notAllowed(ChainBuilder chain, void Function(ChainBuilder) add) async => refused(chain, add, ChainProblem.notAllowed);

  test('a valid chain is accepted, and its state is the chain\'s', () async {
    final result = await verify(base());
    expect(result.ok, isTrue);
    expect(result.accepted, hasLength(5));
    expect(result.anchor!.seq, 4);
    expect(result.anchor!.epoch, 1);
    expect(result.state.member(bob.id)!.role, SpaceRole.admin);
    expect(result.state.accessOf(carol.id, everyone)!.edit, isTrue);
    expect(result.droppedFrom, isNull);
  });

  group('the signatures, and the order of the checks', () {
    test('a record signed by another key than its signer is recorded with is a bad signature', () async {
      await refused(
        base(),
        (c) => c.add(bob, ChainKind.group, {'group': team, 'nameHash': hash64()}, signer: carol),
        ChainProblem.badSignature,
      );
    });

    test('a signer who is not a member, is only invited, or was removed is unknown', () async {
      await refused(base(), (c) => c.add(dan, ChainKind.group, {'group': team, 'nameHash': hash64()}), ChainProblem.unknownSigner);
      await refused(
        base()..invite(alice, dan),
        (c) => c.add(dan, ChainKind.group, {'group': team, 'nameHash': hash64()}),
        ChainProblem.unknownSigner,
      );
      await refused(
        base()..remove(alice, carol, replace: []),
        (c) => c.add(carol, ChainKind.group, {'group': team, 'nameHash': hash64()}),
        ChainProblem.unknownSigner,
      );
    });

    test('a record that breaks the authority table and is signed by a key the chain doesn\'t record is a bad signature', () async {
      await refused(
        base(),
        (c) => c.add(carol, ChainKind.fence, {'home': uuid(0xf2), 'promotion': hash64()}, signer: dan, epochOverride: 2),
        ChainProblem.badSignature,
      );
    });

    test('a record with a bad link and a bad signature is a bad link', () async {
      await refused(
        base(),
        (c) => c.add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()}, signer: bob, prevOverride: Uint8List(32)),
        ChainProblem.badLink,
      );
    });

    test('a link, a sequence number and an epoch that don\'t follow', () async {
      final skipped = base()..add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()}, seqOverride: 9);
      final result = await verify(skipped);
      expect(result.problem, ChainProblem.badSequence);
      expect(result.problemSeq, 9);
      await refused(
        base(),
        (c) => c.add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()}, epochOverride: 2),
        ChainProblem.badEpoch,
      );
    });

    test('a first record of another space, or one that is not a create', () async {
      final other = ChainBuilder(uuid(0x99))..create(alice);
      final wrong = await verifyChain(space: space, entries: other.entries, crypto: crypto);
      expect(wrong.problem, ChainProblem.wrongSpace);
      final first = ChainBuilder(space)..add(alice, ChainKind.group, {'group': team, 'nameHash': hash64()});
      expect((await verify(first)).problem, ChainProblem.invalid);
    });

    test('a first record whose bundle isn\'t the signer\'s, or isn\'t signed by its own key', () async {
      final foreign = ChainBuilder(space)
        ..add(alice, ChainKind.create, {
          'bundle': b64urlEncode(bob.bundle.bytes),
          'bundleSignature': b64urlEncode(bob.bundleSignature),
          'collection': {'id': everyone, 'nameHash': hash64()},
          'member': alice.id,
          'nameHash': hash64(),
          'seals': [commitment(KeyRef.collection(everyone), 1, 1, makes: true), commitment(spaceKey, 1, 1, makes: true)],
        });
      expect((await verify(foreign)).problem, ChainProblem.badBundle);
      final forged = ChainBuilder(space)
        ..add(alice, ChainKind.create, {
          'bundle': b64urlEncode(alice.bundle.bytes),
          'bundleSignature': b64urlEncode(bob.bundleSignature),
          'collection': {'id': everyone, 'nameHash': hash64()},
          'member': alice.id,
          'nameHash': hash64(),
          'seals': [commitment(KeyRef.collection(everyone), 1, 1, makes: true), commitment(spaceKey, 1, 1, makes: true)],
        });
      expect((await verify(forged)).problem, ChainProblem.badBundle);
    });

    test('a confirmation with a bundle not signed by its own key, or a statement not signed by the confirmer', () async {
      final invited = ChainBuilder(space)
        ..create(alice)
        ..invite(alice, bob);
      await refused(invited, (c) => c.confirm(alice, bob, bundleSigner: carol), ChainProblem.badBundle);
      await refused(invited, (c) => c.confirm(alice, bob, statementSigner: carol), ChainProblem.badConfirmation);
      await refused(invited, (c) => c.confirm(alice, bob, statementConfirmer: carol), ChainProblem.badConfirmation);
      await accepted(invited, (c) => c.confirm(alice, bob));
    });

    test('a record the state refuses is invalid, after its signatures were checked', () async {
      await refused(base(), (c) => c.invite(alice, bob), ChainProblem.invalid);
      await refused(base(), (c) => c.invite(alice, dan, role: SpaceRole.owner), ChainProblem.invalid);
    });
  });

  group('a rekey (the only Owner replaces their keys)', () {
    final alice2 = alice.withNewKeys();

    test('is accepted with a cosignature, and the next record is signed with the new key', () async {
      final chain = base()..rekey(alice, alice2);
      expect((await verify(chain)).ok, isTrue);
      await accepted(chain, (c) => c.collection(alice2, finance, recipients: 1));
      await refused(chain, (c) => c.collection(alice, finance, recipients: 1), ChainProblem.badSignature);
    });

    test('with a cosignature by another key is a bad signature, and without one too', () async {
      await refused(base(), (c) => c.rekey(alice, alice2, cosigner: bob), ChainProblem.badSignature);
      await refused(
        base(),
        (c) => c.add(alice, ChainKind.rekey, {
          'bundle': b64urlEncode(alice2.bundle.bytes),
          'bundleSignature': b64urlEncode(alice2.bundleSignature),
        }),
        ChainProblem.badSignature,
      );
    });

    test('to a bundle of the same key version is invalid, and a bundle not signed by its own key a bad bundle', () async {
      await refused(base(), (c) => c.rekey(alice, alice), ChainProblem.invalid);
      await refused(
        base(),
        (c) => c.add(alice, ChainKind.rekey, {
          'bundle': b64urlEncode(alice2.bundle.bytes),
          'bundleSignature': b64urlEncode(bob.bundleSignature),
        }, cosigner: alice2),
        ChainProblem.badBundle,
      );
    });

    test('keeps the Owner able to sign, and any member may rekey for themselves', () async {
      await accepted(base(), (c) => c.rekey(carol, carol.withNewKeys()));
      await accepted(base(), (c) => c.rekey(bob, bob.withNewKeys()));
    });
  });

  group('who may sign what', () {
    /// base() and dan as a Custom member with only manage-groups, a collection "Finance" with carol's view.
    ChainBuilder withGroups() => base()
      ..invite(alice, dan, role: SpaceRole.custom, custom: [CustomPermission.manageGroups])
      ..confirm(alice, dan)
      ..collection(alice, finance, grants: {'user:${carol.id}': CollectionPermission.view})
      ..group(alice, team);

    test('1: self-widening through a group is not allowed; a group with no grants is, and a later grant is not', () async {
      final granted = withGroups()..grant(alice, finance, 'group:$team', CollectionPermission.edit);
      await notAllowed(granted, (c) => c.groupMembers(dan, team, add: [dan]));
      final empty = withGroups();
      await accepted(empty, (c) => c.groupMembers(dan, team, add: [dan]));
      await notAllowed(
        empty.fork()..groupMembers(dan, team, add: [dan]),
        (c) => c.grant(dan, finance, 'group:$team', CollectionPermission.view),
      );
    });

    test('2: adding someone to a group that is granted needs manage on that collection', () async {
      final granted = withGroups()..grant(alice, finance, 'group:$team', CollectionPermission.edit);
      await notAllowed(granted, (c) => c.groupMembers(dan, team, add: [carol]));
      final managing = granted.fork()..grant(alice, finance, 'user:${dan.id}', CollectionPermission.manage);
      final result = await accepted(managing, (c) => c.groupMembers(dan, team, add: [carol]));
      expect(result.state.accessOf(carol.id, finance)!.edit, isTrue);
      // The grant of a collection to the group by the member who manages it
      await accepted(
        withGroups()..grant(alice, finance, 'user:${dan.id}', CollectionPermission.manage),
        (c) => c.grant(dan, finance, 'group:$team', CollectionPermission.view),
      );
    });

    test('3: an Admin changes no Owner, even through a group, and the other Owner does', () async {
      ChainBuilder owners() => base()
        ..invite(alice, erin, role: SpaceRole.member, grants: {everyone: CollectionPermission.view})
        ..confirm(alice, erin)
        ..role(alice, erin, SpaceRole.owner)
        ..group(alice, team)
        ..groupMembers(alice, team, add: [erin]);
      final chain = owners();
      expect((await verify(chain)).ok, isTrue);
      expect((await verify(chain)).state.confirmedOwners, 2);
      // ungrant of an Owner's grant
      await notAllowed(chain, (c) => c.ungrant(bob, everyone, 'user:${erin.id}'));
      await accepted(chain, (c) => c.ungrant(alice, everyone, 'user:${erin.id}'));
      // a group that holds an Owner changes, and an Owner is removed from one
      await notAllowed(chain, (c) => c.groupMembers(bob, team, remove: [erin]));
      await accepted(chain, (c) => c.groupMembers(alice, team, remove: [erin]));
      await notAllowed(chain, (c) => c.grant(bob, everyone, 'group:$team', CollectionPermission.edit));
      await accepted(chain, (c) => c.grant(alice, everyone, 'group:$team', CollectionPermission.edit));
      // a demotion
      await notAllowed(chain, (c) => c.role(bob, erin, SpaceRole.member));
      await accepted(chain, (c) => c.role(alice, erin, SpaceRole.member));
      await notAllowed(chain, (c) => c.remove(bob, erin));
      await accepted(chain, (c) => c.remove(alice, erin));
    });

    test('3: with one confirmed Owner, demoting or removing them is invalid whoever signs it', () async {
      await refused(base(), (c) => c.role(alice, alice, SpaceRole.admin), ChainProblem.invalid);
      await refused(base(), (c) => c.remove(alice, alice, replace: [spaceKey, KeyRef.collection(everyone)]), ChainProblem.invalid);
      await refused(base(), (c) => c.remove(bob, alice, replace: [spaceKey, KeyRef.collection(everyone)]), ChainProblem.invalid);
    });

    test('an Admin makes members and roles but no Owner, and invites no Owner', () async {
      await accepted(base(), (c) => c.invite(bob, dan, role: SpaceRole.admin));
      await notAllowed(base(), (c) => c.role(bob, carol, SpaceRole.owner));
      await accepted(base(), (c) => c.role(bob, carol, SpaceRole.admin));
    });

    test('a Member only leaves, and a Member invites, confirms and grants nobody', () async {
      await accepted(base(), (c) => c.remove(carol, carol));
      await notAllowed(base(), (c) => c.remove(carol, bob));
      await notAllowed(base(), (c) => c.invite(carol, dan));
      await notAllowed(base(), (c) => c.collection(carol, finance, recipients: 1));
      await notAllowed(base(), (c) => c.group(carol, team));
      await notAllowed(base(), (c) => c.role(carol, carol, SpaceRole.admin));
    });

    test('nobody widens themselves: a role, a permission set or an access', () async {
      await notAllowed(base(), (c) => c.role(bob, bob, SpaceRole.owner));
      await accepted(base(), (c) => c.role(bob, bob, SpaceRole.member));
      await notAllowed(
        base()..grant(alice, everyone, 'user:${bob.id}', CollectionPermission.view),
        (c) => c.grant(bob, everyone, 'user:${bob.id}', CollectionPermission.manage),
      );
      final custom = base()
        ..invite(alice, dan, role: SpaceRole.custom, custom: [CustomPermission.manageUsers])
        ..confirm(alice, dan);
      await notAllowed(
        custom,
        (c) => c.role(dan, dan, SpaceRole.custom, custom: [CustomPermission.manageUsers, CustomPermission.createCollections]),
      );
      await accepted(custom, (c) => c.role(dan, dan, SpaceRole.member));
    });

    test('17: a Custom member with manage-users manages only members whose permissions are all its own', () async {
      final chain = base()
        ..invite(alice, dan, role: SpaceRole.custom, custom: [CustomPermission.manageUsers])
        ..confirm(alice, dan)
        ..invite(alice, erin, role: SpaceRole.custom, custom: [CustomPermission.createCollections])
        ..confirm(alice, erin);
      await notAllowed(chain, (c) => c.role(dan, erin, SpaceRole.member));
      await notAllowed(chain, (c) => c.remove(dan, erin));
      await notAllowed(chain, (c) => c.invite(dan, gus, role: SpaceRole.custom, custom: [CustomPermission.createCollections]));
      await notAllowed(chain, (c) => c.invite(dan, gus, role: SpaceRole.admin));
      await accepted(chain, (c) => c.invite(dan, gus, role: SpaceRole.custom, custom: [CustomPermission.manageUsers]));
      await accepted(chain, (c) => c.invite(dan, gus));
      await accepted(chain, (c) => c.remove(dan, carol));
      await notAllowed(chain, (c) => c.remove(dan, bob));
    });

    test('a Custom member makes collections with create-collections, and names groups with manage-groups', () async {
      final chain = base()
        ..invite(alice, dan, role: SpaceRole.custom, custom: [CustomPermission.createCollections])
        ..confirm(alice, dan);
      await accepted(chain, (c) => c.collection(dan, finance, recipients: 1));
      await notAllowed(chain, (c) => c.group(dan, team));
    });

    test('collections move, are renamed and are deleted only by who may grant them', () async {
      final chain = base()
        ..collection(alice, finance, grants: {'user:${carol.id}': CollectionPermission.manage})
        ..collection(alice, uuid(0xf2), recipients: 1);
      await accepted(chain, (c) => c.move(carol, finance, parent: everyone));
      await notAllowed(chain, (c) => c.move(carol, uuid(0xf2), parent: everyone));
      await accepted(chain, (c) => c.rename(carol, NameTarget.collection(finance)));
      await notAllowed(chain, (c) => c.rename(carol, NameTarget.collection(uuid(0xf2))));
      await notAllowed(chain, (c) => c.rename(carol, const NameTarget.space()));
      await accepted(chain, (c) => c.rename(bob, const NameTarget.space()));
      await accepted(chain, (c) => c.collectionDelete(carol, finance));
    });

    test('a seal is made only by a member who holds every key it seals', () async {
      await notAllowed(base(), (c) => c.seal(bob, [spaceKey]));
      final result = await accepted(base(), (c) => c.seal(alice, [spaceKey]));
      expect(result.state.awaiting(spaceKey), isEmpty);
    });

    test('8: a fence is an Owner\'s, one epoch up', () async {
      await accepted(base(), (c) => c.fence(alice));
      await notAllowed(base(), (c) => c.fence(bob));
      await refused(base(), (c) => c.fence(alice, epochOverride: 3), ChainProblem.badEpoch);
      await refused(base(), (c) => c.fence(alice, epochOverride: 1), ChainProblem.badEpoch);
    });

    test('15: policies are an Owner\'s or an Admin\'s, and account recovery is an Owner\'s', () async {
      final keyed = base()..recoveryKey(alice);
      await notAllowed(keyed, (c) => c.policies(bob, {'accountRecovery': true}));
      await accepted(keyed, (c) => c.policies(alice, {'accountRecovery': true}));
      await accepted(base(), (c) => c.policies(bob, {'requireSso': true}));
      await notAllowed(base(), (c) => c.policies(carol, {'requireSso': true}));
      await refused(base(), (c) => c.policies(alice, {'accountRecovery': true}), ChainProblem.invalid);
      await refused(
        base(),
        (c) => c.policies(alice, {
          'sessionTimeout': {'action': 'lock', 'minutes': 0},
        }),
        ChainProblem.invalid,
      );
    });

    test('a recovery key is an Owner\'s, and is checked as a usable key', () async {
      await notAllowed(base(), (c) => c.recoveryKey(bob));
      await accepted(base(), (c) => c.recoveryKey(alice));
      final bad = base();
      bad.add(alice, ChainKind.recoveryKey, {'key': b64urlEncode(Uint8List(Kx1.publicKeyLength))});
      expect((await verify(bad)).problem, ChainProblem.invalid);
    });

    test('16: a key is replaced by an entitled Owner, Admin or manager, or by any entitled member while it is marked', () async {
      // finance: alice manages it, carol and gus view it, and the record that made it sealed its key to all three
      ChainBuilder held() => base()
        ..invite(alice, gus)
        ..confirm(alice, gus)
        ..collection(alice, finance, grants: {'user:${carol.id}': CollectionPermission.view, 'user:${gus.id}': CollectionPermission.view})
        ..seal(alice, [spaceKey]);
      final chain = held();
      expect((await verify(chain)).ok, isTrue);
      // An Admin without access to Finance can't replace its key, and a member with view can't while it isn't marked
      await notAllowed(chain, (c) => c.keys(bob, [financeKey]));
      await notAllowed(chain, (c) => c.keys(carol, [financeKey]));
      await accepted(chain, (c) => c.keys(alice, [financeKey]));
      // Marked by gus losing his grant: any member entitled to it may replace it
      final marked = chain.fork()..ungrant(alice, finance, 'user:${gus.id}', replace: [financeKey]);
      expect(marked.state.markedKeys, {financeKey});
      await accepted(marked, (c) => c.keys(carol, [financeKey]));
      await notAllowed(marked, (c) => c.keys(bob, [financeKey]));
    });

    test('keys for the space key are an Owner\'s or an Admin\'s', () async {
      await accepted(base(), (c) => c.keys(alice, [spaceKey]));
      await accepted(base(), (c) => c.keys(bob, [spaceKey]));
      await notAllowed(base(), (c) => c.keys(carol, [spaceKey]));
    });

    test('a removal that names its keys, by whoever manages the member', () async {
      final chain = base()..seal(alice, [spaceKey, KeyRef.collection(everyone)]);
      await accepted(chain, (c) => c.remove(bob, carol, replace: [KeyRef.collection(everyone), spaceKey]));
      await notAllowed(chain, (c) => c.remove(carol, bob, replace: [spaceKey]));
    });
  });

  group('the anchor: rollback, fork and fence', () {
    /// base() and policy toggles by alice up to [n] records, seq 0 to n - 1, all of epoch 1.
    ChainBuilder upTo(int n) {
      final chain = base();
      for (var i = 0; chain.entries.length < n; i++) {
        chain.policies(alice, {'requireSso': i.isEven});
      }
      return chain;
    }

    ChainAnchor anchorOf(ChainBuilder chain) => ChainAnchor.of(chain.state, chain.entries)!;

    Future<ChainResult> verifyWith(ChainBuilder chain, ChainAnchor? anchor) =>
        verifyChain(space: space, entries: chain.entries, anchor: anchor, crypto: crypto);

    test('a chain the device accepted, or one that goes on from it, is accepted', () async {
      final device = upTo(13);
      final same = await verifyWith(device, anchorOf(device));
      expect(same.ok, isTrue, reason: same.detail);
      expect(same.anchor, anchorOf(device));
      final longer = upTo(13)..policies(alice, {'requireSso': false, 'twoStep': true});
      final result = await verifyWith(longer, anchorOf(device));
      expect(result.ok, isTrue);
      expect(result.anchor!.seq, 13);
      expect(result.droppedFrom, isNull);
      // A device with no anchor accepts a chain that is consistent: first contact is what ties it to people
      expect((await verifyWith(longer, null)).ok, isTrue);
    });

    test('14: a chain that ends before the anchor is rolled back, and another record at an accepted seq is forked', () async {
      final device = upTo(13);
      final shorter = upTo(10);
      final rolledBack = await verifyWith(shorter, anchorOf(device));
      expect(rolledBack.problem, ChainProblem.rolledBack);
      expect(rolledBack.problemSeq, 9, reason: "names the seq of the served chain's last record, as the server's vectors do");
      expect(rolledBack.state.headSeq, 9, reason: 'the last valid state of the served chain');
      expect(rolledBack.anchor!.seq, 9);
      final empty = await verifyChain(space: space, entries: const [], anchor: anchorOf(device), crypto: crypto);
      expect(empty.problem, ChainProblem.rolledBack);
      expect(empty.problemSeq, isNull);

      final other = upTo(12)..policies(alice, {'requireSso': true, 'twoStep': true});
      final forked = await verifyWith(other, anchorOf(device));
      expect(forked.problem, ChainProblem.forked);
      expect(forked.problemSeq, 12);
    });

    test('9: a fence at seq 10 above an anchor at seq 12 is accepted, and the device\'s records 10 to 12 are dropped', () async {
      final prefix = upTo(10);
      final device = prefix.fork()
        ..policies(alice, {'requireSso': true, 'twoStep': true})
        ..policies(alice, {'twoStep': false})
        ..policies(alice, {'twoStep': true});
      expect(device.entries, hasLength(13));
      final served = prefix.fork()
        ..fence(alice)
        ..policies(alice, {'requireSso': false});
      final result = await verifyWith(served, anchorOf(device));
      expect(result.ok, isTrue, reason: result.detail);
      expect(result.droppedFrom, 10);
      expect(result.droppedTo, 12);
      expect(result.state.epoch, 2);
      // The anchor that replaces it is the served chain's, and it is kept past the older one, by the fence
      expect(result.anchor!.seq, 11);
      expect(result.anchor!.epoch, 2);
      expect(SpaceAnchors({uuid(1): anchorOf(device)}).remembering(uuid(1), result.anchor!, afterFence: true).of(uuid(1))!.seq, 11);
    });

    test('9: if the device\'s link at seq 9 differs, the chain is forked', () async {
      final device = upTo(13);
      final prefix = upTo(9)..policies(alice, {'requireSso': true, 'twoStep': true});
      final served = prefix.fork()..fence(alice);
      final result = await verifyWith(served, anchorOf(device));
      expect(result.problem, ChainProblem.forked);
      expect(result.problemSeq, 9);
    });

    test('9: a device anchored at epoch 2 served the old home\'s epoch-1 records past the fence is forked', () async {
      final prefix = upTo(10);
      final device = prefix.fork()
        ..fence(alice)
        ..policies(alice, {'requireSso': false});
      final old = prefix.fork()
        ..policies(alice, {'twoStep': true})
        ..policies(alice, {'twoStep': false});
      final result = await verifyWith(old, anchorOf(device));
      expect(result.problem, ChainProblem.forked);
      expect(result.problemSeq, 10);
    });

    test('a fence that doesn\'t raise the epoch above the anchor\'s is forked', () async {
      final prefix = upTo(10);
      final device = prefix.fork()..fence(alice, home: uuid(0xf2));
      final other = prefix.fork()..fence(alice, home: uuid(0xf3));
      final result = await verifyWith(other, anchorOf(device));
      expect(result.problem, ChainProblem.forked);
    });

    test('a fence is held to its promotion record when the device holds it', () async {
      final chain = base()..fence(alice, home: uuid(0xf2));
      final matching = await verifyChain(
        space: space,
        entries: chain.entries,
        crypto: crypto,
        fenceCheck: (epoch, home, promotion) => epoch == 2 && home == uuid(0xf2),
      );
      expect(matching.ok, isTrue);
      final other = await verifyChain(
        space: space,
        entries: chain.entries,
        crypto: crypto,
        fenceCheck: (epoch, home, promotion) => home == uuid(0xf9),
      );
      expect(other.problem, ChainProblem.badEpoch);
    });
  });

  group('with real sig1 keys', () {
    test('a chain of one create is verified under the real signatures, and refused for another key', () async {
      final pair = await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 1)));
      final other = await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 70)));
      final bundle = KeyBundle(
        accountId: uuidBytes(alice.id),
        keyVersion: 1,
        kx1PublicKey: alice.bundle.kx1PublicKey,
        sig1PublicKey: pair.publicKey,
      );
      final bundleSignature = await signBundle(bundle, pair.privateKey);
      final entry = SpaceChainEntry(
        space: space,
        seq: 0,
        prev: chainGenesisLink,
        epoch: 1,
        at: 5,
        by: alice.id,
        kind: ChainKind.create,
        body: {
          'bundle': b64urlEncode(bundle.bytes),
          'bundleSignature': b64urlEncode(bundleSignature),
          'collection': {'id': everyone, 'nameHash': hash64()},
          'member': alice.id,
          'nameHash': hash64(),
          'seals': [commitment(KeyRef.collection(everyone), 1, 1, makes: true), commitment(spaceKey, 1, 1, makes: true)],
        },
      );
      final good = await signChainEntry(entry, pair.privateKey);
      expect((await verifyChain(space: space, entries: [good])).ok, isTrue);
      final forged = await signChainEntry(entry, other.privateKey);
      expect((await verifyChain(space: space, entries: [forged])).problem, ChainProblem.badSignature);
    });
  });
}
