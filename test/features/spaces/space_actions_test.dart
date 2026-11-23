@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/space_actions.dart';
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_chain_client.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

Uint8List _seq(int n, int start) => Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));

/// A space kept in memory: the verified chain the actions read, and every request they appended, applied as the server
/// would apply it to the chain.
class _Space {
  _Space(this.id, this.keys);

  final String id;

  /// The key bytes each key has, whatever its version.
  final Uint8List Function(KeyRef key) keys;
  late SpaceState state = SpaceState.empty(id);
  final requests = <Map<String, Object?>>[];

  /// Runs once, just before the next append: another member's record landing meanwhile.
  void Function()? beforeAppend;
  var refuse = false;

  SpaceActions actions(Person who) => SpaceActions(
    account: who.id,
    readChain: () async => state,
    openKeyring: (chain) async => SpaceKeyring.fromKeys(
      space: id,
      member: who.id,
      spaceKeyVersion: chain.spaceKeyVersion,
      spaceKey: keys(const KeyRef.space()),
      collectionKeys: {
        for (final MapEntry(:key, :value) in chain.collections.entries) key: {value.keyVersion: keys(KeyRef.collection(key))},
      },
    ),
    append: (request) async {
      final hook = beforeAppend;
      beforeAppend = null;
      hook?.call();
      final signed = SignedChainEntry.fromJson((request['records']! as List<Object?>).single);
      if (refuse) {
        throw const ChainAppendError(ChainAppendFailure.refused, reason: 'not-allowed');
      }
      if (signed.entry.seq != state.nextSeq) {
        throw const ChainAppendError(ChainAppendFailure.headMoved);
      }
      requests.add(request);
      state = state.apply(signed.entry);
    },
    sign: (entry) async => SignedChainEntry(entry, fakeSignature(who.bundle.sig1PublicKey, 'space-chain', entry.bytes)),
    now: () => 100,
  );
}

List<Map<String, Object?>> _sealsOf(Map<String, Object?> request) => (request['seals']! as List<Object?>).cast<Map<String, Object?>>();

// Making a space, inviting, confirming, changing roles and grants, removing and leaving (tasks 5.2 to 5.6), and sharing
// keys with a member who replaced their key pair (task 6.3), against a space kept in memory.
void main() {
  final id = uuid(0x5a);
  final everyone = uuid(0xe0);
  final finance = uuid(0xf1);
  const spaceRef = KeyRef.space();
  final everyoneRef = KeyRef.collection(everyone);
  late Person alice;
  late Person bob;
  late Person carol;
  late ({Uint8List publicKey, Uint8List privateKey}) aliceSig;
  final kx1Private = <String, Uint8List>{};

  Future<Person> person(int n, {int keyVersion = 1}) async {
    final priv = _seq(96, n * 13 + keyVersion);
    final made = Person(n, keyVersion: keyVersion, kx1PublicKey: await Kx1.publicKeyOf(priv));
    kx1Private['${made.id}/$keyVersion'] = priv;
    return made;
  }

  setUpAll(() async {
    alice = await person(1);
    bob = await person(2);
    carol = await person(3);
    aliceSig = await Sig1.generate(_seq(64, 5));
  });

  Uint8List keyOf(KeyRef key) => key.isSpace ? _seq(32, 1) : _seq(32, 40);

  /// A space Alice made through [buildCreateSpace], with "Everyone" holding her.
  Future<_Space> made() async {
    final space = _Space(id, keyOf);
    final built = await buildCreateSpace(
      account: alice.id,
      bundle: alice.bundle,
      bundleSignature: alice.bundleSignature,
      space: id,
      collection: everyone,
      name: 'Example Co',
      collectionName: 'Everyone',
      at: 5,
      makeKey: (key, version) => keyOf(key),
    );
    expect(checkAction(space.state, built.action.entry).problem, isNull);
    space.state = space.state.apply(built.action.entry);
    final signed = SignedChainEntry(built.action.entry, fakeSignature(alice.bundle.sig1PublicKey, 'space-chain', built.action.entry.bytes));
    space.requests.add(built.action.request(signed));
    return space;
  }

  Future<void> confirmBob(_Space space) => space
      .actions(alice)
      .confirm(member: bob.id, bundle: bob.bundle, bundleSignature: bob.bundleSignature, confirmerSig1PrivateKey: aliceSig.privateKey);

  Matcher failsAs(SpaceActionProblem problem) => throwsA(isA<SpaceActionError>().having((e) => e.problem, 'problem', problem));

  group('making a space', () {
    test('is the first record: its maker as Owner, "Everyone" granted to them, both keys sealed to them, and the names', () async {
      final space = await made();
      final state = space.state;

      expect(state.member(alice.id)!.role, SpaceRole.owner);
      expect(state.member(alice.id)!.isConfirmed, isTrue);
      expect(state.collections.keys, [everyone]);
      expect(state.accessOf(alice.id, everyone), isNotNull);
      expect(state.awaiting(spaceRef), isEmpty);
      expect(state.awaiting(everyoneRef), isEmpty);

      final request = space.requests.single;
      expect(request['records'], hasLength(1));
      final seals = _sealsOf(request);
      expect({for (final seal in seals) seal['key']}, {'space', 'collection:$everyone'});
      expect(seals.every((seal) => seal['member'] == alice.id && seal['seq'] == 0 && seal['version'] == 1), isTrue);
      final names = (request['names']! as List<Object?>).cast<Map<String, Object?>>();
      expect({for (final name in names) name['target']}, {'space', 'collection:$everyone'});
    });

    test('seals the keys so the maker opens them with their own key', () async {
      final space = await made();
      final seal = _sealsOf(space.requests.single).firstWhere((seal) => seal['key'] == 'space');

      final key = await openSpaceKey(
        box: b64urlDecode(seal['box']! as String),
        kx1PrivateKey: kx1Private['${alice.id}/1']!,
        space: id,
        keyVersion: 1,
        member: alice.id,
      );

      expect(key, keyOf(spaceRef));
    });
  });

  group('inviting', () {
    test('an invitation seals nothing, and the member awaits no key until confirmed', () async {
      final space = await made();

      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});

      expect(space.state.member(bob.id)!.status, MemberStatus.invited);
      expect(space.state.awaiting(spaceRef), isEmpty);
      expect(space.state.awaiting(everyoneRef), isEmpty);
      expect(_sealsOf(space.requests.last), isEmpty);
    });

    test('is refused to a Member, who may invite nobody', () async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});
      await confirmBob(space);

      await expectLater(space.actions(bob).invite(carol.id, SpaceRole.member), failsAs(SpaceActionProblem.notAllowed));
    });

    test('revoking an invitation removes the invited member and marks nothing', () async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});

      await space.actions(alice).remove(bob.id);

      expect(space.state.member(bob.id)!.status, MemberStatus.removed);
      expect(space.state.keysNeedReplacing, isFalse);
    });
  });

  group('confirming', () {
    test('records the member’s bundle, then seals them the space key and the keys of their grants, which they open', () async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});

      await confirmBob(space);

      expect(space.state.member(bob.id)!.isConfirmed, isTrue);
      expect(space.state.member(bob.id)!.confirmation!.by, alice.id);
      expect(space.state.awaiting(spaceRef), isEmpty);
      expect(space.state.awaiting(everyoneRef), isEmpty);
      expect(_sealsOf(space.requests[space.requests.length - 2]), isEmpty);
      final seals = _sealsOf(space.requests.last);
      expect({for (final seal in seals) seal['key']}, {'space', 'collection:$everyone'});
      expect(seals.every((seal) => seal['member'] == bob.id), isTrue);
      final box = b64urlDecode(seals.firstWhere((seal) => seal['key'] == 'space')['box']! as String);
      expect(
        await openSpaceKey(box: box, kx1PrivateKey: kx1Private['${bob.id}/1']!, space: id, keyVersion: 1, member: bob.id),
        keyOf(spaceRef),
      );
    });

    test('refuses a bundle that is not the member’s, before anything is signed', () async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member);

      await expectLater(
        space
            .actions(alice)
            .confirm(
              member: bob.id,
              bundle: carol.bundle,
              bundleSignature: carol.bundleSignature,
              confirmerSig1PrivateKey: aliceSig.privateKey,
            ),
        throwsStateError,
      );
      expect(space.state.member(bob.id)!.status, MemberStatus.invited);
    });
  });

  group('roles and grants', () {
    Future<_Space> withBob() async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member);
      await confirmBob(space);
      return space;
    }

    test('granting a collection to a confirmed member seals its key to them', () async {
      final space = await withBob();
      expect(space.state.holds(everyoneRef, bob.id), isFalse);

      await space.actions(alice).grant(everyone, Grantee.user(bob.id), CollectionPermission.view);

      expect(space.state.accessOf(bob.id, everyone), isNotNull);
      expect(space.state.holds(everyoneRef, bob.id), isTrue);
      expect([for (final seal in _sealsOf(space.requests.last)) seal['key']], ['collection:$everyone']);
    });

    test('a role change and taking a grant away are records of their own, and the second marks the key', () async {
      final space = await withBob();
      await space.actions(alice).grant(everyone, Grantee.user(bob.id), CollectionPermission.view);

      await space.actions(alice).setRole(bob.id, SpaceRole.admin);
      expect(space.state.member(bob.id)!.role, SpaceRole.admin);

      await space.actions(alice).ungrant(everyone, Grantee.user(bob.id));
      expect(space.state.accessOf(bob.id, everyone), isNull);
      expect(space.state.markedKeys, contains(everyoneRef));
    });

    test('a collection that isn’t in the space can’t be granted', () async {
      final space = await withBob();

      await expectLater(
        space.actions(alice).grant(finance, Grantee.user(bob.id), CollectionPermission.view),
        failsAs(SpaceActionProblem.cantApply),
      );
    });
  });

  group('removing and leaving', () {
    Future<_Space> withBob() async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});
      await confirmBob(space);
      return space;
    }

    test('removing a confirmed member names the keys they held and marks them for replacement', () async {
      final space = await withBob();

      await space.actions(alice).remove(bob.id);

      expect(space.state.member(bob.id)!.status, MemberStatus.removed);
      expect(space.state.markedKeys, {spaceRef, everyoneRef});
      final entry = SignedChainEntry.fromJson((space.requests.last['records']! as List<Object?>).single).entry;
      expect(entry.body['replace'], ['collection:$everyone', 'space']);
    });

    test('a member who leaves makes the same record for themselves, and admins see the keys need replacing', () async {
      final space = await withBob();

      await space.actions(bob).leave();

      expect(space.state.member(bob.id)!.status, MemberStatus.removed);
      expect(space.state.keysNeedReplacing, isTrue);
      expect(SignedChainEntry.fromJson((space.requests.last['records']! as List<Object?>).single).entry.by, bob.id);
    });

    test('the only Owner can’t leave until another confirmed member is made Owner', () async {
      final space = await withBob();

      await expectLater(space.actions(alice).leave(), failsAs(SpaceActionProblem.cantApply));

      await space.actions(alice).setRole(bob.id, SpaceRole.owner);
      await space.actions(alice).leave();
      expect(space.state.member(alice.id)!.status, MemberStatus.removed);
    });

    test('a refusal while the record is prepared keeps its reason', () async {
      final space = await withBob();

      await expectLater(
        space.actions(alice).remove(alice.id),
        throwsA(isA<SpaceActionError>().having((e) => e.detail, 'detail', contains('at least one confirmed owner'))),
      );
    });
  });

  group('when the chain moves under a record', () {
    test('a record is made again from the new head, and a refusal is named', () async {
      final space = await made();
      space.beforeAppend = () {
        // Another admin's record lands first
        space.state = space.state.apply(
          SpaceChainEntry(
            space: id,
            seq: space.state.nextSeq,
            prev: space.state.headHash!,
            epoch: space.state.epoch,
            at: 6,
            by: alice.id,
            kind: ChainKind.invite,
            body: {'custom': <String>[], 'grants': <Object?>[], 'member': carol.id, 'role': 'member'},
          ),
        );
      };

      await space.actions(alice).invite(bob.id, SpaceRole.member);

      expect(space.state.member(carol.id)!.status, MemberStatus.invited);
      expect(space.state.member(bob.id)!.status, MemberStatus.invited);

      space.refuse = true;
      await expectLater(space.actions(alice).remove(bob.id), failsAs(SpaceActionProblem.refused));
    });
  });

  group('a member who replaced their key pair', () {
    test('is sealed the keys again to the new bundle the chain records, and not before the record is on the chain', () async {
      final space = await made();
      await space.actions(alice).invite(bob.id, SpaceRole.member, grants: {everyone: CollectionPermission.edit});
      await confirmBob(space);
      final bob2 = await person(2, keyVersion: 2);
      expect(space.state.holds(spaceRef, bob.id), isTrue);

      // Their new bundle is on the chain by their own rekey, which the old key vouched for
      space.state = space.state.apply(
        SpaceChainEntry(
          space: id,
          seq: space.state.nextSeq,
          prev: space.state.headHash!,
          epoch: space.state.epoch,
          at: 9,
          by: bob.id,
          kind: ChainKind.rekey,
          body: {'bundle': b64urlEncode(bob2.bundle.bytes), 'bundleSignature': b64urlEncode(bob2.bundleSignature)},
        ),
      );
      expect(space.state.awaiting(spaceRef), [bob.id]);

      await space.actions(alice).shareKeys();

      expect(space.state.awaiting(spaceRef), isEmpty);
      expect(space.state.sealOf(spaceRef, bob.id)!.bundleVersion, 2);
      final seal = _sealsOf(space.requests.last).firstWhere((seal) => seal['key'] == 'space');
      final box = b64urlDecode(seal['box']! as String);
      expect(
        await openSpaceKey(box: box, kx1PrivateKey: kx1Private['${bob.id}/2']!, space: id, keyVersion: 1, member: bob.id),
        keyOf(spaceRef),
      );
    });

    test('shares nothing when no key awaits anyone', () async {
      final space = await made();
      final before = space.requests.length;

      await space.actions(alice).shareKeys();

      expect(space.requests, hasLength(before));
    });
  });
}
