@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/hkdf.dart';
import 'package:kemlock_core/features/spaces/chain_body.dart' show SealCommitment;
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:kemlock_core/features/spaces/space_seals.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

Uint8List _seq(int n, int start) => Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));

// Keys through the chain (the space chain section, "Commitments" and "Using the state"): the digest and the check
// written out by hand, and a refusal for each way a server can hand a member a key the chain didn't commit to.
// Real `kx1` keys are used, and fake signatures, which the state doesn't look at.
void main() {
  final space = uuid(0x5a);
  final everyone = uuid(0xe0);
  final finance = uuid(0xf1);
  final spaceRef = const KeyRef.space();
  final everyoneRef = KeyRef.collection(everyone);
  final financeRef = KeyRef.collection(finance);
  final spaceKey = _seq(32, 1);
  final everyoneKey = _seq(32, 2);
  final financeKey = _seq(32, 3);
  late Uint8List alicePrivate;
  late Uint8List bobPrivate;
  late Person alice;
  late Person bob;

  setUpAll(() async {
    alicePrivate = _seq(96, 11);
    bobPrivate = _seq(96, 77);
    alice = Person(1, kx1PublicKey: await Kx1.publicKeyOf(alicePrivate));
    bob = Person(2, kx1PublicKey: await Kx1.publicKeyOf(bobPrivate));
  });

  /// The chain of a space made by alice with real seals of its two first keys, and bob confirmed with edit on
  /// "Everyone" and sealed both by alice's `seal` record.
  Future<({ChainBuilder chain, Map<KeyRef, Uint8List> aliceBoxes, Map<KeyRef, Uint8List> bobBoxes})> world() async {
    final chain = ChainBuilder(space);
    final collection = await sealKeyTo(
      space: space,
      key: everyoneRef,
      version: 1,
      keyBytes: everyoneKey,
      recipients: {alice.id: alice.bundle},
      makes: true,
    );
    final own = await sealKeyTo(
      space: space,
      key: spaceRef,
      version: 1,
      keyBytes: spaceKey,
      recipients: {alice.id: alice.bundle},
      makes: true,
    );
    chain.add(alice, ChainKind.create, {
      'bundle': b64urlEncode(alice.bundle.bytes),
      'bundleSignature': b64urlEncode(alice.bundleSignature),
      'collection': {'id': everyone, 'nameHash': hash64(8)},
      'member': alice.id,
      'nameHash': hash64(7),
      'seals': [collection.commitment.toJson(), own.commitment.toJson()],
    });
    chain
      ..invite(alice, bob, grants: {everyone: CollectionPermission.edit})
      ..confirm(alice, bob);
    final record = (await buildSealRecord(
      state: chain.state,
      signer: alice.id,
      keys: {spaceRef: spaceKey, everyoneRef: everyoneKey},
      at: 5000,
    ))!;
    chain.add(alice, ChainKind.seal, record.entry.body);
    return (
      chain: chain,
      aliceBoxes: {spaceRef: own.boxes[alice.id]!, everyoneRef: collection.boxes[alice.id]!},
      bobBoxes: {spaceRef: record.boxes[spaceRef]![bob.id]!, everyoneRef: record.boxes[everyoneRef]![bob.id]!},
    );
  }

  test('the digest and the check are the spec\'s, written out by hand', () {
    final box = _seq(1661, 5);
    final sealHash = sealHashOf(box);
    expect(sealHash, hash.sha256.convert(box).bytes);
    final digest = sealsDigest(
      space: space,
      key: financeRef,
      version: 3,
      recipients: [(account: bob.id, bundleVersion: 2, sealHash: hash32(9)), (account: alice.id, bundleVersion: 1, sealHash: sealHash)],
    );
    final expected = hash.sha256.convert([
      ...utf8.encode('kemlock/v1/space-chain/seals'),
      ...uuidBytes(space),
      2,
      ...uuidBytes(finance),
      0, 0, 0, 3,
      0, 0, 0, 2,
      // Ascending order of account id: alice, then bob
      ...uuidBytes(alice.id), 0, 0, 0, 1, ...sealHash,
      ...uuidBytes(bob.id), 0, 0, 0, 2, ...hash32(9),
    ]);
    expect(digest, expected.bytes);
    // The key ref is u8(1) for the space key
    final own = sealsDigest(
      space: space,
      key: spaceRef,
      version: 1,
      recipients: [(account: alice.id, bundleVersion: 1, sealHash: sealHash)],
    );
    expect(
      own,
      hash.sha256.convert([
        ...utf8.encode('kemlock/v1/space-chain/seals'),
        ...uuidBytes(space),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        1,
        ...uuidBytes(alice.id),
        0,
        0,
        0,
        1,
        ...sealHash,
      ]).bytes,
    );
    final check = keyCheckOf(key: financeKey, space: space, ref: financeRef, version: 3);
    expect(
      check,
      hkdfSha256(
        financeKey,
        salt: const [],
        info: [...utf8.encode('kemlock/v1/space-chain/key-check'), ...uuidBytes(space), 2, ...uuidBytes(finance), 0, 0, 0, 3],
        length: 32,
      ),
    );
    expect(keyCheckOf(key: financeKey, space: space, ref: financeRef, version: 4), isNot(check));
  });

  test('the seal aads are the server\'s: the space key and the collection key', () {
    expect(spaceKeyAad(space: space, keyVersion: 3, member: bob.id), [...uuidBytes(space), 0, 0, 0, 3, ...uuidBytes(bob.id)]);
    expect(collectionKeyAad(space: space, collection: finance, keyVersion: 3, member: bob.id), [
      ...uuidBytes(space),
      ...uuidBytes(finance),
      0,
      0,
      0,
      3,
      ...uuidBytes(bob.id),
    ]);
  });

  test('a member opens the keys the chain committed to, alone in a commitment or from the server\'s hash list', () async {
    final w = await world();
    final state = w.chain.state;
    for (final (person, private, boxes) in [(alice, alicePrivate, w.aliceBoxes), (bob, bobPrivate, w.bobBoxes)]) {
      final space1 = await openCommittedKey(
        state: state,
        key: spaceRef,
        member: person.id,
        kx1PrivateKey: private,
        bundleVersion: 1,
        box: boxes[spaceRef]!,
      );
      expect(space1.key, spaceKey, reason: space1.why);
      final collection1 = await openCommittedKey(
        state: state,
        key: everyoneRef,
        member: person.id,
        kx1PrivateKey: private,
        bundleVersion: 1,
        box: boxes[everyoneRef]!,
      );
      expect(collection1.key, everyoneKey, reason: collection1.why);
    }

    // A commitment of two recipients: a collection granted to both, which needs the server's list
    final both = await sealKeyTo(
      space: space,
      key: financeRef,
      version: 1,
      keyBytes: financeKey,
      recipients: {alice.id: alice.bundle, bob.id: bob.bundle},
      makes: true,
    );
    w.chain.add(alice, ChainKind.collection, {
      'collection': finance,
      'grants': [
        {'grantee': 'user:${alice.id}', 'permission': 'manage'},
        {'grantee': 'user:${bob.id}', 'permission': 'view'},
      ],
      'nameHash': hash64(9),
      'seals': [both.commitment.toJson()],
    });
    final two = w.chain.state;
    List<ChainSealHash> list({List<ChainSealHash> extra = const []}) => [
      for (final entry in both.boxes.entries)
        ChainSealHash(bundleVersion: 1, key: financeRef, member: entry.key, sealHash: sealHashOf(entry.value), version: 1),
      ...extra,
    ];
    Future<OpenedKey> open({List<ChainSealHash>? hashes, Uint8List? box, int bundleVersion = 1}) => openCommittedKey(
      state: two,
      key: financeRef,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: bundleVersion,
      box: box ?? both.boxes[bob.id]!,
      hashes: hashes,
    );
    expect((await open(hashes: list())).key, financeKey);
    // No list, an extra recipient, a missing one, a hash that isn't this box's, another bundle version in the list
    expect((await open()).key, isNull);
    expect(
      (await open(
        hashes: list(
          extra: [ChainSealHash(bundleVersion: 1, key: financeRef, member: uuid(9), sealHash: hash32(), version: 1)],
        ),
      )).key,
      isNull,
    );
    expect((await open(hashes: list().sublist(0, 1))).key, isNull);
    expect((await open(hashes: list(), box: Uint8List.fromList(both.boxes[bob.id]!)..[100] ^= 1)).key, isNull);
    final other = list();
    other[1] = ChainSealHash(bundleVersion: 2, key: financeRef, member: bob.id, sealHash: other[1].sealHash, version: 1);
    expect((await open(hashes: other)).key, isNull);
    // A device that holds another bundle version than the one the chain sealed to
    expect((await open(hashes: list(), bundleVersion: 2)).key, isNull);
  });

  test('a box the chain didn\'t commit to is refused, though it opens', () async {
    final w = await world();
    final state = w.chain.state;
    // The same key sealed to bob again: a good box, with other randomness, whose hash is not the committed one
    final again = await sealKeyTo(
      space: space,
      key: spaceRef,
      version: 1,
      keyBytes: spaceKey,
      recipients: {bob.id: bob.bundle},
      makes: false,
    );
    final opened = await openCommittedKey(
      state: state,
      key: spaceRef,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      box: again.boxes[bob.id]!,
    );
    expect(opened.key, isNull);
    expect(opened.why, contains('not the one the chain committed'));
    // Another member's box is not bob's
    final alices = await openCommittedKey(
      state: state,
      key: spaceRef,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      box: w.aliceBoxes[spaceRef]!,
    );
    expect(alices.key, isNull);
  });

  test('a box of an older key version is not used once the chain is at a newer one', () async {
    final w = await world();
    final next = await sealKeyTo(
      space: space,
      key: everyoneRef,
      version: 2,
      keyBytes: _seq(32, 50),
      recipients: {alice.id: alice.bundle, bob.id: bob.bundle},
      makes: true,
    );
    w.chain.add(alice, ChainKind.keys, {
      'rotate': [next.commitment.toJson()],
    });
    final state = w.chain.state;
    expect(state.keyVersionOf(everyoneRef), 2);
    final old = await openCommittedKey(
      state: state,
      key: everyoneRef,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      box: w.bobBoxes[everyoneRef]!,
      hashes: [
        for (final entry in next.boxes.entries)
          ChainSealHash(bundleVersion: 1, key: everyoneRef, member: entry.key, sealHash: sealHashOf(entry.value), version: 2),
      ],
    );
    expect(old.key, isNull);
    final fresh = await openCommittedKey(
      state: state,
      key: everyoneRef,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      box: next.boxes[bob.id]!,
      hashes: [
        for (final entry in next.boxes.entries)
          ChainSealHash(bundleVersion: 1, key: everyoneRef, member: entry.key, sealHash: sealHashOf(entry.value), version: 2),
      ],
    );
    expect(fresh.key, _seq(32, 50));
  });

  test('a box that opens to a key whose check isn\'t the chain\'s is refused', () async {
    final chain = ChainBuilder(space);
    final real = await sealKeyTo(
      space: space,
      key: everyoneRef,
      version: 1,
      keyBytes: everyoneKey,
      recipients: {alice.id: alice.bundle},
      makes: true,
    );
    final own = await sealKeyTo(
      space: space,
      key: spaceRef,
      version: 1,
      keyBytes: spaceKey,
      recipients: {alice.id: alice.bundle},
      makes: true,
    );
    // The chain's check is of another key than the one the box holds
    final forged = SealCommitment(
      key: everyoneRef,
      version: 1,
      count: 1,
      digest: real.commitment.digest,
      check: keyCheckOf(key: _seq(32, 99), space: space, ref: everyoneRef, version: 1),
    );
    chain.add(alice, ChainKind.create, {
      'bundle': b64urlEncode(alice.bundle.bytes),
      'bundleSignature': b64urlEncode(alice.bundleSignature),
      'collection': {'id': everyone, 'nameHash': hash64(8)},
      'member': alice.id,
      'nameHash': hash64(7),
      'seals': [forged.toJson(), own.commitment.toJson()],
    });
    final opened = await openCommittedKey(
      state: chain.state,
      key: everyoneRef,
      member: alice.id,
      kx1PrivateKey: alicePrivate,
      bundleVersion: 1,
      box: real.boxes[alice.id]!,
    );
    expect(opened.key, isNull);
    expect(opened.why, contains('check'));
  });

  test('a keyring opens only the chain\'s version, and leaves out a collection whose copy is of another', () async {
    final w = await world();
    final state = w.chain.state;
    final keyring = await openKeyringFromChain(
      state: state,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      spaceKeyBox: w.bobBoxes[spaceRef],
      collectionBoxes: [SealedCollectionKey(collection: everyone, keyVersion: 1, sealed: w.bobBoxes[everyoneRef]!)],
      hashesAt: (seq) async => throw StateError('a commitment of one member needs no list'),
    );
    expect(keyring.spaceKey, spaceKey);
    expect(keyring.spaceKeyVersion, 1);
    expect(keyring.collectionKey(everyone, 1), everyoneKey);
    expect(keyring.unreadable, isEmpty);
    keyring.dispose();

    // The server names a version the chain doesn't have: nothing of it is opened
    final wrong = await openKeyringFromChain(
      state: state,
      member: bob.id,
      kx1PrivateKey: bobPrivate,
      bundleVersion: 1,
      spaceKeyBox: w.bobBoxes[spaceRef],
      collectionBoxes: [SealedCollectionKey(collection: everyone, keyVersion: 2, sealed: w.bobBoxes[everyoneRef]!)],
      hashesAt: (seq) async => const [],
    );
    expect(wrong.collectionKey(everyone, 1), isNull);
    expect(wrong.unreadable, {everyone});
    wrong.dispose();
  });

  test('a seal record shares a key only with the members awaiting it, and none while the key is marked', () async {
    final w = await world();
    expect(await buildSealRecord(state: w.chain.state, signer: alice.id, keys: {spaceRef: spaceKey}, at: 6000), isNull);
    final carol = Person(3, kx1PublicKey: await Kx1.publicKeyOf(_seq(96, 33)));
    w.chain
      ..invite(alice, carol, grants: {everyone: CollectionPermission.view})
      ..confirm(alice, carol);
    final record = (await buildSealRecord(
      state: w.chain.state,
      signer: alice.id,
      keys: {spaceRef: spaceKey, everyoneRef: everyoneKey},
      at: 6000,
    ))!;
    expect(record.entry.kind, ChainKind.seal);
    expect(record.entry.seq, w.chain.state.nextSeq);
    expect(record.boxes[spaceRef]!.keys, [carol.id]);
    expect(record.boxes[everyoneRef]!.keys, [carol.id]);
    // The record is one the state accepts, and carol is covered afterwards
    w.chain.add(alice, ChainKind.seal, record.entry.body);
    expect(w.chain.state.awaiting(spaceRef), isEmpty);
    expect(w.chain.state.sealOf(spaceRef, carol.id)!.seq, record.entry.seq);
    // Once the chain marks the space key, a seal is not built
    w.chain.remove(alice, bob, replace: [everyoneRef, spaceRef]);
    expect(w.chain.state.spaceKeyMarked, isTrue);
    expect(await buildSealRecord(state: w.chain.state, signer: alice.id, keys: {spaceRef: spaceKey}, at: 7000), isNull);
  });
}
