@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sealed_box.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

Uint8List _seq(int n, int start) => Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));

// Space and collection keys (design 3): the aad layouts written out by hand, and a refusal for each way a seal can
// be bound elsewhere. The sealed box itself is held to the server's vectors in test/crypto/server.
void main() {
  final space = uuid(0x5a);
  final collection = uuid(0xf1);
  final theo = uuid(2);
  final mina = uuid(3);
  late Uint8List theoPrivate;
  late Uint8List minaPrivate;
  late KeyBundle theoBundle;
  final key = _seq(32, 0x40);

  setUpAll(() async {
    theoPrivate = _seq(96, 11);
    minaPrivate = _seq(96, 77);
    theoBundle = KeyBundle(
      accountId: uuidBytes(theo),
      keyVersion: 1,
      kx1PublicKey: await Kx1.publicKeyOf(theoPrivate),
      sig1PublicKey: Uint8List(Sig1.publicKeyLength),
    );
  });

  test('a new key is 32 random bytes, and a second one differs', () {
    expect(newSpaceKey(), hasLength(32));
    expect(newSpaceKey(), isNot(newSpaceKey()));
  });

  test('the aad of a space key is the space, the key version and the member, 36 bytes', () {
    // Worked out from design 3: space uuid (16) || u32be(version) || member account id (16)
    expect(spaceKeyAad(space: space, keyVersion: 7, member: theo), [...uuidBytes(space), 0, 0, 0, 7, ...uuidBytes(theo)]);
    expect(spaceKeyAad(space: space, keyVersion: 7, member: theo), hasLength(36));
  });

  test('the aad of a collection key adds the collection, 52 bytes', () {
    expect(collectionKeyAad(space: space, collection: collection, keyVersion: 7, member: theo), [
      ...uuidBytes(space),
      ...uuidBytes(collection),
      0,
      0,
      0,
      7,
      ...uuidBytes(theo),
    ]);
    expect(collectionKeyAad(space: space, collection: collection, keyVersion: 7, member: theo), hasLength(52));
  });

  group('a space key', () {
    late Uint8List box;

    setUpAll(() async {
      box = await sealSpaceKey(to: theoBundle, key: key, space: space, keyVersion: 3);
    });

    test('is the sealed box of crypto.md for a 32-byte key, 1,661 bytes, and opens to the key', () async {
      expect(box, hasLength(1 + 1600 + 12 + 32 + 16));
      expect(box[0], 1);
      expect(await openSpaceKey(box: box, kx1PrivateKey: theoPrivate, space: space, keyVersion: 3, member: theo), key);
    });

    test('does not open when bound to another space, another key version or another member', () async {
      await expectLater(
        openSpaceKey(box: box, kx1PrivateKey: theoPrivate, space: uuid(0x5b), keyVersion: 3, member: theo),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openSpaceKey(box: box, kx1PrivateKey: theoPrivate, space: space, keyVersion: 4, member: theo),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openSpaceKey(box: box, kx1PrivateKey: theoPrivate, space: space, keyVersion: 3, member: mina),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('a seal made for Mina, handed to Theo, does not open', () async {
      final forMina = await sealSpaceKey(
        to: KeyBundle(
          accountId: uuidBytes(mina),
          keyVersion: 1,
          kx1PublicKey: await Kx1.publicKeyOf(minaPrivate),
          sig1PublicKey: Uint8List(Sig1.publicKeyLength),
        ),
        key: key,
        space: space,
        keyVersion: 3,
      );
      await expectLater(
        openSpaceKey(box: forMina, kx1PrivateKey: theoPrivate, space: space, keyVersion: 3, member: theo),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openSpaceKey(box: forMina, kx1PrivateKey: theoPrivate, space: space, keyVersion: 3, member: mina),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('does not open as a collection key', () async {
      await expectLater(
        openCollectionKey(box: box, kx1PrivateKey: theoPrivate, space: space, collection: collection, keyVersion: 3, member: theo),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('is refused when it is not a key of 32 bytes, or when the key to seal is not', () async {
      final short = await sealBox(
        theoBundle.kx1PublicKey,
        _seq(31, 1),
        context: SealContext.spaceKey,
        aad: spaceKeyAad(space: space, keyVersion: 3, member: theo),
      );
      await expectLater(
        openSpaceKey(box: short, kx1PrivateKey: theoPrivate, space: space, keyVersion: 3, member: theo),
        throwsA(isA<MalformedException>()),
      );
      await expectLater(sealSpaceKey(to: theoBundle, key: _seq(31, 1), space: space, keyVersion: 3), throwsA(isA<MalformedException>()));
    });
  });

  group('a collection key', () {
    late Uint8List box;

    setUpAll(() async {
      box = await sealCollectionKey(to: theoBundle, key: key, space: space, collection: collection, keyVersion: 2);
    });

    test('opens to the key under its own space, collection, key version and member', () async {
      expect(box, hasLength(1 + 1600 + 12 + 32 + 16));
      expect(
        await openCollectionKey(box: box, kx1PrivateKey: theoPrivate, space: space, collection: collection, keyVersion: 2, member: theo),
        key,
      );
    });

    test('does not open when bound to another space, collection, key version or member', () async {
      for (final (name, forSpace, forCollection, version, member) in <(String, String, String, int, String)>[
        ('another space', uuid(0x5b), collection, 2, theo),
        ('another collection', space, uuid(0xf2), 2, theo),
        ('another key version', space, collection, 3, theo),
        ('another member', space, collection, 2, mina),
      ]) {
        await expectLater(
          openCollectionKey(
            box: box,
            kx1PrivateKey: theoPrivate,
            space: forSpace,
            collection: forCollection,
            keyVersion: version,
            member: member,
          ),
          throwsA(isA<CorruptedException>()),
          reason: name,
        );
      }
    });

    test('does not open as a space key, and a seal for another key pair does not open', () async {
      await expectLater(
        openSpaceKey(box: box, kx1PrivateKey: theoPrivate, space: space, keyVersion: 2, member: theo),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openCollectionKey(box: box, kx1PrivateKey: minaPrivate, space: space, collection: collection, keyVersion: 2, member: theo),
        throwsA(isA<CorruptedException>()),
      );
    });
  });

  group('a name', () {
    final spaceKey = _seq(32, 3);

    Future<Uint8List> sealed({NameKind kind = NameKind.collection, String? id, int version = 1, String name = 'Finance'}) =>
        sealName(spaceKey: spaceKey, space: space, keyVersion: version, kind: kind, id: id ?? collection, name: name);

    test('is a kem1 envelope under the space key\'s "kemlock/v1/space-name" child', () async {
      final value = await sealed(name: 'Finance é');
      expect(value.length, inInclusiveRange(28, 4096));
      expect(value.length, 12 + utf8.encode('Finance é').length + 16);
      expect(KeyLabel.spaceName, 'kemlock/v1/space-name');
      // Opened by hand: the child key, with the item id, revision, kind and owner of the envelope
      final child = deriveChildKey(spaceKey, 'kemlock/v1/space-name');
      final plain = await Kem1.openItem(
        itemKey: child,
        itemId: uuidBytes(collection),
        revision: 1,
        kind: 'collection-name',
        owner: Owner.space(space),
        ciphertext: value,
      );
      expect(utf8.decode(plain), 'Finance é');
      expect(
        await openName(spaceKey: spaceKey, space: space, keyVersion: 1, kind: NameKind.collection, id: collection, sealed: value),
        'Finance é',
      );
    });

    test('names the kinds space-name, collection-name and group-name, and the space\'s own name is under its id', () {
      expect(NameKind.space.wire, 'space-name');
      expect(NameKind.collection.wire, 'collection-name');
      expect(NameKind.group.wire, 'group-name');
    });

    test('does not open as another kind, for another id, space, key version or key, or as the item-wrap child', () async {
      final value = await sealed();
      for (final (kind, id, version, k, owner) in <(NameKind, String, int, Uint8List, String)>[
        (NameKind.group, collection, 1, spaceKey, space),
        (NameKind.collection, uuid(0xf2), 1, spaceKey, space),
        (NameKind.collection, collection, 2, spaceKey, space),
        (NameKind.collection, collection, 1, _seq(32, 4), space),
        (NameKind.collection, collection, 1, spaceKey, uuid(0x5b)),
      ]) {
        await expectLater(
          openName(spaceKey: k, space: owner, keyVersion: version, kind: kind, id: id, sealed: value),
          throwsA(isA<CorruptedException>()),
          reason: '$kind $id $version',
        );
      }
      await expectLater(
        Kem1.openItem(
          itemKey: deriveChildKey(spaceKey, KeyLabel.itemWrap),
          itemId: uuidBytes(collection),
          revision: 1,
          kind: 'collection-name',
          owner: Owner.space(space),
          ciphertext: value,
        ),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('shorter than a nonce and a tag is malformed', () async {
      await expectLater(
        openName(spaceKey: spaceKey, space: space, keyVersion: 1, kind: NameKind.space, id: space, sealed: Uint8List(27)),
        throwsA(isA<MalformedException>()),
      );
    });

    test('is shown only when its hash is the chain\'s and it opens at the chain\'s name version', () async {
      final own = await sealed(kind: NameKind.space, id: space, name: 'Team');
      final state = (ChainBuilder(space)..create(Person(1), spaceNameHash: nameHash(own))).state;
      Future<String?> shown(List<int> bytes, {int version = 1, Uint8List? key}) => openCommittedName(
        state: state,
        target: const NameTarget.space(),
        sealed: bytes,
        spaceKey: key ?? spaceKey,
        spaceKeyVersion: version,
      );
      expect(await shown(own), 'Team');
      // Another sealed name, even a good one, is not the chain's
      expect(await shown(await sealed(kind: NameKind.space, id: space, name: 'Other')), isNull);
      // A changed byte
      expect(await shown(Uint8List.fromList(own)..[20] ^= 1), isNull);
      // Held under another version of the space key than the name's
      expect(await shown(own, version: 2), isNull);
      // A key that isn't the one it was sealed under
      expect(await shown(own, key: _seq(32, 9)), isNull);
      // A target the chain doesn't have
      expect(
        await openCommittedName(state: state, target: NameTarget.group(uuid(0x91)), sealed: own, spaceKey: spaceKey, spaceKeyVersion: 1),
        isNull,
      );
    });
  });

  group('the keys a member holds', () {
    final engineering = uuid(0xf2);

    // Keys come out of a seal only through the chain (space_seals_test.dart); the keyring holds what that gave
    Future<SpaceKeyring> open() async => SpaceKeyring.fromKeys(
      space: space,
      member: theo,
      spaceKeyVersion: 1,
      spaceKey: _seq(32, 1),
      collectionKeys: {
        collection: {1: _seq(32, 2), 2: _seq(32, 3)},
      },
      unreadable: {engineering},
    );

    test('holds the keys by collection and version, and names the collection whose copy did not open', () async {
      final keyring = await open();
      expect(keyring.spaceKey, _seq(32, 1));
      expect(keyring.spaceKeyVersion, 1);
      expect(keyring.collections, {collection});
      expect(keyring.unreadable, {engineering}, reason: 'a key problem for that collection, not for the others');
      expect(keyring.currentVersion(collection), 2);
      expect(keyring.collectionKey(collection, 1), _seq(32, 2));
      expect(keyring.collectionKey(collection, 2), _seq(32, 3));
      expect(keyring.collectionKey(collection, 3), isNull);
      expect(keyring.currentVersion(engineering), isNull);
    });

    test('has no space key when none was given, and zeroes every key when disposed', () async {
      final none = SpaceKeyring.fromKeys(space: space, member: theo, spaceKeyVersion: 2);
      expect(none.spaceKey, isNull);
      expect(none.collections, isEmpty);

      final keyring = await open();
      final spaceKey = keyring.spaceKey!;
      final finance = keyring.collectionKey(collection, 2)!;
      keyring.dispose();
      expect(spaceKey, everyElement(0));
      expect(finance, everyElement(0));
    });

    group('and the items of a collection', () {
      late SpaceKeyring keyring;
      late SpaceItemCrypto crypto;
      final itemId = '3f2c9a71-e4b0-4856-8a00-000000000001';

      setUp(() async {
        keyring = await open();
        crypto = SpaceItemCrypto(space: space, keyring: keyring);
      });

      Kem1Item wire(SpaceSealedItem sealed, {int revision = 1, String? kind, Owner? owner}) => Kem1Item(
        id: itemId,
        owner: owner ?? Owner.space(space),
        kind: kind ?? 'login',
        revision: revision,
        keyVersion: sealed.keyVersion,
        ciphertext: sealed.ciphertext,
        itemKey: sealed.itemKey,
      );

      test('are sealed under the collection’s current key and open with it, with the space as owner', () async {
        final sealed = await crypto.sealItem(
          itemId: itemId,
          revision: 1,
          kind: 'login',
          collection: collection,
          plaintext: Uint8List.fromList(utf8.encode('{"id":"a"}')),
        );
        expect(sealed.keyVersion, 2);
        expect(sealed.itemKey, hasLength(kem1WrappedKeyLength));
        expect(utf8.decode(await crypto.openItem(wire(sealed), collection)), '{"id":"a"}');
      });

      test('have their key wrapped under the item-wrap child of the collection key, as crypto.md derives it', () async {
        final sealed = await crypto.sealItem(itemId: itemId, revision: 1, kind: 'login', collection: collection, plaintext: Uint8List(3));
        final wrapKey = deriveChildKey(_seq(32, 3), KeyLabel.itemWrap);
        final itemKey = await Kem1.unwrapItemKey(
          itemWrapKey: wrapKey,
          itemId: uuidBytes(itemId),
          owner: Owner.space(space),
          keyVersion: 2,
          wrapped: sealed.itemKey,
        );
        expect(
          await Kem1.openItem(
            itemKey: itemKey,
            itemId: uuidBytes(itemId),
            revision: 1,
            kind: 'login',
            owner: Owner.space(space),
            ciphertext: sealed.ciphertext,
          ),
          Uint8List(3),
        );
        // The collection key itself is not the wrap key
        await expectLater(
          Kem1.unwrapItemKey(
            itemWrapKey: _seq(32, 3),
            itemId: uuidBytes(itemId),
            owner: Owner.space(space),
            keyVersion: 2,
            wrapped: sealed.itemKey,
          ),
          throwsA(isA<CorruptedException>()),
        );
      });

      test('do not open as another collection’s, another revision, another kind or another owner', () async {
        final sealed = await crypto.sealItem(itemId: itemId, revision: 1, kind: 'login', collection: collection, plaintext: Uint8List(3));
        await expectLater(crypto.openItem(wire(sealed), engineering), throwsA(isA<NoCollectionKey>()));
        await expectLater(crypto.openItem(wire(sealed, revision: 2), collection), throwsA(isA<CorruptedException>()));
        await expectLater(crypto.openItem(wire(sealed, kind: 'note'), collection), throwsA(isA<CorruptedException>()));
        await expectLater(crypto.openItem(wire(sealed, owner: Owner.space(uuid(0x5b))), collection), throwsA(isA<CorruptedException>()));
        await expectLater(crypto.openItem(wire(sealed, owner: Owner.user(theo)), collection), throwsA(isA<CorruptedException>()));
      });

      test('are never written without a key of their collection, or opened under a version the member lacks', () async {
        await expectLater(
          crypto.sealItem(itemId: itemId, revision: 1, kind: 'login', collection: engineering, plaintext: Uint8List(3)),
          throwsA(isA<NoCollectionKey>()),
        );
        final sealed = await crypto.sealItem(itemId: itemId, revision: 1, kind: 'login', collection: collection, plaintext: Uint8List(3));
        final lacking = Kem1Item(
          id: itemId,
          owner: Owner.space(space),
          kind: 'login',
          revision: 1,
          keyVersion: 9,
          ciphertext: sealed.ciphertext,
          itemKey: sealed.itemKey,
        );
        await expectLater(crypto.openItem(lacking, collection), throwsA(isA<NoCollectionKey>().having((e) => e.version, 'version', 9)));
      });

      test('a tombstone holds nothing to open', () async {
        final tombstone = Kem1Item.tombstone(id: itemId, owner: Owner.space(space), kind: 'login', revision: 2, keyVersion: 2);
        await expectLater(crypto.openItem(tombstone, collection), throwsA(isA<MalformedException>()));
      });
    });
  });
}
