// The keys of a space on Kemlock Server (docs/plans/add-server-spaces.md, design 3): a
// space key for the names of the space, its collections and its groups, and a key per
// collection that wraps the item keys of that collection's items. Each is 32 random bytes
// made on a member's device, has a version, and reaches a member only in crypto.md's sealed
// box to the member's `kx1` key, under the context "space-key" or "collection-key":
//
//   space key:      seal(pk, key, context = "space-key",
//                        aad = space uuid (16) || u32be(space key version) || member account id (16))
//   collection key: seal(pk, key, context = "collection-key",
//                        aad = space uuid (16) || collection uuid (16)
//                              || u32be(collection key version) || member account id (16))
//
// Every field of the `aad` has a fixed length, so none can run into another, and the sealed
// box adds `lp(context) || lp(aad)` itself. A seal made for another member, space, collection
// or key version, or opened under the other context, doesn't open.
//
// Names are `kem1` envelopes under the space key's "kemlock/v1/space-name" child (below), which the server
// confirmed. server: to confirm
// The child key a collection key makes for item keys is this plan's.
//
// Pure Dart, no Flutter.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../crypto/account/bundle.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/kem1.dart';
import '../../crypto/account/keys.dart';
import '../../crypto/account/sealed_box.dart';
import '../../crypto/bytes.dart';
import 'space_state.dart';

/// The length of a space key and of a collection key.
const spaceKeyLength = 32;

/// A fresh space key, or collection key, from the secure random source.
Uint8List newSpaceKey() => randomBytes(spaceKeyLength);

/// The binding of a space key's seal to [member], the account it is sealed to.
Uint8List spaceKeyAad({required String space, required int keyVersion, required String member}) =>
    concatBytes([uuidBytes(space), u32be(keyVersion), uuidBytes(member)]);

/// The binding of a collection key's seal to [member], the account it is sealed to.
Uint8List collectionKeyAad({required String space, required String collection, required int keyVersion, required String member}) =>
    concatBytes([uuidBytes(space), uuidBytes(collection), u32be(keyVersion), uuidBytes(member)]);

/// Seals the space [key] at [keyVersion] to [to], a bundle the chain confirms. 1,661 bytes.
Future<Uint8List> sealSpaceKey({required KeyBundle to, required Uint8List key, required String space, required int keyVersion}) async {
  requireLength(key, spaceKeyLength, 'a space key');
  return sealBox(
    to.kx1PublicKey,
    key,
    context: SealContext.spaceKey,
    aad: spaceKeyAad(space: space, keyVersion: keyVersion, member: uuidText(to.accountId)),
  );
}

/// Opens a space key sealed to [member]. A seal made for another member, space or key version, or as a collection
/// key, is a [CorruptedException]; a plaintext that isn't 32 bytes is a [MalformedException].
Future<Uint8List> openSpaceKey({
  required Uint8List box,
  required Uint8List kx1PrivateKey,
  required String space,
  required int keyVersion,
  required String member,
}) async => _key(
  await openBox(
    box,
    kx1PrivateKey,
    context: SealContext.spaceKey,
    aad: spaceKeyAad(space: space, keyVersion: keyVersion, member: member),
  ),
);

/// Seals [collection]'s [key] at [keyVersion] to [to], a bundle the chain confirms.
Future<Uint8List> sealCollectionKey({
  required KeyBundle to,
  required Uint8List key,
  required String space,
  required String collection,
  required int keyVersion,
}) async {
  requireLength(key, spaceKeyLength, 'a collection key');
  return sealBox(
    to.kx1PublicKey,
    key,
    context: SealContext.collectionKey,
    aad: collectionKeyAad(space: space, collection: collection, keyVersion: keyVersion, member: uuidText(to.accountId)),
  );
}

/// Opens a collection key sealed to [member]. A seal made for another member, space, collection or key version, or as
/// a space key, is a [CorruptedException].
Future<Uint8List> openCollectionKey({
  required Uint8List box,
  required Uint8List kx1PrivateKey,
  required String space,
  required String collection,
  required int keyVersion,
  required String member,
}) async => _key(
  await openBox(
    box,
    kx1PrivateKey,
    context: SealContext.collectionKey,
    aad: collectionKeyAad(space: space, collection: collection, keyVersion: keyVersion, member: member),
  ),
);

Uint8List _key(Uint8List plaintext) {
  if (plaintext.length != spaceKeyLength) {
    wipe(plaintext);
    throw const MalformedException('a sealed key is 32 bytes');
  }
  return plaintext;
}

// ─── Names ───────────────────────────────────────────────────────────────

/// What a name names, as the `kind` of its `kem1` envelope.
enum NameKind {
  space('space-name'),
  collection('collection-name'),
  group('group-name');

  const NameKind(this.wire);

  final String wire;
}

/// Seals [name], the text of a space, collection or group, as a `kem1` envelope under the space key's
/// `"kemlock/v1/space-name"` child key, the way the server's names are sealed: kind [kind], item id [id] (the
/// space's own for the space's name), owner `space:<space>` and revision [keyVersion], the space key version the
/// name is sealed under. The result is `nonce || ciphertext || tag`, 28 bytes to 4 KiB, and the chain commits to its
/// SHA-256 ([nameHash]).
Future<Uint8List> sealName({
  required Uint8List spaceKey,
  required String space,
  required int keyVersion,
  required NameKind kind,
  required String id,
  required String name,
}) async {
  requireLength(spaceKey, spaceKeyLength, 'a space key');
  final nameKey = deriveChildKey(spaceKey, KeyLabel.spaceName);
  try {
    return await Kem1.sealItem(
      itemKey: nameKey,
      itemId: uuidBytes(id),
      revision: keyVersion,
      kind: kind.wire,
      owner: Owner.space(space),
      plaintext: utf8.encode(name),
    );
  } finally {
    wipe(nameKey);
  }
}

/// Opens a name sealed with [sealName]. A name sealed for another thing, space, key version or key is a
/// [CorruptedException]; one that is too short, or not UTF-8, is a [MalformedException].
Future<String> openName({
  required Uint8List spaceKey,
  required String space,
  required int keyVersion,
  required NameKind kind,
  required String id,
  required List<int> sealed,
}) async {
  requireLength(spaceKey, spaceKeyLength, 'a space key');
  final nameKey = deriveChildKey(spaceKey, KeyLabel.spaceName);
  try {
    final plain = await Kem1.openItem(
      itemKey: nameKey,
      itemId: uuidBytes(id),
      revision: keyVersion,
      kind: kind.wire,
      owner: Owner.space(space),
      ciphertext: sealed,
    );
    return utf8.decode(plain);
  } on FormatException {
    throw const MalformedException('a name is UTF-8');
  } finally {
    wipe(nameKey);
  }
}

/// The hash the chain commits a sealed name by: `SHA-256(sealed name)`.
Uint8List nameHash(List<int> sealed) => Uint8List.fromList(hash.sha256.convert(sealed).bytes);

/// The name of [target] to show, or null for "Name can't be checked". The server's [sealed] name is used only when its
/// hash is the one the chain committed for the target and its name version is [spaceKeyVersion], the version of the
/// [spaceKey] held: an envelope that doesn't open at that version, or isn't of that target, shows nothing.
Future<String?> openCommittedName({
  required SpaceState state,
  required NameTarget target,
  required List<int> sealed,
  required Uint8List spaceKey,
  required int spaceKeyVersion,
}) async {
  final committed = state.nameOf(target);
  if (committed == null || committed.version != spaceKeyVersion || !constantTimeEquals(committed.hash, nameHash(sealed))) {
    return null;
  }
  try {
    return await openName(
      spaceKey: spaceKey,
      space: state.space,
      keyVersion: committed.version,
      kind: switch (target.type) {
        NameType.space => NameKind.space,
        NameType.collection => NameKind.collection,
        NameType.group => NameKind.group,
      },
      id: target.id ?? state.space,
      sealed: sealed,
    );
  } on CorruptedException {
    return null;
  } on MalformedException {
    return null;
  }
}

// ─── The keys a member holds ─────────────────────────────────────────────

/// A collection key as the server serves it to a member: sealed, with the version it was sealed at.
final class SealedCollectionKey {
  SealedCollectionKey({required this.collection, required this.keyVersion, required List<int> sealed}) : sealed = copyBytes(sealed);

  final String collection;
  final int keyVersion;
  final Uint8List sealed;
}

/// The keys one member of one space holds in memory: the space key, and each collection key they were sealed, all at
/// the versions the chain has as current.
/// [dispose] zeroes every buffer, which the sync run calls when it is done.
final class SpaceKeyring {
  SpaceKeyring._(this.space, this.member, this.spaceKeyVersion, this._spaceKey, this._collectionKeys, this.unreadable);

  /// A keyring of keys already opened through the chain (`openKeyringFromChain` in space_seals.dart): [spaceKey] is
  /// null when it didn't open, and each of [unreadable] is a collection whose key didn't open. The keyring owns the
  /// buffers and wipes them in [dispose].
  factory SpaceKeyring.fromKeys({
    required String space,
    required String member,
    required int spaceKeyVersion,
    Uint8List? spaceKey,
    Map<String, Map<int, Uint8List>> collectionKeys = const {},
    Set<String> unreadable = const {},
  }) => SpaceKeyring._(space, member, spaceKeyVersion, spaceKey, collectionKeys, unreadable);

  final String space;

  /// The account the keys are sealed to.
  final String member;
  final int spaceKeyVersion;
  final Uint8List? _spaceKey;
  final Map<String, Map<int, Uint8List>> _collectionKeys;

  /// The collections whose key copy didn't open.
  final Set<String> unreadable;

  /// The space key, or null when it didn't open.
  Uint8List? get spaceKey => _spaceKey;

  /// The collections this member holds a key of.
  Set<String> get collections => _collectionKeys.keys.toSet();

  /// The highest key version held for [collection], or null when none is.
  int? currentVersion(String collection) {
    final versions = _collectionKeys[collection];
    if (versions == null || versions.isEmpty) {
      return null;
    }
    return versions.keys.reduce((a, b) => a > b ? a : b);
  }

  /// [collection]'s key at [version], or null when the member holds none of that version.
  Uint8List? collectionKey(String collection, int version) => _collectionKeys[collection]?[version];

  void dispose() {
    final space = _spaceKey;
    if (space != null) {
      wipe(space);
    }
    for (final versions in _collectionKeys.values) {
      for (final key in versions.values) {
        wipe(key);
      }
    }
  }
}

/// A member has no key of this version of [collection]: it isn't granted it, its copy didn't open, or the key was
/// replaced and this phone hasn't fetched the new one. Nothing is written under another version.
class NoCollectionKey implements Exception {
  const NoCollectionKey(this.collection, this.version);

  final String collection;
  final int? version;

  @override
  String toString() => 'NoCollectionKey($collection, ${version ?? 'any'})';
}

/// What sealing a space item gave: the ciphertext, the wrapped item key and the collection key version it is under.
typedef SpaceSealedItem = ({Uint8List ciphertext, Uint8List itemKey, int keyVersion});

/// Seals and opens the items of one space under their collections' keys (design 3). An item's key is wrapped under
/// the `item-wrap` child of its collection's key, which takes the space key's place as the parent in crypto.md's
/// "Child keys", with the wrap's additional data as crypto.md gives it: the item, the owner, which is the space,
/// and the key version, which is the collection key's.
// server: to confirm
// crypto.md names the space key and the user key as parents of child keys; a collection key as the parent of
// `item-wrap` for its items is this plan's.
final class SpaceItemCrypto {
  SpaceItemCrypto({required this.space, required this.keyring}) : owner = Owner.space(space);

  final String space;

  /// The owner every item is bound to: the space.
  final Owner owner;
  final SpaceKeyring keyring;

  /// Seals [plaintext] for [itemId] at [revision] as an item of [kind] in [collection], under a fresh item key
  /// wrapped under the collection's current key. A [NoCollectionKey] when the member holds none.
  Future<SpaceSealedItem> sealItem({
    required String itemId,
    required int revision,
    required String kind,
    required String collection,
    required Uint8List plaintext,
  }) async {
    final version = keyring.currentVersion(collection);
    final collectionKey = version == null ? null : keyring.collectionKey(collection, version);
    if (version == null || collectionKey == null) {
      throw NoCollectionKey(collection, null);
    }
    final id = uuidBytes(itemId);
    final itemKey = Kem1.newItemKey();
    final wrapKey = deriveChildKey(collectionKey, KeyLabel.itemWrap);
    try {
      final ciphertext = await Kem1.sealItem(
        itemKey: itemKey,
        itemId: id,
        revision: revision,
        kind: kind,
        owner: owner,
        plaintext: plaintext,
      );
      final wrapped = await Kem1.wrapItemKey(itemWrapKey: wrapKey, itemId: id, owner: owner, keyVersion: version, itemKey: itemKey);
      return (ciphertext: ciphertext, itemKey: wrapped, keyVersion: version);
    } finally {
      wipe(itemKey);
      wipe(wrapKey);
    }
  }

  /// Opens a live space item of [collection] under the collection key of the item's own key version. A
  /// [NoCollectionKey] when the member holds no key of that version; an item of another space, collection or
  /// version, or a changed byte, is a [CorruptedException].
  Future<Uint8List> openItem(Kem1Item item, String collection) async {
    final ciphertext = item.ciphertext;
    final wrapped = item.itemKey;
    if (ciphertext == null || wrapped == null) {
      throw const MalformedException('a tombstone holds nothing to open');
    }
    if (item.owner != owner) {
      throw const CorruptedException('an item of another owner');
    }
    final collectionKey = keyring.collectionKey(collection, item.keyVersion);
    if (collectionKey == null) {
      throw NoCollectionKey(collection, item.keyVersion);
    }
    final id = uuidBytes(item.id);
    final wrapKey = deriveChildKey(collectionKey, KeyLabel.itemWrap);
    Uint8List? itemKey;
    try {
      itemKey = await Kem1.unwrapItemKey(itemWrapKey: wrapKey, itemId: id, owner: owner, keyVersion: item.keyVersion, wrapped: wrapped);
      return await Kem1.openItem(
        itemKey: itemKey,
        itemId: id,
        revision: item.revision,
        kind: item.kind,
        owner: owner,
        ciphertext: ciphertext,
      );
    } finally {
      wipe(wrapKey);
      if (itemKey != null) {
        wipe(itemKey);
      }
    }
  }
}
