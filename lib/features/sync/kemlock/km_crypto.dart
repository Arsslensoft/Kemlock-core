/// What the Kemlock Server sync run asks of the account's crypto: sealing and
/// opening an item, and signing and checking the manifest. The primitives are
/// `lib/crypto/account`'s (`add-account-crypto`); this is the narrow interface
/// the engine codes against, so a test can put a fake that uses cheap
/// signatures in its place. Sign-in's parts (OPAQUE, the password wrap) join
/// it when sign-in is built.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/dedup.dart' as dedup;
import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/kem1.dart';
import '../../../crypto/account/manifest.dart';
import '../../../crypto/account/session.dart';
import 'km_dedup.dart' show KmDedupKeys;

/// A sealed item as it goes on the wire: the ciphertext and the wrapped item key.
typedef KmSealedItem = ({Uint8List ciphertext, Uint8List itemKey});

/// A manifest's exact bytes with the signature over them, as they travel.
class KmSignedManifest {
  const KmSignedManifest(this.bytes, this.signature);

  final Uint8List bytes;
  final Uint8List signature;
}

/// Seals and opens the items of one owner, and signs that owner's manifests.
abstract interface class KmItemCrypto {
  /// The owner every item and manifest is bound to.
  Owner get owner;

  /// The key version items are sealed under.
  int get keyVersion;

  /// Seals [plaintext] (the entry's JSON as UTF-8) for [itemId] at [revision]
  /// as an item of [kind], under a fresh item key.
  Future<KmSealedItem> sealItem({required String itemId, required int revision, required String kind, required Uint8List plaintext});

  /// Opens a live item. An item that doesn't authenticate throws a
  /// [CorruptedException].
  Future<Uint8List> openItem(Kem1Item item);

  /// Signs [manifest] with the account's signing key.
  Future<KmSignedManifest> signManifest(Manifest manifest);

  /// Reads [bytes] as a manifest of this owner, if [signature] is the
  /// account's signature over them. A manifest that is malformed or whose
  /// signature fails throws a [MalformedException] or a [CorruptedException].
  Future<Manifest> verifyManifest(Uint8List bytes, Uint8List signature);
}

/// [KmItemCrypto] over an open [AccountSession], with `add-account-crypto`'s
/// `kem1` and manifest code.
class AccountItemCrypto implements KmItemCrypto, KmDedupKeys {
  AccountItemCrypto({required this.session, required this.sig1PublicKey, required this.owner, this.keyVersion = 1});

  /// The dedup key of `crypto.md` "Duplicate tags": HKDF of the user key, with this owner and the key [version] in its
  /// info. The caller wipes it.
  @override
  Uint8List dedupKeyAt(int version) => dedup.dedupKey(session.keys.userKey, owner, version);

  /// The account's keys, held until it is disposed.
  final AccountSession session;

  /// The account's `sig1` public key, 1,984 bytes, which manifests verify with.
  final Uint8List sig1PublicKey;

  @override
  final Owner owner;

  @override
  final int keyVersion;

  @override
  Future<KmSealedItem> sealItem({required String itemId, required int revision, required String kind, required Uint8List plaintext}) async {
    final id = uuidBytes(itemId);
    final itemKey = Kem1.newItemKey();
    try {
      final ciphertext = await Kem1.sealItem(
        itemKey: itemKey,
        itemId: id,
        revision: revision,
        kind: kind,
        owner: owner,
        plaintext: plaintext,
      );
      final wrapped = await Kem1.wrapItemKey(
        itemWrapKey: session.keys.itemWrapKey,
        itemId: id,
        owner: owner,
        keyVersion: keyVersion,
        itemKey: itemKey,
      );
      return (ciphertext: ciphertext, itemKey: wrapped);
    } finally {
      wipe(itemKey);
    }
  }

  @override
  Future<Uint8List> openItem(Kem1Item item) async {
    final ciphertext = item.ciphertext;
    final wrapped = item.itemKey;
    if (ciphertext == null || wrapped == null) throw const MalformedException('a tombstone holds nothing to open');
    final id = uuidBytes(item.id);
    final itemKey = await Kem1.unwrapItemKey(
      itemWrapKey: session.keys.itemWrapKey,
      itemId: id,
      owner: item.owner,
      keyVersion: item.keyVersion,
      wrapped: wrapped,
    );
    try {
      return await Kem1.openItem(
        itemKey: itemKey,
        itemId: id,
        revision: item.revision,
        kind: item.kind,
        owner: item.owner,
        ciphertext: ciphertext,
      );
    } finally {
      wipe(itemKey);
    }
  }

  @override
  Future<KmSignedManifest> signManifest(Manifest manifest) async =>
      KmSignedManifest(manifest.bytes, await signManifestBytes(manifest, session.sig1PrivateKey));

  @override
  Future<Manifest> verifyManifest(Uint8List bytes, Uint8List signature) async {
    final manifest = await verifyManifestBytes(bytes, signature, sig1PublicKey);
    if (manifest.owner != owner) throw const MalformedException('a manifest of another owner');
    return manifest;
  }
}

/// `signManifest` of `add-account-crypto`, named apart from [KmItemCrypto.signManifest].
Future<Uint8List> signManifestBytes(Manifest manifest, Uint8List sig1PrivateKey) => signManifest(manifest, sig1PrivateKey);

/// `verifyManifest` of `add-account-crypto`, named apart from [KmItemCrypto.verifyManifest].
Future<Manifest> verifyManifestBytes(List<int> bytes, Uint8List signature, Uint8List publicKey) =>
    verifyManifest(bytes, signature, publicKey);
