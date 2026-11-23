import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_crypto.dart';

/// [KmItemCrypto] for tests: the real `kem1` sealing under a random item-wrap key, and a MAC in place of
/// the `sig1` signature, which is slow in pure Dart. Two fakes made [alike] share the key, as two phones
/// of one account do.
class FakeKmCrypto implements KmItemCrypto {
  FakeKmCrypto({Owner? owner, this.keyVersion = 1, Uint8List? wrapKey, Uint8List? macKey})
    : owner = owner ?? Owner.user('00000000-0000-4000-8000-000000000001'),
      _wrapKey = wrapKey ?? randomBytes(32),
      _macKey = macKey ?? randomBytes(32);

  /// Another phone of the same account.
  FakeKmCrypto alike() => FakeKmCrypto(owner: owner, keyVersion: keyVersion, wrapKey: _wrapKey, macKey: _macKey);

  @override
  final Owner owner;

  @override
  final int keyVersion;

  final Uint8List _wrapKey;
  final Uint8List _macKey;

  /// How many items were sealed.
  int sealed = 0;

  @override
  Future<KmSealedItem> sealItem({required String itemId, required int revision, required String kind, required Uint8List plaintext}) async {
    sealed++;
    final id = uuidBytes(itemId);
    final itemKey = Kem1.newItemKey();
    final ciphertext = await Kem1.sealItem(
      itemKey: itemKey,
      itemId: id,
      revision: revision,
      kind: kind,
      owner: owner,
      plaintext: plaintext,
    );
    final wrapped = await Kem1.wrapItemKey(itemWrapKey: _wrapKey, itemId: id, owner: owner, keyVersion: keyVersion, itemKey: itemKey);
    return (ciphertext: ciphertext, itemKey: wrapped);
  }

  @override
  Future<Uint8List> openItem(Kem1Item item) async {
    final id = uuidBytes(item.id);
    final itemKey = await Kem1.unwrapItemKey(
      itemWrapKey: _wrapKey,
      itemId: id,
      owner: item.owner,
      keyVersion: item.keyVersion,
      wrapped: item.itemKey!,
    );
    return Kem1.openItem(
      itemKey: itemKey,
      itemId: id,
      revision: item.revision,
      kind: item.kind,
      owner: item.owner,
      ciphertext: item.ciphertext!,
    );
  }

  Uint8List _mac(List<int> bytes) => Uint8List.fromList(Hmac(sha256, _macKey).convert([...utf8.encode('fake-sig1'), ...bytes]).bytes);

  @override
  Future<KmSignedManifest> signManifest(Manifest manifest) async => KmSignedManifest(manifest.bytes, _mac(manifest.bytes));

  @override
  Future<Manifest> verifyManifest(Uint8List bytes, Uint8List signature) async {
    final manifest = Manifest.parse(bytes);
    if (!constantTimeEquals(_mac(bytes), signature)) throw const CorruptedException('the manifest signature does not verify');
    if (manifest.owner != owner) throw const MalformedException('a manifest of another owner');
    return manifest;
  }
}
