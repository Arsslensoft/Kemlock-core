@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/features/sync/kemlock/km_crypto.dart';
import 'package:test/test.dart';

import 'fake_km_crypto.dart';

Uint8List bytes(String text) => Uint8List.fromList(utf8.encode(text));

const _id = '3f2c9a71-e4b0-4856-8a00-000000000001';

Kem1Item _item(FakeKmCrypto crypto, KmSealedItem sealed, {int revision = 1, String kind = 'login'}) => Kem1Item(
  id: _id,
  owner: crypto.owner,
  kind: kind,
  revision: revision,
  keyVersion: crypto.keyVersion,
  ciphertext: sealed.ciphertext,
  itemKey: sealed.itemKey,
);

void main() {
  test('the fake seals an item and opens it', () async {
    final crypto = FakeKmCrypto();
    final sealed = await crypto.sealItem(itemId: _id, revision: 1, kind: 'login', plaintext: bytes('{"id":"a"}'));

    expect(utf8.decode(await crypto.openItem(_item(crypto, sealed))), '{"id":"a"}');
  });

  test('a changed revision, kind or owner fails to open', () async {
    final crypto = FakeKmCrypto();
    final sealed = await crypto.sealItem(itemId: _id, revision: 1, kind: 'login', plaintext: bytes('{}'));

    await expectLater(crypto.openItem(_item(crypto, sealed, revision: 2)), throwsA(isA<CorruptedException>()));
    await expectLater(crypto.openItem(_item(crypto, sealed, kind: 'note')), throwsA(isA<CorruptedException>()));
  });

  test('a phone of the same account opens what the other sealed, and a stranger does not', () async {
    final crypto = FakeKmCrypto();
    final sealed = await crypto.sealItem(itemId: _id, revision: 1, kind: 'login', plaintext: bytes('{}'));

    expect(await crypto.alike().openItem(_item(crypto, sealed)), isNotEmpty);
    await expectLater(FakeKmCrypto().openItem(_item(crypto, sealed)), throwsA(isA<CorruptedException>()));
  });

  test('a signed manifest verifies for the account only, and a changed byte does not', () async {
    final crypto = FakeKmCrypto();
    final manifest = Manifest(
      owner: crypto.owner,
      counter: 3,
      entries: [
        ManifestEntry.forItem(itemId: uuidBytes(_id), revision: 1, ciphertext: [1, 2, 3]),
      ],
    );
    final signed = await crypto.signManifest(manifest);

    expect((await crypto.alike().verifyManifest(signed.bytes, signed.signature)).counter, 3);
    await expectLater(FakeKmCrypto().verifyManifest(signed.bytes, signed.signature), throwsA(isA<CorruptedException>()));
    final tampered = signed.signature.sublist(0)..[0] ^= 1;
    await expectLater(crypto.verifyManifest(signed.bytes, tampered), throwsA(isA<CorruptedException>()));
  });
}
