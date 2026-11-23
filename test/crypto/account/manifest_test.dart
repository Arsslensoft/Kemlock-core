@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

Uint8List _id(int last) => Uint8List.fromList([...List.filled(15, 0x10), last]);

void main() {
  final owner = Owner.user('11111111-2222-7333-8444-555555555555');
  final sig1Private = Uint8List.fromList(List.generate(64, (i) => (i * 13 + 2) & 0xff));
  final ciphertextA = Uint8List.fromList(List.generate(40, (i) => i));
  final ciphertextB = Uint8List.fromList(List.generate(50, (i) => 100 + i));

  Manifest build({int counter = 7}) => Manifest(
    owner: owner,
    counter: counter,
    entries: [
      // out of order on purpose: the manifest sorts them
      ManifestEntry.forItem(itemId: _id(0x30), revision: 1, ciphertext: ciphertextB),
      ManifestEntry.forItem(itemId: _id(0x10), revision: 4, ciphertext: ciphertextA),
      ManifestEntry.forItem(itemId: _id(0x20), revision: 9),
    ],
  );

  test('is the label, owner, counter, count and the sorted entries, as crypto.md says', () {
    final manifest = build();
    final expected = <int>[
      ...utf8.encode('kemlock/v1/manifest'),
      ...owner.bytes,
      0, 0, 0, 0, 0, 0, 0, 7,
      0, 0, 0, 3,
      // item 0x10: revision 4, SHA-256(ciphertext A), not deleted
      ..._id(0x10), 0, 0, 0, 0, 0, 0, 0, 4, ...hash.sha256.convert(ciphertextA).bytes, 0,
      // item 0x20: a tombstone at revision 9, 32 zero bytes
      ..._id(0x20), 0, 0, 0, 0, 0, 0, 0, 9, ...List.filled(32, 0), 1,
      // item 0x30: revision 1, SHA-256(ciphertext B)
      ..._id(0x30), 0, 0, 0, 0, 0, 0, 0, 1, ...hash.sha256.convert(ciphertextB).bytes, 0,
    ];
    expect(manifest.bytes, expected);
    expect(manifest.bytes, hasLength(19 + 17 + 8 + 4 + 3 * 57));
    expect(ManifestEntry.length, 57);
  });

  test('an empty manifest is the header and a count of zero', () {
    final manifest = Manifest(owner: owner, counter: 1, entries: const []);
    expect(manifest.bytes, hasLength(19 + 17 + 8 + 4));
    expect(Manifest.parse(manifest.bytes).entries, isEmpty);
  });

  test('parses its own bytes and finds an entry by item id', () {
    final manifest = build();
    final parsed = Manifest.parse(manifest.bytes);
    expect(parsed.bytes, manifest.bytes);
    expect(parsed.owner, owner);
    expect(parsed.counter, 7);
    expect(parsed.entryFor(_id(0x10))!.revision, 4);
    expect(parsed.entryFor(_id(0x20))!.deleted, isTrue);
    expect(parsed.entryFor(_id(0x99)), isNull);
  });

  test('refuses what a strict reader refuses', () {
    final bytes = build().bytes;
    expect(() => Manifest.parse([...bytes, 0]), throwsA(isA<MalformedException>()));
    expect(() => Manifest.parse(bytes.sublist(0, bytes.length - 1)), throwsA(isA<MalformedException>()));
    expect(() => Manifest.parse(Uint8List.fromList(bytes)..[0] = 0x4c), throwsA(isA<MalformedException>()));
    // a count that promises more entries than there are bytes
    expect(() => Manifest.parse(Uint8List.fromList(bytes)..[19 + 17 + 8 + 3] = 0x40), throwsA(isA<MalformedException>()));
    // the deleted byte of the first entry is 2
    expect(() => Manifest.parse(Uint8List.fromList(bytes)..[19 + 17 + 8 + 4 + 56] = 2), throwsA(isA<MalformedException>()));
    // a tombstone with a non-zero hash
    final tombstoneHash = 19 + 17 + 8 + 4 + 57 + 24;
    expect(() => Manifest.parse(Uint8List.fromList(bytes)..[tombstoneHash] = 1), throwsA(isA<MalformedException>()));
  });

  test('refuses entries out of order, and two entries for one item', () {
    final bytes = build().bytes;
    const start = 19 + 17 + 8 + 4;
    final swapped = Uint8List.fromList(bytes)
      ..setRange(start, start + 57, bytes.sublist(start + 57, start + 114))
      ..setRange(start + 57, start + 114, bytes.sublist(start, start + 57));
    expect(() => Manifest.parse(swapped), throwsA(isA<MalformedException>()));
    expect(
      () => Manifest(
        owner: owner,
        counter: 1,
        entries: [
          ManifestEntry.forItem(itemId: _id(1), revision: 1, ciphertext: ciphertextA),
          ManifestEntry.forItem(itemId: _id(1), revision: 2, ciphertext: ciphertextA),
        ],
      ),
      throwsA(isA<MalformedException>()),
    );
  });

  test('is signed with sig1 under the context "manifest" and verifies', () async {
    final publicKey = await Sig1.publicKeyOf(sig1Private);
    final manifest = build();
    final signature = await signManifest(manifest, sig1Private);
    expect(await Sig1.verify(publicKey, manifest.bytes, signature, context: 'manifest'), isTrue);
    final verified = await verifyManifest(manifest.bytes, signature, publicKey);
    expect(verified.counter, 7);
  });

  test('a manifest with a bad signature is refused', () async {
    final publicKey = await Sig1.publicKeyOf(sig1Private);
    final manifest = build();
    final signature = await signManifest(manifest, sig1Private);
    // another counter, another signer, a changed signature and another context
    final other = build(counter: 8);
    await expectLater(verifyManifest(other.bytes, signature, publicKey), throwsA(isA<CorruptedException>()));
    final stranger = await Sig1.publicKeyOf(Uint8List.fromList(sig1Private)..[0] ^= 1);
    await expectLater(verifyManifest(manifest.bytes, signature, stranger), throwsA(isA<CorruptedException>()));
    await expectLater(
      verifyManifest(manifest.bytes, Uint8List.fromList(signature)..[10] ^= 1, publicKey),
      throwsA(isA<CorruptedException>()),
    );
    final asBundle = await Sig1.sign(sig1Private, manifest.bytes, context: 'bundle');
    await expectLater(verifyManifest(manifest.bytes, asBundle, publicKey), throwsA(isA<CorruptedException>()));
  });

  test('the digest is SHA-256 of the bytes', () {
    final manifest = build();
    expect(manifest.digest, hash.sha256.convert(manifest.bytes).bytes);
  });
}
