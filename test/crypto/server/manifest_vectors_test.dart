@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's manifest.json (crypto.md "Signed manifest"): the manifest
// bytes from an owner, a counter and entries (which the case lists unsorted),
// and the writer's sig1 signature under the context "manifest". The case
// doesn't say whether the signature's ML-DSA half is hedged, so the signature
// is verified, and only its Ed25519 half, which is always deterministic, is
// made again and compared.
void main() {
  group("the server's manifest vectors", () {
    for (final c in readServerCases('manifest.json')) {
      final name = c['name']! as String;
      final owner = Owner.fromBytes(fromHex(c['owner']! as String));
      final counter = c['counter']! as int;
      final entryCases = (c['entries']! as List<Object?>).cast<Map<String, Object?>>();
      final manifestBytes = fromHex(c['manifest']! as String);
      final signature = fromHex(c['signature']! as String);
      final privateKey = fromHex(c['signing_private_key']! as String);
      final publicKey = fromHex(c['signing_public_key']! as String);

      List<ManifestEntry> entries() => [
        for (final e in entryCases)
          ManifestEntry.forItem(
            itemId: fromHex(e['item_id']! as String),
            revision: e['revision']! as int,
            ciphertext: e['ciphertext'] == null ? null : fromHex(e['ciphertext']! as String),
          ),
      ];

      test('$name: each entry hashes its ciphertext, and a tombstone is 32 zero bytes', () {
        for (final (index, built) in entries().indexed) {
          final e = entryCases[index];
          expect(toHex(built.ciphertextHash), e['ciphertext_hash'], reason: e['item_id']! as String);
          expect(built.deleted, e['deleted']);
          if (e['deleted']! as bool) expect(built.ciphertextHash, List.filled(32, 0));
        }
      });

      test('$name: the manifest is built from its owner, counter and entries sorted by item id', () {
        final manifest = Manifest(owner: owner, counter: counter, entries: entries());
        expect(toHex(manifest.bytes), c['manifest']);
        expect(manifest.entries, hasLength(entryCases.length));
        for (var i = 1; i < manifest.entries.length; i++) {
          expect(toHex(manifest.entries[i - 1].itemId).compareTo(toHex(manifest.entries[i].itemId)), lessThan(0));
        }
      });

      test('$name: parses back to its owner, counter and entries', () {
        final manifest = Manifest.parse(manifestBytes);
        expect(manifest.owner, owner);
        expect(manifest.counter, counter);
        expect(manifest.entries, hasLength(entryCases.length));
        for (final e in entryCases) {
          final entry = manifest.entryFor(fromHex(e['item_id']! as String));
          expect(entry, isNotNull, reason: e['item_id']! as String);
          expect(entry!.revision, e['revision']);
          expect(entry.deleted, e['deleted']);
          expect(toHex(entry.ciphertextHash), e['ciphertext_hash']);
        }
        expect(toHex(manifest.bytes), c['manifest']);
      });

      test('$name: the signing key is the public key of the private key', () async {
        expect(toHex(await Sig1.publicKeyOf(privateKey)), c['signing_public_key']);
      });

      test('$name: the signature verifies, and its Ed25519 half is made again byte for byte', () async {
        expect(signature, hasLength(Sig1.signatureLength));
        final verified = await verifyManifest(manifestBytes, signature, publicKey);
        expect(verified.counter, counter);

        final again = await signManifest(Manifest.parse(manifestBytes), privateKey);
        expect(toHex(again.sublist(3309)), toHex(signature.sublist(3309)));
        await verifyManifest(manifestBytes, again, publicKey);
      });

      test('$name: a changed manifest, another context or another signer does not verify', () async {
        final changed = Uint8List.fromList(manifestBytes)..[manifestBytes.length - 1] ^= 1;
        // The last byte is a deleted flag or the low byte of the entry count or
        // counter; either way a manifest that parses is no longer the signed one.
        try {
          await verifyManifest(changed, signature, publicKey);
          fail('a changed manifest verified');
        } on MalformedException {
          // Not a manifest any more: nothing was verified.
        } on CorruptedException {
          // The signature does not cover it.
        }
        expect(await Sig1.verify(publicKey, manifestBytes, signature, context: SignContext.bundle), isFalse);
        final other = await Sig1.publicKeyOf(Uint8List.fromList(List.generate(64, (i) => i)));
        await expectLater(verifyManifest(manifestBytes, signature, other), throwsA(isA<CorruptedException>()));
      });

      test('$name: a manifest with trailing bytes, or cut short, is malformed', () {
        expect(() => Manifest.parse([...manifestBytes, 0]), throwsA(isA<MalformedException>()));
        expect(() => Manifest.parse(manifestBytes.sublist(0, manifestBytes.length - 1)), throwsA(isA<MalformedException>()));
      });
    }

    test('three-items: entries out of order or repeated in the bytes are malformed', () {
      final c = readServerCases('manifest.json').firstWhere((c) => c['name'] == 'three-items');
      final bytes = fromHex(c['manifest']! as String);
      const header = 19 + 17 + 8 + 4;
      final first = bytes.sublist(header, header + ManifestEntry.length);
      final second = bytes.sublist(header + ManifestEntry.length, header + 2 * ManifestEntry.length);
      final third = bytes.sublist(header + 2 * ManifestEntry.length);
      final swapped = Uint8List.fromList([...bytes.sublist(0, header), ...second, ...first, ...third]);
      expect(() => Manifest.parse(swapped), throwsA(isA<MalformedException>()));
      final repeated = Uint8List.fromList([...bytes.sublist(0, header), ...first, ...first, ...third]);
      expect(() => Manifest.parse(repeated), throwsA(isA<MalformedException>()));
    });
  });
}
