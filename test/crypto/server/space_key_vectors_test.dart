@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sealed_box.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's sealed-box.json cases for the contexts "space-key" and "collection-key" (crypto.md "Sealed box"),
// held to the code that seals space and collection keys. The server's cases bind no aad, which crypto.md allows, so
// the box of a case opens under its recorded aad and not under the plan's bound one; a box made now by the app opens
// under the plan's, with the case's key pair, and under no other context.
void main() {
  final cases = [
    for (final c in readServerCases('sealed-box.json'))
      if (c['context'] == SealContext.spaceKey || c['context'] == SealContext.collectionKey) c,
  ];
  final space = '00000000-0000-4000-8000-0000000000a1';
  final collection = '00000000-0000-4000-8000-0000000000c1';
  final member = '00000000-0000-4000-8000-0000000000b1';

  test('the server has a case for the space key', () {
    expect(cases.where((c) => c['context'] == SealContext.spaceKey), isNotEmpty);
  });

  for (final c in cases) {
    final name = c['name']! as String;
    final context = c['context']! as String;
    final privateKey = fromHex(c['private_key']! as String);
    final box = fromHex(c['sealed_box']! as String);
    final secret = fromHex(c['secret']! as String);
    final bundle = KeyBundle(
      accountId: uuidBytes(member),
      keyVersion: 1,
      kx1PublicKey: fromHex(c['public_key']! as String),
      sig1PublicKey: Uint8List(Sig1.publicKeyLength),
    );

    test('$name: opens to a 32-byte key under its context and recorded aad, and under no other context', () async {
      expect(secret, hasLength(32));
      expect(await openBox(box, privateKey, context: context, aad: fromHex(c['aad']! as String)), secret);
      for (final wrong in (c['wrong_contexts']! as List<Object?>).cast<String>()) {
        await expectLater(
          openBox(box, privateKey, context: wrong, aad: fromHex(c['aad']! as String)),
          throwsA(isA<CorruptedException>()),
          reason: wrong,
        );
      }
    });

    test('$name: its box is the size the server keeps for a sealed key, 1,661 bytes', () {
      expect(box, hasLength(1661));
    });

    test('$name: a box the app seals to its public key opens with its private key, bound to the space and the member', () async {
      final key = Uint8List.fromList(List.generate(32, (i) => i + 9));
      if (context == SealContext.spaceKey) {
        final made = await sealSpaceKey(to: bundle, key: key, space: space, keyVersion: 2);
        expect(made, hasLength(box.length));
        expect(await openSpaceKey(box: made, kx1PrivateKey: privateKey, space: space, keyVersion: 2, member: member), key);
        await expectLater(
          openCollectionKey(box: made, kx1PrivateKey: privateKey, space: space, collection: collection, keyVersion: 2, member: member),
          throwsA(isA<CorruptedException>()),
        );
        // The case's own box binds no aad, so the bound open refuses it
        await expectLater(
          openSpaceKey(box: box, kx1PrivateKey: privateKey, space: space, keyVersion: 1, member: member),
          throwsA(isA<CorruptedException>()),
        );
      } else {
        final made = await sealCollectionKey(to: bundle, key: key, space: space, collection: collection, keyVersion: 2);
        expect(made, hasLength(box.length));
        expect(
          await openCollectionKey(
            box: made,
            kx1PrivateKey: privateKey,
            space: space,
            collection: collection,
            keyVersion: 2,
            member: member,
          ),
          key,
        );
        await expectLater(
          openSpaceKey(box: made, kx1PrivateKey: privateKey, space: space, keyVersion: 2, member: member),
          throwsA(isA<CorruptedException>()),
        );
      }
    });
  }
}
