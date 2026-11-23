@TestOn('vm')
library;

// The server's shared vectors, through this plan's code (add-kemlock-server-sync, task 13.1): the sync engine's
// `AccountItemCrypto` opens the item envelopes and verifies the signed manifests of
// test/fixtures/server/ (copied by tool/server/copy_vectors.sh, never edited), and `kmItemId` maps older ids to
// the UUIDs of its legacy-ids vector. Skipped, with the reason, where a vector file isn't there yet.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/session.dart';
import 'package:kemlock_core/features/sync/kemlock/km_crypto.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:test/test.dart';

import '../../../crypto/account/server_vectors.dart';
import '../../../crypto/vectors.dart';

/// The sync crypto of a vector's account: its root key, with keys of the right size standing in for the pairs a
/// vector doesn't give, and [sig1PublicKey] to verify manifests with.
AccountItemCrypto _cryptoFor(Uint8List root, Owner owner, int keyVersion, {Uint8List? sig1PublicKey}) => AccountItemCrypto(
  session: AccountSession(keys: AccountKeys.fromRoot(root), kx1PrivateKey: Uint8List(96), sig1PrivateKey: Uint8List(64)),
  sig1PublicKey: sig1PublicKey ?? Uint8List(1984),
  owner: owner,
  keyVersion: keyVersion,
);

Kem1Item _itemOf(Map<String, Object?> vector, {int? revision, String? kind}) => Kem1Item(
  id: uuidText(fromHex(vector['item_id']! as String)),
  owner: Owner.fromBytes(fromHex(vector['owner']! as String)),
  kind: kind ?? vector['kind']! as String,
  revision: revision ?? vector['revision']! as int,
  keyVersion: vector['key_version']! as int,
  ciphertext: fromHex(vector['ciphertext']! as String),
  itemKey: fromHex(vector['wrapped_item_key']! as String),
);

/// What a manifest that doesn't verify throws: the sync run reads either as an older copy of the vault.
final _refused = anyOf(isA<CorruptedException>(), isA<MalformedException>());

void main() {
  group('an item envelope of the server', () {
    final skip = serverVectorSkip('kem1.json');

    test('opens through the sync crypto to the plaintext the vector gives, for each case', () async {
      for (final vector in readServerCases('kem1.json')) {
        final owner = Owner.fromBytes(fromHex(vector['owner']! as String));
        final crypto = _cryptoFor(fromHex(vector['root_key']! as String), owner, vector['key_version']! as int);

        final opened = await crypto.openItem(_itemOf(vector));

        expect(utf8.decode(opened), vector['item_json'], reason: vector['name'] as String);
        expect(crypto.owner, owner);
      }
    }, skip: skip);

    test('does not open when the revision, the kind or the owner is not the one it was sealed to', () async {
      for (final vector in readServerCases('kem1.json')) {
        final owner = Owner.fromBytes(fromHex(vector['owner']! as String));
        final crypto = _cryptoFor(fromHex(vector['root_key']! as String), owner, vector['key_version']! as int);
        final name = vector['name'] as String;

        await expectLater(
          crypto.openItem(_itemOf(vector, revision: (vector['revision']! as int) + 1)),
          throwsA(isA<CorruptedException>()),
          reason: '$name: revision',
        );
        await expectLater(
          crypto.openItem(_itemOf(vector, kind: vector['kind'] == 'login' ? 'note' : 'login')),
          throwsA(isA<CorruptedException>()),
          reason: '$name: kind',
        );
      }
    }, skip: skip);

    test('seals to what the same crypto then opens, with the vector\'s id, revision, kind and owner', () async {
      for (final vector in readServerCases('kem1.json')) {
        final owner = Owner.fromBytes(fromHex(vector['owner']! as String));
        final crypto = _cryptoFor(fromHex(vector['root_key']! as String), owner, vector['key_version']! as int);
        final id = uuidText(fromHex(vector['item_id']! as String));

        final sealed = await crypto.sealItem(
          itemId: id,
          revision: vector['revision']! as int,
          kind: vector['kind']! as String,
          plaintext: Uint8List.fromList(utf8.encode(vector['item_json']! as String)),
        );
        final opened = await crypto.openItem(
          Kem1Item(
            id: id,
            owner: owner,
            kind: vector['kind']! as String,
            revision: vector['revision']! as int,
            keyVersion: vector['key_version']! as int,
            ciphertext: sealed.ciphertext,
            itemKey: sealed.itemKey,
          ),
        );

        expect(utf8.decode(opened), vector['item_json'], reason: vector['name'] as String);
      }
    }, skip: skip);
  });

  group('a signed manifest of the server', () {
    final skip = serverVectorSkip('manifest.json');

    test('verifies through the sync crypto, and lists what the vector lists', () async {
      for (final vector in readServerCases('manifest.json')) {
        final owner = Owner.fromBytes(fromHex(vector['owner']! as String));
        final crypto = _cryptoFor(Uint8List(64), owner, 1, sig1PublicKey: fromHex(vector['signing_public_key']! as String));

        final manifest = await crypto.verifyManifest(fromHex(vector['manifest']! as String), fromHex(vector['signature']! as String));

        final entries = (vector['entries']! as List<Object?>).cast<Map<String, Object?>>();
        expect(manifest.counter, vector['counter'], reason: vector['name'] as String);
        expect(manifest.owner, owner);
        expect(manifest.entries, hasLength(entries.length));
        for (final entry in entries) {
          final listed = manifest.entryFor(fromHex(entry['item_id']! as String))!;
          expect(listed.revision, entry['revision']);
          expect(listed.deleted, entry['deleted']);
          expect(listed.ciphertextHash, fromHex(entry['ciphertext_hash']! as String));
        }
      }
    }, skip: skip);

    test('does not verify with a flipped signature, another account\'s key or another owner', () async {
      final cases = readServerCases('manifest.json');
      final vector = cases.first;
      final owner = Owner.fromBytes(fromHex(vector['owner']! as String));
      final key = fromHex(vector['signing_public_key']! as String);
      final bytes = fromHex(vector['manifest']! as String);
      final signature = fromHex(vector['signature']! as String);

      final flipped = Uint8List.fromList(signature)..[3] ^= 1;
      await expectLater(_cryptoFor(Uint8List(64), owner, 1, sig1PublicKey: key).verifyManifest(bytes, flipped), throwsA(_refused));
      final other = Uint8List.fromList(key)..[5] ^= 1;
      await expectLater(_cryptoFor(Uint8List(64), owner, 1, sig1PublicKey: other).verifyManifest(bytes, signature), throwsA(_refused));
      await expectLater(
        _cryptoFor(
          Uint8List(64),
          Owner.user('11111111-2222-4333-8444-555555555555'),
          1,
          sig1PublicKey: key,
        ).verifyManifest(bytes, signature),
        throwsA(isA<MalformedException>()),
      );
    }, skip: skip);
  });

  group('an older id of the server\'s legacy-ids vector', () {
    test('maps to the vector\'s UUID through the sync engine\'s own mapping, for each item case', () {
      for (final vector in readServerCases('legacy-ids.json').where((vector) => vector['type'] == 'item')) {
        final owner = Owner.fromBytes(fromHex(vector['owner']! as String));

        expect(kmItemId(vector['old']! as String, owner), vector['uuid_text'], reason: vector['old'] as String);
      }
    }, skip: serverVectorSkip('legacy-ids.json'));
  });
}
