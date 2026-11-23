@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's kem1.json (crypto.md "kem1"): the key chain from the root to
// the item-wrap key, the item aad and ciphertext, and the item key's wrap
// and aad. The nonce of each sealed value is in its bytes, so each is opened
// and then sealed again with that nonce and compared.
void main() {
  group("the server's kem1 vectors", () {
    for (final c in readServerCases('kem1.json')) {
      final name = c['name']! as String;
      final itemId = fromHex(c['item_id']! as String);
      final owner = Owner.fromBytes(fromHex(c['owner']! as String));
      final kind = c['kind']! as String;
      final revision = c['revision']! as int;
      final keyVersion = c['key_version']! as int;
      final itemKey = fromHex(c['item_key']! as String);
      final ciphertext = fromHex(c['ciphertext']! as String);
      final wrapped = fromHex(c['wrapped_item_key']! as String);
      final wrapKey = fromHex(c['wrap_key']! as String);
      final itemJson = c['item_json']! as String;

      test('$name: the root gives the user key and the item-wrap key', () {
        final root = fromHex(c['root_key']! as String);
        expect(toHex(deriveUserKey(root)), c['user_key']);
        expect(toHex(deriveChildKey(fromHex(c['user_key']! as String), KeyLabel.itemWrap)), c['wrap_key']);
        final keys = AccountKeys.fromRoot(root);
        expect(toHex(keys.userKey), c['user_key']);
        expect(toHex(keys.itemWrapKey), c['wrap_key']);
        keys.dispose();
      });

      test('$name: the item aad and the wrap aad are what crypto.md says', () {
        expect(toHex(Kem1.itemAad(itemId: itemId, revision: revision, kind: kind, owner: owner)), c['aad']);
        expect(toHex(Kem1.wrapAad(itemId: itemId, owner: owner, keyVersion: keyVersion)), c['wrap_aad']);
      });

      test('$name: the wrapped item key unwraps to the item key', () async {
        expect(wrapped, hasLength(kem1WrappedKeyLength));
        final key = await Kem1.unwrapItemKey(itemWrapKey: wrapKey, itemId: itemId, owner: owner, keyVersion: keyVersion, wrapped: wrapped);
        expect(toHex(key), c['item_key']);
      });

      test('$name: wrapping the item key again with the same nonce gives the same bytes', () async {
        final again = await Kem1.wrapItemKey(
          itemWrapKey: wrapKey,
          itemId: itemId,
          owner: owner,
          keyVersion: keyVersion,
          itemKey: itemKey,
          nonce: Uint8List.fromList(wrapped.sublist(0, 12)),
        );
        expect(toHex(again), c['wrapped_item_key']);
      });

      test('$name: the ciphertext opens to the item JSON', () async {
        final plaintext = await Kem1.openItem(
          itemKey: itemKey,
          itemId: itemId,
          revision: revision,
          kind: kind,
          owner: owner,
          ciphertext: ciphertext,
        );
        expect(utf8.decode(plaintext), itemJson);
      });

      test('$name: sealing the item JSON again with the same nonce gives the same ciphertext', () async {
        final again = await Kem1.sealItem(
          itemKey: itemKey,
          itemId: itemId,
          revision: revision,
          kind: kind,
          owner: owner,
          plaintext: utf8.encode(itemJson),
          nonce: Uint8List.fromList(ciphertext.sublist(0, 12)),
        );
        expect(toHex(again), c['ciphertext']);
        expect(ciphertext, hasLength(12 + utf8.encode(itemJson).length + 16));
      });

      test('$name: the ciphertext opens only in its own place', () async {
        Future<Uint8List> open({List<int>? id, int? rev, String? otherKind, Owner? otherOwner}) => Kem1.openItem(
          itemKey: itemKey,
          itemId: id ?? itemId,
          revision: rev ?? revision,
          kind: otherKind ?? kind,
          owner: otherOwner ?? owner,
          ciphertext: ciphertext,
        );

        final otherId = Uint8List.fromList(itemId)..[0] ^= 1;
        final otherType = owner.type == OwnerType.user ? OwnerType.space : OwnerType.user;
        await expectLater(open(id: otherId), throwsA(isA<CorruptedException>()));
        await expectLater(open(rev: revision + 1), throwsA(isA<CorruptedException>()));
        await expectLater(open(rev: revision - 1), throwsA(isA<CorruptedException>()));
        await expectLater(open(otherKind: kind == 'login' ? 'note' : 'login'), throwsA(isA<CorruptedException>()));
        await expectLater(open(otherOwner: Owner(otherType, owner.id)), throwsA(isA<CorruptedException>()));
      });

      test('$name: the item key unwraps only for its own item, owner and key version', () async {
        Future<Uint8List> unwrap({List<int>? id, Owner? otherOwner, int? version, Uint8List? key}) => Kem1.unwrapItemKey(
          itemWrapKey: key ?? wrapKey,
          itemId: id ?? itemId,
          owner: otherOwner ?? owner,
          keyVersion: version ?? keyVersion,
          wrapped: wrapped,
        );

        final otherId = Uint8List.fromList(itemId)..[0] ^= 1;
        final otherType = owner.type == OwnerType.user ? OwnerType.space : OwnerType.user;
        await expectLater(unwrap(id: otherId), throwsA(isA<CorruptedException>()));
        await expectLater(unwrap(otherOwner: Owner(otherType, owner.id)), throwsA(isA<CorruptedException>()));
        await expectLater(unwrap(version: keyVersion + 1), throwsA(isA<CorruptedException>()));
        await expectLater(unwrap(key: Uint8List.fromList(wrapKey)..[0] ^= 1), throwsA(isA<CorruptedException>()));
      });

      test('$name: a changed byte of the ciphertext gives "corrupted"', () async {
        for (final index in [0, 12, ciphertext.length - 1]) {
          final changed = Uint8List.fromList(ciphertext)..[index] ^= 1;
          await expectLater(
            Kem1.openItem(itemKey: itemKey, itemId: itemId, revision: revision, kind: kind, owner: owner, ciphertext: changed),
            throwsA(isA<CorruptedException>()),
            reason: 'byte $index',
          );
        }
      });

      test('$name: its wire JSON reads back, and a tombstone has no ciphertext', () {
        final json = Kem1Item(
          id: uuidText(itemId),
          owner: owner,
          kind: kind,
          revision: revision,
          keyVersion: keyVersion,
          ciphertext: ciphertext,
          itemKey: wrapped,
        ).toJson();
        expect(json['format'], 'kem1');
        expect(json['owner'], owner.toWire());
        expect(json['deleted'], false);
        final read = Kem1Item.fromJson(jsonDecode(jsonEncode(json)));
        expect(read.ciphertext, ciphertext);
        expect(read.itemKey, wrapped);
        expect(read.owner, owner);

        final tombstone = Kem1Item.tombstone(
          id: uuidText(itemId),
          owner: owner,
          kind: kind,
          revision: revision + 1,
          keyVersion: keyVersion,
        ).toJson();
        expect(tombstone['deleted'], true);
        expect(tombstone.containsKey('ciphertext'), isFalse);
        expect(tombstone.containsKey('itemKey'), isFalse);
      });
    }
  });
}
