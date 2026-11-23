@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

void main() {
  const idA = '0189f7c2-5a3e-7b21-8d4f-0123456789ab';
  const idB = '0189f7c2-5a3e-7b21-8d4f-0123456789ac';
  final a = uuidBytes(idA);
  final b = uuidBytes(idB);
  final user = Owner.user('11111111-2222-7333-8444-555555555555');
  final space = Owner.space('11111111-2222-7333-8444-555555555555');
  final itemKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final wrapKey = Uint8List.fromList(List.generate(32, (i) => 0x80 + i));
  final plaintext = utf8.encode('{"type":"login","name":"Example"}');

  Future<Uint8List> seal({List<int>? id, int revision = 3, String kind = 'login', Owner? owner}) =>
      Kem1.sealItem(itemKey: itemKey, itemId: id ?? a, revision: revision, kind: kind, owner: owner ?? user, plaintext: plaintext);

  Future<Uint8List> open(Uint8List ciphertext, {List<int>? id, int revision = 3, String kind = 'login', Owner? owner}) =>
      Kem1.openItem(itemKey: itemKey, itemId: id ?? a, revision: revision, kind: kind, owner: owner ?? user, ciphertext: ciphertext);

  group('the item envelope', () {
    test('binds the ciphertext to the id, revision, kind and owner as crypto.md says', () async {
      final nonce = Uint8List.fromList(List.generate(12, (i) => 0x50 + i));
      final sealed = await Kem1.sealItem(
        itemKey: itemKey,
        itemId: a,
        revision: 3,
        kind: 'login',
        owner: user,
        plaintext: plaintext,
        nonce: nonce,
      );
      // aad = "kemlock/v1/item" || item id || u64be(revision) || lp(kind) || owner, written out by hand
      final aad = [...utf8.encode('kemlock/v1/item'), ...a, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 5, ...utf8.encode('login'), 1, ...user.id];
      expect(Kem1.itemAad(itemId: a, revision: 3, kind: 'login', owner: user), aad);
      final expected = await aesGcmEncrypt(itemKey, plaintext, nonce: nonce, aad: aad);
      expect(sealed, [...nonce, ...expected.ct]);
    });

    test('opens with the same id, revision, kind and owner', () async {
      expect(await open(await seal()), plaintext);
    });

    test('sealing one plaintext twice gives different ciphertexts', () async {
      expect(await seal(), isNot(await seal()));
    });

    test("item A's ciphertext and key served as item B does not open", () async {
      await expectLater(open(await seal(), id: b), throwsA(isA<CorruptedException>()));
    });

    test('revision 3 served as revision 4 does not open', () async {
      await expectLater(open(await seal(revision: 3), revision: 4), throwsA(isA<CorruptedException>()));
    });

    test('a login served as a note does not open', () async {
      await expectLater(open(await seal(kind: 'login'), kind: 'note'), throwsA(isA<CorruptedException>()));
    });

    test("a user's item served as a space's does not open", () async {
      await expectLater(open(await seal(owner: user), owner: space), throwsA(isA<CorruptedException>()));
    });

    test('a changed byte does not open', () async {
      final sealed = await seal();
      for (final index in [0, 11, 12, sealed.length - 17, sealed.length - 1]) {
        final changed = Uint8List.fromList(sealed)..[index] ^= 1;
        await expectLater(open(changed), throwsA(isA<CorruptedException>()), reason: 'byte $index');
      }
    });

    test('malformed input is refused before anything is decrypted', () async {
      await expectLater(open(Uint8List(27)), throwsA(isA<MalformedException>()));
      await expectLater(
        Kem1.openItem(itemKey: Uint8List(31), itemId: a, revision: 3, kind: 'login', owner: user, ciphertext: Uint8List(40)),
        throwsA(isA<MalformedException>()),
      );
      expect(() => Kem1.itemAad(itemId: a.sublist(1), revision: 1, kind: 'login', owner: user), throwsA(isA<MalformedException>()));
      expect(() => Kem1.itemAad(itemId: a, revision: 0, kind: 'login', owner: user), throwsArgumentError);
      for (final kind in ['', 'Login', 'a b', 'x' * 65, 'tëst']) {
        expect(
          () => Kem1.itemAad(itemId: a, revision: 1, kind: kind, owner: user),
          throwsArgumentError,
          reason: kind,
        );
      }
      expect(isValidKind('backup-codes'), isTrue);
      expect(isValidKind('x' * 64), isTrue);
    });

    test('refuses a plaintext over 2 MiB', () async {
      await expectLater(
        Kem1.sealItem(itemKey: itemKey, itemId: a, revision: 1, kind: 'note', owner: user, plaintext: Uint8List(2 * 1024 * 1024 + 1)),
        throwsArgumentError,
      );
    });
  });

  group('the item-key wrap', () {
    Future<Uint8List> wrap({List<int>? id, Owner? owner, int keyVersion = 1, Uint8List? key}) =>
        Kem1.wrapItemKey(itemWrapKey: key ?? wrapKey, itemId: id ?? a, owner: owner ?? user, keyVersion: keyVersion, itemKey: itemKey);

    Future<Uint8List> unwrap(Uint8List wrapped, {List<int>? id, Owner? owner, int keyVersion = 1, Uint8List? key}) =>
        Kem1.unwrapItemKey(itemWrapKey: key ?? wrapKey, itemId: id ?? a, owner: owner ?? user, keyVersion: keyVersion, wrapped: wrapped);

    test('is bound to the id, owner and key version as crypto.md says', () async {
      final nonce = Uint8List.fromList(List.generate(12, (i) => 0x20 + i));
      final wrapped = await Kem1.wrapItemKey(itemWrapKey: wrapKey, itemId: a, owner: user, keyVersion: 1, itemKey: itemKey, nonce: nonce);
      // wrap aad = "kemlock/v1/item-key" || item id || owner || u32be(key version), by hand
      final aad = [...utf8.encode('kemlock/v1/item-key'), ...a, 1, ...user.id, 0, 0, 0, 1];
      expect(Kem1.wrapAad(itemId: a, owner: user, keyVersion: 1), aad);
      final expected = await aesGcmEncrypt(wrapKey, itemKey, nonce: nonce, aad: aad);
      expect(wrapped, [...nonce, ...expected.ct]);
      expect(wrapped, hasLength(60));
    });

    test('unwraps under the same id, owner, key version and wrap key', () async {
      expect(await unwrap(await wrap()), itemKey);
    });

    test('does not unwrap as another item, owner or key version, or under another key', () async {
      final wrapped = await wrap();
      await expectLater(unwrap(wrapped, id: b), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, owner: space), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, keyVersion: 2), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, key: Uint8List(32)), throwsA(isA<CorruptedException>()));
    });

    test('is not bound to the revision, so an edit may keep the item key', () async {
      final wrapped = await wrap();
      final revision3 = await seal(revision: 3);
      final revision4 = await seal(revision: 4);
      final key = await unwrap(wrapped);
      expect(await Kem1.openItem(itemKey: key, itemId: a, revision: 3, kind: 'login', owner: user, ciphertext: revision3), plaintext);
      expect(await Kem1.openItem(itemKey: key, itemId: a, revision: 4, kind: 'login', owner: user, ciphertext: revision4), plaintext);
    });

    test('a wrapped key of another length is malformed', () async {
      await expectLater(unwrap(Uint8List(59)), throwsA(isA<MalformedException>()));
      await expectLater(unwrap(Uint8List(61)), throwsA(isA<MalformedException>()));
    });

    test('a fresh item key is 32 random bytes', () {
      expect(Kem1.newItemKey(), hasLength(32));
      expect(Kem1.newItemKey(), isNot(Kem1.newItemKey()));
    });
  });

  group('the wire JSON', () {
    late Kem1Item item;

    setUpAll(() async {
      item = Kem1Item(
        id: idA,
        owner: user,
        kind: 'login',
        revision: 4,
        keyVersion: 1,
        ciphertext: await seal(revision: 4),
        itemKey: await Kem1.wrapItemKey(itemWrapKey: wrapKey, itemId: a, owner: user, keyVersion: 1, itemKey: itemKey),
      );
    });

    test('has the fields crypto.md shows', () {
      final json = item.toJson();
      expect(json.keys.toSet(), {'id', 'owner', 'kind', 'format', 'revision', 'keyVersion', 'ciphertext', 'itemKey', 'deleted'});
      expect(json['owner'], 'user:11111111-2222-7333-8444-555555555555');
      expect(json['format'], 'kem1');
      expect(json['deleted'], false);
      expect(json['ciphertext'], isNot(contains('=')));
    });

    test('round-trips through JSON text', () {
      final again = Kem1Item.fromJson(jsonDecode(jsonEncode(item.toJson())));
      expect(again.toJson(), item.toJson());
      expect(again.ciphertext, item.ciphertext);
      expect(again.deleted, isFalse);
    });

    test('a tombstone has no ciphertext or itemKey, and its revision still moves on', () {
      final tombstone = Kem1Item.tombstone(id: idA, owner: user, kind: 'login', revision: 5, keyVersion: 1);
      final json = tombstone.toJson();
      expect(json.containsKey('ciphertext'), isFalse);
      expect(json.containsKey('itemKey'), isFalse);
      expect(json['deleted'], true);
      final again = Kem1Item.fromJson(json);
      expect(again.deleted, isTrue);
      expect(again.revision, 5);
    });

    test('refuses unknown fields, formats and versions', () {
      final json = item.toJson();
      expect(() => Kem1Item.fromJson({...json, 'extra': 1}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'format': 'kem2'}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json}..remove('keyVersion')), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson([json]), throwsA(isA<MalformedException>()));
    });

    test('refuses padded and standard-alphabet base64 and a ciphertext too short', () {
      final json = item.toJson();
      expect(() => Kem1Item.fromJson({...json, 'ciphertext': '${json['ciphertext']}='}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'itemKey': '${'A' * 79}+'}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'ciphertext': b64urlEncode(Uint8List(27))}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'itemKey': b64urlEncode(Uint8List(59))}), throwsA(isA<MalformedException>()));
    });

    test('refuses a tombstone with a ciphertext, an item without one, and a bad id, kind or revision', () {
      final json = item.toJson();
      expect(() => Kem1Item.fromJson({...json, 'deleted': true}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json}..remove('ciphertext')), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'id': idA.toUpperCase()}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'kind': 'Login'}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'revision': 0}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'revision': '4'}), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...json, 'owner': 'user:acc-1'}), throwsA(isA<MalformedException>()));
    });

    test('a space item carries space:<uuid> both ways', () async {
      final spaceItem = Kem1Item(
        id: idA,
        owner: space,
        kind: 'note',
        revision: 1,
        keyVersion: 1,
        ciphertext: item.ciphertext,
        itemKey: item.itemKey,
      );
      final json = spaceItem.toJson();
      expect(json['owner'], 'space:11111111-2222-7333-8444-555555555555');
      expect(Kem1Item.fromJson(jsonDecode(jsonEncode(json))).owner, space);
      final tombstone = Kem1Item.tombstone(id: idA, owner: space, kind: 'note', revision: 2, keyVersion: 1).toJson();
      expect(tombstone['owner'], 'space:11111111-2222-7333-8444-555555555555');
      expect(Kem1Item.fromJson(tombstone).owner, space);
    });

    test('deleted is always written, and an item without it is refused', () {
      expect(item.toJson()['deleted'], false);
      expect(Kem1Item.tombstone(id: idA, owner: user, kind: 'login', revision: 5, keyVersion: 1).toJson()['deleted'], true);
      expect(() => Kem1Item.fromJson({...item.toJson()}..remove('deleted')), throwsA(isA<MalformedException>()));
      expect(() => Kem1Item.fromJson({...item.toJson(), 'deleted': null}), throwsA(isA<MalformedException>()));
    });

    test('what it carries opens with the unwrapped key', () async {
      final again = Kem1Item.fromJson(item.toJson());
      final key = await Kem1.unwrapItemKey(
        itemWrapKey: wrapKey,
        itemId: uuidBytes(again.id),
        owner: again.owner,
        keyVersion: again.keyVersion,
        wrapped: again.itemKey!,
      );
      final opened = await Kem1.openItem(
        itemKey: key,
        itemId: uuidBytes(again.id),
        revision: again.revision,
        kind: again.kind,
        owner: again.owner,
        ciphertext: again.ciphertext!,
      );
      expect(opened, plaintext);
    });
  });
}
