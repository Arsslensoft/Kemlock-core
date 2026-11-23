@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's space-names.json (crypto.md, "Space, collection and group names"): a name is a kem1 envelope under the
// space key's "kemlock/v1/space-name" child, which is the item key itself, of kind space-name, collection-name or
// group-name, with the object's own id as the item id, the owner 0x02 || space id and the space key version as the
// revision:
//
//   name_key   = HKDF-SHA256(space_key, salt = absent, info = "kemlock/v1/space-name", L = 32)
//   aad        = "kemlock/v1/item" || id || u64be(key_version) || lp(kind) || owner
//   ciphertext = nonce (12) || AES-256-GCM(name_key, nonce, text as UTF-8, aad) || tag (16)
//
// Each case holds the ciphertext, the name key, the aad and the text it opens to. Binary values are lower-case hex, and
// the space and the id are 16 bytes, which this test writes as UUIDs, as the app does.
void main() {
  final cases = readServerCases('space-names.json');

  NameKind kindOf(String wire) =>
      NameKind.values.firstWhere((kind) => kind.wire == wire, orElse: () => throw FormatException('not a name kind: $wire'));

  test('the file has a name of each kind', () {
    expect({for (final c in cases) c['kind']}, {for (final kind in NameKind.values) kind.wire});
  });

  for (final c in cases) {
    final name = c['name']! as String;
    final spaceKey = fromHex(c['space_key']! as String);
    final space = uuidText(fromHex(c['space_id']! as String));
    final id = uuidText(fromHex(c['id']! as String));
    final kind = kindOf(c['kind']! as String);
    final version = c['key_version']! as int;
    final sealed = fromHex(c['ciphertext']! as String);
    final text = c['text']! as String;
    final owner = Owner.space(space);

    test('$name: the name key is the space key\'s "kemlock/v1/space-name" child, and the owner is the space', () {
      expect(spaceKey, hasLength(32));
      expect(toHex(deriveChildKey(spaceKey, KeyLabel.spaceName)), c['name_key']);
      expect(toHex(owner.bytes), c['owner']);
      expect(owner.bytes, [0x02, ...fromHex(c['space_id']! as String)]);
    });

    test('$name: the aad is "kemlock/v1/item" || id || u64be(key version) || lp(kind) || owner', () {
      final aad = Kem1.itemAad(itemId: uuidBytes(id), revision: version, kind: kind.wire, owner: owner);
      expect(toHex(aad), c['aad']);
    });

    test('$name: opens to its text under the space key at its version, bound to its id, kind, space and key version', () async {
      Future<String> open({NameKind? asKind, String? asId, int? asVersion, String? inSpace}) => openName(
        spaceKey: spaceKey,
        space: inSpace ?? space,
        keyVersion: asVersion ?? version,
        kind: asKind ?? kind,
        id: asId ?? id,
        sealed: sealed,
      );

      expect(await open(), text);
      // A name must not open under another space, id, kind or key version
      await expectLater(
        open(asKind: NameKind.values.firstWhere((other) => other != kind)),
        throwsA(isA<CorruptedException>()),
        reason: 'another kind',
      );
      await expectLater(open(asVersion: version + 1), throwsA(isA<CorruptedException>()), reason: 'another key version');
      await expectLater(open(asId: uuidText(Uint8List(16)..[15] = 1)), throwsA(isA<CorruptedException>()), reason: 'another id');
      await expectLater(open(inSpace: uuidText(Uint8List(16)..[15] = 1)), throwsA(isA<CorruptedException>()), reason: 'another space');
    });

    test('$name: sealed again under the nonce it carries, the ciphertext is the same', () async {
      final nonce = Uint8List.fromList(sealed.sublist(0, 12));
      final again = await Kem1.sealItem(
        itemKey: deriveChildKey(spaceKey, KeyLabel.spaceName),
        itemId: uuidBytes(id),
        revision: version,
        kind: kind.wire,
        owner: owner,
        plaintext: utf8.encode(text),
        nonce: nonce,
      );
      expect(toHex(again), c['ciphertext']);
      // And what the app seals itself, with a nonce of its own, opens to the same name under the same binding
      final made = await sealName(spaceKey: spaceKey, space: space, keyVersion: version, kind: kind, id: id, name: text);
      expect(made, hasLength(sealed.length));
      expect(await openName(spaceKey: spaceKey, space: space, keyVersion: version, kind: kind, id: id, sealed: made), text);
    });
  }
}
