@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/dedup.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's dedup.json (crypto.md "Duplicate tags"): for two owners, a user
// vault at key version 1 and a space at version 2, the dedup key HKDF made of
// the owner key, and a tag of every kind over values taken as already
// normalised, each with its canonical RFC 8785 input as text and hex.
void main() {
  group("the server's dedup vectors", () {
    final cases = readServerCases('dedup.json');

    for (final c in cases) {
      final name = c['name']! as String;
      final ownerKey = fromHex(c['owner_key']! as String);
      final owner = Owner.fromBytes(fromHex(c['owner']! as String));
      final version = c['key_version']! as int;
      final key = fromHex(c['dedup_key']! as String);

      group(name, () {
        test('the dedup key comes from the owner key, the owner and the key version', () {
          expect(toHex(dedupKey(ownerKey, owner, version)), c['dedup_key']);
        });

        for (final tag in (c['tags']! as List<Object?>).cast<Map<String, Object?>>()) {
          final tagName = tag['name']! as String;
          final values = (tag['values']! as List<Object?>).cast<String>();

          test('$tagName ${values.map((v) => '"$v"').join(', ')}: canonical input and tag', () {
            expect(jcsStringArray([tagName, ...values]), tag['canonical_input']);
            expect(toHex(dedupInput(tagName, values)), tag['canonical_input_hex']);
            final made = dedupTag(key, tagName, values);
            expect(made, hasLength(dedupTagLength));
            expect(toHex(made), tag['tag']);
            expect(dedupTagsEqual(made, fromHex(tag['tag']! as String)), isTrue);
          });
        }
      });
    }

    test('the same value gives other tags for the other owner and key version', () {
      final user = cases.firstWhere((c) => c['key_version'] == 1);
      final space = cases.firstWhere((c) => c['key_version'] == 2);
      List<Map<String, Object?>> tags(Map<String, Object?> c) => (c['tags']! as List<Object?>).cast<Map<String, Object?>>();

      expect(user['dedup_key'], isNot(space['dedup_key']));
      for (var i = 0; i < tags(user).length; i++) {
        expect(tags(user)[i]['canonical_input'], tags(space)[i]['canonical_input']);
        expect(tags(user)[i]['tag'], isNot(tags(space)[i]['tag']));
      }
    });

    test('the key version and the owner are part of the key', () {
      final c = cases.first;
      final ownerKey = fromHex(c['owner_key']! as String);
      final owner = Owner.fromBytes(fromHex(c['owner']! as String));
      final version = c['key_version']! as int;

      expect(toHex(dedupKey(ownerKey, owner, version + 1)), isNot(c['dedup_key']));
      expect(toHex(dedupKey(ownerKey, Owner(OwnerType.space, owner.id), version)), isNot(c['dedup_key']));
    });
  });
}
