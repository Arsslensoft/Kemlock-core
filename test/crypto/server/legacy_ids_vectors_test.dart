@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's legacy-ids.json (crypto.md "Legacy ids"): space and item ids
// mapped to UUIDv8, and which texts already are a UUID.
void main() {
  group("the server's legacy-ids vectors", () {
    for (final c in readServerCases('legacy-ids.json')) {
      final type = c['type']! as String;
      switch (type) {
        case 'space':
          test('space "${c['old']}"', () {
            final uuid = spaceUuid(c['old']! as String);
            expect(uuid, c['uuid_text']);
            expect(toHex(uuidBytes(uuid)), c['uuid']);
          });
        case 'item':
          test('item "${c['old']}" under the owner ${c['owner_label']}', () {
            final owner = Owner.fromBytes(fromHex(c['owner']! as String));
            final uuid = itemUuid(c['old']! as String, owner);
            expect(uuid, c['uuid_text']);
            expect(toHex(uuidBytes(uuid)), c['uuid']);
            // The owner's label says what it is: a space owner is the mapped
            // space uuid, here the one of the first space case.
            expect(owner.type, c['owner_label'] == 'user' ? OwnerType.user : OwnerType.space);
          });
        case 'is_uuid':
          test('"${c['input']}" ${c['is_uuid']! as bool ? 'is' : 'is not'} a UUID', () {
            final input = c['input']! as String;
            expect(isUuidText(input), c['is_uuid']);
            // A UUID is never mapped: both functions give it back as it is.
            if (c['is_uuid']! as bool) {
              expect(spaceUuid(input), input);
              expect(itemUuid(input, Owner.fromBytes(List.filled(17, 1))), input);
            }
          });
        default:
          throw StateError('legacy-ids.json has a case of the unknown type $type');
      }
    }

    test('the item cases of a mapped space use that space\'s uuid as their owner', () {
      final cases = readServerCases('legacy-ids.json');
      final space = cases.firstWhere((c) => c['type'] == 'space' && c['old'] == 'team_Alpha-01');
      final owners = cases.where((c) => c['owner_label'] == 'mapped-space').map((c) => c['owner']).toSet();
      expect(owners, {'02${space['uuid']}'});
    });
  });
}
