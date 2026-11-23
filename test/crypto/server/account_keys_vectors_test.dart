@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's account-keys.json (crypto.md "Account keys"): the user key
// HKDF(root, "kemlock/v1/user") and its labelled children.
void main() {
  group("the server's account-keys vectors", () {
    for (final c in readServerCases('account-keys.json')) {
      test(c['name']! as String, () {
        final root = fromHex(c['root_key']! as String);
        expect(root, hasLength(rootKeyLength));
        expect(c['user_label'], KeyLabel.user);

        final user = deriveUserKey(root);
        expect(toHex(user), c['user_key']);

        final children = (c['children']! as List<Object?>).cast<Map<String, Object?>>();
        expect(children.map((child) => child['label']), [KeyLabel.itemWrap, KeyLabel.privateKeys, KeyLabel.manifest]);
        for (final child in children) {
          final childLabel = child['label']! as String;
          expect(toHex(deriveChildKey(user, childLabel)), child['key'], reason: childLabel);
        }

        // The holder the app uses derives the same keys.
        final keys = AccountKeys.fromRoot(root);
        expect(toHex(keys.userKey), c['user_key']);
        expect(toHex(keys.itemWrapKey), children[0]['key']);
        expect(toHex(keys.privateKeysKey), children[1]['key']);
        expect(toHex(keys.manifestKey), children[2]['key']);
        keys.dispose();
      });
    }
  });
}
