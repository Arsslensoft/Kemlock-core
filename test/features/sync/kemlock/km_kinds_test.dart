@TestOn('vm')
library;

// One item per entry (add-kemlock-server-sync, task 8.3): each kind of
// test/fixtures/kemlock/items.json round trips byte for byte through the
// mapping, the fake server and another phone, and ids map as crypto.md says.
import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

final _fixture = jsonDecode(File('test/fixtures/kemlock/items.json').readAsStringSync()) as Map<String, Object?>;
final _items = [
  for (final item in _fixture['items']! as List<Object?>)
    (kind: (item! as Map<String, Object?>)['kind']! as String, entry: (item as Map<String, Object?>)['entry']! as Map<String, Object?>),
];

void main() {
  test('the fixture holds one entry of each kind crypto.md lists that the app has a model for', () {
    expect(_items.map((item) => item.kind), ['login', 'otp', 'note', 'backup-codes', 'passkey', 'pgp-key', 'ssh-key']);
  });

  for (final item in _items) {
    test('${item.kind}: an entry reads and writes the JSON of the fixture, byte for byte, under the kind its list gives', () {
      final doc = kmDocOf([(kind: item.kind, json: item.entry)]);

      final entries = kmEntriesOf(doc);

      expect(entries, hasLength(1));
      expect(entries.single.kind, item.kind);
      expect(canonical(entries.single.json), canonical(item.entry));
      expect(jsonEncode(entries.single.json).length, greaterThan(0));
    });

    test('${item.kind}: goes up sealed, and another phone opens the same JSON', () async {
      final world = (server: FakeKemlockServer()..checkTokens = false, clock: KmClock());
      final doc = kmDocOf([(kind: item.kind, json: item.entry)]);
      final one = KmPhone(world.server, clock: world.clock, lists: doc);

      await one.run();
      final uuid = kmItemId(item.entry['id']! as String, one.crypto.owner);
      final stored = world.server.items[uuid]!;
      final opened = utf8.decode(
        await one.crypto.openItem(
          Kem1Item(
            id: stored.id,
            owner: one.crypto.owner,
            kind: stored.kind,
            revision: stored.revision,
            keyVersion: stored.keyVersion,
            ciphertext: stored.ciphertext,
            itemKey: stored.itemKey,
          ),
        ),
      );
      final two = one.another();
      await two.run();

      expect(stored.kind, item.kind);
      expect(canonical(jsonDecode(opened)), canonical(item.entry));
      expect(kmEntriesOf(two.lists).map((entry) => entry.kind), [item.kind]);
      expect(canonical(kmEntriesOf(two.lists).single.json), canonical(item.entry));
    });
  }

  group('a key’s kind', () {
    Map<String, Object?> key(String kind, {Map<String, Object?> more = const {}}) => {
      'id': 'b1d7a4c4-1f0e-4c0a-9a56-3a8c1f0f2a99',
      'name': 'k',
      'kind': kind,
      'algorithm': 'x',
      'private': 'AAAA',
      'origin': 'imported',
      'addedAt': 1,
      ...more,
    };

    String kindOf(Map<String, Object?> json) => kmEntriesOf(
      SyncDoc.fromJson({
        'keys': [json],
      }),
    ).single.kind;

    test('is pgp-key, ssh-key, certificate or key, as the key’s own kind says', () {
      expect(kindOf(key('pgp')), 'pgp-key');
      expect(kindOf(key('ssh')), 'ssh-key');
      expect(kindOf(key('signing')), 'key');
      expect(kindOf(key('exchange')), 'key');
      expect(kindOf(key('other')), 'key');
      expect(kindOf(key('signing', more: {'certificate': 'MIIB'})), 'certificate');
    });
  });

  group('the kinds this version knows', () {
    test('are the thirteen of the table, and a later kind is not read', () {
      for (final kind in [
        'otp',
        'backup-codes',
        'pgp-key',
        'ssh-key',
        'certificate',
        'key',
        'note',
        'passkey',
        'key-otp',
        'contact',
        'login',
        'card',
        'identity',
      ]) {
        expect(kmKnowsKind(kind), isTrue, reason: kind);
      }
      expect(kmKnowsKind('future-thing'), isFalse);
      expect(
        kmDocOf([
          (kind: 'future-thing', json: {'id': 'x'}),
        ]).ids,
        isEmpty,
      );
    });

    test('cards and identities are items of the kinds card and identity, and come back in their lists', () {
      const cardId = 'b2d7a4c4-1f0e-4c0a-9a56-3a8c1f0f2a01';
      const identityId = 'b2d7a4c4-1f0e-4c0a-9a56-3a8c1f0f2a02';
      final doc = SyncDoc.fromJson({
        'cards': [
          {'id': cardId, 'name': 'Visa', 'addedAt': 1},
        ],
        'identities': [
          {'id': identityId, 'name': 'Me', 'addedAt': 1},
        ],
      });

      final entries = kmEntriesOf(doc);
      final back = kmDocOf(entries);

      expect(entries.map((entry) => entry.kind), ['card', 'identity']);
      expect(entries.map((entry) => kmEntryId(entry)), [cardId, identityId]);
      expect(back.cards.map((card) => card.id), [cardId]);
      expect(back.identities.map((identity) => identity.id), [identityId]);
    });
  });

  group('ids', () {
    final user = Owner.user('00000000-0000-4000-8000-000000000001');
    final space = Owner.space('00000000-0000-4000-8000-0000000000aa');

    test('an id that is a UUID is the item’s id, whoever owns it', () {
      const id = 'b0d7a4c4-1f0e-4c0a-9a56-3a8c1f0f2a11';

      expect(kmItemId(id, user), id);
      expect(kmItemId(id, space), id);
    });

    test('an id like acc-1 maps to the legacy-id UUID of its owner, and the entry keeps acc-1', () {
      expect(kmItemId('acc-1', user), itemUuid('acc-1', user));
      expect(kmItemId('acc-1', user), isNot('acc-1'));
      expect(isUuidText(kmItemId('acc-1', user)), isTrue);
      expect(kmItemId('3f2c9a71e4b0d856', user), isNot(kmItemId('acc-1', user)));
    });

    test('an entry with an older id that moves into a space gets a new UUID, and is paired by its original id', () {
      final inUser = kmItemId('acc-1', user);
      final inSpace = kmItemId('acc-1', space);
      const entry = {'id': 'acc-1', 'issuer': 'ACME'};

      expect(inSpace, isNot(inUser));
      expect(kmReadable('otp', entry, inUser, user), isTrue);
      expect(kmReadable('otp', entry, inSpace, space), isTrue);
      expect(kmReadable('otp', entry, inSpace, user), isFalse, reason: 'the item belongs to the other owner');
      expect(entry['id'], 'acc-1', reason: 'both copies keep the id the merge pairs by');
    });

    test('an entry whose id does not map to its item’s id, or that is no entry, is not read', () {
      final id = kmItemId('acc-1', user);

      expect(kmReadable('otp', {'id': 'acc-2'}, id, user), isFalse);
      expect(kmReadable('otp', {'id': ''}, id, user), isFalse);
      expect(kmReadable('otp', {'name': 'no id'}, id, user), isFalse);
      expect(kmReadable('otp', 'not an object', id, user), isFalse);
      expect(kmReadable('future-thing', {'id': 'acc-1'}, id, user), isFalse, reason: 'a kind this version does not read');
    });
  });
}
