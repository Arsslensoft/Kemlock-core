@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/item_link.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:test/test.dart';

const _a = '3f2c9a71-e4b0-4856-8a00-000000000001';
const _b = '3f2c9a71-e4b0-4856-8a00-000000000002';
const _c = '3f2c9a71-e4b0-4856-8a00-000000000003';

void main() {
  group('ItemLink', () {
    test('reads an entry with a UUID id and keeps its other keys', () {
      final link = ItemLink.fromJson({'id': _a, 'since': 5});
      expect(link.isReadable, isTrue);
      expect(link.id, _a);
      expect(link.extra, {'since': 5});
      expect(link.toJson(), {'id': _a, 'since': 5});
    });

    test('compares ids as lower-case text', () {
      final link = ItemLink.fromJson({'id': _a.toUpperCase()});
      expect(link.isReadable, isTrue);
      expect(link.key, _a);
    });

    test('keeps an entry it cannot read, whatever it is', () {
      for (final raw in <Object?>[
        null,
        5,
        'text',
        <Object?>[],
        {'id': 'acc-1'},
        {'name': 'x'},
        {'id': 7},
      ]) {
        final link = ItemLink.fromJson(raw);
        expect(link.isReadable, isFalse);
        expect(link.toJson(), raw);
      }
    });

    test('writes a link made here as {id}', () {
      expect(const ItemLink(_a).toJson(), {'id': _a});
      expect(const ItemLink(_a, extra: {'x': 1}).toJson(), {'id': _a, 'x': 1});
    });
  });

  group('readLinks and writeLinks', () {
    test('write back the list exactly as it was read, entry by entry and in the same order', () {
      final json = [
        {'note': 'first', 'id': _c},
        'odd',
        {'id': _a},
        {'id': 'legacy-id'},
        {'id': _b, 'x': null},
      ];
      final links = readLinks(json);
      expect(links, hasLength(5));
      expect(jsonEncode(writeLinks(links)), jsonEncode(json));
    });

    test('leave out the member when there are none', () {
      expect(writeLinks(const []), isNull);
      expect(readLinks(null), isEmpty);
      expect(readLinks('no'), isEmpty);
    });
  });

  group('normaliseLinks', () {
    test('sorts by id, keeps each once, drops the item itself and puts the entries it cannot read last', () {
      final links = normaliseLinks(
        [
          const ItemLink(_c),
          const ItemLink.unread('odd'),
          ItemLink.fromJson({'id': _a, 'note': 'kept'}),
          const ItemLink(_a),
          const ItemLink(_b),
        ],
        ownIds: [_b.toUpperCase()],
      );
      expect(writeLinks(links), [
        {'id': _a, 'note': 'kept'},
        {'id': _c},
        'odd',
      ]);
    });
  });

  group('on an entry', () {
    const login = Login(id: 'l1', name: 'Mail', addedAt: 1);

    test('withLinks sorts them and never names the item itself', () {
      final linked = login.withLinks([const ItemLink(_b), const ItemLink(_a), const ItemLink('l1')]);
      expect(linked.links.map((link) => link.id), [_a, _b]);
      expect(linked.toJson()['links'], [
        {'id': _a},
        {'id': _b},
      ]);
      expect(linked.stamped(9).links, linked.links);
    });

    test('a body without links has none, and an empty list is left out', () {
      expect(login.toJson().containsKey('links'), isFalse);
      expect(login.withLinks(const []).toJson().containsKey('links'), isFalse);
    });

    test('a body that holds links writes them back, and they are no longer among the unknown keys', () {
      final json = {
        ...login.toJson(),
        'links': [
          {'id': _b},
          {'id': _a},
        ],
        'other': true,
      };
      final read = Login.fromJson(json);
      expect(read.extra, {'other': true});
      expect(read.links.map((link) => link.id), [_b, _a]);
      expect(read.toJson(), json);
      expect(read.copyWith(name: 'Mail 2').links, read.links);
    });

    test('a links member that is not a list stays among the unknown keys', () {
      final read = Login.fromJson({...login.toJson(), 'links': 'x'});
      expect(read.links, isEmpty);
      expect(read.toJson()['links'], 'x');
    });

    test('names, adding and removing work on the readable entries', () {
      final links = [const ItemLink(_a), const ItemLink.unread(3)];
      expect(links.names(_a.toUpperCase()), isTrue);
      expect(links.names(_b), isFalse);
      expect(links.adding(_b).map((link) => link.toJson()), [
        {'id': _a},
        {'id': _b},
        3,
      ]);
      expect(links.removing(_a).map((link) => link.toJson()), [3]);
    });
  });
}
