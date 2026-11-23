@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart' show canonical;
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

const _json = <String, Object?>{
  'id': 'n1',
  'title': 'Passport',
  'text': 'In the drawer, left side',
  'tags': ['travel'],
  'pinned': true,
  'spaceId': 'space-1',
  'addedAt': 100,
  'updatedAt': 200,
  'attachments': [
    {
      'id': 'AAECAwQFBgcICQoLDA0ODw',
      'name': 'passport-scan.pdf',
      'size': 2048,
      'type': 'application/pdf',
      'key': 'q83vEjRWeJCrze8SNFZ4kKvN7xI0VniQq83vEjRWeJA=',
      'addedAt': 150,
      'thumbnail': 'later',
    },
  ],
  'colour': 'amber',
};

void main() {
  group('SecureNote', () {
    test('reads every field', () {
      final note = SecureNote.fromJson(_json);

      expect((note.id, note.title, note.text, note.pinned, note.spaceId), ('n1', 'Passport', 'In the drawer, left side', true, 'space-1'));
      expect(note.tags, ['travel']);
      expect((note.addedAt, note.updatedAt, note.changedAt), (100, 200, 200));
      final file = note.files.single;
      expect(
        (file.id, file.name, file.size, file.type, file.addedAt),
        ('AAECAwQFBgcICQoLDA0ODw', 'passport-scan.pdf', 2048, 'application/pdf', 150),
      );
    });

    test('writes back what it read, keys it does not know at both levels included', () {
      final note = SecureNote.fromJson(jsonDecode(jsonEncode(_json)) as Map<String, Object?>);

      expect(canonical(note.toJson()), canonical(_json));
      expect(note.extra, {'colour': 'amber'});
      expect(note.files.single.extra, {'thumbnail': 'later'});
    });

    test('never prints its text or its files’ keys', () {
      final printed = SecureNote.fromJson(_json).toString();

      expect(printed, allOf(contains('Passport'), isNot(contains('drawer')), isNot(contains('q83vEjRW'))));
    });

    test('keeps a note without files without an attachments key', () {
      const plain = {'id': 'n2', 'title': 'Wi-Fi', 'text': 'hunter2', 'addedAt': 1};

      final note = SecureNote.fromJson(plain);

      expect(note.files, isEmpty);
      expect(note.toJson(), plain);
    });

    test('keeps an empty list of files as it was', () {
      final note = SecureNote.fromJson(const {'id': 'n3', 'title': 'x', 'text': '', 'addedAt': 1, 'attachments': <Object?>[]});

      expect(note.toJson()['attachments'], isEmpty);
    });

    test('reads what is missing or of the wrong type as empty', () {
      final note = SecureNote.fromJson(const {'id': 'n4', 'title': 7, 'tags': 'x', 'attachments': 'x'});

      expect((note.title, note.text, note.tags, note.attachments, note.addedAt), ('', '', null, null, 0));
    });

    test('compares by its JSON', () {
      expect(SecureNote.fromJson(_json), SecureNote.fromJson(_json));
      expect(SecureNote.fromJson(_json), isNot(SecureNote.fromJson({..._json, 'text': 'changed'})));
    });

    test('changes fields with copyWith, and removes optional ones with unset', () {
      final note = SecureNote.fromJson(_json);

      final changed = note.copyWith(title: 'ID card', pinned: unset, attachments: unset);

      expect((changed.title, changed.pinned, changed.attachments), ('ID card', null, null));
      expect(changed.extra, {'colour': 'amber'});
    });

    test('is stamped and moved between scopes as other entries are', () {
      final note = SecureNote.fromJson(_json);

      expect(note.stamped(999).updatedAt, 999);
      expect(note.inSpace(null).spaceId, isNull);
      expect(note.inSpace('').spaceId, isNull);
      expect(note.inSpace('space-2').spaceId, 'space-2');
    });
  });
}
