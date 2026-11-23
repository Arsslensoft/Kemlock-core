@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart' show canonical;
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:test/test.dart';

const _fingerprint = '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495';

const _json = <String, Object?>{
  'id': 'c1',
  'name': 'Grace Hopper',
  'public': 'mDMEavvBvhYJKwYBBAHaRw8BAQdA',
  'source': 'qr',
  'checkedAt': 1_799_000_000_000,
  'checkedFingerprint': _fingerprint,
  'note': 'Met at the conference',
  'addedAt': 100,
  'updatedAt': 200,
  'trustLevel': 'later',
};

const _bare = Contact(id: 'c2', name: 'Alan Turing', publicKey: 'AAAA', source: ContactSource.file, addedAt: 5);

void main() {
  test('reads every key and writes back what it read, unknown keys included', () {
    final contact = Contact.fromJson(jsonDecode(jsonEncode(_json)) as Map<String, Object?>);

    expect(
      (contact.id, contact.name, contact.publicKey, contact.source),
      ('c1', 'Grace Hopper', 'mDMEavvBvhYJKwYBBAHaRw8BAQdA', ContactSource.qr),
    );
    expect((contact.checkedAt, contact.checkedFingerprint, contact.note), (1_799_000_000_000, _fingerprint, 'Met at the conference'));
    expect((contact.addedAt, contact.updatedAt, contact.changedAt), (100, 200, 200));
    expect(contact.extra, {'trustLevel': 'later'});
    expect(canonical(contact.toJson()), canonical(_json));
  });

  test('optional keys are absent until set', () {
    expect(_bare.toJson().keys, ['id', 'name', 'public', 'source', 'addedAt']);
    expect(_bare.changedAt, 5);

    final read = Contact.fromJson(_bare.toJson());

    expect((read.checkedAt, read.checkedFingerprint, read.note, read.updatedAt), (null, null, null, null));
    expect(read, _bare);
  });

  test('a source this version does not know is kept', () {
    final contact = Contact.fromJson({..._bare.toJson(), 'source': 'keyserver'});

    expect(contact.source, 'keyserver');
    expect(contact.toJson()['source'], 'keyserver');
  });

  // openspec: add-key-lookup, task 1.3. A contact a lookup found, as a version with lookups writes it, read and
  // written back by any version with contacts.
  test('a key found by lookup keeps its source and the address it was found for', () {
    for (final source in ['wkd', 'keyserver']) {
      final json = {..._bare.toJson(), 'source': source, 'sourceEmail': 'Grace@example.org'};

      final contact = Contact.fromJson(jsonDecode(jsonEncode(json)) as Map<String, Object?>);

      expect(contact.source, source);
      expect(canonical(contact.toJson()), canonical(json), reason: source);
    }
  });

  test('reads, writes and clears the address a key was found for, and writes nothing for one without', () {
    final found = Contact.fromJson({..._bare.toJson(), 'source': ContactSource.wkd, 'sourceEmail': 'Grace@example.org'});

    expect((found.source, found.sourceEmail), (ContactSource.wkd, 'Grace@example.org'));
    expect(found.extra, isEmpty);
    expect(found.toJson()['sourceEmail'], 'Grace@example.org');
    expect(found.copyWith(name: 'Grace').sourceEmail, 'Grace@example.org');

    final cleared = found.copyWith(source: ContactSource.file, sourceEmail: unset);
    expect(cleared.toJson(), {..._bare.toJson(), 'source': 'file'});
    expect(jsonEncode(_bare.toJson()), '{"id":"c2","name":"Alan Turing","public":"AAAA","source":"file","addedAt":5}');
  });

  test('copyWith keeps what it is not given and unsets what it is told to', () {
    final contact = Contact.fromJson(_json);

    final renamed = contact.copyWith(name: 'Grace');
    expect(renamed.toJson(), {..._json, 'name': 'Grace'});

    final cleared = contact.copyWith(note: unset, checkedAt: unset, checkedFingerprint: unset);
    expect(cleared.toJson().keys, isNot(containsAll(<String>['note', 'checkedAt', 'checkedFingerprint'])));
    expect(cleared.extra, {'trustLevel': 'later'});
    expect(contact.copyWith(note: keep).note, 'Met at the conference');

    final replaced = contact.copyWith(publicKey: 'BBBB', source: ContactSource.paste);
    expect((replaced.publicKey, replaced.source, replaced.id), ('BBBB', 'paste', 'c1'));
  });

  test('checking writes the date and the fingerprint, and taking it back removes both', () {
    final checked = _bare.checked(_fingerprint, 42);

    expect((checked.checkedAt, checked.checkedFingerprint), (42, _fingerprint));
    expect(checked.unchecked(), _bare);
  });

  test('a check keeps the addresses it covers, in lower case, and taking it back removes them', () {
    final checked = _bare.checked(_fingerprint, 42, addresses: ['grace@example.org', 'Grace@Navy.mil', 'grace@example.org']);

    expect(checked.checkedAddresses, ['grace@example.org', 'grace@navy.mil']);
    expect(checked.toJson()['checkedAddresses'], ['grace@example.org', 'grace@navy.mil']);
    expect(Contact.fromJson(jsonDecode(jsonEncode(checked.toJson())) as Map<String, Object?>), checked);
    expect(checked.extra, isEmpty);
    expect(checked.unchecked(), _bare);
    // A key with no address is checked for none; checking again without addresses covers the key as it is
    expect(_bare.checked(_fingerprint, 42, addresses: const []).checkedAddresses, isEmpty);
    expect(checked.checked(_fingerprint, 43).checkedAddresses, isNull);
  });

  test('a contact checked by a version that kept no addresses reads with none', () {
    final contact = Contact.fromJson(_json);

    expect(contact.checkedAddresses, isNull);
    expect(contact.toJson().containsKey('checkedAddresses'), isFalse);
  });

  test('a contact never moves to a space', () {
    expect(_bare.spaceId, isNull);
    expect(identical(_bare.inSpace('space-1'), _bare), isTrue);
    expect(identical(_bare.inSpace(null), _bare), isTrue);
  });

  test('stamped sets updatedAt', () {
    final stamped = _bare.stamped(900);

    expect((stamped.updatedAt, stamped.changedAt, stamped.addedAt), (900, 900, 5));
  });
}
