@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:test/test.dart';

void main() {
  const login = Login(
    id: 'l1',
    name: 'Larkspur Mail',
    username: 'ada@example.org',
    password: 'one',
    websites: ['larkspur.example'],
    addedAt: 1,
  );

  test('writes the fields that are set, in order, and reads them back', () {
    expect(
      jsonEncode(login.toJson()),
      '{"id":"l1","name":"Larkspur Mail","username":"ada@example.org","password":"one","websites":["larkspur.example"],"addedAt":1}',
    );
    final full = login.copyWith(
      note: 'n',
      tags: ['mail'],
      pinned: true,
      spaceId: 'fam',
      accountId: 'a1',
      passwordChangedAt: 5,
      previousPasswords: [const PreviousPassword(password: 'zero', until: 5)],
      codeWarning: false,
      source: Login.fromAutofill,
      updatedAt: 6,
    );
    expect(Login.fromJson(jsonDecode(jsonEncode(full.toJson())) as Map<String, Object?>), full);
  });

  test('keeps keys it doesn’t know, in the login and in its previous passwords', () {
    final json = {
      ...login.toJson(),
      'fields': [
        {'name': 'PIN', 'value': '1234'},
      ],
      'previousPasswords': [
        {'password': 'zero', 'until': 2, 'by': 'phone'},
      ],
    };
    final read = Login.fromJson(json);
    expect(read.extra, {
      'fields': [
        {'name': 'PIN', 'value': '1234'},
      ],
    });
    expect(read.previousPasswords!.single.extra, {'by': 'phone'});
    expect(read.copyWith(name: 'Larkspur').toJson()['fields'], json['fields']);
    expect(read.toJson(), json);
  });

  test('leaves out empty websites and previous passwords', () {
    expect(login.copyWith(websites: <String>[], previousPasswords: <PreviousPassword>[]).toJson().keys, isNot(contains('websites')));
    expect(login.copyWith(previousPasswords: <PreviousPassword>[]).toJson().keys, isNot(contains('previousPasswords')));
  });

  test('ignores fields of the wrong type rather than failing', () {
    final read = Login.fromJson({'id': 'l', 'name': 3, 'password': 4, 'previousPasswords': 'x', 'addedAt': 'now'});
    expect(read.name, '');
    expect(read.password, isNull);
    expect(read.previousPasswords, isNull);
    expect(read.addedAt, 0);
  });

  group('withPassword', () {
    test('keeps the password it replaces, newest first', () {
      final changed = login.withPassword('two', 10).withPassword('three', 20);
      expect(changed.password, 'three');
      expect(changed.passwordChangedAt, 20);
      expect(changed.previousPasswords, [
        const PreviousPassword(password: 'two', until: 20),
        const PreviousPassword(password: 'one', until: 10),
      ]);
    });

    test('keeps five, dropping the oldest first', () {
      var changed = login;
      for (var i = 2; i <= 7; i++) {
        changed = changed.withPassword('p$i', i);
      }
      expect(changed.password, 'p7');
      expect([for (final p in changed.previousPasswords!) p.password], ['p6', 'p5', 'p4', 'p3', 'p2']);
    });

    test('changes nothing for the same password', () {
      expect(login.withPassword('one', 10), same(login));
    });

    test('takes a previous password back out of the list when it is set again', () {
      final back = login.withPassword('two', 10).withPassword('one', 20);
      expect(back.password, 'one');
      expect(back.previousPasswords, [const PreviousPassword(password: 'two', until: 20)]);
    });

    test('removes the password, keeping it among the previous ones', () {
      final none = login.withPassword('', 10);
      expect(none.password, isNull);
      expect(none.toJson().containsKey('password'), isFalse);
      expect(none.previousPasswords!.single.password, 'one');
    });
  });

  group('keepingPrevious', () {
    test('adds a password in date order, once, never the one now', () {
      final kept = login.withPassword('two', 10).keepingPrevious('lost', 5);
      expect([for (final p in kept.previousPasswords!) p.password], ['one', 'lost']);
      expect(kept.keepingPrevious('lost', 7), same(kept));
      expect(kept.keepingPrevious('two', 7), same(kept));
      expect(kept.keepingPrevious('', 7), same(kept));
    });
  });

  test('needs a name and a username or a password', () {
    expect(login.isComplete, isTrue);
    expect(login.copyWith(password: unset).isComplete, isTrue);
    expect(login.copyWith(username: unset, password: unset).isComplete, isFalse);
    expect(login.copyWith(name: ' ').isComplete, isFalse);
  });

  test('is stamped, moved between scopes and compared as other entries are', () {
    expect(login.stamped(9).changedAt, 9);
    expect(login.changedAt, 1);
    expect(login.inSpace('fam').spaceId, 'fam');
    expect(login.inSpace('fam').inSpace('').toJson().containsKey('spaceId'), isFalse);
    expect(Login.fromJson(login.toJson()), login);
  });

  test('never shows its secrets in toString', () {
    expect(login.toString(), isNot(contains('one')));
    expect(login.toString(), isNot(contains('ada@example.org')));
    expect(const PreviousPassword(password: 'secret', until: 1).toString(), isNot(contains('secret')));
  });
}
