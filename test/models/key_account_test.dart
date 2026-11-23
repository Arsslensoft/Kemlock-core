@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart' show canonical;
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:test/test.dart';

const _json = <String, Object?>{
  'id': 'ka1',
  'device': '0102030405060708',
  'keyName': 'YubiKey 5C NFC',
  'name': '60/Example:alice@example.org',
  'issuer': 'Example',
  'label': 'alice@example.org',
  'period': 60,
  'type': 'totp',
  'algorithm': 'SHA256',
  'touch': true,
  'tags': ['work'],
  'note': 'The admin account',
  'addedAt': 100,
  'updatedAt': 200,
};

void main() {
  group('KeyAccount', () {
    test('reads every field and writes back what it read, unknown keys included', () {
      final json = {
        ..._json,
        'colour': 'teal',
        'later': {'n': 1},
      };
      final account = KeyAccount.fromJson(jsonDecode(jsonEncode(json)) as Map<String, Object?>);

      expect(account.device, '0102030405060708');
      expect(account.keyName, 'YubiKey 5C NFC');
      expect(account.name, '60/Example:alice@example.org');
      expect((account.issuer, account.label, account.period), ('Example', 'alice@example.org', 60));
      expect(account.type, KeyAccountType.totp);
      expect(account.algorithm, 'SHA256');
      expect(account.touch, isTrue);
      expect(account.tags, ['work']);
      expect(account.note, 'The admin account');
      expect(account.changedAt, 200);
      expect(account.extra, {
        'colour': 'teal',
        'later': {'n': 1},
      });
      expect(canonical(account.toJson()), canonical(json));
    });

    test('writes optional keys only once they are set', () {
      const account = KeyAccount(id: 'ka1', device: 'ab', name: 'Example:alice', issuer: 'Example', label: 'alice', addedAt: 5);

      expect(account.toJson().keys, ['id', 'device', 'name', 'issuer', 'label', 'period', 'type', 'algorithm', 'addedAt']);
      expect(account.changedAt, 5);
      expect(account.spaceId, isNull);
      expect(account.inSpace('fam').spaceId, isNull, reason: 'an on-key account is never in a shared space');
      expect(account.stamped(9).updatedAt, 9);
    });

    test('reads a counter-based account, and anything else as time-based', () {
      expect(KeyAccount.fromJson({..._json, 'type': 'hotp'}).type, KeyAccountType.hotp);
      expect(KeyAccount.fromJson({..._json, 'type': 'steam'}).type, KeyAccountType.totp);
      expect(KeyAccount.fromJson({..._json}..remove('type')).isTimeBased, isTrue);
    });

    test('copyWith changes and removes fields, and keeps the unknown keys', () {
      final account = KeyAccount.fromJson({..._json, 'colour': 'teal'});

      final edited = account.copyWith(tags: ['bank'], note: unset, keyName: unset);

      expect(edited.tags, ['bank']);
      expect(edited.note, isNull);
      expect(edited.keyName, isNull);
      expect(edited.name, account.name);
      expect(edited.extra, {'colour': 'teal'});
      expect(edited == account, isFalse);
      expect(account.copyWith() == account, isTrue);
    });

    test('never writes a secret, a code or digits, even when a file carried them', () {
      final account = KeyAccount.fromJson({..._json, 'secret': 'JBSWY3DPEHPK3PXP', 'code': '287082', 'digits': 6, 'colour': 'teal'});

      final written = account.copyWith(tags: ['x']).stamped(3).toJson();

      for (final name in ['secret', 'code', 'digits']) {
        expect(written.containsKey(name), isFalse, reason: name);
      }
      expect(jsonEncode(written), isNot(contains('JBSWY3DPEHPK3PXP')));
      expect(written['colour'], 'teal');
      expect(KeyAccount.neverWritten, {'secret', 'code', 'digits'});
    });

    test('is named by its issuer, or by its label without one', () {
      expect(KeyAccount.fromJson(_json).displayName, 'Example');
      expect(KeyAccount.fromJson({..._json, 'issuer': ''}).displayName, 'alice@example.org');
    });
  });
}
