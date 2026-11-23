@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

void main() {
  group('OtpAccount', () {
    test('reads an account saved before HOTP and Steam as TOTP', () {
      final account = OtpAccount.fromJson(
        jsonDecode(
          '{"id":"acc-1","issuer":"RFC6238","label":"alice@example.com","secret":"GEZDGNBVGY3TQOJQ",'
          '"algorithm":"SHA1","digits":6,"period":30,"addedAt":1700000000000}',
        ) as Map<String, Object?>,
      );

      expect(account.type, isNull);
      expect(account.kind, OtpType.totp);
      expect(account.digits, 6);
      expect(account.addedAt, 1700000000000);
    });

    test('writes back the JSON it read, leaving out fields that were absent', () {
      const json =
          '{"id":"a","type":"hotp","issuer":"Acme","label":"me","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA256",'
          '"digits":8,"period":30,"counter":4,"pinned":true,"tags":["work"],"order":2,"note":"n",'
          '"noBackupCodes":true,"spaceId":"s1","addedAt":1,"updatedAt":2}';

      expect(jsonEncode(OtpAccount.fromJson(jsonDecode(json) as Map<String, Object?>).toJson()), json);
    });

    test('keeps keys it does not know', () {
      final account = OtpAccount.fromJson({
        'id': 'a',
        'issuer': 'X',
        'label': '',
        'secret': 'S',
        'algorithm': 'SHA1',
        'digits': 6,
        'period': 30,
        'addedAt': 1,
        'icon': {'slug': 'github'},
      });

      expect(account.extra, {
        'icon': {'slug': 'github'},
      });
      expect(account.copyWith(label: 'me').toJson()['icon'], {'slug': 'github'});
    });

    test('changes and removes optional fields with copyWith', () {
      const account = OtpAccount(id: 'a', issuer: 'X', label: '', secret: 'S', note: 'old', pinned: true, addedAt: 1);

      final changed = account.copyWith(note: 'new', pinned: unset);

      expect(changed.note, 'new');
      expect(changed.pinned, isNull);
      expect(changed.toJson().containsKey('pinned'), isFalse);
      expect(account.copyWith().note, 'old');
    });

    test('reads whole numbers written with a fraction', () {
      final account = OtpAccount.fromJson({'id': 'a', 'digits': 6.0, 'period': 30.0, 'addedAt': 1.0});

      expect(account.digits, 6);
      expect(jsonEncode(account.toJson()['period']), '30');
    });

    test('ignores fields of the wrong type rather than failing', () {
      final account = OtpAccount.fromJson({'id': 'a', 'pinned': 'yes', 'tags': 'work', 'note': 3, 'addedAt': 1});

      expect(account.pinned, isNull);
      expect(account.tags, isNull);
      expect(account.note, isNull);
    });

    test('keeps the breaches an account has marked dealt with', () {
      final account = OtpAccount.fromJson({
        'id': 'a',
        'issuer': 'Adobe',
        'label': '',
        'secret': 'S',
        'addedAt': 1,
        'breachesDismissed': ['Adobe'],
      });

      expect(account.toJson()['breachesDismissed'], ['Adobe']);
      expect(account.copyWith(note: 'edited').toJson()['breachesDismissed'], ['Adobe']);
    });

    test('marks and unmarks a breach dealt with, leaving the key out when there is none', () {
      const account = OtpAccount(id: 'a', issuer: 'Adobe', label: '', secret: 'S', addedAt: 1);
      final before = jsonEncode(account.toJson());

      final marked = account.copyWith(breachesDismissed: ['Adobe']);

      expect(marked.breachesDismissed, ['Adobe']);
      expect(marked.extra, isEmpty);
      expect(jsonEncode(marked.toJson()), endsWith(',"addedAt":1,"breachesDismissed":["Adobe"]}'));
      expect(jsonEncode(marked.copyWith(breachesDismissed: unset).toJson()), before);
      expect(jsonEncode(marked.copyWith(breachesDismissed: <String>[]).toJson()), before);
      expect(OtpAccount.fromJson(marked.toJson()), marked);
      expect(OtpAccount.fromJson({...account.toJson(), 'breachesDismissed': 'Adobe'}).breachesDismissed, isNull);
    });

    test('keeps the websites given to an account, leaving the key out when there is none', () {
      const account = OtpAccount(id: 'a', issuer: 'Nextcloud', label: 'alice', secret: 'S', addedAt: 1);
      final before = jsonEncode(account.toJson());

      final given = account.copyWith(websites: ['cloud.example.org']);

      expect(given.extra, isEmpty);
      expect(jsonEncode(given.toJson()), endsWith(',"addedAt":1,"websites":["cloud.example.org"]}'));
      expect(OtpAccount.fromJson(given.toJson()), given);
      expect(given.copyWith(note: 'edited').websites, ['cloud.example.org']);
      expect(jsonEncode(given.copyWith(websites: unset).toJson()), before);
      expect(jsonEncode(given.copyWith(websites: <String>[]).toJson()), before);
      expect(OtpAccount.fromJson({...account.toJson(), 'websites': 'cloud.example.org'}).websites, isNull);
    });

    test('compares by content', () {
      const a = OtpAccount(id: 'a', issuer: 'X', label: '', secret: 'S', tags: ['t'], addedAt: 1);

      expect(a, OtpAccount.fromJson(a.toJson()));
      expect(a == a.copyWith(tags: ['u']), isFalse);
    });

    test('never prints its secret or its note', () {
      const account = OtpAccount(id: 'a', issuer: 'GitHub', label: 'octocat', secret: 'JBSWY3DPEHPK3PXP', note: 'PIN 4321', addedAt: 1);

      expect(account.toString(), allOf(contains('GitHub'), isNot(contains('JBSWY3DPEHPK3PXP')), isNot(contains('4321'))));
    });
  });

  group('BackupService', () {
    test('writes back the JSON it read', () {
      const json =
          '{"id":"svc-1","serviceName":"GitHub","codes":[{"code":"aaaa-1111","used":false},'
          '{"code":"bbbb-2222","used":true,"usedAt":5}],"note":"n","addedAt":1700000002000}';

      expect(jsonEncode(BackupService.fromJson(jsonDecode(json) as Map<String, Object?>).toJson()), json);
    });

    test('keeps the breaches a service has marked dealt with', () {
      final service = BackupService.fromJson({
        'id': 's',
        'serviceName': 'Adobe',
        'codes': <Object?>[],
        'addedAt': 1,
        'breachesDismissed': ['Adobe'],
      });

      expect(service.toJson()['breachesDismissed'], ['Adobe']);
      expect(service.copyWith(note: 'edited').toJson()['breachesDismissed'], ['Adobe']);
    });

    test('marks and unmarks a breach dealt with, leaving the key out when there is none', () {
      const service = BackupService(id: 's', serviceName: 'Adobe', codes: [], addedAt: 1);
      final before = jsonEncode(service.toJson());

      final marked = service.copyWith(breachesDismissed: ['Adobe']);

      expect(marked.breachesDismissed, ['Adobe']);
      expect(marked.extra, isEmpty);
      expect(jsonEncode(marked.toJson()), endsWith(',"addedAt":1,"breachesDismissed":["Adobe"]}'));
      expect(jsonEncode(marked.copyWith(breachesDismissed: unset).toJson()), before);
      expect(BackupService.fromJson(marked.toJson()), marked);
    });

    test('marks a code used and unused', () {
      const code = BackupCode(code: '1234');

      final used = code.copyWith(used: true, usedAt: 9);

      expect(used.toJson(), {'code': '1234', 'used': true, 'usedAt': 9});
      expect(used.copyWith(used: false, usedAt: unset).toJson(), {'code': '1234', 'used': false});
    });

    test('never prints its codes or its note', () {
      const service = BackupService(
        id: 's',
        serviceName: 'GitHub',
        codes: [
          BackupCode(code: 'aaaa-1111'),
          BackupCode(code: 'bbbb-2222', used: true),
        ],
        note: 'recovery email hunter2',
        addedAt: 1,
      );

      expect(
        '$service ${service.codes}',
        allOf(contains('GitHub'), isNot(contains('aaaa-1111')), isNot(contains('bbbb-2222')), isNot(contains('hunter2'))),
      );
    });
  });
}
