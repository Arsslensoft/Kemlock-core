@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../../compat/before_key_accounts/sync_merge.dart' as before_key_accounts;
import '../../compat/before_logins/sync_merge.dart' as before_logins;

const now = 1_800_000_000_000;

const _mail = Login(
  id: 'l1',
  name: 'Larkspur Mail',
  username: 'ada@example.org',
  password: 'hunter2',
  websites: ['larkspur.example'],
  addedAt: 9,
);

const _tombstoneOfALogin = {'id': 'l-gone', 'at': 1_799_999_800_000};

OtpAccount _account(String id) => OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: 100);

/// A sync file a version with logins wrote: an account, a login, and a login's deletion.
Map<String, Object?> _file({List<Login> logins = const [_mail]}) => jsonDecode(
  jsonEncode({
    'accounts': [_account('a1').toJson()],
    'backupServices': <Object?>[],
    'deleted': [_tombstoneOfALogin],
    'logins': [for (final login in logins) login.toJson()],
  }),
) as Map<String, Object?>;

List<String> _ids(Object? list) => [for (final entry in list! as List<Object?>) (entry! as Map<String, Object?>)['id']! as String];

// openspec: add-passwords, task 7.2
void main() {
  // What a phone that stays on the version from before logins does, with that version's own merge code
  group('a phone from before logins', () {
    test('keeps the logins list in the extra keys of SyncDoc, and writes the file back as it was', () {
      final doc = before_logins.SyncDoc.fromJson(_file());

      expect(doc.extra['logins'], _file()['logins']);
      expect(before_logins.canonical(doc.toJson()), before_logins.canonical(_file()));
    });

    test('writes them back unchanged, with their deletion, when it merges', () {
      final remote = before_logins.SyncDoc.fromJson(_file());

      final merged = before_logins.mergeScope(before_logins.Lists(accounts: [_account('a1'), _account('a2')]), ['a1'], remote, now: now);

      final written = jsonDecode(jsonEncode(merged.doc.toJson())) as Map<String, Object?>;
      expect(written['logins'], _file()['logins']);
      expect(written['deleted'], [_tombstoneOfALogin]);
      expect(_ids(written['accounts']), ['a1', 'a2']);
      expect(merged.known, isNot(contains('l1')), reason: 'it never counts them as entries it holds, so never as ones it deleted');
    });

    test('from before accounts on a security key, too', () {
      final remote = before_key_accounts.SyncDoc.fromJson(_file());

      final merged = before_key_accounts.mergeScope(before_key_accounts.Lists(accounts: [_account('a1')]), ['a1'], remote, now: now);

      final written = jsonDecode(jsonEncode(merged.doc.toJson())) as Map<String, Object?>;
      expect(written['logins'], _file()['logins']);
      expect(written['deleted'], [_tombstoneOfALogin]);
    });
  });

  group('this version', () {
    test('reads the logins, and writes the file back as it was', () {
      final doc = SyncDoc.fromJson(_file());

      expect(doc.logins.single.password, 'hunter2');
      expect(doc.extra, isEmpty);
      expect(canonical(doc.toJson()), canonical(_file()));
    });

    test('writes a file without logins as it always was', () {
      expect(SyncDoc(accounts: [_account('a1')]).toJson().keys, ['accounts', 'backupServices', 'deleted']);
    });

    test('takes them as entries it holds, the later copy winning', () {
      final remote = SyncDoc.fromJson(_file());
      final edited = _mail.copyWith(username: 'ada@larkspur.example', updatedAt: 50);

      final merged = mergeScope(
        Lists(accounts: [_account('a1')], logins: [edited]),
        ['a1', 'l1'],
        remote,
        now: now,
      );

      expect(merged.known..sort(), ['a1', 'l1']);
      expect(merged.doc.logins.single.username, 'ada@larkspur.example');
      // The other phone's newer copy wins in turn
      final theirs = SyncDoc(logins: [edited.copyWith(name: 'Mail', updatedAt: 60)]);
      expect(mergeScope(Lists(logins: [edited]), ['l1'], theirs, now: now).doc.logins.single.name, 'Mail');
    });

    test('drops a login deleted on another phone, and writes down one deleted here', () {
      final deletedThere = SyncDoc(
        deleted: [Tombstone(id: 'l1', at: now - 1000)],
      );
      expect(mergeScope(const Lists(logins: [_mail]), ['l1'], deletedThere, now: now).doc.logins, isEmpty);

      final deletedHere = mergeScope(const Lists(), ['l1'], SyncDoc.fromJson(_file()), now: now);
      expect(deletedHere.doc.logins, isEmpty);
      expect([for (final tomb in deletedHere.doc.deleted) tomb.id], containsAll(['l1', 'l-gone']));
    });

    test('syncs a space’s logins in its own document, and puts them back there', () {
      final shared = _mail.copyWith(id: 'l2', spaceId: 's1');
      final lists = Lists(accounts: [_account('a1')], logins: [_mail, shared]);

      expect(scopeLists(lists, null).logins.map((login) => login.id), ['l1']);
      expect(scopeLists(lists, 's1').logins.map((login) => login.id), ['l2']);

      final fromSpace = SyncDoc(logins: [shared.copyWith(password: 'changed', updatedAt: 70)]);
      final applied = applyScope(lists, 's1', fromSpace);
      expect(applied.logins.map((login) => (login.id, login.password)), [('l1', 'hunter2'), ('l2', 'changed')]);
      expect(sameDoc(SyncDoc(logins: [_mail, shared]), SyncDoc(logins: [shared, _mail])), isTrue);
    });
  });

  // openspec: add-passwords, task 7.3
  group('a sync never loses a password', () {
    const minute = 60 * 1000;
    final phoneA = _mail.withPassword('one', now).copyWith(updatedAt: now);
    final phoneB = _mail.withPassword('two', now + minute).copyWith(updatedAt: now + minute);

    test('when two phones change one password, both keep the later one and the other among the previous', () {
      // A syncs first, then B merges A's copy, then A takes B's
      final first = mergeScope(
        Lists(logins: [phoneA]),
        ['l1'],
        SyncDoc(logins: [_mail]),
        now: now + 2 * minute,
      ).doc;
      final onB = mergeScope(Lists(logins: [phoneB]), ['l1'], first, now: now + 3 * minute).doc;
      final onA = mergeScope(Lists(logins: [phoneA]), ['l1'], onB, now: now + 4 * minute).doc;

      for (final doc in [onB, onA]) {
        final login = doc.logins.single;
        expect(login.password, 'two');
        expect(login.previousPasswords!.map((p) => (p.password, p.until)), [('hunter2', now + minute), ('one', now)]);
        expect(login.changedAt, now + minute, reason: 'the winner keeps its own change time');
      }
      expect(sameDoc(onA, onB), isTrue);
    });

    test('merging again changes nothing', () {
      final merged = mergeScope(
        Lists(logins: [phoneB]),
        ['l1'],
        SyncDoc(logins: [phoneA]),
        now: now,
      ).doc;

      final again = mergeScope(
        Lists(logins: merged.logins),
        ['l1'],
        SyncDoc(logins: [phoneA]),
        now: now,
      ).doc;
      final twice = mergeScope(Lists(logins: again.logins), ['l1'], merged, now: now).doc;

      expect(sameDoc(again, merged), isTrue);
      expect(sameDoc(twice, merged), isTrue);
    });

    test('adds nothing when the losing password is the winner’s or one it keeps', () {
      final same = phoneA.copyWith(name: 'Mail', updatedAt: now + 2 * minute);
      expect(
        mergeScope(
          Lists(logins: [same]),
          ['l1'],
          SyncDoc(logins: [phoneA]),
          now: now,
        ).doc.logins.single.previousPasswords,
        phoneA.previousPasswords,
      );

      // B's copy already holds A's old password among its previous ones
      final older = _mail.copyWith(updatedAt: 5);
      expect(
        mergeScope(
          Lists(logins: [phoneB]),
          ['l1'],
          SyncDoc(logins: [older]),
          now: now,
        ).doc.logins.single.previousPasswords,
        phoneB.previousPasswords,
      );
    });

    test('keeps the five most recent', () {
      var many = _mail;
      for (var i = 1; i <= 5; i++) {
        many = many.withPassword('p$i', now + i);
      }
      many = many.copyWith(updatedAt: now + 10);
      final lost = _mail.copyWith(password: 'lost', updatedAt: now + 9);

      final login = mergeScope(
        Lists(logins: [many]),
        ['l1'],
        SyncDoc(logins: [lost]),
        now: now,
      ).doc.logins.single;

      expect(login.previousPasswords, hasLength(previousPasswordsKept));
      expect(login.previousPasswords!.first.password, 'lost');
    });
  });
}
