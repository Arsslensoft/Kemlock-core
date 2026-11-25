@TestOn('vm')
library;

import 'package:kemlock_core/core/public_suffix_list.dart';
import 'package:kemlock_core/features/duplicates/duplicate_sites.dart';
import 'package:kemlock_core/features/import/import_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:test/test.dart';

import '../keys/pgp_kit.dart';

OtpAccount _account(String id, String issuer, String secret) => OtpAccount(id: id, issuer: issuer, label: 'me', secret: secret, addedAt: 0);

OtpAccount _hotp(String id, int counter) =>
    OtpAccount(id: id, type: OtpType.hotp, issuer: 'Bank', label: 'me', secret: 'JBSWY3DPEHPK3PXP', counter: counter, addedAt: 0);

BackupService _service(String id, String name, [List<String> codes = const []]) => BackupService(
  id: id,
  serviceName: name,
  codes: [for (final code in codes) BackupCode(code: code)],
  addedAt: 0,
);

Passkey _passkey(String id, String rpId, String credentialId) =>
    Passkey(id: id, credentialId: credentialId, rpId: rpId, userHandle: 'h', userName: 'u', privateKey: 'k', addedAt: 0);

void main() {
  final gitlab = _account('1', 'GitLab', 'AAAA');
  final github = _account('2', 'GitHub', 'BBBB');
  final gitlabAgain = _account('3', 'GitLab', 'AAAA');
  final gitlabOther = _account('4', 'GitLab', 'CCCC');
  final codes = _service('s1', 'GitLab', ['aaaa-bbbb', 'cccc-dddd']);

  test('merging adds the accounts whose secret isn’t in the vault, after the vault’s own', () {
    final preview = ImportPreview(
      accounts: [gitlabAgain, github, gitlabOther],
      backupServices: [
        _service('s2', 'GitLab', ['cccc-dddd', 'aaaa-bbbb']),
        _service('s3', 'Proton', ['pppp-qqqq']),
      ],
    );

    final merged = mergeImport(preview, accounts: [gitlab], services: [codes], mode: ImportMode.merge);

    expect(merged.accounts, [gitlab, github, gitlabOther]);
    expect(merged.backupServices.map((s) => s.id), ['s1', 's3']);
    expect(countImport(preview, accounts: [gitlab], services: [codes], mode: ImportMode.merge), (
      newAccounts: 2,
      duplicates: 1,
      newServices: 1,
    ));
  });

  test('merging adds a second list of codes for a service the vault holds, and skips one by id or by its codes', () {
    final preview = ImportPreview(
      accounts: const [],
      backupServices: [
        // The same codes under another name and id: the same list
        _service('s2', 'GitLab (old)', ['cccc-dddd', 'aaaa-bbbb']),
        // Other codes for the same service: its own list
        _service('s3', 'GitLab', ['xxxx-yyyy']),
        // The same id, other codes: the held list again
        _service('s1', 'GitLab', ['zzzz-zzzz']),
        // No codes at all matches nothing but its id
        _service('s4', 'Proton'),
      ],
    );

    final merged = mergeImport(preview, accounts: const [], services: [codes], mode: ImportMode.merge);

    expect(merged.backupServices.map((s) => s.id), ['s1', 's3', 's4']);
    expect(countImport(preview, accounts: const [], services: [codes], mode: ImportMode.merge).newServices, 2);
  });

  test('replacing takes the import whole, or keeps the vault’s backup services when asked', () {
    final preview = ImportPreview(accounts: [gitlabAgain], backupServices: const []);

    final replaced = mergeImport(preview, accounts: [gitlab, github], services: [codes], mode: ImportMode.replace);
    expect(replaced.accounts, [gitlabAgain]);
    expect(replaced.backupServices, isEmpty);
    expect(mergeImport(preview, accounts: [gitlab], services: [codes], mode: ImportMode.replace, keepServices: true).backupServices, [
      codes,
    ]);
    expect(countImport(preview, accounts: [gitlab], services: [codes], mode: ImportMode.replace), (
      newAccounts: 1,
      duplicates: 0,
      newServices: 0,
    ));
  });

  test('tells a duplicate by the secret alone, whatever its id, label, issuer or spacing', () {
    expect(isDuplicateAccount(gitlabAgain.copyWith(label: 'someone else'), [gitlab]), isTrue);
    expect(isDuplicateAccount(gitlabAgain.copyWith(issuer: 'gitlab.com'), [gitlab]), isTrue);
    expect(isDuplicateAccount(_account('5', 'Google', 'jbsw y3dp ehpk 3pxp'), [_account('6', 'google.com', 'JBSWY3DPEHPK3PXP')]), isTrue);
    expect(isDuplicateAccount(gitlabOther, [gitlab]), isFalse);
  });

  test('merging keeps one copy of a code held under another issuer name', () {
    final preview = ImportPreview(accounts: [_account('5', 'google.com', 'JBSWY3DPEHPK3PXP')], backupServices: const []);
    final held = _account('6', 'Google', 'JBSWY3DPEHPK3PXP');

    final merged = mergeImport(preview, accounts: [held], services: const [], mode: ImportMode.merge);

    expect(merged.accounts, [held]);
    expect(countImport(preview, accounts: [held], services: const [], mode: ImportMode.merge).duplicates, 1);
  });

  group('a held HOTP code', () {
    ImportPreview preview(int counter) => ImportPreview(accounts: [_hotp('import', counter)], backupServices: const []);

    test('takes a higher counter from the import and keeps everything else', () {
      final merged = mergeImport(preview(12), accounts: [_hotp('held', 9)], services: const [], mode: ImportMode.merge);

      expect(merged.accounts, [_hotp('held', 12)]);
    });

    test('keeps its own counter when the import’s is the same or lower', () {
      expect(mergeImport(preview(9), accounts: [_hotp('held', 9)], services: const [], mode: ImportMode.merge).accounts, [
        _hotp('held', 9),
      ]);
      expect(mergeImport(preview(3), accounts: [_hotp('held', 9)], services: const [], mode: ImportMode.merge).accounts, [
        _hotp('held', 9),
      ]);
    });

    test('is left alone by a time-based code with the same secret', () {
      final totp = ImportPreview(accounts: [_account('import', 'Bank', 'JBSWY3DPEHPK3PXP')], backupServices: const []);

      expect(mergeImport(totp, accounts: [_hotp('held', 9)], services: const [], mode: ImportMode.merge).accounts, [_hotp('held', 9)]);
    });
  });

  test('newKeys tells the PGP keys the vault holds by their fingerprint', () async {
    final before = await pgpVaultKey();
    final after = await pgpVaultKey(path: 'gnupg/editing/signing-subkey.after.secret.asc', id: 'k-after');
    final again = before.copyWith(id: 'k-again', name: 'Same key');
    final other = await pgpVaultKey(path: 'gnupg/editing/protected.secret.asc', id: 'k-other');
    final preview = ImportPreview(accounts: const [], backupServices: const [], keys: [again, after, other]);

    // The key GnuPG changed is the same key: it is combined with the held one, not added
    expect(newKeys(preview, [before]), [other]);
    expect(newKeys(preview, const []), [again, other]);
  });

  group('newPasskeys', () {
    final held = _passkey('p1', 'github.com', 'c1');

    test('skips a passkey with a held relying party and credential id, or a held id, and adds each other once', () {
      final preview = ImportPreview(
        accounts: const [],
        backupServices: const [],
        passkeys: [
          _passkey('x1', 'GitHub.com', 'c1'),
          _passkey('p1', 'gitlab.com', 'other'),
          _passkey('x2', 'github.com', 'c2'),
          _passkey('x3', 'github.com', 'c2'),
        ],
      );

      expect(newPasskeys(preview, [held]).map((p) => p.id), ['x2']);
    });

    test('adds a passkey whose credential id is held under another relying party', () {
      final preview = ImportPreview(accounts: const [], backupServices: const [], passkeys: [_passkey('x1', 'gitlab.com', 'c1')]);

      expect(newPasskeys(preview, [held]).map((p) => p.id), ['x1']);
    });
  });

  // openspec: add-passwords, task 7.5
  group('newLogins', () {
    const linkedToTheDuplicate = Login(id: 'l1', name: 'GitLab', password: 'p1', accountId: '3', addedAt: 0);
    const linkedToANewAccount = Login(id: 'l2', name: 'GitLab work', password: 'p2', accountId: '4', addedAt: 0);
    const unlinked = Login(id: 'l3', name: 'Bank', password: 'p3', addedAt: 0);
    final preview = ImportPreview(
      accounts: [gitlabAgain, gitlabOther],
      backupServices: const [],
      logins: const [linkedToTheDuplicate, linkedToANewAccount, unlinked],
    );

    test('links a login to the vault’s account when its own was a duplicate the merge skips', () {
      final logins = newLogins(preview, const [], accounts: [gitlab, github], mode: ImportMode.merge);

      expect(logins.map((login) => (login.id, login.accountId)), [('l1', '1'), ('l2', '4'), ('l3', null)]);
    });

    test('leaves the links as they are when replacing, as the imported accounts come in whole', () {
      final logins = newLogins(preview, const [], accounts: [gitlab, github], mode: ImportMode.replace);

      expect(logins.map((login) => login.accountId), ['3', '4', null]);
    });

    test('adds only the logins the vault doesn’t hold, by id', () {
      final held = linkedToANewAccount.copyWith(password: 'changed here');

      expect(newLogins(preview, [held], accounts: const [], mode: ImportMode.merge).map((login) => login.id), ['l1', 'l3']);
    });

    group('by credential', () {
      final sites = siteResolver(suffixes: PublicSuffixList.parse('example\ncom\n'));
      const held = Login(id: 'held', name: 'Larkspur', username: 'sam', password: 'hunter2', websites: ['larkspur.example'], addedAt: 0);

      List<String> added(List<Login> logins) => newLogins(
        ImportPreview(accounts: const [], backupServices: const [], logins: logins),
        const [held],
        accounts: const [],
        mode: ImportMode.merge,
        sites: sites,
      ).map((login) => login.id).toList();

      test('skips a new-id login with the same site, username and password, on another host of the site', () {
        const again = Login(
          id: 'new',
          name: 'Larkspur Mail',
          username: ' Sam',
          password: 'hunter2',
          websites: ['mail.larkspur.example'],
          addedAt: 0,
        );

        expect(added([again]), isEmpty);
      });

      test('adds one that matches in site and username only, for the cleaner to show', () {
        const other = Login(id: 'new', name: 'Larkspur', username: 'sam', password: 'another', websites: ['larkspur.example'], addedAt: 0);

        expect(added([other]), ['new']);
      });

      test('adds one with the same username and password on another site', () {
        const elsewhere = Login(
          id: 'new',
          name: 'Elsewhere',
          username: 'sam',
          password: 'hunter2',
          websites: ['elsewhere.example'],
          addedAt: 0,
        );

        expect(added([elsewhere]), ['new']);
      });
    });
  });
}
