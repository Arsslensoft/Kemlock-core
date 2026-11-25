@TestOn('vm')
library;

import 'package:kemlock_core/features/backup/coverage.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

OtpAccount acct(String id, String issuer, {String label = 'me@example.com', bool? noBackupCodes}) =>
    OtpAccount(id: id, issuer: issuer, label: label, secret: 'S', noBackupCodes: noBackupCodes, addedAt: 1);

BackupService svc(String serviceName) => BackupService(
  id: serviceName,
  serviceName: serviceName,
  codes: const [BackupCode(code: '1234-5678')],
  addedAt: 1,
);

void main() {
  // The sameService cases of coverage.test.ts are in ../accounts/service_names_test.dart.
  group('coverage', () {
    test('finds each account’s backup codes by service name', () {
      final services = [svc('GitHub'), svc('dropbox.com')];
      expect(backupFor(acct('1', 'GitHub, Inc.'), services)?.serviceName, 'GitHub');
      expect(backupFor(acct('2', 'Dropbox'), services)?.serviceName, 'dropbox.com');
      expect(backupFor(acct('3', 'Steam'), services), isNull);
    });

    test('reads the service from the label when there is no issuer', () {
      final account = acct('1', '', label: 'Discord:me');
      expect(serviceOf(account), 'Discord');
      expect(backupFor(account, [svc('Discord')]), isNotNull);
    });

    test('lists the accounts without codes, A–Z, skipping those marked as offering none', () {
      final accounts = [acct('1', 'Steam'), acct('2', 'GitHub'), acct('3', 'amazon'), acct('4', 'Bank', noBackupCodes: true)];

      final result = coverage(accounts, [svc('GitHub')]);

      expect(result.total, 3);
      expect(result.covered, 1);
      expect(result.missing.map((a) => a.issuer), ['amazon', 'Steam']);
    });

    test('sorts ignoring case and accents, keeping names that compare equal in their order', () {
      // The order localeCompare(…, { sensitivity: 'base' }) gives these names.
      final names = ['Zoom', 'école', 'Ecole', 'apple', 'Apple', 'Éclair', 'eBay', '1Password', 'Ünicode', 'banana'];

      final result = coverage([for (final (i, name) in names.indexed) acct('$i', name)], []);

      expect(result.missing.map((a) => a.issuer), [
        '1Password',
        'apple',
        'Apple',
        'banana',
        'eBay',
        'Éclair',
        'école',
        'Ecole',
        'Ünicode',
        'Zoom',
      ]);
    });

    test('has no service for an account with neither issuer nor label', () {
      expect(backupFor(acct('1', '  ', label: ' '), [svc('GitHub')]), isNull);
    });
  });
}
