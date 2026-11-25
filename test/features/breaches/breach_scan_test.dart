@TestOn('vm')
library;

import 'package:kemlock_core/features/breaches/breach_list.dart';
import 'package:kemlock_core/features/breaches/breach_scan.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import 'breach_list_test.dart' show hibpFixture;

/// Epoch ms of midnight UTC on a day.
int day(int year, int month, int d) => DateTime.utc(year, month, d).millisecondsSinceEpoch;

OtpAccount account(String id, String issuer, {int? addedAt, List<String>? dismissed, String? spaceId}) => OtpAccount(
  id: id,
  issuer: issuer,
  label: 'me@example.com',
  secret: 'JBSWY3DPEHPK3PXP',
  addedAt: addedAt ?? day(2020, 1, 1),
  breachesDismissed: dismissed,
  spaceId: spaceId,
);

BackupService codes(String id, String name, {int? addedAt, List<String>? dismissed}) =>
    BackupService(id: id, serviceName: name, codes: const [], addedAt: addedAt ?? day(2020, 1, 1), breachesDismissed: dismissed);

List<String> names(Iterable<Breach> breaches) => [for (final breach in breaches) breach.name];

void main() {
  // Trello was listed on 2024-01-22, Twitter on 2022-08-13 and 2023-01-05, Adobe on 2013-12-04
  final list = BreachList.fromHibp(hibpFixture(), updated: '2026-11-15');

  BreachFindings scan({List<OtpAccount> accounts = const [], List<BackupService> services = const []}) =>
      scanBreaches(accounts, services, list);

  test('a breach listed after the account was added is new', () {
    final found = scan(accounts: [account('a', 'Trello', addedAt: day(2023, 3, 1))]);

    expect(names(found.of('a').fresh), ['Trello']);
    expect(found.of('a').earlier, isEmpty);
    expect(found.serviceCount, 1);
    expect(found.alerts.single.accounts.single.id, 'a');
  });

  test('a breach listed before the account was added is an earlier one', () {
    final found = scan(accounts: [account('a', 'Adobe', addedAt: day(2026, 11, 15))]);

    expect(found.of('a').fresh, isEmpty);
    expect(names(found.of('a').earlier), ['Adobe']);
    expect(found.serviceCount, 0);
    expect(found.alerts, isEmpty);
  });

  test('an account added on the day a breach was listed has it as new', () {
    expect(names(scan(accounts: [account('a', 'Trello', addedAt: day(2024, 1, 22) + 3600000)]).of('a').fresh), ['Trello']);
    expect(scan(accounts: [account('a', 'Trello', addedAt: day(2024, 1, 23))]).of('a').fresh, isEmpty);
  });

  test('an import today has nothing new, whatever the services', () {
    final today = day(2026, 11, 15);

    final found = scan(
      accounts: [
        for (final (i, issuer) in ['Adobe', 'Dropbox', 'LinkedIn', 'Twitter', 'Trello', 'Canva'].indexed)
          account('a$i', issuer, addedAt: today),
      ],
    );

    expect(found.serviceCount, 0);
    expect(names(found.of('a3').earlier), ['Twitter200M', 'Twitter']);
  });

  test('an account without an added date has every breach as new', () {
    expect(names(scan(accounts: [account('a', 'Adobe', addedAt: 0)]).of('a').fresh), ['Adobe']);
  });

  test('a breach marked dealt with is an earlier one', () {
    final found = scan(
      accounts: [
        account('a', 'Trello', dismissed: ['Trello']),
      ],
    );

    expect(found.of('a').fresh, isEmpty);
    expect(names(found.of('a').earlier), ['Trello']);
    expect(found.serviceCount, 0);
  });

  test('another breach of a service with one dealt with is still new', () {
    final found = scan(
      accounts: [
        account('a', 'Twitter', dismissed: ['Twitter']),
      ],
    );

    expect(names(found.of('a').fresh), ['Twitter200M']);
    expect(names(found.of('a').earlier), ['Twitter']);
  });

  test('two breaches of one service are both found, the latest first, and count as one service', () {
    final found = scan(accounts: [account('a', 'twitter.com')]);

    expect(names(found.of('a').fresh), ['Twitter200M', 'Twitter']);
    expect(names([for (final alert in found.alerts) alert.breach]), ['Twitter200M', 'Twitter']);
    expect(found.serviceCount, 1);
  });

  test('an account in a shared space is checked like the vault\'s own', () {
    expect(names(scan(accounts: [account('a', 'Trello', spaceId: 'space-1')]).of('a').fresh), ['Trello']);
  });

  test('a service that is in no breach has nothing', () {
    final found = scan(accounts: [account('a', 'GitHub')], services: [codes('s', 'GitHub')]);

    expect(found.of('a').isEmpty, isTrue);
    expect(found.of('s').isEmpty, isTrue);
    expect(found.of('unknown').isEmpty, isTrue);
  });

  test('two accounts and a backup-code list of one service count once, another service once more', () {
    final found = scan(
      accounts: [account('a1', 'Trello'), account('a2', 'Trello Inc.'), account('a3', 'Duolingo')],
      services: [codes('s1', 'trello.com')],
    );

    expect(found.serviceCount, 2);
    final trello = found.alerts.singleWhere((alert) => alert.breach.name == 'Trello');
    expect([for (final a in trello.accounts) a.id], ['a1', 'a2']);
    expect(trello.services.single.id, 's1');
    expect(names(found.of('s1').fresh), ['Trello']);
  });

  test('a backup-code list has its own date and its own dealt-with breaches', () {
    final found = scan(
      accounts: [
        account('a', 'Trello', dismissed: ['Trello']),
      ],
      services: [
        codes('s', 'Trello'),
        codes('late', 'Trello', addedAt: day(2025, 1, 1)),
      ],
    );

    expect(found.of('a').fresh, isEmpty);
    expect(names(found.of('s').fresh), ['Trello']);
    expect(found.of('late').fresh, isEmpty);
    expect(found.serviceCount, 1);
  });

  test('new breaches come the latest listed first', () {
    final found = scan(accounts: [account('a', 'Adobe', addedAt: 0), account('b', 'Trello'), account('c', 'Duolingo')]);

    expect(names([for (final alert in found.alerts) alert.breach]), ['Trello', 'Duolingo', 'Adobe']);
  });

  test('nothing is found in an empty list', () {
    expect(scanBreaches([account('a', 'Adobe', addedAt: 0)], const [], BreachList.empty).alerts, isEmpty);
    expect(BreachFindings.none.of('a').isEmpty, isTrue);
  });
}
