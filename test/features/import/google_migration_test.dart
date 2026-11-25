@TestOn('vm')
library;

import 'package:kemlock_core/features/import/formats/google_migration.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

OtpAccount _code(
  String issuer,
  String label, {
  String secret = 'JBSWY3DPEHPK3PXP',
  OtpType type = OtpType.totp,
  String algorithm = 'SHA1',
  int digits = 6,
  int period = 30,
  int? counter,
}) => OtpAccount(
  id: issuer + label,
  type: type,
  issuer: issuer,
  label: label,
  secret: secret,
  algorithm: algorithm,
  digits: digits,
  period: period,
  counter: counter,
  addedAt: 1,
);

void main() {
  test('what it writes parseGoogleMigration reads back, code for code', () {
    final codes = [
      _code('Example', 'me@example.com'),
      _code('Bank', 'me', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA256', digits: 8),
      _code('Counter', 'me', type: OtpType.hotp, counter: 41, algorithm: 'SHA512'),
      _code('', 'only a label'),
    ];

    final made = buildGoogleMigration(codes);

    expect(made.uris, hasLength(1));
    expect(made.exported, 4);
    expect(made.leftOut, isEmpty);
    final read = parseGoogleMigration(made.uris.single)!;
    expect(read.accounts, hasLength(4));
    for (final (i, account) in read.accounts.indexed) {
      final from = codes[i];
      expect(
        (account.kind, account.issuer, account.label, account.secret, account.algorithm, account.digits, account.counter),
        (from.kind, from.issuer, from.label, from.secret, from.algorithm, from.digits, from.counter),
        reason: from.id,
      );
    }
  });

  test('is a URI the way Google writes one, with its data encoded', () {
    final uri = buildGoogleMigration([_code('Example', 'me')]).uris.single;

    expect(uri, startsWith('otpauth-migration://offline?data='));
    expect(uri.substring(uri.indexOf('data=') + 5), isNot(contains('+')));
    expect(uri.contains('/', 'otpauth-migration://offline?data='.length), isFalse);
  });

  test('splits a long list into batches that each read back, in order', () {
    final codes = [for (var i = 0; i < 25; i++) _code('Service $i', 'user$i@example.com')];

    final made = buildGoogleMigration(codes, batchId: 7);

    expect(made.uris, hasLength(3));
    final issuers = [
      for (final uri in made.uris) ...parseGoogleMigration(uri)!.accounts.map((account) => account.issuer),
    ];
    expect(issuers, [for (var i = 0; i < 25; i++) 'Service $i']);
  });

  test('leaves out what the format cannot say, and lists it', () {
    final made = buildGoogleMigration([
      _code('Steam', 'me', type: OtpType.steam),
      _code('Slow', 'me', period: 60),
      _code('Seven', 'me', digits: 7),
      _code('Odd', 'me', algorithm: 'SHA224'),
      _code('Bad', 'me', secret: '!!!'),
      _code('Fine', 'me'),
    ]);

    expect(made.exported, 1);
    expect(made.leftOut.map((one) => (one.title, one.reason)), [
      ('Steam', MigrationLeftOutReason.steam),
      ('Slow', MigrationLeftOutReason.period),
      ('Seven', MigrationLeftOutReason.digits),
      ('Odd', MigrationLeftOutReason.algorithm),
      ('Bad', MigrationLeftOutReason.secret),
    ]);
    expect(parseGoogleMigration(made.uris.single)!.accounts.single.issuer, 'Fine');
  });

  test('makes no code for nothing', () {
    final made = buildGoogleMigration(const []);

    expect(made.uris, isEmpty);
    expect(made.exported, 0);
  });
}
