@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/features/import/formats/google_migration.dart';
import 'package:kemlock_core/features/import/import_file.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/vault/export_archive.dart';
import 'package:kemlock_core/vault/qr_transfer.dart';
import 'package:test/test.dart';

import '../../vault/fast_kdf.dart';

Uint8List _fixture(String name) => File('test/fixtures/$name').readAsBytesSync();

String _text(String name) => utf8.decode(_fixture(name));

OtpAccount _account(String id, String issuer, {String secret = 'JBSWY3DPEHPK3PXP'}) =>
    OtpAccount(id: id, issuer: issuer, label: 'me@example.com', secret: secret, addedAt: 1);

Matcher _problem(ImportProblem problem) => throwsA(isA<ImportReadError>().having((e) => e.problem, 'problem', problem));

void main() {
  group('openImportFile', () {
    test('reads the bytes as text, without a byte order mark', () {
      final opened = openImportFile(Uint8List.fromList([0xEF, 0xBB, 0xBF, ...utf8.encode('{"a": 1}')]));

      expect(opened.text, '{"a": 1}');
      expect(opened.archive, isNull);
    });

    test("takes the export out of an archive, and keeps the archive's files at hand", () {
      final opened = openImportFile(_fixture('vault-items/export-archive.zip'));

      expect(opened.archive, isNotNull);
      expect(opened.archive!.files, isNotEmpty);
      expect(opened.text, _text('vault-items/export-encrypted.json'));
    });

    test('refuses a damaged archive with one problem', () {
      expect(() => openImportFile(Uint8List.fromList([0x50, 0x4b, 0x03, 0x04, 1, 2, 3])), _problem(ImportProblem.archive));
    });
  });

  group('detectImport', () {
    test('tells Kemlock exports, plain and encrypted', () {
      final plain = detectImport(_text('vault-items/export-plain.json'))!;
      final sealed = detectImport(_text('vault-items/export-encrypted.json'))!;

      expect((plain.foreign, plain.encrypted), (false, false));
      expect((sealed.foreign, sealed.encrypted), (false, true));
    });

    test("tells another app's file from its content", () {
      expect(detectImport('otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example')!.source, ImportSource.uris);
      expect(detectImport('name,url,username,password\nGitHub,https://github.com,me,pw\n')!.source, ImportSource.csv);
      final cxf = detectImport(_text('import/cxf/fido-example.json'))!;
      expect(cxf.source, ImportSource.cxf);
      expect(cxf.exporter, isNotNull);
    });

    test('says nothing of what it does not read', () {
      expect(detectImport('hello'), isNull);
      expect(detectImport('{"a": 1}'), isNull);
    });

    test("drops another app's format from an archive, which holds a Kemlock export or nothing", () {
      expect(detectImport('otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP', archive: true), isNull);
      expect(detectImport(_text('vault-items/export-plain.json'), archive: true), isNotNull);
    });
  });

  group('readImport', () {
    test('opens a plain Kemlock export with every kind it holds', () async {
      final text = _text('vault-items/export-plain.json');

      final preview = await readImport(text, detectImport(text)!);

      expect(preview.accounts, hasLength(1));
      expect(preview.backupServices, hasLength(1));
      expect(preview.keys, hasLength(1));
      expect(preview.notes, hasLength(1));
      expect(preview.passkeys, hasLength(1));
    });

    test('opens an encrypted export with its password, and says a wrong one is wrong', () async {
      final text = _text('vault-items/export-encrypted.json');
      final detected = detectImport(text)!;

      final preview = await readImport(text, detected, password: 'fixture password');

      expect(preview.accounts, hasLength(1));
      expect(preview.notes, hasLength(1));
      await expectLater(readImport(text, detected, password: 'another password'), _problem(ImportProblem.badPassword));
      await expectLater(readImport(text, detected), _problem(ImportProblem.badPassword));
    });

    test('derives the key with the function it is given', () async {
      // The fixture was sealed with the real parameters, so another derivation gives another key
      final text = _text('vault-items/export-encrypted.json');
      final detected = detectImport(text)!;

      await expectLater(readImport(text, detected, password: 'fixture password', deriveKey: fastKdf), _problem(ImportProblem.badPassword));
    });

    test("gives another app's accounts new ids and the time they were added", () async {
      const text =
          'otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example\n'
          'otpauth://hotp/Bank:me?secret=JBSWY3DPEHPK3PXP&counter=4';
      var next = 0;

      final preview = await readImport(text, detectImport(text)!, newId: () => 'id-${next++}', now: 1234);

      expect([for (final account in preview.accounts) account.id], ['id-0', 'id-1']);
      expect({for (final account in preview.accounts) account.addedAt}, {1234});
      expect(preview.backupServices, isEmpty);
    });

    test('reads a Google Authenticator transfer code made by buildGoogleMigration', () async {
      final made = buildGoogleMigration([_account('a', 'Example'), _account('b', 'Bank')]);
      final text = made.uris.join('\n');

      final preview = await readImport(text, detectImport(text)!, now: 5);

      expect(preview.accounts.map((a) => a.issuer), ['Example', 'Bank']);
    });

    test('reads a Credential Exchange file with its logins, and gives it a preview that names its places', () async {
      final text = _text('import/cxf/fido-example.json');

      final preview = await readImport(text, detectImport(text)!, now: 1);

      expect(preview.logins, isNotEmpty);
    });

    test('reads a CSV of logins and keeps its ids', () async {
      const text = 'name,url,username,password\nGitHub,https://github.com,me,hunter2\n';

      final preview = await readImport(text, detectImport(text)!, now: 9);

      expect(preview.logins.single.name, 'GitHub');
      expect(preview.logins.single.addedAt, 9);
      expect(preview.accounts, isEmpty);
    });

    test('says an empty file is empty, and a file of nothing known is unsupported', () async {
      const empty = '{"encrypted": false, "items": []}';
      const detected = DetectedImport(ImportSource.uris, encrypted: false);

      await expectLater(readImport(empty, detectImport(empty)!), _problem(ImportProblem.empty));
      await expectLater(readImport('hello', detected), _problem(ImportProblem.unsupported));
    });
  });

  group('QR codes', () {
    final accounts = [_account('a', 'Example')];
    final services = [BackupService(id: 's', serviceName: 'Example', codes: [BackupCode(code: 'abcd-1234')], addedAt: 1)];

    test("links and Google transfer codes are another app's accounts", () async {
      expect(detectQr(['otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP']), QrKind.links);
      expect(detectQr(buildGoogleMigration(accounts).uris), QrKind.links);
      expect(detectQr(['hello']), QrKind.none);

      final links = ['otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP', 'otpauth://totp/Bank:me?secret=JBSWY3DPEHPK3PXP'];
      final preview = await readQrImport(links, now: 2);

      expect(preview.accounts, hasLength(2));
    });

    test('a plain Kemlock transfer comes back with its backup codes', () async {
      final chunks = exportVaultQrPlaintext(accounts, services);

      expect(detectQr(chunks), QrKind.transferPlain);
      final preview = await readQrImport(chunks, now: 3);

      expect(preview.accounts.single.secret, 'JBSWY3DPEHPK3PXP');
      expect(preview.backupServices.single.serviceName, 'Example');
    });

    test('an encrypted Kemlock transfer needs its password', () async {
      final chunks = await exportVaultQr(accounts, services, 'transfer password');

      expect(detectQr(chunks), QrKind.transfer);
      final preview = await readQrImport(chunks, password: 'transfer password');

      expect(preview.accounts.single.issuer, 'Example');
      await expectLater(readQrImport(chunks, password: 'wrong'), _problem(ImportProblem.badPassword));
    });

    test('a transfer with a code missing says so', () async {
      await expectLater(readQrImport(['BMCP:01/02:AAAA']), _problem(ImportProblem.qrMissing));
    });

    test('nothing else is read', () async {
      await expectLater(readQrImport(['hello']), _problem(ImportProblem.unsupported));
    });
  });

  test('an archive of the export folds back into one the reader opens', () async {
    final bytes = await buildExportArchive(exportJson: _text('vault-items/export-plain.json'), files: const []);
    final opened = openImportFile(bytes);

    expect(opened.archive, isNotNull);
    expect(detectImport(opened.text, archive: true)!.foreign, isFalse);
  });
}
