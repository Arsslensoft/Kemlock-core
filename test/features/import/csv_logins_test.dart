@TestOn('vm')
library;

import 'package:kemlock_core/features/export/csv_export.dart';
import 'package:kemlock_core/features/import/formats/csv_logins.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

ForeignImport _read(String text) {
  var next = 0;
  return readLoginCsv(text, newId: () => 'id-${next++}', now: 100);
}

void main() {
  group('parseCsv', () {
    test('splits records and fields, with quoted commas, quotes and line breaks', () {
      final rows = parseCsv('a,b,c\r\n1,"x, y","say ""hi"""\r\n"two\nlines",,\r\n');

      expect(rows, [
        ['a', 'b', 'c'],
        ['1', 'x, y', 'say "hi"'],
        ['two\nlines', '', ''],
      ]);
    });

    test('drops a byte order mark and blank lines, and reads the last record without a line break', () {
      expect(parseCsv('\u{FEFF}a,b\n\n1,2'), [
        ['a', 'b'],
        ['1', '2'],
      ]);
    });

    test('reads a file the header of which is separated by semicolons or tabs', () {
      expect(parseCsv('a;b\n1;2'), [
        ['a', 'b'],
        ['1', '2'],
      ]);
      expect(parseCsv('a\tb\n1\t2'), [
        ['a', 'b'],
        ['1', '2'],
      ]);
    });
  });

  group('looksLikeLoginCsv', () {
    test('wants a password column and a site, a name or a user', () {
      expect(looksLikeLoginCsv('name,url,username,password\n'), isTrue);
      expect(looksLikeLoginCsv('url,username,password,httpRealm,formActionOrigin,guid,timeCreated\n'), isTrue);
      expect(looksLikeLoginCsv('Title,URL,Username,Password,Notes,OTPAuth\n'), isTrue);
      expect(looksLikeLoginCsv('name,url\nx,y\n'), isFalse);
      expect(looksLikeLoginCsv('password\nx\n'), isFalse);
    });

    test('is not fooled by JSON or a list of links', () {
      expect(looksLikeLoginCsv('{"name": "a", "password": "b"}'), isFalse);
      expect(looksLikeLoginCsv('otpauth://totp/a?secret=ABC,password'), isFalse);
    });
  });

  group('readLoginCsv', () {
    test("reads Chrome's export", () {
      final result = _read('name,url,username,password,note\nGitHub,https://github.com/login,me,hunter2,"a note"\n');

      final login = result.logins.single;
      expect((login.name, login.username, login.password, login.note), ('GitHub', 'me', 'hunter2', 'a note'));
      expect(login.websites, ['github.com']);
      expect(login.uris!.single.uri, 'https://github.com/login');
      expect((login.id, login.addedAt), ('id-0', 100));
      expect(result.source, ImportSource.csv);
      expect(result.skipped, 0);
    });

    test("reads Firefox's export, which has no name", () {
      final result = _read('url,username,password,httpRealm,formActionOrigin,guid\nhttps://example.org,me,pw,,,{abc}\n');

      expect(result.logins.single.name, 'example.org');
    });

    test("reads Bitwarden's, with several addresses, a folder, a favourite and a code, and keeps a note a note", () {
      final result = _read(
        'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n'
        'Work/Mail,1,login,Mail,,,0,"https://mail.example.com\nhttps://example.com",me,pw,JBSWY3DPEHPK3PXP\n'
        ',,note,Wifi,"the code",,0,,,,\n'
        ',,card,Visa,,,0,,,,\n',
      );

      final login = result.logins.single;
      expect(login.tags, ['Work / Mail']);
      expect(login.isPinned, isTrue);
      expect(login.websites, ['mail.example.com', 'example.com']);
      final code = result.accounts.single;
      expect(login.accountId, code.id);
      expect((code.secret, code.issuer, code.label), ('JBSWY3DPEHPK3PXP', 'Mail', 'me'));
      expect(result.notes.single.title, 'Wifi');
      expect(result.notes.single.text, 'the code');
      expect(result.skipped, 1);
    });

    test("reads LastPass's, whose secure notes are rows at http://sn", () {
      final result = _read('url,username,password,totp,extra,name,grouping,fav\nhttp://sn,,,,"secret text",Passport,Home,0\nhttps://a.com,u,p,,,A,,1\n');

      expect(result.notes.single.title, 'Passport');
      expect(result.notes.single.text, 'secret text');
      expect(result.logins.single.name, 'A');
      expect(result.logins.single.isPinned, isTrue);
    });

    test('keeps a login whose code cannot be read, and lists the code', () {
      final result = _read('name,url,username,password,totp\nA,https://a.com,u,p,not a secret!\n');

      expect(result.logins, hasLength(1));
      expect(result.accounts, isEmpty);
      expect(result.skips.single.reason, SkipReason.totpSecret);
    });

    test('counts rows with nothing in them as skipped, and refuses a file that is no CSV of logins', () {
      expect(_read('name,url,username,password\n,,,\nA,https://a.com,u,p\n').skipped, 1);
      expect(() => readLoginCsv('hello'), throwsA(isA<ImportError>().having((e) => e.code, 'code', ImportErrorCode.unsupported)));
    });

    test('an export of a header only holds nothing', () {
      expect(_read('name,url,username,password\n').holdsNothing, isTrue);
    });
  });

  group('detectFormat and parseForeignExport', () {
    test('find a CSV by its header', () async {
      const text = 'name,url,username,password\nA,https://a.com,u,p\n';

      expect(detectFormat(text), (source: ImportSource.csv, encrypted: false));
      final result = await parseForeignExport(text, newId: () => 'x', now: 1);
      expect(result.logins.single.name, 'A');
    });

    test('leave links and JSON to their own readers', () {
      expect(detectFormat('otpauth://totp/a?secret=JBSWY3DPEHPK3PXP')!.source, ImportSource.uris);
      expect(detectFormat('{"a": 1}'), isNull);
    });
  });

  group('exportLoginsCsv', () {
    final account = OtpAccount(id: 'c1', issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
    final login = Login(
      id: 'l1',
      name: 'Mail, "work"',
      username: 'me',
      password: 'p"w,\n',
      websites: const ['mail.example.com'],
      uris: const [WebsiteRule('https://mail.example.com'), WebsiteRule('https://example.com')],
      note: 'line one\nline two',
      tags: const ['Work / Mail'],
      pinned: true,
      accountId: 'c1',
      addedAt: 1,
    );

    test('quotes what needs it, writes the header Bitwarden does, and puts the linked code in login_totp', () {
      final text = exportLoginsCsv([login], [account]);

      final rows = parseCsv(text);
      expect(rows.first.join(','), loginCsvHeader);
      final row = rows[1];
      expect(row.sublist(0, 4), ['Work/Mail', '1', 'login', 'Mail, "work"']);
      expect(row[4], 'line one\nline two');
      expect(row[7], 'https://mail.example.com\nhttps://example.com');
      expect(row.sublist(8, 10), ['me', 'p"w,\n']);
      expect(row[10], startsWith('otpauth://totp/Mail:me'));
    });

    test('reads back as what it was made from', () {
      final text = exportLoginsCsv([login], [account], notes: [SecureNote(id: 'n1', title: 'Wifi', text: 'pw', addedAt: 1)]);

      final back = _read(text);

      final read = back.logins.single;
      expect((read.name, read.username, read.password, read.note), (login.name, login.username, login.password, login.note));
      expect(read.rules.map((rule) => rule.uri), ['https://mail.example.com', 'https://example.com']);
      expect(read.tags, ['Work / Mail']);
      expect(back.accounts.single.secret, 'JBSWY3DPEHPK3PXP');
      expect(back.notes.single.title, 'Wifi');
    });

    test('a login with no code has an empty field, and an HOTP code is not written', () {
      final hotp = OtpAccount(id: 'h', type: OtpType.hotp, issuer: 'Bank', label: 'me', secret: 'JBSWY3DPEHPK3PXP', counter: 3, addedAt: 1);
      final plain = Login(id: 'l2', name: 'Bank', username: 'me', accountId: 'h', addedAt: 1);

      final rows = parseCsv(exportLoginsCsv([plain], [hotp]));

      expect(rows[1][10], '');
    });
  });

  group('exportCodeLinks', () {
    test('writes one link a line, which the importer reads back', () async {
      final links = exportCodeLinks([
        OtpAccount(id: 'a', issuer: 'Example', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1),
        OtpAccount(id: 'b', issuer: 'Bank', label: 'me', secret: 'GEZDGNBVGY3TQOJQ', addedAt: 1),
      ]);

      expect(links.exported, 2);
      final back = await parseForeignExport(links.text);
      expect(back.accounts.map((a) => a.issuer), ['Example', 'Bank']);
    });

    test('is empty for no codes', () {
      expect(exportCodeLinks(const []).text, '');
    });
  });
}
