@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/accounts/otp.dart';
import 'package:kemlock_core/features/import/importers.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

// "12345678901234567890", the RFC 4226 / 6238 test secret
final rfcBytes = utf8.encode('12345678901234567890');
const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const secretB = 'JBSWY3DPEHPK3PXP';
const secretC = 'KRUGS4ZANFZSAYJAONSWG4TFOQ';

typedef Json = Map<String, Object?>;

Matcher throwsImportError(ImportErrorCode code) => throwsA(isA<ImportError>().having((e) => e.code, 'code', code));

/// A new account as the importers return it: no id yet, added at 0.
OtpAccount newAccount({
  OtpType type = OtpType.totp,
  required String issuer,
  required String label,
  required String secret,
  String algorithm = 'SHA1',
  int digits = 6,
  int period = 30,
  int? counter,
  String? note,
  bool? pinned,
  List<String>? tags,
}) => OtpAccount(
  id: '',
  type: type,
  issuer: issuer,
  label: label,
  secret: secret,
  algorithm: algorithm,
  digits: digits,
  period: period,
  counter: counter,
  note: note,
  pinned: pinned,
  tags: tags,
  addedAt: 0,
);

// ─── Google Authenticator fixtures ───────────────────────────────────────────

List<int> varint(int n) {
  final out = <int>[];
  for (; n > 0x7f; n ~/= 128) {
    out.add(n % 128 | 0x80);
  }
  return out..add(n);
}

/// One protobuf field: numbers as varints, strings and bytes length-delimited.
List<int> field(int no, Object value) {
  if (value is int) return [...varint(no * 8), ...varint(value)];
  final bytes = value is String ? utf8.encode(value) : value as List<int>;
  return [...varint(no * 8 + 2), ...varint(bytes.length), ...bytes];
}

class GoogleOtp {
  const GoogleOtp({this.secret, required this.name, this.issuer, this.algorithm, this.digits, this.type, this.counter});

  final List<int>? secret;
  final String name;
  final String? issuer;

  /// 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
  final int? algorithm;

  /// 0 unspecified, 1 six, 2 eight
  final int? digits;

  /// 0 unspecified, 1 HOTP, 2 TOTP
  final int? type;
  final int? counter;
}

/// A MigrationPayload as Google Authenticator writes it, base64-encoded.
String migrationData(List<GoogleOtp> otps, [List<int> extraFields = const []]) {
  final payload = [
    for (final otp in otps)
      ...field(1, [
        ...field(1, otp.secret ?? rfcBytes),
        ...field(2, otp.name),
        if (otp.issuer case final issuer? when issuer.isNotEmpty) ...field(3, issuer),
        ...field(4, otp.algorithm ?? 1),
        ...field(5, otp.digits ?? 1),
        ...field(6, otp.type ?? 2),
        if (otp.counter case final counter?) ...field(7, counter),
      ]),
    // version, batch_size, batch_index, batch_id
    ...field(2, 1),
    ...field(3, 1),
    ...field(4, 0),
    ...field(5, 1234567),
  ];
  return base64.encode([...payload, ...extraFields]);
}

String migrationUri(List<GoogleOtp> otps, [List<int> extraFields = const []]) =>
    'otpauth-migration://offline?data=${Uri.encodeComponent(migrationData(otps, extraFields))}';

// ─── Aegis fixtures ──────────────────────────────────────────────────────────

const aegisDb = <String, Object?>{
  'version': 3,
  'entries': [
    {
      'type': 'totp',
      'uuid': 'e1',
      'name': 'alice@example.com',
      'issuer': 'GitHub',
      'note': 'Work laptop',
      'favorite': true,
      'icon': null,
      'info': {'secret': rfcSecret, 'algo': 'SHA1', 'digits': 6, 'period': 30},
      'groups': ['g-work', 'g-dev'],
    },
    {
      'type': 'hotp',
      'uuid': 'e2',
      'name': 'bob',
      'issuer': 'Bank',
      'note': '',
      'favorite': false,
      'icon': null,
      'info': {'secret': secretB, 'algo': 'SHA256', 'digits': 8, 'counter': 7},
      'groups': <Object?>[],
    },
    {
      'type': 'steam',
      'uuid': 'e3',
      'name': 'gamer',
      'issuer': 'Steam',
      'note': '',
      'favorite': false,
      'icon': null,
      'info': {'secret': secretC, 'algo': 'SHA1', 'digits': 5, 'period': 30},
      'groups': ['g-deleted'],
    },
    {
      'type': 'totp',
      'uuid': 'e4',
      'name': 'carol',
      'issuer': 'Cloud',
      'note': '',
      'favorite': false,
      'icon': null,
      'info': {'secret': secretB, 'algo': 'SHA512', 'digits': 8, 'period': 60},
      'groups': <Object?>[],
    },
    // Unsupported: Yandex, mOTP, MD5, 7 digits, a secret that isn't base32
    {
      'type': 'yandex',
      'uuid': 'e5',
      'name': 'yan',
      'issuer': 'Yandex',
      'info': {'secret': secretB, 'algo': 'SHA256', 'digits': 8, 'period': 30, 'pin': '1234'},
    },
    {
      'type': 'motp',
      'uuid': 'e6',
      'name': 'mo',
      'issuer': 'mOTP',
      'info': {'secret': 'abcdef0123456789', 'algo': 'MD5', 'digits': 6, 'period': 10, 'pin': '1234'},
    },
    {
      'type': 'totp',
      'uuid': 'e7',
      'name': 'md5',
      'issuer': 'Old',
      'info': {'secret': secretB, 'algo': 'MD5', 'digits': 6, 'period': 30},
    },
    {
      'type': 'totp',
      'uuid': 'e8',
      'name': 'seven',
      'issuer': 'Odd',
      'info': {'secret': secretB, 'algo': 'SHA1', 'digits': 7, 'period': 30},
    },
    {
      'type': 'totp',
      'uuid': 'e9',
      'name': 'broken',
      'issuer': 'Broken',
      'info': {'secret': 'not base32!', 'algo': 'SHA1', 'digits': 6, 'period': 30},
    },
  ],
  'groups': [
    {'uuid': 'g-work', 'name': 'Work'},
    {'uuid': 'g-dev', 'name': 'Dev'},
  ],
};

final aegisPlain = jsonEncode({
  'version': 1,
  'header': {'slots': null, 'params': null},
  'db': aegisDb,
});

// ─── 2FAS fixtures ───────────────────────────────────────────────────────────

const twoFasServices = <Json>[
  {
    'name': 'GitHub',
    'secret': rfcSecret,
    'updatedAt': 1700000000000,
    'otp': {
      'label': 'GitHub:alice',
      'account': 'alice',
      'issuer': 'GitHub',
      'digits': 6,
      'period': 30,
      'algorithm': 'SHA1',
      'tokenType': 'TOTP',
      'source': 'Link',
    },
    'order': {'position': 1},
    'groupId': 'grp-work',
  },
  {
    'name': 'My bank',
    'secret': 'jbsw y3dp ehpk 3pxp',
    'otp': {'digits': 8, 'algorithm': 'SHA256', 'tokenType': 'HOTP', 'counter': 5},
    'order': {'position': 0},
  },
  {
    'name': 'Steam',
    'secret': secretC,
    'otp': {'account': 'gamer', 'issuer': 'Steam', 'digits': 5, 'tokenType': 'STEAM'},
    'order': {'position': 2},
  },
  {
    'name': 'Legacy',
    'secret': secretB,
    'otp': {'label': 'Legacy:dave', 'issuer': 'Legacy'},
    'order': {'position': 3},
    'groupId': 'grp-unknown',
  },
  {
    'name': 'Old',
    'secret': secretB,
    'otp': {'account': 'eve', 'algorithm': 'MD5', 'tokenType': 'TOTP'},
    'order': {'position': 4},
  },
];

String twoFasFile(List<Json> services, [Json extra = const {}]) => jsonEncode({
  'services': services,
  'groups': [
    {'id': 'grp-work', 'name': 'Work', 'isExpanded': true},
  ],
  'updatedAt': 1700000000000,
  'schemaVersion': 4,
  'appVersionCode': 5000000,
  'appVersionName': '5.0.0',
  'appOrigin': 'android',
  ...extra,
});

// ─── Bitwarden fixtures ──────────────────────────────────────────────────────

Json bitwardenLogin(String name, String? totp, [String? username, Json extra = const {}]) => {
  'id': 'id-$name',
  'organizationId': null,
  'folderId': null,
  'type': 1,
  'reprompt': 0,
  'name': name,
  'notes': null,
  'favorite': false,
  'login': {'uris': <Object?>[], 'username': username, 'password': 'hunter2', 'totp': totp},
  'collectionIds': null,
  ...extra,
};

final bitwarden = jsonEncode({
  'encrypted': false,
  'folders': [
    {'id': 'f-2fa', 'name': '2FA'},
  ],
  'items': [
    bitwardenLogin('GitHub', 'otpauth://totp/GitHub:alice?secret=$rfcSecret&issuer=GitHub', 'alice', {
      'folderId': 'f-2fa',
      'notes': 'Recovery codes are in the safe',
    }),
    bitwardenLogin('Example', 'otpauth://totp/bob?secret=$secretB&digits=8', 'bob'),
    bitwardenLogin('Steam', 'steam://$secretC', 'gamer'),
    bitwardenLogin('Forum', 'jbsw y3dp ehpk 3pxp', 'carol'),
    bitwardenLogin('No 2FA', null, 'dave'),
    {
      'id': 'note',
      'type': 2,
      'name': 'A secure note',
      'notes': 'hello',
      'secureNote': {'type': 0},
    },
    bitwardenLogin('Garbage', 'not-a-secret!'),
    bitwardenLogin('Seven digits', 'otpauth://totp/x?secret=$secretB&digits=7'),
  ],
});

// ─── Encrypted fixtures ──────────────────────────────────────────────────────

// Made by tool/fixtures/importers_encrypted.mjs as importers.test.ts makes
// them, with noble's scrypt and PBKDF2 and WebCrypto's AES-GCM: the vault
// above under 'correct horse' (and 'backup battery' in a backup slot), and
// the services above under 'staple'.
final encrypted = jsonDecode(File('test/fixtures/import/encrypted.json').readAsStringSync()) as Json;
final aegisEncrypted = encrypted['aegis']! as String;
final twoFasEncrypted = encrypted['twoFas']! as String;

// ─── Expected accounts ───────────────────────────────────────────────────────

final aegisAccounts = [
  newAccount(issuer: 'GitHub', label: 'alice@example.com', secret: rfcSecret, note: 'Work laptop', pinned: true, tags: ['Work', 'Dev']),
  newAccount(type: OtpType.hotp, issuer: 'Bank', label: 'bob', secret: secretB, algorithm: 'SHA256', digits: 8, counter: 7),
  newAccount(type: OtpType.steam, issuer: 'Steam', label: 'gamer', secret: secretC),
  newAccount(issuer: 'Cloud', label: 'carol', secret: secretB, algorithm: 'SHA512', digits: 8, period: 60),
];

final twoFasAccounts = [
  newAccount(type: OtpType.hotp, issuer: 'My bank', label: '', secret: secretB, algorithm: 'SHA256', digits: 8, counter: 5),
  newAccount(issuer: 'GitHub', label: 'alice', secret: rfcSecret, tags: ['Work']),
  newAccount(type: OtpType.steam, issuer: 'Steam', label: 'gamer', secret: secretC),
  newAccount(issuer: 'Legacy', label: 'dave', secret: secretB),
];

// ─── Tests ───────────────────────────────────────────────────────────────────

void main() {
  group('detectFormat', () {
    final recognised = <String, (String, DetectedFormat)>{
      'an Aegis vault': (aegisPlain, (source: ImportSource.aegis, encrypted: false)),
      'a 2FAS backup': (twoFasFile(twoFasServices), (source: ImportSource.twoFas, encrypted: false)),
      'a Bitwarden export': (bitwarden, (source: ImportSource.bitwarden, encrypted: false)),
      'a list of URIs': ('otpauth://totp/a?secret=$secretB\nhello', (source: ImportSource.uris, encrypted: false)),
      'Google transfer payloads': (migrationUri([const GoogleOtp(name: 'a')]), (source: ImportSource.google, encrypted: false)),
    };
    for (final MapEntry(key: name, value: (text, expected)) in recognised.entries) {
      test('recognises $name', () {
        expect(detectFormat(text), expected);
      });
    }

    test('reports encrypted Aegis and 2FAS files without decrypting them', () {
      expect(detectFormat(aegisEncrypted), (source: ImportSource.aegis, encrypted: true));
      expect(detectFormat(twoFasEncrypted), (source: ImportSource.twoFas, encrypted: true));
    });

    test('reads a file that starts with a byte order mark', () {
      expect(detectFormat('${String.fromCharCode(0xfeff)}$aegisPlain'), (source: ImportSource.aegis, encrypted: false));
    });

    final ignored = {
      'a plaintext Kemlock export': exportVaultPlaintext([], []),
      'an encrypted Kemlock export': jsonEncode({'version': 2, 'app': 'BackMyCodes', 'scheme': 'ML-KEM-1024', 'kemCT': 'x'}),
      'unrelated JSON': jsonEncode({'hello': 'world'}),
      'a JSON array': jsonEncode([
        {'secret': secretB},
      ]),
      'plain text': 'just some notes\nnothing to see',
      'an empty file': '',
    };
    for (final MapEntry(key: name, value: text) in ignored.entries) {
      test('ignores $name', () {
        expect(detectFormat(text), isNull);
      });
    }
  });

  group('parseForeignExport errors', () {
    test('rejects Kemlock exports, which have their own importer', () async {
      await expectLater(parseForeignExport(exportVaultPlaintext([], [])), throwsImportError(ImportErrorCode.unsupported));
    });

    test('rejects files that are no known format', () async {
      await expectLater(parseForeignExport('{"hello":"world"}'), throwsImportError(ImportErrorCode.unsupported));
      await expectLater(parseForeignExport('hello'), throwsImportError(ImportErrorCode.unsupported));
    });

    test('throws ImportError instances', () async {
      await expectLater(parseForeignExport('hello'), throwsA(isA<ImportError>()));
    });

    test('asks for a password before decrypting', () async {
      await expectLater(parseForeignExport(aegisEncrypted), throwsImportError(ImportErrorCode.passwordRequired));
      await expectLater(parseForeignExport(twoFasEncrypted, password: ''), throwsImportError(ImportErrorCode.passwordRequired));
    });

    test('reports a recognised file without any 2FA entries as empty', () async {
      final aegisEmpty = {
        'version': 1,
        'header': {'slots': null, 'params': null},
        'db': {'entries': <Object?>[]},
      };
      await expectLater(parseForeignExport(jsonEncode(aegisEmpty)), throwsImportError(ImportErrorCode.empty));
      await expectLater(parseForeignExport(twoFasFile([])), throwsImportError(ImportErrorCode.empty));
      final noTotp = {
        'encrypted': false,
        'items': [bitwardenLogin('Mail', null)],
      };
      await expectLater(parseForeignExport(jsonEncode(noTotp)), throwsImportError(ImportErrorCode.empty));
    });
  });

  group('Google Authenticator', () {
    test('reads a transfer QR and strips the issuer from the name', () {
      final uri = migrationUri([GoogleOtp(name: 'ACME:alice', issuer: 'ACME', secret: rfcBytes)]);
      expect(
        parseGoogleMigration(uri),
        ForeignImport(
          source: ImportSource.google,
          skipped: 0,
          accounts: [newAccount(issuer: 'ACME', label: 'alice', secret: rfcSecret)],
        ),
      );
    });

    test('imports a secret that generates the RFC 6238 code', () {
      final [account] = parseGoogleMigration(migrationUri([const GoogleOtp(name: 'alice', issuer: 'ACME')]))!.accounts;
      expect(codeAt(account, 59), '287082');
    });

    test('reads HOTP, SHA-256, SHA-512 and 8 digits, and skips what it cannot generate', () {
      final result = parseGoogleMigration(
        migrationUri([
          const GoogleOtp(name: 'bob', issuer: 'Bank', type: 1, counter: 42),
          const GoogleOtp(name: 'carol', issuer: 'Cloud', algorithm: 2, digits: 2),
          const GoogleOtp(name: 'dave', issuer: 'Dev', algorithm: 3),
          const GoogleOtp(name: 'erin', issuer: 'Unspecified', algorithm: 0, digits: 0, type: 0),
          const GoogleOtp(name: 'md5', issuer: 'Old', algorithm: 4),
          const GoogleOtp(name: 'nine', issuer: 'Odd', digits: 3),
          const GoogleOtp(name: 'future', issuer: 'New', type: 3),
          const GoogleOtp(name: 'empty', issuer: 'None', secret: []),
        ]),
      )!;
      expect(result.skipped, 4);
      expect(result.accounts, [
        newAccount(type: OtpType.hotp, issuer: 'Bank', label: 'bob', secret: rfcSecret, counter: 42),
        newAccount(issuer: 'Cloud', label: 'carol', secret: rfcSecret, algorithm: 'SHA256', digits: 8),
        newAccount(issuer: 'Dev', label: 'dave', secret: rfcSecret, algorithm: 'SHA512'),
        newAccount(issuer: 'Unspecified', label: 'erin', secret: rfcSecret),
      ]);
    });

    test('splits "Issuer:account" when the issuer field is empty', () {
      final result = parseGoogleMigration(
        migrationUri([const GoogleOtp(name: 'Mail: alice@example.com'), const GoogleOtp(name: 'plain')]),
      )!;
      expect(result.accounts.map((a) => (a.issuer, a.label)), [('Mail', 'alice@example.com'), ('', 'plain')]);
    });

    test('keeps a name that does not start with the issuer', () {
      final result = parseGoogleMigration(migrationUri([const GoogleOtp(name: 'alice@example.com', issuer: 'GitHub')]))!;
      expect((result.accounts[0].issuer, result.accounts[0].label), ('GitHub', 'alice@example.com'));
    });

    test("reads base64 with a '+', whether or not the URI escapes it", () {
      final data = migrationData([GoogleOtp(name: 'alice', issuer: 'ACME', secret: List.filled(20, 0xfb))]);
      expect(data, contains('+'));
      final escaped = parseGoogleMigration('otpauth-migration://offline?data=${Uri.encodeComponent(data)}');
      final raw = parseGoogleMigration('otpauth-migration://offline?data=$data');
      expect(escaped?.accounts[0].secret, '7P57X6737P57X6737P57X6737P57X673');
      expect(raw, escaped);
    });

    test('skips protobuf fields it does not know', () {
      final fixed32 = [...varint(100 * 8 + 5), 1, 2, 3, 4];
      final fixed64 = [...varint(101 * 8 + 1), 1, 2, 3, 4, 5, 6, 7, 8];
      final unknown = [...field(102, 99), ...field(103, 'later'), ...fixed32, ...fixed64];
      final result = parseGoogleMigration(migrationUri([const GoogleOtp(name: 'alice', issuer: 'ACME')], unknown));
      expect(result?.accounts, hasLength(1));
    });

    final invalid = {
      'an otpauth URI': 'otpauth://totp/a?secret=$secretB',
      'a migration URI without data': 'otpauth-migration://offline',
      'data that is not base64': 'otpauth-migration://offline?data=%%%',
      'a truncated payload': 'otpauth-migration://offline?data=${base64.encode(field(1, [10, 50, 1, 2]))}',
      'text': 'hello',
    };
    for (final MapEntry(key: name, value: uri) in invalid.entries) {
      test('returns null for $name', () {
        expect(parseGoogleMigration(uri), isNull);
      });
    }
  });

  group('URI lists', () {
    final list = [
      'otpauth://totp/GitHub:alice?secret=$rfcSecret&issuer=GitHub',
      '',
      'otpauth://hotp/Bank:bob?secret=$secretB&counter=3&issuer=Bank',
      'steam://$secretC',
      'this line is not a URI',
      'otpauth://totp/Odd?secret=$secretB&digits=7',
      migrationUri([const GoogleOtp(name: 'carol', issuer: 'Cloud'), const GoogleOtp(name: 'md5', issuer: 'Old', algorithm: 4)]),
      '',
    ].join('\r\n');

    test('reads every URI and counts the lines it could not read', () async {
      final result = await parseForeignExport(list);
      expect(result.source, ImportSource.uris);
      expect(result.skipped, 3);
      expect(result.accounts.map((a) => (a.type, a.issuer, a.label)), [
        (OtpType.totp, 'GitHub', 'alice'),
        (OtpType.hotp, 'Bank', 'bob'),
        (OtpType.steam, 'Steam', ''),
        (OtpType.totp, 'Cloud', 'carol'),
      ]);
      expect(result.accounts[1].counter, 3);
    });

    test('calls a file of only transfer payloads a Google export', () async {
      final text = [
        migrationUri([const GoogleOtp(name: 'a')]),
        migrationUri([const GoogleOtp(name: 'b')]),
      ].join('\n');
      expect(detectFormat(text), (source: ImportSource.google, encrypted: false));
      final result = await parseForeignExport(text);
      expect(result.source, ImportSource.google);
      expect(result.accounts.map((a) => a.label), ['a', 'b']);
    });

    test('counts a malformed transfer payload as one skipped entry', () async {
      const text = 'otpauth-migration://offline?data=%%%\notpauth://totp/a?secret=$secretB';
      final result = await parseForeignExport(text);
      expect((result.source, result.skipped), (ImportSource.uris, 1));
    });
  });

  group('Aegis', () {
    test('reads a plain vault with notes, favourites and groups', () async {
      expect(await parseForeignExport(aegisPlain), ForeignImport(source: ImportSource.aegis, accounts: aegisAccounts, skipped: 5));
    });

    test('reads the single group name of vaults from before multiple groups', () async {
      final entry = {...(aegisDb['entries']! as List<Object?>)[3]! as Json, 'groups': null, 'group': 'Legacy'};
      final vault = {
        'version': 1,
        'header': {'slots': null, 'params': null},
        'db': {
          'version': 2,
          'entries': [entry],
        },
      };
      final result = await parseForeignExport(jsonEncode(vault));
      expect(result.accounts[0].tags, ['Legacy']);
    });

    test('decrypts an encrypted vault with its password', () async {
      expect(
        await parseForeignExport(aegisEncrypted, password: 'correct horse'),
        ForeignImport(source: ImportSource.aegis, accounts: aegisAccounts, skipped: 5),
      );
    });

    test('decrypts with the backup password slot too', () async {
      final result = await parseForeignExport(aegisEncrypted, password: 'backup battery');
      expect(result.accounts, hasLength(4));
    });

    test('rejects a wrong password', () async {
      await expectLater(parseForeignExport(aegisEncrypted, password: 'wrong'), throwsImportError(ImportErrorCode.badPassword));
    });

    test('refuses a slot whose scrypt cost would exhaust memory instead of running it', () async {
      final vault = jsonDecode(aegisEncrypted) as Json;
      for (final slot in ((vault['header']! as Json)['slots']! as List<Object?>).cast<Json>()) {
        slot['n'] = 1 << 30;
      }
      await expectLater(parseForeignExport(jsonEncode(vault), password: 'correct horse'), throwsImportError(ImportErrorCode.badPassword));
    });

    test('refuses a cost a phone has no memory for, though the old bound let it run', () async {
      // 1 GiB a slot (N=2^20, r=8), or sixteen runs at once, were within the bound before
      for (final (name, value) in [('n', 1 << 20), ('n', 1 << 18), ('r', 16), ('p', 16)]) {
        final vault = jsonDecode(aegisEncrypted) as Json;
        for (final slot in ((vault['header']! as Json)['slots']! as List<Object?>).cast<Json>()) {
          slot[name] = value;
        }
        await expectLater(
          parseForeignExport(jsonEncode(vault), password: 'correct horse'),
          throwsImportError(ImportErrorCode.badPassword),
          reason: '$name=$value',
        );
      }
    });

    test('tries a few password slots, not as many as a file lists', () async {
      final vault = jsonDecode(aegisEncrypted) as Json;
      final header = vault['header']! as Json;
      final slots = (header['slots']! as List<Object?>).cast<Json>();
      final real = slots.firstWhere((slot) => slot['type'] == 1);
      // Slots another password opens, at the least cost, in front of the real one
      Json decoy() => {...real, 'n': 2, 'r': 1, 'p': 1, 'salt': '00' * 32};
      header['slots'] = [for (var i = 0; i < 8; i++) decoy(), real];
      await expectLater(parseForeignExport(jsonEncode(vault), password: 'backup battery'), throwsImportError(ImportErrorCode.badPassword));
      // Within the number tried, the real slot still opens
      header['slots'] = [for (var i = 0; i < 7; i++) decoy(), real];
      expect((await parseForeignExport(jsonEncode(vault), password: 'backup battery')).accounts, hasLength(4));
    });
  });

  group('2FAS', () {
    test('reads a plain backup in the app’s order, with groups as tags', () async {
      expect(
        await parseForeignExport(twoFasFile(twoFasServices)),
        ForeignImport(source: ImportSource.twoFas, accounts: twoFasAccounts, skipped: 1),
      );
    });

    test('decrypts an encrypted backup with its password', () async {
      expect(
        await parseForeignExport(twoFasEncrypted, password: 'staple'),
        ForeignImport(source: ImportSource.twoFas, accounts: twoFasAccounts, skipped: 1),
      );
    });

    test('rejects a wrong password', () async {
      await expectLater(parseForeignExport(twoFasEncrypted, password: 'wrong'), throwsImportError(ImportErrorCode.badPassword));
    });
  });

  group('Bitwarden', () {
    test('reads otpauth, steam and bare-secret TOTP fields, with folders as tags', () async {
      expect(
        await parseForeignExport(bitwarden),
        ForeignImport(
          source: ImportSource.bitwarden,
          skipped: 2,
          accounts: [
            newAccount(issuer: 'GitHub', label: 'alice', secret: rfcSecret, tags: ['2FA']),
            newAccount(issuer: 'Example', label: 'bob', secret: secretB, digits: 8),
            newAccount(type: OtpType.steam, issuer: 'Steam', label: 'gamer', secret: secretC),
            newAccount(issuer: 'Forum', label: 'carol', secret: secretB),
          ],
        ),
      );
    });

    final refused = <String, Json>{
      'account-restricted': {
        'encrypted': true,
        'encKeyValidation_DO_NOT_EDIT': '2.a|b|c',
        'folders': <Object?>[],
        'items': [
          {
            'type': 1,
            'name': '2.d|e|f',
            'login': {'totp': '2.g|h|i'},
          },
        ],
      },
      'password-protected': {
        'encrypted': true,
        'passwordProtected': true,
        'salt': 'c2FsdA==',
        'kdfType': 0,
        'kdfIterations': 600000,
        'encKeyValidation_DO_NOT_EDIT': '2.a|b|c',
        'data': '2.d|e|f',
      },
    };
    for (final MapEntry(key: name, value: file) in refused.entries) {
      test('refuses $name exports', () async {
        final text = jsonEncode(file);
        expect(detectFormat(text), (source: ImportSource.bitwarden, encrypted: true));
        await expectLater(parseForeignExport(text, password: 'any password'), throwsImportError(ImportErrorCode.bitwardenEncrypted));
      });
    }
  });
}
