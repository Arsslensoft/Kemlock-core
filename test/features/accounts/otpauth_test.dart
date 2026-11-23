@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/accounts/otpauth.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

// RFC 6238 Appendix B seeds ("1234567890" repeated to the hash's block size), base32-encoded
const rfcSeeds = {
  'SHA1': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  'SHA256': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  'SHA512': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
};

OtpAccount account({
  OtpType type = OtpType.totp,
  String issuer = 'ACME',
  String label = 'alice',
  String? secret,
  String algorithm = 'SHA1',
  int digits = 6,
  int period = 30,
  int? counter,
}) => OtpAccount(
  id: 'id',
  type: type,
  issuer: issuer,
  label: label,
  secret: secret ?? rfcSeeds['SHA1']!,
  algorithm: algorithm,
  digits: digits,
  period: period,
  counter: counter,
  addedAt: 0,
);

typedef Json = Map<String, Object?>;

/// The account's fields without its id and addedAt, as the TypeScript's NewAccount.
Json? newAccount(OtpAccount? account) => account == null
    ? null
    : (account.toJson()
        ..remove('id')
        ..remove('addedAt'));

List<Json> cases(Json fixture, String key) => (fixture[key]! as List<Object?>).cast<Json>();

void main() {
  group('parseOtpUri', () {
    test('parses a fully specified TOTP URI', () {
      const uri =
          'otpauth://totp/ACME%20Co:john@example.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ'
          '&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60';

      expect(newAccount(parseOtpUri(uri)), {
        'type': 'totp',
        'issuer': 'ACME Co',
        'label': 'john@example.com',
        'secret': 'HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ',
        'algorithm': 'SHA256',
        'digits': 8,
        'period': 60,
      });
    });

    test('applies RFC defaults when parameters are omitted', () {
      expect(newAccount(parseOtpUri('otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP')), {
        'type': 'totp',
        'issuer': '',
        'label': 'bob',
        'secret': 'JBSWY3DPEHPK3PXP',
        'algorithm': 'SHA1',
        'digits': 6,
        'period': 30,
      });
    });

    test('accepts SHA512', () {
      expect(parseOtpUri('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512')?.algorithm, 'SHA512');
    });

    test('parses HOTP URIs with their counter', () {
      expect(newAccount(parseOtpUri('otpauth://hotp/ACME:bob?secret=JBSWY3DPEHPK3PXP&issuer=ACME&counter=42')), {
        'type': 'hotp',
        'issuer': 'ACME',
        'label': 'bob',
        'secret': 'JBSWY3DPEHPK3PXP',
        'algorithm': 'SHA1',
        'digits': 6,
        'period': 30,
        'counter': 42,
      });
    });

    for (final (app, uri) in [
      ('Aegis', 'otpauth://steam/Steam:gaben?secret=JBSWY3DPEHPK3PXP&issuer=Steam&digits=5'),
      ('KeePassXC', 'otpauth://totp/Steam:gaben?secret=JBSWY3DPEHPK3PXP&issuer=Steam&encoder=steam'),
      ('a 5-digit Steam TOTP', 'otpauth://totp/Steam:gaben?secret=JBSWY3DPEHPK3PXP&digits=5'),
    ]) {
      test('reads Steam Guard as written by $app', () {
        final parsed = parseOtpUri(uri)!;
        expect(parsed.type, OtpType.steam);
        expect(parsed.issuer, 'Steam');
        expect(parsed.label, 'gaben');
        expect(parsed.secret, 'JBSWY3DPEHPK3PXP');
      });
    }

    test('reads a bare steam:// secret', () {
      final parsed = parseOtpUri('steam://jbswy3dpehpk3pxp')!;
      expect(parsed.type, OtpType.steam);
      expect(parsed.issuer, 'Steam');
      expect(parsed.secret, 'JBSWY3DPEHPK3PXP');
    });

    test('rejects digit counts other than 6 and 8, which would show wrong codes', () {
      expect(parseOtpUri('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7'), isNull);
      expect(parseOtpUri('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=5'), isNull);
    });

    for (final uri in ['', 'https://example.com', 'otpauth://totp/bob', 'not a uri at all']) {
      test('returns null for ${jsonEncode(uri)}', () {
        expect(parseOtpUri(uri), isNull);
      });
    }

    test('leaves the id and addedAt for the caller to set', () {
      final parsed = parseOtpUri('otpauth://totp/bob?secret=JBSWY3DPEHPK3PXP')!;
      expect(parsed.id, '');
      expect(parsed.addedAt, 0);
    });

    test('reads letters outside ASCII written without escapes', () {
      final parsed = parseOtpUri('otpauth://totp/Café ☕:bob?secret=JBSWY3DPEHPK3PXP')!;
      expect(parsed.issuer, 'Café ☕');
      expect(parsed.label, 'bob');
    });

    test('does not take the Kelvin sign for a k, as JavaScript does not', () {
      expect(parseOtpUri('otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&Key=1'), isNull);
    });
  });

  group('buildOtpUri', () {
    test('round-trips through parseOtpUri', () {
      final acc = account(issuer: 'Café ☕', label: 'user name', secret: rfcSeeds['SHA512'], algorithm: 'SHA512', digits: 8, period: 60);

      expect(newAccount(parseOtpUri(buildOtpUri(acc))), newAccount(acc));
    });

    test('produces a standard otpauth://totp URI', () {
      final uri = buildOtpUri(account());
      expect(uri, startsWith('otpauth://totp/ACME:alice?'));
      expect(uri, contains('secret=${rfcSeeds['SHA1']}'));
    });

    test('round-trips an HOTP account with its counter', () {
      final acc = account(type: OtpType.hotp, counter: 7);
      expect(buildOtpUri(acc), startsWith('otpauth://hotp/'));
      expect(newAccount(parseOtpUri(buildOtpUri(acc))), newAccount(acc));
    });

    test('writes Steam accounts with the otpauth://steam scheme', () {
      final acc = account(type: OtpType.steam, issuer: 'Steam', label: 'gaben');
      final uri = buildOtpUri(acc);
      expect(uri, startsWith('otpauth://steam/Steam:gaben?'));
      final parsed = parseOtpUri(uri)!;
      expect(parsed.type, OtpType.steam);
      expect(parsed.secret, acc.secret);
    });

    test("writes the v0.1.0 fixture's accounts as the TypeScript app does", () {
      final cafe = OtpAccount.fromJson({
        'id': 'acc-2',
        'issuer': 'Café ☕',
        'label': 'bob',
        'secret': 'JBSWY3DPEHPK3PXP',
        'algorithm': 'SHA256',
        'digits': 8,
        'period': 60,
        'addedAt': 1700000001000,
      });

      expect(
        buildOtpUri(cafe),
        'otpauth://totp/Caf%C3%A9%20%E2%98%95:bob?issuer=Caf%C3%A9%20%E2%98%95&secret=JBSWY3DPEHPK3PXP'
        '&algorithm=SHA256&digits=8&period=60',
      );
    });

    test('throws for a secret that is not base32 or an unknown algorithm', () {
      expect(() => buildOtpUri(account(secret: 'not base32!')), throwsFormatException);
      expect(() => buildOtpUri(account(algorithm: 'MD5')), throwsFormatException);
    });
  });

  group('against the TypeScript app (test/fixtures/otp/links.json)', () {
    final fixture = jsonDecode(File('test/fixtures/otp/links.json').readAsStringSync()) as Json;

    test('reads every link as parseOtpUri does', () {
      for (final item in cases(fixture, 'parse')) {
        final uri = item['uri']! as String;
        expect(newAccount(parseOtpUri(uri)), item['account'], reason: jsonEncode(uri));
      }
    });

    test('writes every account as buildOtpUri does', () {
      for (final item in cases(fixture, 'build')) {
        final acc = OtpAccount.fromJson({...item['account']! as Json, 'id': 'id', 'addedAt': 0});
        final uri = item['uri'] as String?;
        if (uri == null) {
          expect(() => buildOtpUri(acc), throwsFormatException, reason: jsonEncode(item['account']));
        } else {
          expect(buildOtpUri(acc), uri, reason: jsonEncode(item['account']));
          expect(newAccount(parseOtpUri(uri)), item['parsed'], reason: uri);
        }
      }
    });
  });

  group("Bitwarden's totp field", () {
    test('reads links, steam:// and bare secrets, filling the issuer and label from the login', () {
      final link = parseBitwardenTotp('otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&digits=8', name: 'GitHub', username: 'someone else')!;
      expect((link.issuer, link.label, link.digits, link.kind), ('GitHub', 'me', 8, OtpType.totp));

      final steam = parseBitwardenTotp('steam://GEZDGNBVGY3TQOJQ', name: 'Steam', username: 'gamer')!;
      expect((steam.kind, steam.secret, steam.label), (OtpType.steam, 'GEZDGNBVGY3TQOJQ', 'gamer'));

      final bare = parseBitwardenTotp(' jbsw y3dp ehpk 3pxp== ', name: 'Old', username: '')!;
      expect((bare.kind, bare.secret, bare.algorithm, bare.digits, bare.period), (OtpType.totp, 'JBSWY3DPEHPK3PXP', 'SHA1', 6, 30));

      expect(parseBitwardenTotp('not a secret!'), isNull);
      expect(parseBitwardenTotp('otpauth://totp/?secret=JBSWY3DPEHPK3PXP&digits=7'), isNull);
    });

    test('writes what Bitwarden makes codes for, and nothing for HOTP', () {
      const totp = OtpAccount(
        id: 'a',
        issuer: 'GitHub',
        label: 'me',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA256',
        digits: 8,
        addedAt: 0,
      );
      final written = buildBitwardenTotp(totp)!;
      expect(written, startsWith('otpauth://totp/'));
      final back = parseBitwardenTotp(written)!;
      expect((back.issuer, back.label, back.secret, back.algorithm, back.digits), ('GitHub', 'me', 'JBSWY3DPEHPK3PXP', 'SHA256', 8));

      expect(buildBitwardenTotp(totp.copyWith(type: OtpType.steam)), 'steam://JBSWY3DPEHPK3PXP');
      expect(buildBitwardenTotp(totp.copyWith(type: OtpType.hotp, counter: 3)), isNull);
    });
  });
}
