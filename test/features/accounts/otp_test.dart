@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/features/accounts/otp.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

// "12345678901234567890", the RFC 4226 / 6238 test secret
const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// RFC 6238 Appendix B seeds ("1234567890" repeated to the hash's block size), base32-encoded
const rfcSeeds = {
  'SHA1': rfcSecret,
  'SHA256': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  'SHA512': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
};

// (unix seconds, SHA1, SHA256, SHA512): RFC 6238 Appendix B, 8 digits, 30 s period
const rfcVectors = [
  (59, '94287082', '46119246', '90693936'),
  (1111111109, '07081804', '68084774', '25091201'),
  (1111111111, '14050471', '67062674', '99943326'),
  (1234567890, '89005924', '91819424', '93441116'),
  (2000000000, '69279037', '90698825', '38618901'),
  (20000000000, '65353130', '77737706', '47863826'),
];

OtpAccount account({OtpType? type, String secret = rfcSecret, String algorithm = 'SHA1', int digits = 6, int period = 30, int? counter}) =>
    OtpAccount(
      id: 'id',
      type: type,
      issuer: 'ACME',
      label: 'alice',
      secret: secret,
      algorithm: algorithm,
      digits: digits,
      period: period,
      counter: counter,
      addedAt: 0,
    );

typedef Json = Map<String, Object?>;

List<Json> cases(Json fixture, String key) => (fixture[key]! as List<Object?>).cast<Json>();

String hex(List<int> bytes) => bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('otp type', () {
    test('treats accounts saved before typed accounts as TOTP', () {
      expect(account().kind, OtpType.totp);
      expect(isTimeBased(account()), isTrue);
    });

    test('reads the stored type', () {
      expect(account(type: OtpType.hotp).kind, OtpType.hotp);
      expect(isTimeBased(account(type: OtpType.hotp)), isFalse);
      expect(isTimeBased(account(type: OtpType.steam)), isTrue);
    });
  });

  group('codeAt', () {
    test('matches RFC 6238 for TOTP', () {
      expect(codeAt(account(), 59), '287082');
      expect(codeAt(account(digits: 8), 1111111109), '07081804');
    });

    test('gives dashes, six of them, for more digits than a code has, however many a file asked for', () {
      for (final digits in [11, 5000000, 1 << 40]) {
        expect(hasCodeLength(account(digits: digits)), isFalse, reason: '$digits');
        expect(codeLength(account(digits: digits)), 6, reason: '$digits');
        expect(codeAt(account(digits: digits), 59), '------', reason: '$digits');
        expect(
          codeAt(account(type: OtpType.hotp, counter: 1, digits: digits), 0),
          '------',
          reason: '$digits',
        );
      }
      // Steam codes have five characters whatever the digits say
      expect(codeAt(account(type: OtpType.steam, digits: 5000000), 59), hasLength(5));
      // The lengths codes do have are as before
      expect(codeAt(account(digits: 1), 59), hasLength(1));
      expect(codeAt(account(digits: 10), 59), hasLength(10));
    });

    test('shifts TOTP by whole windows', () {
      expect(codeAt(account(digits: 8), 1111111109, 1), '14050471');
    });

    for (final (index, algorithm) in ['SHA1', 'SHA256', 'SHA512'].indexed) {
      group('RFC 6238 vectors ($algorithm)', () {
        for (final row in rfcVectors) {
          final expected = [row.$2, row.$3, row.$4][index];
          test('T=${row.$1} → $expected', () {
            expect(codeAt(account(algorithm: algorithm, secret: rfcSeeds[algorithm]!, digits: 8), row.$1), expected);
          });
        }
      });
    }

    test('truncates to 6 digits', () {
      expect(codeAt(account(), 59), '287082');
    });

    test("makes the code of the v0.1.0 fixture's RFC account", () {
      final rfc = OtpAccount.fromJson({
        'id': 'acc-1',
        'issuer': 'RFC6238',
        'label': 'alice@example.com',
        'secret': 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        'algorithm': 'SHA1',
        'digits': 6,
        'period': 30,
        'addedAt': 1700000000000,
      });

      expect(codeAt(rfc, 59), '287082');
    });

    // RFC 4226 Appendix D
    for (final (counter, expected) in [
      (0, '755224'),
      (1, '287082'),
      (2, '359152'),
      (3, '969429'),
      (4, '338314'),
      (5, '254676'),
      (6, '287922'),
      (7, '162583'),
      (8, '399871'),
      (9, '520489'),
    ]) {
      test('matches RFC 4226 for HOTP counter $counter → $expected', () {
        expect(codeAt(account(type: OtpType.hotp, counter: counter), 0), expected);
      });
    }

    test('ignores the clock for HOTP and offsets from the stored counter', () {
      final hotp = account(type: OtpType.hotp, counter: 2);
      expect(codeAt(hotp, 1000000), codeAt(hotp, 0));
      expect(codeAt(hotp, 0, 1), '969429');
    });

    test('treats a missing HOTP counter as 0', () {
      expect(codeAt(account(type: OtpType.hotp), 0), '755224');
    });

    // Vectors from the python-steam test suite, secret b"superdupersecret"
    for (final (time, expected) in [(3000030, 'YRGQJ'), (3000029, '94R9D')]) {
      test('matches Steam Guard at t=$time → $expected', () {
        final steam = account(type: OtpType.steam, secret: 'ON2XAZLSMR2XAZLSONSWG4TFOQ');
        expect(codeAt(steam, time), expected);
      });
    }

    test('returns the codes of the next and previous windows', () {
      final acc = account(digits: 8);
      // 1111111109 is the last second of its 30 s window
      expect(codeAt(acc, 1111111109, 1), codeAt(acc, 1111111111));
      expect(codeAt(acc, 1111111109, 1), '14050471');
      expect(codeAt(acc, 1111111109, -1), codeAt(acc, 1111111109 - 30));
    });

    test('honours non-default periods', () {
      final acc = account(period: 60);
      // 120 is the start of a 60 s window
      expect(codeAt(acc, 120, 1), codeAt(acc, 180));
      expect(codeAt(acc, 120, 1), isNot(codeAt(acc, 120)));
    });

    test('returns a placeholder of the right length for an invalid secret', () {
      expect(codeAt(account(secret: 'not base32!'), 0), '------');
      expect(codeAt(account(secret: '!!!'), 0, 1), '------');
      expect(codeAt(account(type: OtpType.steam, secret: '!!'), 0), '-----');
    });

    test('returns a placeholder for an algorithm it does not know', () {
      expect(codeAt(account(algorithm: 'MD5', digits: 8), 59), '--------');
    });

    test('reads the secret and algorithm the way otpauth does', () {
      expect(codeAt(account(secret: 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq==='), 59), '287082');
      expect(codeAt(account(secret: rfcSeeds['SHA256']!, algorithm: 'sha-256', digits: 8), 59), '46119246');
    });

    test('makes the new code after a copy changes the secret', () {
      final acc = account();
      expect(codeAt(acc, 59), '287082');
      expect(codeAt(acc.copyWith(secret: 'JBSWY3DPEHPK3PXP'), 59), isNot('287082'));
    });
  });

  group('codeLength', () {
    test('is 5 for Steam whatever the stored digits', () {
      expect(codeLength(account(type: OtpType.steam, digits: 8)), 5);
      expect(codeLength(account(digits: 8)), 8);
    });
  });

  group('secondsRemaining', () {
    for (final (time, period, expected) in [(0, 30, 30), (1, 30, 29), (29, 30, 1), (30, 30, 30), (59, 30, 1), (45, 60, 15)]) {
      test('at t=${time}s with period $period → $expected', () {
        expect(secondsRemaining(period, DateTime.fromMillisecondsSinceEpoch(time * 1000)), expected);
      });
    }

    test('ignores the sub-second part of the clock', () {
      expect(secondsRemaining(30, DateTime.fromMillisecondsSinceEpoch(29999)), 1);
    });
  });

  group('secrets', () {
    test('formats 6- and 8-digit codes in two halves', () {
      expect(formatCode('287082'), '287 082');
      expect(formatCode('94287082'), '9428 7082');
      expect(formatCode('YRGQJ'), 'YRGQJ');
    });

    test('normalises a typed secret', () {
      expect(normalizeSecret('jbsw y3dp-ehpk 3pxp'), 'JBSWY3DPEHPK3PXP');
    });

    test('accepts upper-case base32 of at least 10 bytes', () {
      expect(isValidSecret('JBSWY3DPEHPK3PXP'), isTrue);
      expect(isValidSecret('JBSWY3DPEHPK3PXP=='), isTrue);
      expect(isValidSecret('jbswy3dpehpk3pxp'), isFalse);
      expect(isValidSecret('JBSWY3DPEHPK3PX'), isFalse);
      expect(isValidSecret('JBSWY3DPEHPK3PX1'), isFalse);
    });

    test('groups a secret by four for showing', () {
      expect(groupSecret('JBSWY3DPEHPK3PXP'), 'JBSW Y3DP EHPK 3PXP');
      expect(groupSecret('ABCDE'), 'ABCD E');
    });
  });

  group('base32', () {
    test('decodes the RFC test secret', () {
      expect(utf8.decode(base32Decode(rfcSecret)), '12345678901234567890');
      expect(base32Encode(utf8.encode('12345678901234567890')), rfcSecret);
    });

    test('takes lower case, spaces and padding, and drops leftover bits', () {
      expect(base32Decode('mzxw 6==='), utf8.encode('foo'));
      expect(base32Decode('ABC'), [0]);
      expect(base32Decode(''), isEmpty);
    });

    test('throws on characters outside the alphabet', () {
      expect(() => base32Decode('JBSWY3DPEHPK3PX1'), throwsFormatException);
      expect(() => base32Decode('MZ=XW6'), throwsFormatException);
    });
  });

  group('against the TypeScript app (test/fixtures/otp/codes.json)', () {
    final fixture = jsonDecode(File('test/fixtures/otp/codes.json').readAsStringSync()) as Json;

    test('decodes base32 as otpauth does', () {
      for (final item in cases(fixture, 'base32')) {
        final input = item['input']! as String;
        if (item['bytes'] == null) {
          expect(() => base32Decode(input), throwsFormatException, reason: jsonEncode(input));
        } else {
          final bytes = base32Decode(input);
          expect(hex(bytes), item['bytes'], reason: jsonEncode(input));
          expect(base32Encode(bytes), item['base32'], reason: jsonEncode(input));
        }
      }
    });

    test('encodes base32 as otpauth does', () {
      for (final item in cases(fixture, 'encode')) {
        final text = item['bytes']! as String;
        final bytes = [for (var i = 0; i < text.length; i += 2) int.parse(text.substring(i, i + 2), radix: 16)];
        expect(base32Encode(bytes), item['base32'], reason: text);
      }
    });

    test('makes the same codes', () {
      for (final item in cases(fixture, 'codes')) {
        final acc = OtpAccount.fromJson({...item['account']! as Json, 'id': 'id', 'issuer': 'ACME', 'label': 'alice', 'addedAt': 0});
        expect(codeAt(acc, item['nowSec']! as int, item['offset']! as int), item['code'], reason: jsonEncode(item));
      }
    });

    test('normalises, checks and groups secrets the same way', () {
      for (final item in cases(fixture, 'secrets')) {
        final input = item['input']! as String;
        expect(normalizeSecret(input), item['normalized'], reason: jsonEncode(input));
        expect(isValidSecret(input), item['valid'], reason: jsonEncode(input));
        expect(groupSecret(input), item['grouped'], reason: jsonEncode(input));
      }
    });

    test('formats codes the same way', () {
      for (final item in cases(fixture, 'format')) {
        expect(formatCode(item['code']! as String), item['formatted']);
      }
    });
  });
}
