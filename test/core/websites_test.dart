@TestOn('vm')
library;

import 'package:kemlock_core/core/websites.dart';
import 'package:test/test.dart';

String _chars(List<int> codePoints) => String.fromCharCodes(codePoints);

void main() {
  group('punycodeEncode', () {
    test('encodes the sample strings of RFC 3492', () {
      // 7.1 (A) Arabic (Egyptian)
      expect(
        punycodeEncode(
          _chars([
            0x0644,
            0x064A,
            0x0647,
            0x0645,
            0x0627,
            0x0628,
            0x062A,
            0x0643,
            0x0644,
            0x0645,
            0x0648,
            0x0634,
            0x0639,
            0x0631,
            0x0628,
            0x064A,
            0x061F,
          ]),
        ),
        'egbpdaj6bu4bxfgehfvwxn',
      );
      // 7.1 (B) Chinese (simplified)
      expect(punycodeEncode(_chars([0x4ED6, 0x4EEC, 0x4E3A, 0x4EC0, 0x4E48, 0x4E0D, 0x8BF4, 0x4E2D, 0x6587])), 'ihqwcrb4cv8a8dqg056pqjye');
      // 7.1 (C) Chinese (traditional)
      expect(
        punycodeEncode(_chars([0x4ED6, 0x5011, 0x7232, 0x4EC0, 0x9EBD, 0x4E0D, 0x8AAA, 0x4E2D, 0x6587])),
        'ihqwctvzc91f659drss3x8bo0yb',
      );
      // 7.1 (L) 3<nen>B<gumi><kinpachi><sensei>, whose basic code points keep their case
      expect(punycodeEncode(_chars([0x0033, 0x5E74, 0x0042, 0x7D44, 0x91D1, 0x516B, 0x5148, 0x751F])), '3B-ww4c5e180e575a65lsy2b');
    });

    test('encodes a name with a few accents', () {
      expect(punycodeEncode('bücher'), 'bcher-kva');
      expect(punycodeEncode('münchen'), 'mnchen-3ya');
    });
  });

  group('normaliseWebsite', () {
    test('keeps the host of a pasted address, in lowercase', () {
      expect(normaliseWebsite('https://Mail.Larkspur.example/login?next=/inbox'), 'mail.larkspur.example');
      expect(normaliseWebsite('larkspur.example'), 'larkspur.example');
      expect(normaliseWebsite('  http://user:secret@larkspur.example:8443/#top '), 'larkspur.example');
      expect(normaliseWebsite('//cdn.larkspur.example/a'), 'cdn.larkspur.example');
      expect(normaliseWebsite('Larkspur.Example.'), 'larkspur.example');
    });

    test('drops www', () {
      expect(normaliseWebsite('https://www.larkspur.example'), 'larkspur.example');
    });

    test('keeps an internationalised name in its ASCII form', () {
      expect(normaliseWebsite('bücher.example'), 'xn--bcher-kva.example');
      expect(normaliseWebsite('https://BÜCHER.example/'), 'xn--bcher-kva.example');
    });

    test('keeps an IPv4 address, for a router or a NAS', () {
      expect(normaliseWebsite('http://192.168.1.1/admin'), '192.168.1.1');
    });

    test('refuses what is not a website', () {
      for (final input in [
        '',
        'my bank',
        'larkspur',
        'https://',
        'larkspur..example',
        '-larkspur.example',
        'larkspur.example:http',
        '[::1]',
        'a.123',
        'under_score.example',
      ]) {
        expect(normaliseWebsite(input), isNull, reason: input);
      }
    });
  });
}
