@TestOn('vm')
library;

import 'package:kemlock_core/features/duplicates/duplicate_normalise.dart';
import 'package:test/test.dart';

// The plan's design 3: what is made equal before values are matched or tagged
void main() {
  group('trimWhite', () {
    test('removes the White_Space code points at both ends, as Rust does', () {
      expect(trimWhite('\u2028 \u00a0a b\u3000\n'), 'a b');
      // Dart's own trim would take U+FEFF, which isn't White_Space
      expect(trimWhite('\ufeffa'), '\ufeffa');
      expect(trimWhite('  '), '');
    });
  });

  group('lowerCase', () {
    test('maps ASCII and other letters one to one', () {
      expect(lowerCase('Sam@Example.ORG'), 'sam@example.org');
      expect(lowerCase('\u00c9'), '\u00e9');
      expect(lowerCase('\u1e9e'), '\u00df'); // ẞ is ß
    });

    test('turns the dotted capital I into a plain i, with no combining dot', () {
      expect(lowerCase('\u0130'), 'i');
      expect(lowerCase('\u0130stanbul'), 'istanbul');
      expect(lowerCase('I\u0307'), 'i\u0307');
    });

    test('gives a capital sigma its plain form wherever it is, with no final sigma', () {
      expect(lowerCase('\u03a3\u0391\u03a3'), '\u03c3\u03b1\u03c3');
      expect(lowerCase('\u039f\u0394\u039f\u03a3'), '\u03bf\u03b4\u03bf\u03c3');
      expect(lowerCase('\u03a3'), '\u03c3');
      expect(lowerCase('\u0391\u0301\u03a3'), '\u03b1\u0301\u03c3');
    });

    test('keeps the sharp s apart from ss', () {
      expect(lowerCase('Stra\u00dfe'), 'stra\u00dfe');
      expect(lowerCase('STRASSE'), 'strasse');
      expect(lowerCase('STRA\u1e9eE'), 'stra\u00dfe');
      expect(lowerCase('Stra\u00dfe'), isNot(lowerCase('STRASSE')));
    });

    test('leaves a decomposed letter as it is: its combining mark has no case', () {
      expect(lowerCase('E\u0301'), 'e\u0301');
    });
  });

  group('normaliseUsername', () {
    test('trims and lower-cases', () {
      expect(normaliseUsername(' Sam@Example.org'), 'sam@example.org');
    });

    test('puts a decomposed letter and its precomposed form together', () {
      expect(normaliseUsername('Ame\u0301lie'), normaliseUsername('Am\u00e9lie'));
      expect(normaliseUsername('Am\u00e9lie'), 'am\u00e9lie');
    });

    test('makes \u0130stanbul, \u03a3\u0391\u03a3, Stra\u00dfe and STRASSE the values crypto.md gives', () {
      expect(normaliseUsername('\u0130stanbul'), 'istanbul');
      expect(normaliseUsername('\u03a3\u0391\u03a3'), '\u03c3\u03b1\u03c3');
      expect(normaliseUsername('Stra\u00dfe'), 'stra\u00dfe');
      expect(normaliseUsername('STRASSE'), 'strasse');
      expect(normaliseUsername('Stra\u00dfe'), isNot(normaliseUsername('STRASSE')));
    });

    test('takes a capital I with a combining dot, which NFC joins into \u0130, to i', () {
      expect(normaliseUsername('I\u0307'), 'i');
      expect(normaliseUsername('i\u0307'), 'i\u0307');
    });
  });

  group('normaliseNote', () {
    test('uses \n line ends and drops the blanks at the end of lines and of the text', () {
      expect(normaliseNote('a  \r\nb\t\r\n\r\n'), 'a\nb');
      expect(normaliseNote('one\rtwo \n'), 'one\ntwo');
    });

    test('keeps the blanks at the start and between words, and puts letters in NFC', () {
      expect(normaliseNote('  a  b\ne\u0301'), '  a  b\n\u00e9');
    });

    test('takes off spaces and tabs at the end of a line and no other white space', () {
      expect(normaliseNote('a \t \nb'), 'a\nb');
      expect(normaliseNote('a\u00a0\nb\u3000'), 'a\u00a0\nb\u3000');
      expect(normaliseNote('a\u2028'), 'a\u2028');
    });

    test('drops the lines at the end that hold only spaces and tabs', () {
      expect(normaliseNote('a\n \t\n\n  '), 'a');
      expect(normaliseNote('a\n\n b'), 'a\n\n b');
      expect(normaliseNote(' \t \r\n'), '');
    });
  });

  group('secretBase32', () {
    test('is the decoded bytes in upper-case base32 without padding, whatever the spacing and case', () {
      expect(secretBase32('JBSWY3DPEHPK3PXP'), 'JBSWY3DPEHPK3PXP');
      expect(secretBase32('jbsw y3dp ehpk 3pxp'), 'JBSWY3DPEHPK3PXP');
      expect(secretBase32('JBSWY3DPEHPK3PXP=='), 'JBSWY3DPEHPK3PXP');
      expect(secretBase32('JBSWY3DPEE======'), 'JBSWY3DPEE');
      expect(secretBase32('jbswy3dpee'), 'JBSWY3DPEE');
    });

    test("is nothing for a secret that is not base32, as the server's vector has it, and for an empty one", () {
      expect(secretBase32('not base32!'), isNull);
      expect(secretBase32('a1'), isNull);
      expect(secretBase32('A 1'), isNull);
      expect(secretBase32(''), isNull);
      expect(secretBase32('  '), isNull);
    });
  });

  group('normaliseDocumentNumber', () {
    test('keeps the letters and digits, in NFC and lower case, as the server vectors have it', () {
      expect(normaliseDocumentNumber('X 1234-567'), 'x1234567');
      expect(normaliseDocumentNumber('Café 9'), 'café9');
      expect(normaliseDocumentNumber('1-2-3'), isNull);
    });

    test('drops a combining mark that no precomposed letter takes: it is not alphabetic', () {
      // x has no precomposed form with an acute accent, so NFC leaves the mark, and the server drops it
      expect(normaliseDocumentNumber('X́ 1234'), 'x1234');
      expect(normaliseDocumentNumber('B́-12 34'), 'b1234');
    });

    test('keeps a mark that is part of a letter', () {
      // U+093E, a Devanagari vowel sign, is alphabetic
      expect(normaliseDocumentNumber('का 1234'), 'का1234');
    });
  });

  group('cards', () {
    test('takes the digits of a number, or nothing', () {
      expect(normaliseCardNumber('4111-1111 1111-1111'), '4111111111111111');
      expect(normaliseCardNumber(''), isNull);
      expect(normaliseCardNumber(null), isNull);
    });

    test('writes the expiry as year and month, and as empty when either is missing', () {
      expect(normaliseCardExpiry(12, 2030), '2030-12');
      expect(normaliseCardExpiry(5, 2029), '2029-05');
      expect(normaliseCardExpiry(null, 2029), '');
      expect(normaliseCardExpiry(5, null), '');
      expect(normaliseCardExpiry(null, null), '');
    });
  });

  group('normaliseCodes', () {
    test('sorts by UTF-8 bytes, which is not the order of UTF-16 code units', () {
      // U+10000 is two surrogates in UTF-16 and sorts before U+E000 there, and after it in UTF-8
      expect('\u{10000}'.compareTo('\ue000'), isNegative);
      expect(normaliseCodes(['\u{10000}', '\ue000']), ['\ue000', '\u{10000}']);
    });

    test('trims, and leaves out the empty codes and the repeats', () {
      expect(normaliseCodes([' b ', 'a', 'a', '', '  ']), ['a', 'b']);
      expect(normaliseCodes(['a', ' a', 'a\t']), ['a']);
    });

    test('leaves a code as it is: no NFC and no lower case', () {
      expect(normaliseCodes(['e\u0301', '\u00e9']), ['e\u0301', '\u00e9']);
      expect(normaliseCodes(['AbC']), ['AbC']);
    });

    test('puts the same set in one order', () {
      expect(normaliseCodes(['22222222', '11111111', '33333333']), normaliseCodes(['33333333', '22222222', '11111111']));
    });
  });

  group('SiteResolver', () {
    // A stand-in for the Public Suffix List: the last two labels, and okta.com tenants kept whole
    final resolver = SiteResolver(
      registrable: (host) => host.split('.').reversed.take(2).toList().reversed.join('.'),
      isShared: (host) => host.endsWith('okta.com'),
    );

    test('gives a host its registrable domain', () {
      expect(resolver.site('accounts.larkspur.example'), 'larkspur.example');
      expect(resolver.site('https://www.mail.larkspur.example/inbox'), 'larkspur.example');
    });

    test('keeps a shared host and an address whole', () {
      expect(resolver.site('alpha.okta.com'), 'alpha.okta.com');
      expect(resolver.site('beta.okta.com'), 'beta.okta.com');
      expect(resolver.site('192.168.1.10'), '192.168.1.10');
    });

    test('leaves a host whole without a list, and gives text that is no host as empty', () {
      expect(const SiteResolver().site('mail.larkspur.example'), 'mail.larkspur.example');
      expect(resolver.site('not a host'), '');
      expect(resolver.site(''), '');
    });
  });
}
