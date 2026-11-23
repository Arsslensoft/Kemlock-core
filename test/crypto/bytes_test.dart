@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:test/test.dart';

void main() {
  group('b64', () {
    test('writes standard base64 with padding, as btoa does', () {
      expect(b64([]), '');
      expect(b64(utf8.encode('hello')), 'aGVsbG8=');
      expect(b64([0xfb, 0xff, 0xfe]), '+//+');
      expect(b64([0xff]), '/w==');
    });

    test('reads it back, with or without padding and around whitespace, as atob does', () {
      expect(unb64('aGVsbG8='), utf8.encode('hello'));
      expect(unb64('aGVsbG8'), utf8.encode('hello'));
      expect(unb64(' aGVs\nbG8= '), utf8.encode('hello'));
      expect(unb64('+//+'), [0xfb, 0xff, 0xfe]);
      expect(unb64(''), isEmpty);
    });

    test('refuses what atob refuses', () {
      expect(() => unb64('-__-'), throwsFormatException);
      expect(() => unb64('aGVsb'), throwsFormatException);
      expect(() => unb64('aG=s'), throwsFormatException);
      expect(() => unb64('aGVsbG8!'), throwsFormatException);
    });
  });

  group('b64url', () {
    test('writes the URL alphabet without padding', () {
      expect(b64url([0xfb, 0xff, 0xfe]), '-__-');
      expect(b64url([0xff]), '_w');
      expect(b64url(utf8.encode('hello')), 'aGVsbG8');
    });

    test('reads it back with or without padding, and the standard alphabet too, as qrVault.ts does', () {
      expect(unb64url('-__-'), [0xfb, 0xff, 0xfe]);
      expect(unb64url('_w'), [0xff]);
      expect(unb64url('_w=='), [0xff]);
      expect(unb64url('+//+'), [0xfb, 0xff, 0xfe]);
      expect(() => unb64url('aGVsb'), throwsFormatException);
    });
  });

  test('concatBytes joins the parts in order', () {
    expect(
      concatBytes([
        [1, 2],
        [],
        [3],
      ]),
      [1, 2, 3],
    );
    expect(concatBytes([]), isEmpty);
  });

  test('constantTimeEquals tells equal bytes from any others', () {
    expect(constantTimeEquals([], []), isTrue);
    expect(constantTimeEquals([1, 2, 3], [1, 2, 3]), isTrue);
    expect(constantTimeEquals([1, 2, 3], [1, 2, 4]), isFalse);
    expect(constantTimeEquals([9, 2, 3], [1, 2, 3]), isFalse);
    expect(constantTimeEquals([1, 2, 3], [1, 2]), isFalse);
    expect(constantTimeEquals([1, 2], [1, 2, 3]), isFalse);
    expect(constantTimeEquals([1, 2], [1, 2, 0]), isFalse, reason: 'a missing byte is not a zero');
    expect(constantTimeEquals([], [0]), isFalse);
  });

  test('randomBytes gives as many bytes as asked, different each time', () {
    expect(randomBytes(0), isEmpty);
    expect(randomBytes(32), hasLength(32));
    expect(randomBytes(32), isNot(randomBytes(32)));
  });
}
