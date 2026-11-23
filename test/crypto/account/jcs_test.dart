@Tags(['wasm'])
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/account/jcs.dart';
import 'package:test/test.dart';

// Known answers worked out from RFC 8785 by hand: members sorted by the UTF-16
// code units of their names, no whitespace, strings escaped as ECMAScript's
// JSON.stringify does, integers as digits.
void main() {
  test('sorts members by name and writes no whitespace', () {
    expect(jcs({'b': 2, 'a': 1}), '{"a":1,"b":2}');
    expect(jcs(<String, Object?>{}), '{}');
    expect(jcs(<Object?>[]), '[]');
  });

  test('sorts nested objects and keeps the order of arrays', () {
    expect(
      jcs({
        'v': 1,
        'body': {
          'z': [
            3,
            {'y': null, 'x': true},
            'b',
            'a',
          ],
          'a': 'é',
        },
      }),
      '{"body":{"a":"é","z":[3,{"x":true,"y":null},"b","a"]},"v":1}',
    );
  });

  test('sorts the property names of RFC 8785 section 3.2.3 by UTF-16 code unit', () {
    // A carriage return, "1", a C1 control, "ö", the euro sign, a grinning face (a surrogate pair), and
    // Hebrew dalet with dagesh (U+FB33). The face sorts before U+FB33 because its high surrogate, D83D, does.
    final value = <String, Object?>{
      '€': 'Euro Sign',
      '\r': 'Carriage Return',
      'דּ': 'Hebrew Letter Dalet With Dagesh',
      '1': 'One',
      '\u{1f600}': 'Emoji: Grinning Face',
      '\u0080': 'Control',
      'ö': 'Latin Small Letter O With Diaeresis',
    };
    expect(
      jcs(value),
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",'
      '"€":"Euro Sign","\u{1f600}":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  test('escapes the quote, the backslash and the control characters, and nothing else', () {
    expect(jcs('a"b\\c'), r'"a\"b\\c"');
    expect(jcs('\b\f\n\r\t'), r'"\b\f\n\r\t"');
    expect(jcs('\u0001\u001f'), r'"\u0001\u001f"');
    expect(jcs('/\u007f '), '"/\u007f "');
  });

  test('writes integers as digits, to the limit ECMAScript writes as digits', () {
    expect(jcs([0, -1, 12345678901, jcsMaxSafeInteger, -jcsMaxSafeInteger]), '[0,-1,12345678901,9007199254740991,-9007199254740991]');
    expect(() => jcs(jcsMaxSafeInteger + 1), throwsArgumentError);
  });

  test('refuses a fraction, and anything that is not JSON', () {
    expect(() => jcs(1.5), throwsArgumentError);
    expect(() => jcs(DateTime(2026)), throwsArgumentError);
    expect(() => jcs({'a': Object()}), throwsArgumentError);
  });

  test('writes true, false and null', () {
    expect(jcs({'t': true, 'f': false, 'n': null}), '{"f":false,"n":null,"t":true}');
  });

  test('jcsBytes is the text as UTF-8', () {
    expect(jcsBytes({'a': 'é'}), utf8.encode('{"a":"é"}'));
  });
}
