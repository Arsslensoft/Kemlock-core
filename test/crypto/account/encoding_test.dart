@Tags(['wasm'])
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:test/test.dart';

void main() {
  group('integers', () {
    test('write big-endian', () {
      expect(u8(0xab), [0xab]);
      expect(u16be(0x0102), [1, 2]);
      expect(u32be(0x01020304), [1, 2, 3, 4]);
      expect(u64be(0x0102030405060708), [1, 2, 3, 4, 5, 6, 7, 8]);
      expect(u64be(4), [0, 0, 0, 0, 0, 0, 0, 4]);
    });

    test('refuse what does not fit', () {
      expect(() => u8(256), throwsArgumentError);
      expect(() => u16be(-1), throwsArgumentError);
      expect(() => u32be(0x100000000), throwsArgumentError);
      expect(() => u64be(-1), throwsArgumentError);
    });

    test('lp puts a four-byte length before the field', () {
      expect(lp([9, 8, 7]), [0, 0, 0, 3, 9, 8, 7]);
      expect(lp([]), [0, 0, 0, 0]);
    });

    test('a label is ASCII, with no terminator', () {
      expect(label('kemlock/v1/user'), 'kemlock/v1/user'.codeUnits);
      expect(() => label('kemlöck'), throwsArgumentError);
    });
  });

  group('UUIDs and owners', () {
    const text = '0189f7c2-5a3e-7b21-8d4f-0123456789ab';

    test('round trip between the hyphenated text and 16 bytes', () {
      final bytes = uuidBytes(text);
      expect(bytes, [0x01, 0x89, 0xf7, 0xc2, 0x5a, 0x3e, 0x7b, 0x21, 0x8d, 0x4f, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab]);
      expect(uuidText(bytes), text);
    });

    test('refuse upper case, braces and a missing hyphen', () {
      expect(() => uuidBytes(text.toUpperCase()), throwsA(isA<MalformedException>()));
      expect(() => uuidBytes('{$text}'), throwsA(isA<MalformedException>()));
      expect(() => uuidBytes(text.replaceAll('-', '')), throwsA(isA<MalformedException>()));
      expect(isUuidText('acc-1'), isFalse);
      expect(isUuidText(text), isTrue);
    });

    test('an owner is the type byte then the UUID', () {
      expect(Owner.user(text).bytes, [0x01, ...uuidBytes(text)]);
      expect(Owner.space(text).bytes, [0x02, ...uuidBytes(text)]);
      expect(Owner.fromBytes(Owner.space(text).bytes), Owner.space(text));
      expect(Owner.user(text) == Owner.space(text), isFalse);
    });

    test('an owner of another length or type is refused', () {
      expect(() => Owner.fromBytes(Uint8List(16)), throwsA(isA<MalformedException>()));
      expect(() => Owner.fromBytes([3, ...uuidBytes(text)]), throwsA(isA<MalformedException>()));
    });

    test('the JSON form is user:<uuid> or space:<uuid>', () {
      expect(Owner.fromWire('user:$text').toWire(), 'user:$text');
      expect(Owner.fromWire('space:$text').toWire(), 'space:$text');
      expect(Owner.fromWire('user:$text').bytes, [0x01, ...uuidBytes(text)]);
      expect(Owner.fromWire('space:$text').bytes, [0x02, ...uuidBytes(text)]);
      expect(Owner.fromWire('space:$text'), Owner.space(text));
      expect(Owner.space(text).toWire(), 'space:$text');
    });

    test('another prefix, case or UUID form is refused', () {
      for (final bad in [
        'team:$text',
        'Space:$text',
        'space-$text',
        'space:',
        'space:${text.toUpperCase()}',
        'space:{$text}',
        'space:acc-1',
        text,
        '',
      ]) {
        expect(() => Owner.fromWire(bad), throwsA(isA<MalformedException>()), reason: bad);
      }
    });
  });

  group('base64url', () {
    test('writes no padding and the URL alphabet', () {
      expect(b64urlEncode([0xfb, 0xff, 0xfe]), '-__-');
      expect(b64urlEncode([0xff]), '_w');
      expect(b64urlEncode([]), '');
    });

    test('reads it back', () {
      expect(b64urlDecode('-__-'), [0xfb, 0xff, 0xfe]);
      expect(b64urlDecode('_w'), [0xff]);
      expect(b64urlDecode(''), isEmpty);
    });

    test('refuses padding, the standard alphabet and whitespace', () {
      expect(() => b64urlDecode('_w=='), throwsA(isA<MalformedException>()));
      expect(() => b64urlDecode('+//+'), throwsA(isA<MalformedException>()));
      expect(() => b64urlDecode('_w '), throwsA(isA<MalformedException>()));
      expect(() => b64urlDecode('_w\n'), throwsA(isA<MalformedException>()));
    });

    test('refuses a length no bytes give and a final character with stray bits', () {
      expect(() => b64urlDecode('_'), throwsA(isA<MalformedException>()));
      expect(() => b64urlDecode('_x'), throwsA(isA<MalformedException>()));
    });
  });

  group('ByteReader', () {
    test('reads in order and refuses trailing bytes', () {
      final reader = ByteReader([1, 0, 2, 0, 0, 0, 3, 9, 9]);
      expect(reader.readU8('a'), 1);
      expect(reader.readU16('b'), 2);
      expect(reader.readU32('c'), 3);
      expect(() => reader.finish(), throwsA(isA<MalformedException>()));
      expect(reader.readRest(), [9, 9]);
      reader.finish();
    });

    test('refuses a read past the end', () {
      expect(() => ByteReader([1, 2]).read(3, 'x'), throwsA(isA<MalformedException>()));
    });

    test('requireLength checks before anything else', () {
      expect(requireLength([1, 2], 2, 'x'), [1, 2]);
      expect(() => requireLength([1, 2], 3, 'x'), throwsA(isA<MalformedException>()));
    });
  });

  group('strictObject', () {
    test('refuses unknown and missing fields', () {
      expect(strictObject({'a': 1}, required: {'a'}), {'a': 1});
      expect(strictObject({'a': 1, 'b': 2}, required: {'a'}, optional: {'b'}), {'a': 1, 'b': 2});
      expect(() => strictObject({'a': 1, 'c': 2}, required: {'a'}), throwsA(isA<MalformedException>()));
      expect(() => strictObject(<String, Object?>{}, required: {'a'}), throwsA(isA<MalformedException>()));
      expect(() => strictObject([1], required: {'a'}), throwsA(isA<MalformedException>()));
    });
  });

  test('wipe zeroes a buffer in place', () {
    final bytes = Uint8List.fromList([1, 2, 3]);
    wipe(bytes);
    expect(bytes, [0, 0, 0]);
  });
}
