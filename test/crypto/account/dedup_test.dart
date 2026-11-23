@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/account/dedup.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:test/test.dart';

import '../vectors.dart';

// The tag builder of crypto.md "Duplicate tags": RFC 8785's escaping, the key's
// inputs and the comparison. HKDF itself is held to RFC 5869's vectors in
// hkdf_test.dart, and the whole chain to the server's in
// server/dedup_vectors_test.dart.
void main() {
  group('RFC 8785 string escaping', () {
    test('writes the example of section 3.2.2.2 as the RFC does', () {
      // "€$\u000F\u000aA'B"\\\\"/" in the RFC, which is these characters:
      final value = '€\$\u000f\nA\'B"\\\\"/';
      final expected =
          '["€\$'
          r'\u000f\nA'
          "'"
          r'B\"\\\\\"/'
          '"]';

      expect(jcsStringArray([value]), expected);
    });

    test('escapes the quote and the backslash, and the controls with their short forms', () {
      expect(jcsStringArray(['"']), r'["\""]');
      expect(jcsStringArray([r'\']), r'["\\"]');
      expect(jcsStringArray(['\b\f\n\r\t']), r'["\b\f\n\r\t"]');
    });

    test('writes every other control below U+0020 as \\u00xx in lower-case hex', () {
      expect(jcsStringArray(['\u0000\u0001\u000b\u001f']), r'["\u0000\u0001\u000b\u001f"]');
    });

    test('leaves everything else as it is: the slash, DEL, U+2028, accents and emoji', () {
      final value = 'a/b\u007f é\u{1f600}';

      expect(jcsStringArray([value]), '["$value"]');
    });

    test('writes a lone surrogate as ECMAScript does, and a pair as one character', () {
      expect(jcsStringArray(['\ud800']), r'["\ud800"]');
      expect(jcsStringArray(['\udfff!']), r'["\udfff!"]');
      expect(jcsStringArray(['\u{1f600}']), '["\u{1f600}"]');
    });
  });

  group('the array', () {
    test('has no whitespace, and holds each value in order', () {
      expect(jcsStringArray([]), '[]');
      expect(jcsStringArray(['']), '[""]');
      expect(jcsStringArray(['cred', 'example.com', 'alice', 'hunter2']), '["cred","example.com","alice","hunter2"]');
    });

    test('takes the name first and encodes the text as UTF-8', () {
      expect(utf8.decode(dedupInput('cred', ['a', 'é'])), '["cred","a","é"]');
      expect(toHex(dedupInput('note', ['\u{1f600}'])), toHex(utf8.encode('["note","\u{1f600}"]')));
      expect(toHex(dedupInput('note', ['\u{1f600}'])), contains('f09f9880'));
    });
  });

  group('the key', () {
    final ownerKey = List<int>.generate(32, (i) => i);
    final owner = Owner.user('019c8e8e-b1af-b0f9-b325-020c136d40d6');

    test('is 32 bytes, and another for another version or owner', () {
      final key = dedupKey(ownerKey, owner, 1);

      expect(key, hasLength(dedupKeyLength));
      expect(dedupKey(ownerKey, owner, 1), key);
      expect(dedupKey(ownerKey, owner, 2), isNot(key));
      expect(dedupKey(ownerKey, Owner.space('019c8e8e-b1af-b0f9-b325-020c136d40d6'), 1), isNot(key));
    });

    test('takes only a 32-byte owner key, and a version that fits u32', () {
      expect(() => dedupKey(List.filled(31, 0), owner, 1), throwsA(isA<MalformedException>()));
      expect(() => dedupKey(List.filled(64, 0), owner, 1), throwsA(isA<MalformedException>()));
      expect(() => dedupKey(ownerKey, owner, -1), throwsArgumentError);
      expect(() => dedupKey(ownerKey, owner, 0x100000000), throwsArgumentError);
    });

    test('makes a tag of 32 bytes, and refuses a key of another length', () {
      expect(dedupTag(dedupKey(ownerKey, owner, 1), 'cred', ['a']), hasLength(dedupTagLength));
      expect(() => dedupTag(List.filled(16, 0), 'cred', ['a']), throwsA(isA<MalformedException>()));
    });
  });

  group('comparing tags', () {
    final tag = dedupTag(List.filled(32, 7), 'note', ['text']);

    test('says equal bytes are equal, and any other pair is not', () {
      expect(dedupTagsEqual(tag, List<int>.of(tag)), isTrue);
      for (var i = 0; i < tag.length; i++) {
        final other = List<int>.of(tag);
        other[i] ^= 1;
        expect(dedupTagsEqual(tag, other), isFalse, reason: 'byte $i differs');
      }
      expect(dedupTagsEqual(tag, tag.sublist(0, 31)), isFalse);
    });
  });
}
