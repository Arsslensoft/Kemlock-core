@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/key_error.dart';
import 'package:test/test.dart';

Uint8List _hex(String hex) {
  final clean = hex.replaceAll(' ', '');
  return Uint8List.fromList([for (var i = 0; i < clean.length; i += 2) int.parse(clean.substring(i, i + 2), radix: 16)]);
}

String _toHex(List<int> bytes) => [for (final byte in bytes) byte.toRadixString(16).padLeft(2, '0')].join();

final _damaged = throwsA(isA<KeyFormatException>().having((e) => e.problem, 'problem', KeyProblem.damaged));

void main() {
  group('reading elements', () {
    test('gives the tag, the content and the element as it appeared', () {
      final reader = DerReader(_hex('0403 010203 0500'));
      final first = reader.read();
      expect((first.tag, _toHex(first.content), _toHex(first.encoded)), (tagOctetString, '010203', '0403010203'));
      expect(reader.nextTag, tagNull);
      expect(reader.isEmpty, isFalse);
      reader.readNull();
      expect((reader.isEmpty, reader.nextTag), (true, null));
      reader.done();
    });

    test('reads long lengths of one to four bytes', () {
      expect(DerReader(Uint8List.fromList([0x04, 0x81, 0x80, ...List.filled(0x80, 1)])).octetString(), hasLength(0x80));
      expect(DerReader(Uint8List.fromList([0x04, 0x82, 0x01, 0x00, ...List.filled(0x100, 1)])).octetString(), hasLength(0x100));
      expect(DerReader(Uint8List.fromList([0x04, 0x83, 0x01, 0x00, 0x00, ...List.filled(0x10000, 1)])).octetString(), hasLength(0x10000));
    });

    test('refuses what is not DER', () {
      for (final bad in [
        '', // nothing
        '04', // no length
        '0402 01', // length past the end
        '0481 01 01', // a long length that fits the short form
        '048200 80 ${'00' * 0x80}', // a length with a leading zero byte
        '0480 0000', // indefinite length
        '0485 0000000001 01', // five length bytes
        '0482 01', // length bytes cut short
        '1f8101 00', // a high tag number
      ]) {
        expect(() => DerReader(_hex(bad)).read(), _damaged, reason: bad);
      }
    });

    test('expect, sequence, optional and optionalContent go by the tag', () {
      final reader = readSequence(_hex('300a a003 020101 8101ff 0400'));
      expect(reader.optional(contextTag(1)), isNull);
      expect(reader.optionalContent(contextTag(1, constructed: false)), isNull);
      expect(reader.optional(contextTag(0))!.smallInteger(), 1);
      expect(reader.optionalContent(contextTag(1, constructed: false)), [0xff]);
      expect(() => DerReader(_hex('0400')).expect(tagInteger), _damaged);
      expect(() => DerReader(_hex('0400')).sequence(), _damaged);
      expect(reader.octetString(), isEmpty);
      reader.done();
    });

    test('readSequence and done refuse trailing bytes', () {
      expect(() => readSequence(_hex('3000 00')), _damaged);
      expect(
        () => DerReader(_hex('0500 0500'))
          ..readNull()
          ..done(),
        _damaged,
      );
    });

    test('context tags are constructed unless said otherwise', () {
      expect((contextTag(0), contextTag(3), contextTag(1, constructed: false)), (0xa0, 0xa3, 0x81));
    });
  });

  group('reading values', () {
    test('an INTEGER, with a redundant leading zero read as its value', () {
      expect(DerReader(_hex('0201 7f')).integer(), BigInt.from(127));
      expect(DerReader(_hex('0202 0080')).integer(), BigInt.from(128));
      expect(DerReader(_hex('0203 000001')).integer(), BigInt.one);
      expect(DerReader(_hex('0201 00')).integer(), BigInt.zero);
      expect(DerReader(_hex('0201 00')).unsignedInteger(), isEmpty);
      expect(DerReader(_hex('0203 00ff01')).unsignedInteger(), [0xff, 0x01]);
    });

    test('refuses a negative or an empty INTEGER', () {
      expect(() => DerReader(_hex('0201 80')).integer(), _damaged);
      expect(() => DerReader(_hex('0201 ff')).unsignedInteger(), _damaged);
      expect(() => DerReader(_hex('0200')).integer(), _damaged);
    });

    test('a small INTEGER fits in six bytes', () {
      expect(DerReader(_hex('0206 010203040506')).smallInteger(), 0x010203040506);
      expect(() => DerReader(_hex('0207 01020304050607')).smallInteger(), _damaged);
    });

    test('an OBJECT IDENTIFIER, dotted', () {
      expect(DerReader(_hex('0609 2a864886f70d010101')).oid(), '1.2.840.113549.1.1.1');
      expect(DerReader(_hex('0603 2b6570')).oid(), '1.3.101.112');
      expect(DerReader(_hex('0603 551d13')).oid(), '2.5.29.19');
      expect(decodeOid(_hex('8837')), '2.999');
    });

    test('refuses an OBJECT IDENTIFIER that is empty, cut short, padded or huge', () {
      expect(() => DerReader(_hex('0600')).oid(), _damaged);
      expect(() => decodeOid(_hex('2a86')), _damaged);
      expect(() => decodeOid(_hex('2a8001')), _damaged);
      expect(() => decodeOid(_hex('2a ffffffffffffffff7f')), _damaged);
    });

    test('a BIT STRING of whole bytes, and none with unused bits', () {
      expect(DerReader(_hex('0303 00a5a5')).bitString(), [0xa5, 0xa5]);
      expect(() => DerReader(_hex('0302 0780')).bitString(), _damaged);
      expect(() => DerReader(_hex('0300')).bitString(), _damaged);
    });

    test('NULL has no content', () {
      expect(() => DerReader(_hex('0501 00')).readNull(), _damaged);
    });
  });

  group('writing', () {
    test('uses the shortest length', () {
      expect(_toHex(derTlv(0x04, List.filled(0x7f, 0)).sublist(0, 2)), '047f');
      expect(_toHex(derTlv(0x04, List.filled(0x80, 0)).sublist(0, 3)), '048180');
      expect(_toHex(derTlv(0x04, List.filled(0x100, 0)).sublist(0, 4)), '04820100');
      expect(_toHex(derTlv(0x04, List.filled(0x10000, 0)).sublist(0, 5)), '0483010000');
    });

    test('an INTEGER gets a zero byte in front when its top bit is set', () {
      expect(_toHex(derInteger(BigInt.zero)), '020100');
      expect(_toHex(derInteger(BigInt.from(127))), '02017f');
      expect(_toHex(derInteger(BigInt.from(128))), '02020080');
      expect(_toHex(derSmallInteger(65537)), '0203010001');
      expect(() => derInteger(BigInt.from(-1)), throwsArgumentError);
    });

    test('an OBJECT IDENTIFIER round-trips', () {
      for (final oid in ['1.2.840.113549.1.1.11', '1.3.101.112', '2.5.4.3', '2.16.840.1.101.3.4.2.1', '0.9.2342.19200300.100.1.25']) {
        expect(DerReader(derOid(oid)).oid(), oid);
      }
      expect(_toHex(derOid('1.2.840.10045.2.1')), '06072a8648ce3d0201');
    });

    test('the other types', () {
      expect(
        _toHex(
          derSequence([
            derNull(),
            derOctetString(const [1]),
          ]),
        ),
        '30050500040101',
      );
      expect(_toHex(derBitString(const [0xff])), '030200ff');
      expect(_toHex(derNull()), '0500');
    });

    test('what is written reads back', () {
      final reader = readSequence(
        derSequence([derInteger(BigInt.parse('123456789012345678901234567890')), derOctetString(List.filled(300, 7))]),
      );
      expect(reader.integer(), BigInt.parse('123456789012345678901234567890'));
      expect(reader.octetString(), List.filled(300, 7));
      reader.done();
    });
  });

  group('integers as bytes', () {
    test('go both ways, at the fewest bytes or a given length', () {
      expect(bytesToBigInt(const [0x01, 0x00]), BigInt.from(256));
      expect(bytesToBigInt(const []), BigInt.zero);
      expect(bigIntToBytes(BigInt.from(256)), [1, 0]);
      expect(bigIntToBytes(BigInt.zero), isEmpty);
      expect(bigIntToBytes(BigInt.from(256), 4), [0, 0, 1, 0]);
      expect(() => bigIntToBytes(BigInt.from(65536), 2), throwsArgumentError);
    });
  });

  group('the types certificates add', () {
    test('a SET is read, and written in the order of its encodings', () {
      expect(_toHex(derSet([derSmallInteger(2), derNull(), derSmallInteger(1)])), '31080201010201020500');
      final sorted = DerReader(
        derSet([
          derOctetString(const [9]),
          derSmallInteger(5),
        ]),
      ).set();
      expect(sorted.smallInteger(), 5);
      expect(sorted.octetString(), [9]);
      sorted.done();
      expect(() => DerReader(_hex('3000')).set(), _damaged);
    });

    test('a BOOLEAN round-trips, and is one byte of 00 or ff', () {
      expect(_toHex(derBoolean(true)), '0101ff');
      expect(_toHex(derBoolean(false)), '010100');
      expect(DerReader(derBoolean(true)).boolean(), isTrue);
      expect(DerReader(derBoolean(false)).boolean(), isFalse);
      expect(() => DerReader(_hex('0101 01')).boolean(), _damaged);
      expect(() => DerReader(_hex('0102 ffff')).boolean(), _damaged);
    });

    test('the string types round-trip or are read for display', () {
      expect(_toHex(derUtf8String('Zoé')), '0c045a6fc3a9');
      expect(DerReader(derUtf8String('Zoé Müller')).string(), 'Zoé Müller');
      expect(_toHex(derPrintableString('FR')), '13024652');
      expect(DerReader(derPrintableString("Ada O'Example (test)")).string(), "Ada O'Example (test)");
      expect(() => derPrintableString('ada@example.org'), throwsArgumentError);
      expect(() => derPrintableString('Zoé'), throwsArgumentError);
      expect(DerReader(_hex('1603 612e62')).string(), 'a.b');
      expect(DerReader(_hex('1403 5a6fe9')).string(), 'Zoé', reason: 'TeletexString, read as Latin-1');
      expect(DerReader(_hex('1e06 005a006f00e9')).string(), 'Zoé', reason: 'BMPString');
      expect(DerReader(_hex('1e03 005a00')).string(), 'Z', reason: 'an odd byte is dropped');
    });

    test('a string that is not what its type says is refused', () {
      expect(() => DerReader(_hex('0c02 c328')).string(), _damaged);
      expect(() => DerReader(_hex('1301 e9')).string(), _damaged);
      expect(() => DerReader(_hex('0401 41')).string(), _damaged);
    });

    test('UTCTime is written through 2049 and GeneralizedTime from 2050', () {
      expect(String.fromCharCodes(derTime(DateTime.utc(2049, 12, 31, 23, 59, 59)).sublist(2)), '491231235959Z');
      expect(derTime(DateTime.utc(2049, 12, 31, 23, 59, 59))[0], tagUtcTime);
      expect(String.fromCharCodes(derTime(DateTime.utc(2050)).sublist(2)), '20500101000000Z');
      expect(derTime(DateTime.utc(2050))[0], tagGeneralizedTime);
      expect(String.fromCharCodes(derUtcTime(DateTime.utc(2026, 11, 16, 9, 5, 7, 999)).sublist(2)), '261116090507Z');
      expect(() => derUtcTime(DateTime.utc(2050)), throwsArgumentError);
      expect(() => derUtcTime(DateTime.utc(1949, 12, 31)), throwsArgumentError);
    });

    test('a time in another zone is written in UTC', () {
      final local = DateTime.utc(2026, 11, 16, 9).toLocal();
      expect(String.fromCharCodes(derGeneralizedTime(local).sublist(2)), '20261116090000Z');
    });

    test('times round-trip, and two-digit years below 50 are in this century', () {
      for (final time in [
        DateTime.utc(1950),
        DateTime.utc(1999, 12, 31, 23, 59, 59),
        DateTime.utc(2026, 2, 28, 12),
        DateTime.utc(2090, 6, 1),
      ]) {
        expect(DerReader(derTime(time)).time(), time);
      }
      expect(DerReader(_hex('170d 3439313233313233353935395a')).time(), DateTime.utc(2049, 12, 31, 23, 59, 59));
      expect(DerReader(_hex('170d 3530303130313030303030305a')).time(), DateTime.utc(1950));
    });

    test('a time that is not DER, or not a time, is refused', () {
      List<int> utc(String text) => derTlv(tagUtcTime, text.codeUnits);
      List<int> general(String text) => derTlv(tagGeneralizedTime, text.codeUnits);
      for (final bad in [
        utc('2611160905Z'), // no seconds
        utc('261116090507+0100'), // an offset
        utc('261116090507'), // no Z
        utc('26111609050aZ'), // not digits
        utc('260230000000Z'), // 30 February
        utc('261116250000Z'), // hour 25
        general('20261116090507.5Z'), // a fraction
        general('261116090507Z'), // a short year
        derNull(),
      ]) {
        expect(() => DerReader(Uint8List.fromList(bad)).time(), _damaged, reason: String.fromCharCodes(bad.sublist(2)));
      }
    });

    test('rawInteger gives a serial number as it is, negative or not', () {
      expect(DerReader(_hex('0201 f6')).rawInteger(), [0xf6]);
      expect(DerReader(_hex('0203 00ff01')).rawInteger(), [0x00, 0xff, 0x01]);
      expect(() => DerReader(_hex('0200')).rawInteger(), _damaged);
      // integer() still refuses it
      expect(() => DerReader(_hex('0201 f6')).integer(), _damaged);
    });

    test('named bits are written without their trailing zeros, and read with their unused bits', () {
      expect(_toHex(derNamedBits({0})), '03020780');
      expect(_toHex(derNamedBits({0, 1})), '030206c0');
      expect(_toHex(derNamedBits({2})), '03020520');
      expect(_toHex(derNamedBits({4})), '03020308');
      expect(_toHex(derNamedBits({0, 8})), '0303078080');
      expect(_toHex(derNamedBits({})), '030100');
      final bits = DerReader(derNamedBits({0, 1})).bitStringWithUnused();
      expect(bits.bytes, [0xc0]);
      expect(bits.unused, 6);
      expect(DerReader(_hex('0301 00')).bitStringWithUnused().bytes, isEmpty);
      expect(() => DerReader(_hex('0302 0880')).bitStringWithUnused(), _damaged);
      expect(() => DerReader(_hex('0301 03')).bitStringWithUnused(), _damaged);
      expect(() => DerReader(_hex('0300')).bitStringWithUnused(), _damaged);
    });
  });
}
