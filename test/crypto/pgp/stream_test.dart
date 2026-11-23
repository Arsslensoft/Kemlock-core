@TestOn('vm')
library;

// Packets read and written in pieces (RFC 9580 section 4.2).

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

Matcher throwsPgp(PgpProblem problem, [Object? detail]) =>
    throwsA(isA<PgpException>().having((e) => e.problem, 'problem', problem).having((e) => e.detail, 'detail', detail ?? anything));

Uint8List _body(int length) => Uint8List.fromList([for (var i = 0; i < length; i++) (i * 7 + 3) & 0xff]);

/// The packets of [data], each body read whole.
List<(int, Uint8List)> _read(Uint8List data, {int pieceSize = pgpPieceSize}) {
  final reader = PacketReader(PgpReader(BytesSource(data, pieceSize: pieceSize)));
  return [for (var p = reader.next(); p != null; p = reader.next()) (p.tag, p.body.rest(max: 1 << 24))];
}

void main() {
  group('headers', () {
    final body = _body(300);
    Uint8List packet(List<int> header, [int? length]) => Uint8List.fromList([...header, ...body.sublist(0, length ?? body.length)]);

    test('every length form of both formats', () {
      final cases = {
        'old, one octet': packet([0x80 | (11 << 2), 100], 100),
        'old, two octets': packet([0x80 | (11 << 2) | 1, 0x01, 0x2c]),
        'old, four octets': packet([0x80 | (11 << 2) | 2, 0, 0, 0x01, 0x2c]),
        'old, to the end': packet([0x80 | (11 << 2) | 3]),
        'new, one octet': packet([0xc0 | 11, 100], 100),
        'new, two octets': packet([0xc0 | 11, 192, 108]),
        'new, five octets': packet([0xc0 | 11, 255, 0, 0, 0x01, 0x2c]),
      };
      for (final MapEntry(key: name, value: data) in cases.entries) {
        final (tag, read) = _read(data).single;
        expect(tag, 11, reason: name);
        expect(read, name.contains('one octet') ? body.sublist(0, 100) : body, reason: name);
      }
    });

    test('partial lengths are joined', () {
      final big = _body(2000);
      // 1024, 512, then a last piece of 464 in two octets
      final data = Uint8List.fromList([
        0xc0 | 11,
        224 + 10,
        ...big.sublist(0, 1024),
        224 + 9,
        ...big.sublist(1024, 1536),
        192 + ((464 - 192) >> 8),
        (464 - 192) & 0xff,
        ...big.sublist(1536),
        // and a second packet after it
        0xc0 | 2,
        3,
        1,
        2,
        3,
      ]);
      for (final pieceSize in [1, 7, 65536]) {
        final packets = _read(data, pieceSize: pieceSize);
        expect(packets.map((p) => p.$1), [11, 2], reason: 'pieces of $pieceSize');
        expect(packets[0].$2, big);
        expect(packets[1].$2, [1, 2, 3]);
      }
    });

    test('a body the caller did not read is skipped', () {
      final data = Uint8List.fromList([0xc0 | 11, 3, 1, 2, 3, 0xc0 | 2, 1, 9]);
      final reader = PacketReader(PgpReader.bytes(data));
      expect(reader.next()!.tag, 11);
      final second = reader.next()!;
      expect(second.tag, 2);
      expect(second.body.rest(max: 10), [9]);
      expect(reader.next(), isNull);
    });

    test('a first partial piece under 512 bytes is refused', () {
      final data = Uint8List.fromList([0xc0 | 11, 224 + 8, ..._body(256), 0]);
      expect(() => _read(data), throwsPgp(PgpProblem.damaged));
    });

    test('partial lengths are for data packets only', () {
      final data = Uint8List.fromList([0xc0 | 2, 224 + 9, ..._body(512), 0]);
      expect(() => _read(data), throwsPgp(PgpProblem.damaged));
    });

    test('a length past the end, a cut header and a byte that is no header', () {
      expect(() => _read(Uint8List.fromList([0xc0 | 11, 10, 1, 2, 3])), throwsPgp(PgpProblem.damaged));
      expect(() => _read(Uint8List.fromList([0xc0 | 11])), throwsPgp(PgpProblem.damaged));
      expect(() => _read(Uint8List.fromList([0xc0 | 11, 255, 0, 0])), throwsPgp(PgpProblem.damaged));
      expect(() => _read(Uint8List.fromList([0x41, 1, 2])), throwsPgp(PgpProblem.damaged));
      expect(() => _read(Uint8List.fromList([0xc0 | 11, 224 + 9, ..._body(100)])), throwsPgp(PgpProblem.damaged));
    });
  });

  group('the writer', () {
    for (final length in [0, 1, 191, 192, 8383, 8384, 65536, 200000]) {
      test('$length bytes, with and without a known length', () {
        final body = _body(length);
        for (final known in [true, false]) {
          final out = BytesSink();
          final writer = PacketWriter(out, 11, length: known ? length : null);
          // Given in uneven pieces
          for (var pos = 0; pos < length; pos += 5000) {
            writer.add(Uint8List.sublistView(body, pos, pos + 5000 > length ? length : pos + 5000));
          }
          writer.close();
          final written = out.takeBytes();
          final (tag, read) = _read(written).single;
          expect(tag, 11);
          expect(read, body, reason: known ? 'definite' : 'partial');
          // A body over 64 KiB with no known length goes out in partial pieces
          if (!known && length > 65536) expect(written[1], 0xf0);
          if (known || length <= 65536) expect(written[1], isNot(0xf0));
        }
      });
    }

    test('a known length must be kept', () {
      final writer = PacketWriter(BytesSink(), 11, length: 4)..add(Uint8List(3));
      expect(writer.close, throwsStateError);
    });
  });

  test('the reader gives counts across pieces', () {
    final reader = PgpReader(BytesSource(_body(100), pieceSize: 7));
    expect(reader.peek(), 3);
    expect(reader.bytes(20), _body(100).sublist(0, 20));
    expect(reader.uint16(), (_body(100)[20] << 8) | _body(100)[21]);
    expect(reader.rest(max: 100), _body(100).sublist(22));
    expect(reader.atEnd, isTrue);
    expect(() => PgpReader.bytes(Uint8List(5)).bytes(6), throwsPgp(PgpProblem.damaged));
    expect(() => PgpReader.bytes(Uint8List(50)).rest(max: 49), throwsPgp(PgpProblem.tooLarge));
  });

  test('a count far past the end is cut short, and sets nothing aside for it', () {
    // A length the data gives, as a Kyber session key packet's four bytes do:
    // more than any phone holds, and here more than a list may be
    for (final count in [0xffffffff, 1 << 40]) {
      final reader = PgpReader(BytesSource(_body(100), pieceSize: 7));
      expect(() => reader.bytes(count), throwsPgp(PgpProblem.damaged, 'cut short'), reason: '$count');
    }
    // Across pieces it still gives exactly what was asked
    final reader = PgpReader(BytesSource(_body(100), pieceSize: 7));
    expect(reader.bytes(99), _body(100).sublist(0, 99));
    expect(reader.bytes(1), [_body(100)[99]]);
  });

  test('GnuPG wrote the large fixture in partial lengths', () {
    final reader = PacketReader(PgpReader.bytes(pgpFixture('gnupg/large.gpg')));
    final pkesk = reader.next()!;
    expect((pkesk.tag, pkesk.partial), (1, false));
    final seipd = reader.next()!;
    expect((seipd.tag, seipd.partial), (18, true));
    // The version octet, an 18-byte prefix, the literal data in partial
    // lengths of its own and the 22-byte MDC
    expect(seipd.body.rest(max: 6 << 20).length, greaterThan(5242880 + 41));
    expect(reader.next(), isNull);
  });
}
