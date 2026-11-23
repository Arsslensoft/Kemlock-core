@TestOn('vm')
library;

// BZip2 is unpacked into memory whole, so its bound must not grow with the
// message as the bound of ZIP and ZLIB does.
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:kemlock_core/crypto/keys/openpgp/message.dart' show maxBzip2Output, maxUnpackedSize;
import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'decrypt_test.dart' show throwsProblem;

/// A packet of [tag] in the new format, with a five-octet length.
Uint8List _packet(int tag, List<int> body) {
  final n = body.length;
  return Uint8List.fromList([0xc0 | tag, 0xff, n >> 24 & 0xff, n >> 16 & 0xff, n >> 8 & 0xff, n & 0xff, ...body]);
}

/// A message that is one compressed packet (BZip2) of a literal packet of [size] zero bytes.
Uint8List _zeros(int size) {
  final literal = _packet(11, Uint8List(6 + size)..[0] = 0x62);
  return _packet(8, [3, ...BZip2Encoder().encodeBytes(literal)]);
}

void main() {
  test('a small BZip2 message that unpacks to more than the bound is refused, not unpacked', () async {
    final message = _zeros(maxBzip2Output + 1024);
    // A few hundred bytes, which the bound that grows with the message would let unpack to more
    expect(message.length, lessThan(1 << 20));
    expect(maxUnpackedSize(message.length), greaterThan(maxBzip2Output + 1024));

    await expectLater(verify(signed: PgpData.bytes(message)), throwsProblem(PgpProblem.tooLarge));
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a BZip2 message within the bound is still read', () async {
    // No signature in it: read to the end, and then said to hold none
    await expectLater(verify(signed: PgpData.bytes(_zeros(100000))), throwsProblem(PgpProblem.notAMessage));
  });
}
