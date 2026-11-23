@TestOn('vm')
library;

// CFB as a stream, OCB, EAX, GCM and the chunked AEAD forms, against RFC
// 7253's vectors, RFC 9580's sample packets and GnuPG's files.

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/modes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'stream_test.dart' show throwsPgp;

Uint8List _counting(int length, [int from = 0]) => Uint8List.fromList([for (var i = 0; i < length; i++) (from + i) & 0xff]);

/// The body of the first packet with [tag] in a fixture, armored or not.
Uint8List packetBody(String fixture, int tag) {
  var data = pgpFixture(fixture);
  if (fixture.endsWith('.asc')) data = readArmorBlock(data);
  final reader = PacketReader(PgpReader.bytes(data));
  for (var p = reader.next(); p != null; p = reader.next()) {
    if (p.tag == tag) return p.body.rest(max: 1 << 24);
  }
  throw StateError('no packet $tag in $fixture');
}

Uint8List _all(ByteSource source) => PgpReader(source).rest(max: 1 << 24);

/// The RFC's samples: the session key, and the message key and IV its
/// HKDF must give.
const _rfc = {
  'rfc9580/a8-x25519-ocb.asc': ('dd708f6fa1ed65114d68d2343e7c2f1d', '4512f7149d863341527c6567d5bffc42', '5faf3250212ff9'),
  'rfc9580/a9-skesk6-eax.asc': ('3881bafe985412459b86c36f98cb9a5e', 'b50422ac1c26be9ddd831d5bbb36b64f', '78b833f2e94a60c0'),
  'rfc9580/a10-skesk6-ocb.asc': ('28e79ab82397d3c63de24ac217d7b791', '71662a11ee5b4e08144e6de883a00999', null),
  'rfc9580/a11-skesk6-gcm.asc': ('1936fc8568980274bb900d8319360c77', 'ea1438803cb8a47740ce9b54c338778d', '4d2bdc2b'),
};

/// What A.8 to A.11 decrypt to: a literal data packet, then padding.
final _helloWorld = unhex('cb1362000000000048656c6c6f2c20776f726c6421');

void main() {
  group('CFB with the SEIPD version 1 prefix and MDC', () {
    final key = _counting(32, 7);
    final prefix = _counting(16, 100);
    final text = Uint8List.fromList(utf8.encode('The quick brown fox jumps over the lazy dog, twice over.'));

    Uint8List write(Uint8List plain, {int pieceSize = 1 << 20}) {
      final out = BytesSink();
      final writer = Seipd1Writer(key, prefix, out);
      for (var pos = 0; pos < plain.length; pos += pieceSize) {
        writer.add(Uint8List.sublistView(plain, pos, pos + pieceSize > plain.length ? plain.length : pos + pieceSize));
      }
      writer.close();
      return out.takeBytes();
    }

    test('the stream gives what cfb gives on the same bytes', () {
      final written = write(text);
      expect(written[0], 1);
      // The plain text the cipher runs over: prefix, its last two bytes
      // again, the text and the MDC packet. The MDC is the last 22 bytes.
      final plain = cfb(false, key, Uint8List(16), Uint8List.sublistView(written, 1));
      expect(plain.sublist(0, 18), [...prefix, prefix[14], prefix[15]]);
      expect(plain.sublist(18, plain.length - 22), text);
      expect(plain.sublist(plain.length - 22, plain.length - 20), [0xd3, 0x14]);
      expect(cfb(true, key, Uint8List(16), plain), written.sublist(1));
    });

    test('data fed in pieces of 1 and 4096 bytes gives the same result', () {
      final long = _counting(20000);
      final whole = write(long);
      expect(write(long, pieceSize: 1), whole);
      expect(write(long, pieceSize: 4096), whole);
      for (final pieceSize in [1, 4096, 65536]) {
        final source = BytesSource(Uint8List.sublistView(whole, 1), pieceSize: pieceSize);
        expect(_all(Seipd1Reader(key, source)), long, reason: 'pieces of $pieceSize');
      }
    });

    test('an empty text', () {
      expect(_all(Seipd1Reader(key, BytesSource(Uint8List.sublistView(write(Uint8List(0)), 1)))), isEmpty);
    });

    test('a changed byte fails the MDC', () {
      final written = write(text);
      for (final at in [20, written.length ~/ 2, written.length - 1]) {
        final changed = Uint8List.fromList(written)..[at] ^= 1;
        expect(() => _all(Seipd1Reader(key, BytesSource(Uint8List.sublistView(changed, 1)))), throwsPgp(PgpProblem.damaged));
      }
      // Cut short
      expect(
        () => _all(Seipd1Reader(key, BytesSource(Uint8List.sublistView(written, 1, written.length - 5)))),
        throwsPgp(PgpProblem.damaged),
      );
      expect(() => _all(Seipd1Reader(key, BytesSource(Uint8List.sublistView(written, 1, 10)))), throwsPgp(PgpProblem.damaged));
    });

    test('a wrong key is told by the prefix', () {
      final written = write(text);
      final wrong = Uint8List.fromList(key)..[0] ^= 1;
      expect(
        () => _all(Seipd1Reader(wrong, BytesSource(Uint8List.sublistView(written, 1)), wrongKeyIs: PgpProblem.wrongPassphrase)),
        throwsPgp(PgpProblem.wrongPassphrase),
      );
    });
  });

  group('the AES block', () {
    // FIPS 197 appendix C: the plain text 00112233...ff under the keys 000102...
    final plain = unhex('00112233445566778899aabbccddeeff');
    for (final (bits, expected) in [
      (128, '69c4e0d86a7b0430d8cdb78070b4c55a'),
      (192, 'dda97ca4864cdfe06eaf70a0ec0d7191'),
      (256, '8ea2b7ca516745bfeafc49904b496089'),
    ]) {
      test('AES-$bits encrypts and decrypts the vector of FIPS 197', () {
        final aes = AesBlock(_counting(bits ~/ 8));
        expect(hexOf(aes.encrypted(plain)), expected);
        // At an offset, into an offset, and back
        final input = Uint8List.fromList([9, 9, 9, ...plain]);
        final out = Uint8List(20);
        aes.encrypt(input, 3, out, 4);
        expect(hexOf(out.sublist(4)), expected);
        final back = Uint8List(16);
        aes.decrypt(out, 4, back, 0);
        expect(back, plain);
        // In place
        aes.encrypt(back, 0, back, 0);
        expect(hexOf(back), expected);
      });
    }
  });

  group('OCB', () {
    // RFC 7253 appendix A: key 000102...0F, a 96-bit nonce that counts up,
    // a 128-bit tag
    final ocb = Ocb(_counting(16));
    Uint8List nonce(int n) => unhex('BBAA998877665544332211${n.toRadixString(16).padLeft(2, '0')}');
    final vectors = [
      (0, 0, 0, '785407BFFFC8AD9EDCC5520AC9111EE6'),
      (1, 8, 8, '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'),
      (2, 8, 0, '81017F8203F081277152FADE694A0A00'),
      (3, 0, 8, '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'),
      (4, 16, 16, '571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358'),
      (5, 16, 0, '8CF761B6902EF764462AD86498CA6B97'),
      (6, 0, 16, '5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D'),
      (7, 24, 24, '1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F'),
      (8, 24, 0, '6DC225A071FC1B9F7C69F93B0F1E10DE'),
      (9, 0, 24, '221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF'),
      (10, 32, 32, 'BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240'),
      (11, 32, 0, 'FE80690BEE8A485D11F32965BC9D2A32'),
      (12, 0, 32, '2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF'),
    ];

    test('the vectors of RFC 7253 appendix A', () {
      for (final (n, adLength, plainLength, expected) in vectors) {
        final sealed = ocb.seal(nonce(n), _counting(plainLength), _counting(adLength));
        expect(hexOf(sealed).toUpperCase(), expected, reason: 'nonce $n');
        expect(ocb.open(nonce(n), sealed, _counting(adLength)), _counting(plainLength));
      }
    });

    // RFC 7253 appendix A's last test, run for each key length with a
    // 128-bit tag: 384 encryptions under one key, then their tag
    for (final (bits, expected) in [
      (128, '67E944D23256C5E0B6C61FA22FDF1EA2'),
      (192, 'F673F2C3E7174AAE7BAE986CA9F29E17'),
      (256, 'D90EB8E9C977C88B79DD793D7FFA161C'),
    ]) {
      test('the iterated vector of RFC 7253 appendix A for AES-$bits', () {
        final ocb = Ocb(Uint8List(bits ~/ 8)..[bits ~/ 8 - 1] = 128);
        Uint8List n(int i) => Uint8List(12)..buffer.asByteData().setUint32(8, i);
        final c = BytesBuilder();
        for (var i = 0; i < 128; i++) {
          final s = Uint8List(i);
          c
            ..add(ocb.seal(n(3 * i + 1), s, s))
            ..add(ocb.seal(n(3 * i + 2), s, Uint8List(0)))
            ..add(ocb.seal(n(3 * i + 3), Uint8List(0), s));
        }
        expect(hexOf(ocb.seal(n(385), Uint8List(0), c.takeBytes())).toUpperCase(), expected);
      });
    }

    test('AES-256 with the 15-byte nonce of OpenPGP seals what it opens', () {
      final ocb = Ocb(_counting(32, 1));
      final nonce = _counting(15, 50);
      final sealed = ocb.seal(nonce, _counting(1000), _counting(13));
      expect(sealed, hasLength(1016));
      expect(ocb.open(nonce, sealed, _counting(13)), _counting(1000));
    });

    test('a changed tag, text, header or nonce fails', () {
      final sealed = ocb.seal(nonce(1), _counting(40), _counting(8));
      expect(ocb.open(nonce(1), Uint8List.fromList(sealed)..[sealed.length - 1] ^= 1, _counting(8)), isNull);
      expect(ocb.open(nonce(1), Uint8List.fromList(sealed)..[3] ^= 1, _counting(8)), isNull);
      expect(ocb.open(nonce(1), sealed, _counting(9)), isNull);
      expect(ocb.open(nonce(2), sealed, _counting(8)), isNull);
      expect(ocb.open(nonce(1), Uint8List(15), _counting(8)), isNull);
    });
  });

  group('the chunks of RFC 9580', () {
    for (final MapEntry(key: file, value: (sessionKey, messageKey, iv)) in _rfc.entries) {
      test('$file: HKDF, then the chunk', () {
        final packet = packetBody(file, 18);
        expect(packet[0], 2);
        final info = [0xd2, ...packet.sublist(0, 4)];
        final aeadId = packet[2];
        final nonceLength = Aead(aeadId, Uint8List(16)).nonceLength;
        final derived = hkdfSha256(unhex(sessionKey), salt: packet.sublist(4, 36), info: info, length: 16 + nonceLength - 8);
        expect(hexOf(derived.sublist(0, 16)), messageKey);
        if (iv != null) expect(hexOf(derived.sublist(16)), iv);

        final aead = Aead(aeadId, derived.sublist(0, 16));
        final nonce = Uint8List.fromList([...derived.sublist(16), 0, 0, 0, 0, 0, 0, 0, 0]);
        // One chunk and its tag, then the final tag
        final chunk = Uint8List.sublistView(packet, 36, packet.length - 16);
        final plain = aead.open(nonce, chunk, Uint8List.fromList(info))!;
        expect(plain.sublist(0, _helloWorld.length), _helloWorld);
        expect(plain.sublist(_helloWorld.length, _helloWorld.length + 2), [0xd5, 0x0e]);
        // Sealing it again gives the RFC's bytes
        expect(aead.seal(nonce, plain, Uint8List.fromList(info)), chunk);
        expect(aead.open(nonce, Uint8List.fromList(chunk)..[chunk.length - 1] ^= 1, Uint8List.fromList(info)), isNull);
        expect(aead.open(nonce, Uint8List.fromList(chunk)..[0] ^= 1, Uint8List.fromList(info)), isNull);
      });

      test('$file: the packet decrypts to the text', () {
        final packet = packetBody(file, 18);
        final plain = _all(AeadChunkReader.seipd2(PgpReader.bytes(Uint8List.sublistView(packet, 1)), unhex(sessionKey)));
        expect(plain.sublist(0, _helloWorld.length), _helloWorld);
        expect(utf8.decode(plain.sublist(8, _helloWorld.length)), 'Hello, world!');
      });
    }

    test('a chunk size octet above 16 is refused by name', () {
      final packet = Uint8List.fromList(packetBody('rfc9580/a8-x25519-ocb.asc', 18))..[3] = 17;
      expect(
        () => AeadChunkReader.seipd2(PgpReader.bytes(Uint8List.sublistView(packet, 1)), unhex(_rfc.values.first.$1)),
        throwsPgp(PgpProblem.unsupported, 'AEAD chunks over 4 MiB'),
      );
    });

    test('an unknown mode and cipher are refused by name', () {
      final packet = packetBody('rfc9580/a8-x25519-ocb.asc', 18);
      final key = unhex(_rfc.values.first.$1);
      expect(
        () => AeadChunkReader.seipd2(PgpReader.bytes(Uint8List.fromList(packet.sublist(1))..[1] = 9), key),
        throwsPgp(PgpProblem.unsupported, 'AEAD mode 9'),
      );
      expect(
        () => AeadChunkReader.seipd2(PgpReader.bytes(Uint8List.fromList(packet.sublist(1))..[0] = 3), key),
        throwsPgp(PgpProblem.unsupported, 'CAST5'),
      );
    });

    test('the final tag guards the end', () {
      final packet = packetBody('rfc9580/a9-skesk6-eax.asc', 18);
      final key = unhex(_rfc['rfc9580/a9-skesk6-eax.asc']!.$1);
      Uint8List read(Uint8List body) => _all(AeadChunkReader.seipd2(PgpReader.bytes(body), key));
      // Without the final tag, with a changed one, and with nothing
      expect(() => read(Uint8List.sublistView(packet, 1, packet.length - 16)), throwsPgp(PgpProblem.damaged));
      expect(() => read(Uint8List.fromList(packet.sublist(1))..[packet.length - 2] ^= 1), throwsPgp(PgpProblem.damaged));
      expect(() => read(Uint8List.sublistView(packet, 1, 36)), throwsPgp(PgpProblem.damaged));
    });
  });

  group("GnuPG's OCB packet in sixteen chunks", () {
    final packet = packetBody('gnupg/chunks.ocb.gpg', 20);
    final key = gnupgSessionKey('chunks.ocb.gpg').key;
    const chunk = 65536 + 16;
    // Version, cipher, mode, chunk size octet and a 15-byte IV
    const head = 19;

    Uint8List read(Uint8List body, {int pieceSize = pgpPieceSize}) =>
        _all(AeadChunkReader.ocbPacket(PgpReader(BytesSource(Uint8List.sublistView(body, 1), pieceSize: pieceSize)), key));

    test('it is what the notes say', () {
      expect(packet.sublist(0, 4), [1, 9, 2, 10]);
      // A literal data header in partial lengths, then the megabyte
      expect(packet.length, greaterThan(head + 16 * chunk + 16));
    });

    test('it decrypts, whatever the piece size', () {
      final plain = read(packet);
      expect(plain.length, greaterThan(1048576));
      expect(read(packet, pieceSize: 1000), plain);
      // The megabyte is inside, after the literal data packet's header
      final sample = sampleBytes(1048576);
      expect(plain.sublist(plain.length - 1000), isNot(sample.sublist(sample.length - 1000)), reason: 'partial lengths lie between');
      expect(hexOf(plain).contains(hexOf(sample.sublist(0, 512))), isTrue);
    });

    test('dropping the last chunk fails', () {
      // The last chunk is the short one, before the final tag
      final lastStart = head + ((packet.length - head - 16) ~/ chunk) * chunk;
      final dropped = Uint8List.fromList([...packet.sublist(0, lastStart), ...packet.sublist(packet.length - 16)]);
      expect(() => read(dropped), throwsPgp(PgpProblem.damaged));
    });

    test('swapping two chunks fails', () {
      final swapped = Uint8List.fromList(packet)
        ..setRange(head, head + chunk, packet, head + chunk)
        ..setRange(head + chunk, head + 2 * chunk, packet, head);
      expect(() => read(swapped), throwsPgp(PgpProblem.damaged));
    });

    test('truncating at a chunk boundary fails', () {
      expect(() => read(Uint8List.sublistView(packet, 0, head + 3 * chunk)), throwsPgp(PgpProblem.damaged));
      expect(() => read(Uint8List.sublistView(packet, 0, head + 3 * chunk + 16)), throwsPgp(PgpProblem.damaged));
    });

    test('one changed byte fails', () {
      for (final at in [head + 5, head + 5 * chunk + 9, packet.length - 3]) {
        expect(() => read(Uint8List.fromList(packet)..[at] ^= 0x40), throwsPgp(PgpProblem.damaged));
      }
    });
  });
}
