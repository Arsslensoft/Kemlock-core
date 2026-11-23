@TestOn('vm')
library;

// Armor for messages and signatures (RFC 9580 section 6).

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'stream_test.dart' show throwsPgp;

Uint8List _dearmor(String text, {int pieceSize = pgpPieceSize}) =>
    PgpReader(ArmorReader.open(PgpReader(BytesSource(Uint8List.fromList(latin1.encode(text)), pieceSize: pieceSize)))).rest(max: 1 << 24);

/// The tags of the packets in [data].
List<int> _tags(Uint8List data) {
  final reader = PacketReader(PgpReader.bytes(data));
  return [for (var p = reader.next(); p != null; p = reader.next()) p.tag];
}

void main() {
  final armored = pgpFixtureText('gnupg/armored.asc');
  final binary = _dearmor(armored);

  test('a message GnuPG armored holds its packets', () {
    expect(_tags(binary), [1, 18]);
    // What GnuPG's own CRC line says of the bytes
    final crcLine = RegExp(r'\n=([A-Za-z0-9+/]{4})\n').firstMatch(armored)!.group(1)!;
    final crc = crc24(binary);
    expect(base64.encode([crc >> 16, (crc >> 8) & 0xff, crc & 0xff]), crcLine);
  });

  test('LF and CR LF, and any piece size, give the same bytes', () {
    expect(_dearmor(armored.replaceAll('\n', '\r\n')), binary);
    for (final pieceSize in [1, 3, 64]) {
      expect(_dearmor(armored, pieceSize: pieceSize), binary);
    }
  });

  test('a missing CRC line and a wrong one are both read', () {
    final crcLine = RegExp(r'\n=[A-Za-z0-9+/]{4}\n').firstMatch(armored)!.group(0)!;
    expect(_dearmor(armored.replaceFirst(crcLine, '\n')), binary);
    expect(_dearmor(armored.replaceFirst(crcLine, '\n=AAAA\n')), binary);
  });

  test('Comment and Version headers', () {
    final text = pgpFixtureText('gnupg/armored-headers.asc');
    final armor = ArmorReader.open(PgpReader.bytes(Uint8List.fromList(latin1.encode(text))));
    expect(armor.type, pgpMessageBlock);
    expect(armor.headers.map((h) => h.$1), containsAll(['Version', 'Comment']));
    expect(armor.headers.firstWhere((h) => h.$1 == 'Comment').$2, 'a comment header');
    expect(_tags(PgpReader(armor).rest(max: 1 << 20)), [1, 18]);
  });

  test('the first block is found with other text around it', () {
    final mail = 'Hello,\n\nhere is the message:\n\n$armored\n-- \nsent from a phone\n';
    expect(_dearmor(mail), binary);
    expect(sniffArmor(Uint8List.fromList(utf8.encode(mail))).type, pgpMessageBlock);
    // Text that starts outside ASCII is still text
    expect(sniffArmor(Uint8List.fromList(utf8.encode('Élise écrit :\n$armored'))).type, pgpMessageBlock);
  });

  test('each block type is named', () {
    expect(sniffArmor(pgpFixture('gnupg/message.txt.ed25519.asc')).type, pgpSignatureBlock);
    expect(sniffArmor(pgpFixture('gnupg/clearsigned.asc')).type, pgpSignedMessageBlock);
    expect(sniffArmor(pgpFixture('rfc9580/a8-x25519-ocb.asc')).type, pgpMessageBlock);
    expect(sniffArmor(pgpFixture('gnupg/rsa1024.public.asc')).type, pgpPublicKeyBlock);
    expect(_tags(readArmorBlock(pgpFixture('gnupg/message.txt.ed25519.asc'), type: pgpSignatureBlock)), [2]);
    expect(() => readArmorBlock(pgpFixture('gnupg/armored.asc'), type: pgpSignatureBlock), throwsPgp(PgpProblem.notAMessage));
  });

  test('binary data is told from text', () {
    expect(sniffArmor(pgpFixture('gnupg/to-ed25519.seipd.gpg')).type, isNull);
    // A signed, uncompressed message whose text holds an armored block
    final inline = Uint8List.fromList([0x90, 0x0d, 3, 0, 10, 22, 0, 0, 0, 0, 0, 0, 0, 1, 1, ...utf8.encode('\n$armored')]);
    expect(sniffArmor(inline).type, isNull);
  });

  test('what is no message', () {
    expect(() => sniffArmor(Uint8List.fromList(utf8.encode('just some words\n'))), throwsPgp(PgpProblem.notAMessage));
    expect(() => sniffArmor(Uint8List(0)), throwsPgp(PgpProblem.notAMessage));
    expect(() => _dearmor('no armor here'), throwsPgp(PgpProblem.notAMessage));
  });

  test('one part of a multi-part message is refused by name', () {
    final part = armored.replaceAll('PGP MESSAGE-----', 'PGP MESSAGE, PART 1/2-----');
    expect(() => sniffArmor(Uint8List.fromList(latin1.encode(part))), throwsPgp(PgpProblem.unsupported, 'multi-part armor'));
    expect(() => _dearmor(part), throwsPgp(PgpProblem.unsupported, 'multi-part armor'));
  });

  test('broken armor is damaged', () {
    final lines = armored.split('\n');
    // No END line and no CRC: the block never ends
    expect(() => _dearmor(lines.take(4).join('\n')), throwsPgp(PgpProblem.damaged));
    expect(
      () => _dearmor(armored.replaceFirst(lines[2], '${lines[2].substring(0, 20)}*${lines[2].substring(21)}')),
      throwsPgp(PgpProblem.damaged),
    );
    expect(
      () => _dearmor('-----BEGIN PGP MESSAGE-----\nno colon here\n\nAAAA\n-----END PGP MESSAGE-----\n'),
      throwsPgp(PgpProblem.damaged),
    );
  });
}
