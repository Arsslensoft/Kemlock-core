// OpenPGP packets (RFC 9580 section 4): reading the packets of a key, in
// either header format, and writing them back. Every length is checked
// against what is left; partial lengths, which only data packets may use,
// are refused.

import 'dart:typed_data';

import '../key_error.dart';

/// Packet tags used by transferable keys and by messages.
abstract final class PgpTag {
  static const pkesk = 1;
  static const signature = 2;
  static const skesk = 3;
  static const onePassSignature = 4;
  static const secretKey = 5;
  static const publicKey = 6;
  static const secretSubkey = 7;
  static const compressedData = 8;

  /// Encrypted data with nothing against tampering: refused.
  static const encryptedData = 9;
  static const marker = 10;
  static const literalData = 11;
  static const trust = 12;
  static const userId = 13;
  static const publicSubkey = 14;
  static const userAttribute = 17;

  /// Symmetrically Encrypted and Integrity Protected Data, versions 1 and 2.
  static const seipd = 18;
  static const mdc = 19;

  /// GnuPG's OCB encrypted data packet (LibrePGP).
  static const ocbEncryptedData = 20;
  static const padding = 21;
}

/// One packet: its [tag], its [body], and [encoded], header and body as
/// they appeared. [oldFormat] says which header format it had.
class PgpPacket {
  const PgpPacket(this.tag, this.body, this.encoded, {required this.oldFormat});

  final int tag;
  final Uint8List body;
  final Uint8List encoded;
  final bool oldFormat;
}

/// The packets in [data], in order. Throws [KeyProblem.damaged] for a
/// header that isn't one, a length past the end, or a partial length.
List<PgpPacket> readPackets(Uint8List data) {
  checkSize(data.length);
  final packets = <PgpPacket>[];
  var pos = 0;
  while (pos < data.length) {
    final start = pos;
    final ctb = data[pos++];
    check(ctb & 0x80 != 0, 'OpenPGP: not a packet header');
    final oldFormat = ctb & 0x40 == 0;
    final int tag;
    final int length;
    if (oldFormat) {
      tag = (ctb >> 2) & 0x0f;
      switch (ctb & 3) {
        case 0:
          check(data.length - pos >= 1, 'OpenPGP: cut short');
          length = data[pos++];
        case 1:
          check(data.length - pos >= 2, 'OpenPGP: cut short');
          length = (data[pos] << 8) | data[pos + 1];
          pos += 2;
        case 2:
          check(data.length - pos >= 4, 'OpenPGP: cut short');
          length = _uint32(data, pos);
          pos += 4;
        default:
          // Indeterminate: to the end of the data.
          length = data.length - pos;
      }
    } else {
      tag = ctb & 0x3f;
      check(data.length - pos >= 1, 'OpenPGP: cut short');
      final first = data[pos++];
      if (first < 192) {
        length = first;
      } else if (first < 224) {
        check(data.length - pos >= 1, 'OpenPGP: cut short');
        length = ((first - 192) << 8) + data[pos++] + 192;
      } else if (first == 255) {
        check(data.length - pos >= 4, 'OpenPGP: cut short');
        length = _uint32(data, pos);
        pos += 4;
      } else {
        throw const KeyFormatException(KeyProblem.damaged, 'OpenPGP: partial length in a key');
      }
    }
    check(length <= data.length - pos, 'OpenPGP: length past the end');
    packets.add(
      PgpPacket(
        tag,
        Uint8List.sublistView(data, pos, pos + length),
        Uint8List.sublistView(data, start, pos + length),
        oldFormat: oldFormat,
      ),
    );
    pos += length;
  }
  return packets;
}

int _uint32(Uint8List data, int pos) => (data[pos] << 24) | (data[pos + 1] << 16) | (data[pos + 2] << 8) | data[pos + 3];

/// A packet with [tag] and [body]: in the old header format, with the
/// shortest length that fits, when [oldFormat] (GnuPG writes key, user ID
/// and signature packets so); otherwise in the new format.
Uint8List writePacket(int tag, List<int> body, {bool oldFormat = false}) {
  final length = body.length;
  final List<int> header;
  if (oldFormat && tag < 16) {
    final base = 0x80 | (tag << 2);
    header = length < 0x100
        ? [base, length]
        : length < 0x10000
        ? [base | 1, length >> 8, length & 0xff]
        : [base | 2, ..._be32(length)];
  } else {
    header = length < 192
        ? [0xc0 | tag, length]
        : length < 8384
        ? [0xc0 | tag, ((length - 192) >> 8) + 192, (length - 192) & 0xff]
        : [0xc0 | tag, 0xff, ..._be32(length)];
  }
  return Uint8List(header.length + length)
    ..setAll(0, header)
    ..setAll(header.length, body);
}

List<int> _be32(int v) => [v >>> 24 & 0xff, v >>> 16 & 0xff, v >>> 8 & 0xff, v & 0xff];
