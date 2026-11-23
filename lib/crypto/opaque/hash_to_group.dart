// `expand_message_xmd` with SHA-512 (RFC 9380 section 5.3.1), and the two
// hashes the ristretto255-SHA512 OPRF builds on it (RFC 9497 section 4.1):
//
//   HashToGroup(x)  = the element derivation function of RFC 9496 on
//                     expand_message_xmd(x, DST, 64), which is
//                     hash_to_ristretto255 of RFC 9380;
//   HashToScalar(x) = expand_message_xmd(x, DST, 64) as a 512-bit
//                     little-endian integer, reduced modulo the group order.
//
// The DST is a parameter, because the OPRF and OPAQUE use several.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'ristretto255.dart';
import 'scalar25519.dart';

const _hashLength = 64; // b_in_bytes, SHA-512's output
const _blockLength = 128; // r_in_bytes, SHA-512's block

/// `expand_message_xmd(msg, DST, len_in_bytes)` with SHA-512.
///
/// A [dst] over 255 bytes and an output over 255 blocks (or over 65535 bytes)
/// are refused; RFC 9380 hashes an oversize DST first, which no format here
/// needs.
Uint8List expandMessageXmdSha512(List<int> msg, List<int> dst, int lengthInBytes) {
  final ell = (lengthInBytes + _hashLength - 1) ~/ _hashLength;
  if (lengthInBytes <= 0 || lengthInBytes > 65535 || ell > 255) throw ArgumentError.value(lengthInBytes, 'lengthInBytes', 'out of range');
  if (dst.isEmpty || dst.length > 255) throw ArgumentError.value(dst.length, 'dst', 'expected 1 to 255 bytes');
  final dstPrime = concatBytes([
    dst,
    [dst.length],
  ]);
  final b0 = _sha512(
    concatBytes([
      Uint8List(_blockLength),
      msg,
      [lengthInBytes >> 8, lengthInBytes & 0xff],
      [0],
      dstPrime,
    ]),
  );
  var bi = _sha512(
    concatBytes([
      b0,
      [1],
      dstPrime,
    ]),
  );
  final out = BytesBuilder(copy: false)..add(bi);
  for (var i = 2; i <= ell; i++) {
    final x = Uint8List(_hashLength);
    for (var k = 0; k < _hashLength; k++) {
      x[k] = b0[k] ^ bi[k];
    }
    bi = _sha512(
      concatBytes([
        x,
        [i],
        dstPrime,
      ]),
    );
    out.add(bi);
  }
  return Uint8List.sublistView(out.takeBytes(), 0, lengthInBytes);
}

/// HashToGroup of RFC 9497 section 4.1 for ristretto255-SHA512: [msg] to an
/// element, under the domain separation tag [dst].
RistrettoPoint hashToGroup(List<int> msg, List<int> dst) => RistrettoPoint.fromUniformBytes(expandMessageXmdSha512(msg, dst, 64));

/// HashToScalar of RFC 9497 section 4.1 for ristretto255-SHA512: [msg] to a
/// canonical scalar, under the domain separation tag [dst].
Uint8List hashToScalar(List<int> msg, List<int> dst) => Scalar25519.reduce64(expandMessageXmdSha512(msg, dst, 64));

Uint8List _sha512(List<int> data) => Uint8List.fromList(hash.sha512.convert(data).bytes);
