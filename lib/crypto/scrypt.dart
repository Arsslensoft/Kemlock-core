// scrypt (RFC 7914), as `@noble/hashes/scrypt.js` derives the vault key in
// `crypto.ts` with N=2^17, r=8, p=1. The structure follows noble's: PBKDF2
// fills the blocks, ROMix walks them with BlockMix over Salsa20/8 on 32-bit
// words, and a last PBKDF2 round makes the key. At N=2^17 it fills 128 MB.

import 'dart:typed_data';

import 'pbkdf2.dart';

/// noble's default memory limit: 128 * r * (N + p + 1) bytes for N=2^20, r=8.
const _maxMemory = 128 * 8 * ((1 << 20) + 2);

/// scrypt of [password] and [salt] to [length] bytes, the same bytes as
/// noble's `scrypt(password, salt, { N: n, r, p, dkLen: length })`.
///
/// Throws an [ArgumentError] for parameters noble refuses: [n] not a power
/// of two from 2 to 2^32, [r] or [p] below 1 (or [p] too large), [length]
/// below 1, or more than noble's 1 GiB memory limit.
Uint8List scrypt(List<int> password, List<int> salt, {required int n, required int r, required int p, int length = 32}) {
  if (r < 1) throw ArgumentError.value(r, 'r', 'must be at least 1');
  if (n <= 1 || (n & (n - 1)) != 0 || n > 0x100000000) {
    throw ArgumentError.value(n, 'n', 'must be a power of 2 from 2 to 2^32');
  }
  final blockSize = 128 * r;
  if (p < 1 || p > (0xffffffff * 32) / blockSize) throw ArgumentError.value(p, 'p', 'out of range');
  if (length < 1 || length > 0xffffffff * 32) throw ArgumentError.value(length, 'length', 'out of range');
  if (blockSize * (n + p + 1) > _maxMemory) throw ArgumentError('scrypt: more than 1 GiB of memory for n=$n, r=$r, p=$p');

  // B = PBKDF2-HMAC-SHA256(password, salt, 1, p * 128 * r), read as
  // little-endian 32-bit words.
  final b = pbkdf2Sha256(password, salt, 1, blockSize * p);
  final words = blockSize ~/ 4;
  final b32 = Uint32List(words * p);
  final bytes = ByteData.sublistView(b);
  for (var i = 0; i < b32.length; i++) {
    b32[i] = bytes.getUint32(4 * i, Endian.little);
  }

  final v = Uint32List(words * n);
  final tmp = Uint32List(words);
  for (var block = 0; block < p; block++) {
    final start = block * words;
    // V[0] = B; V[i] = BlockMix(V[i - 1]); X = BlockMix(V[N - 1])
    v.setRange(0, words, b32, start);
    for (var i = 0, pos = 0; i < n - 1; i++, pos += words) {
      _blockMix(v, pos, v, pos + words, r);
    }
    _blockMix(v, (n - 1) * words, b32, start, r);
    // X = BlockMix(X ^ V[Integerify(X) mod N]); Integerify only needs the
    // low word of the last 64-byte block, since N is a power of two.
    final last = start + words - 16;
    for (var i = 0; i < n; i++) {
      final j = (b32[last] & (n - 1)) * words;
      for (var k = 0; k < words; k++) {
        tmp[k] = b32[start + k] ^ v[j + k];
      }
      _blockMix(tmp, 0, b32, start, r);
    }
  }

  final mixed = Uint8List(blockSize * p);
  final mixedBytes = ByteData.sublistView(mixed);
  for (var i = 0; i < b32.length; i++) {
    mixedBytes.setUint32(4 * i, b32[i], Endian.little);
  }
  final key = pbkdf2Sha256(password, mixed, 1, length);
  // Wipe the working memory, as noble does.
  v.fillRange(0, v.length, 0);
  tmp.fillRange(0, tmp.length, 0);
  b32.fillRange(0, b32.length, 0);
  b.fillRange(0, b.length, 0);
  mixed.fillRange(0, mixed.length, 0);
  return key;
}

/// BlockMix (RFC 7914 section 4) of the 2r 64-byte blocks at [input][ii]
/// into [out][oi], the even outputs first, then the odd ones, as noble lays
/// them out. [out] must not overlap the input.
void _blockMix(Uint32List input, int ii, Uint32List out, int oi, int r) {
  var head = oi;
  var tail = oi + 16 * r;
  // X = B[2r - 1], kept where the first odd output goes.
  out.setRange(tail, tail + 16, input, ii + (2 * r - 1) * 16);
  for (var i = 0; i < r; i++, head += 16, ii += 32) {
    _xorSalsa8(out, tail, input, ii, out, head); // Y[2i] = Salsa(X ^ B[2i])
    if (i > 0) tail += 16;
    _xorSalsa8(out, head, input, ii + 16, out, tail); // Y[2i+1] = Salsa(Y[2i] ^ B[2i+1])
  }
}

/// Salsa20/8 of the XOR of the 16 words at [prev][pi] and [input][ii], into
/// [out][oi]. The words sit in 64-bit ints; only the low 32 bits count, and
/// each sum is masked before it is rotated.
void _xorSalsa8(Uint32List prev, int pi, Uint32List input, int ii, Uint32List out, int oi) {
  final y00 = prev[pi] ^ input[ii], y01 = prev[pi + 1] ^ input[ii + 1];
  final y02 = prev[pi + 2] ^ input[ii + 2], y03 = prev[pi + 3] ^ input[ii + 3];
  final y04 = prev[pi + 4] ^ input[ii + 4], y05 = prev[pi + 5] ^ input[ii + 5];
  final y06 = prev[pi + 6] ^ input[ii + 6], y07 = prev[pi + 7] ^ input[ii + 7];
  final y08 = prev[pi + 8] ^ input[ii + 8], y09 = prev[pi + 9] ^ input[ii + 9];
  final y10 = prev[pi + 10] ^ input[ii + 10], y11 = prev[pi + 11] ^ input[ii + 11];
  final y12 = prev[pi + 12] ^ input[ii + 12], y13 = prev[pi + 13] ^ input[ii + 13];
  final y14 = prev[pi + 14] ^ input[ii + 14], y15 = prev[pi + 15] ^ input[ii + 15];
  var x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07;
  var x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  int t;
  for (var i = 0; i < 8; i += 2) {
    // Columns
    t = (x00 + x12) & 0xffffffff;
    x04 ^= (t << 7) | (t >> 25);
    t = (x04 + x00) & 0xffffffff;
    x08 ^= (t << 9) | (t >> 23);
    t = (x08 + x04) & 0xffffffff;
    x12 ^= (t << 13) | (t >> 19);
    t = (x12 + x08) & 0xffffffff;
    x00 ^= (t << 18) | (t >> 14);
    t = (x05 + x01) & 0xffffffff;
    x09 ^= (t << 7) | (t >> 25);
    t = (x09 + x05) & 0xffffffff;
    x13 ^= (t << 9) | (t >> 23);
    t = (x13 + x09) & 0xffffffff;
    x01 ^= (t << 13) | (t >> 19);
    t = (x01 + x13) & 0xffffffff;
    x05 ^= (t << 18) | (t >> 14);
    t = (x10 + x06) & 0xffffffff;
    x14 ^= (t << 7) | (t >> 25);
    t = (x14 + x10) & 0xffffffff;
    x02 ^= (t << 9) | (t >> 23);
    t = (x02 + x14) & 0xffffffff;
    x06 ^= (t << 13) | (t >> 19);
    t = (x06 + x02) & 0xffffffff;
    x10 ^= (t << 18) | (t >> 14);
    t = (x15 + x11) & 0xffffffff;
    x03 ^= (t << 7) | (t >> 25);
    t = (x03 + x15) & 0xffffffff;
    x07 ^= (t << 9) | (t >> 23);
    t = (x07 + x03) & 0xffffffff;
    x11 ^= (t << 13) | (t >> 19);
    t = (x11 + x07) & 0xffffffff;
    x15 ^= (t << 18) | (t >> 14);
    // Rows
    t = (x00 + x03) & 0xffffffff;
    x01 ^= (t << 7) | (t >> 25);
    t = (x01 + x00) & 0xffffffff;
    x02 ^= (t << 9) | (t >> 23);
    t = (x02 + x01) & 0xffffffff;
    x03 ^= (t << 13) | (t >> 19);
    t = (x03 + x02) & 0xffffffff;
    x00 ^= (t << 18) | (t >> 14);
    t = (x05 + x04) & 0xffffffff;
    x06 ^= (t << 7) | (t >> 25);
    t = (x06 + x05) & 0xffffffff;
    x07 ^= (t << 9) | (t >> 23);
    t = (x07 + x06) & 0xffffffff;
    x04 ^= (t << 13) | (t >> 19);
    t = (x04 + x07) & 0xffffffff;
    x05 ^= (t << 18) | (t >> 14);
    t = (x10 + x09) & 0xffffffff;
    x11 ^= (t << 7) | (t >> 25);
    t = (x11 + x10) & 0xffffffff;
    x08 ^= (t << 9) | (t >> 23);
    t = (x08 + x11) & 0xffffffff;
    x09 ^= (t << 13) | (t >> 19);
    t = (x09 + x08) & 0xffffffff;
    x10 ^= (t << 18) | (t >> 14);
    t = (x15 + x14) & 0xffffffff;
    x12 ^= (t << 7) | (t >> 25);
    t = (x12 + x15) & 0xffffffff;
    x13 ^= (t << 9) | (t >> 23);
    t = (x13 + x12) & 0xffffffff;
    x14 ^= (t << 13) | (t >> 19);
    t = (x14 + x13) & 0xffffffff;
    x15 ^= (t << 18) | (t >> 14);
  }
  // Storing into the Uint32List keeps the low 32 bits.
  out[oi] = y00 + x00;
  out[oi + 1] = y01 + x01;
  out[oi + 2] = y02 + x02;
  out[oi + 3] = y03 + x03;
  out[oi + 4] = y04 + x04;
  out[oi + 5] = y05 + x05;
  out[oi + 6] = y06 + x06;
  out[oi + 7] = y07 + x07;
  out[oi + 8] = y08 + x08;
  out[oi + 9] = y09 + x09;
  out[oi + 10] = y10 + x10;
  out[oi + 11] = y11 + x11;
  out[oi + 12] = y12 + x12;
  out[oi + 13] = y13 + x13;
  out[oi + 14] = y14 + x14;
  out[oi + 15] = y15 + x15;
}
