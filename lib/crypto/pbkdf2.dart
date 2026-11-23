// PBKDF2-HMAC-SHA256, as WebCrypto derives the QR export key in
// `qrVault.ts` (200,000 rounds) and noble's scrypt wraps its mixing step
// (one round). SHA-256 is written out here so each round costs two
// compression calls on words already in place: the HMAC key's inner and
// outer blocks are hashed once, up front.

import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// PBKDF2 with HMAC-SHA256 (RFC 8018): [length] bytes from [password] and
/// [salt] after [iterations] rounds. The same bytes as WebCrypto's
/// `deriveBits` with `{ name: 'PBKDF2', hash: 'SHA-256' }` and noble's
/// `pbkdf2(sha256, ...)`.
Uint8List pbkdf2Sha256(List<int> password, List<int> salt, int iterations, int length) {
  if (iterations < 1) throw ArgumentError.value(iterations, 'iterations', 'must be at least 1');
  if (length < 1) throw ArgumentError.value(length, 'length', 'must be at least 1');

  // HMAC: a key longer than a block is hashed first, then zero-padded.
  final key = Uint8List(64)..setAll(0, password.length > 64 ? _sha256(password) : password);
  final inner = _midstate(key, 0x36);
  final outer = _midstate(key, 0x5c);

  // A 32-byte message after the 64-byte key block, padded: 0x80, zeros, and
  // the bit length 96 * 8 in the last word. Only words 0 to 7 change.
  final w = Uint32List(64);
  w[8] = 0x80000000;
  w[15] = 96 * 8;

  final u = Uint32List(8);
  final innerHash = Uint32List(8);
  final t = Uint32List(8);
  final out = Uint8List(length);
  for (var block = 1, pos = 0; pos < length; block++) {
    // U1 = HMAC(password, salt || INT(block))
    final first = Uint8List(salt.length + 4)
      ..setAll(0, salt)
      ..buffer.asByteData().setUint32(salt.length, block);
    _hashFrom(inner, 64, first, innerHash);
    w.setRange(0, 8, innerHash);
    _compress(outer, w, u);
    t.setAll(0, u);

    // U2 ... Uc, each HMAC(password, previous U)
    for (var round = 1; round < iterations; round++) {
      w.setRange(0, 8, u);
      _compress(inner, w, innerHash);
      w.setRange(0, 8, innerHash);
      _compress(outer, w, u);
      for (var i = 0; i < 8; i++) {
        t[i] ^= u[i];
      }
    }

    for (var i = 0; i < 32 && pos < length; i++, pos++) {
      out[pos] = t[i >> 2] >> (24 - ((i & 3) << 3));
    }
  }
  return out;
}

final _iv = Uint32List.fromList([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);

final _k = Uint32List.fromList([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, //
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/// The SHA-256 state after one block: the HMAC key XORed with [pad].
Uint32List _midstate(Uint8List key, int pad) {
  final w = Uint32List(64);
  for (var i = 0; i < 16; i++) {
    w[i] = ((key[4 * i] ^ pad) << 24) | ((key[4 * i + 1] ^ pad) << 16) | ((key[4 * i + 2] ^ pad) << 8) | (key[4 * i + 3] ^ pad);
  }
  final out = Uint32List(8);
  _compress(_iv, w, out);
  return out;
}

/// SHA-256 of [data].
Uint8List _sha256(List<int> data) {
  final h = Uint32List(8);
  _hashFrom(_iv, 0, data, h);
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = h[i >> 2] >> (24 - ((i & 3) << 3));
  }
  return out;
}

/// Finishes SHA-256 from [state], reached after [prefixLength] bytes (whole
/// blocks), over [data] and the padding, into [out].
void _hashFrom(Uint32List state, int prefixLength, List<int> data, Uint32List out) {
  final total = data.length + 9;
  final padded = Uint8List((total + 63) & ~63)..setAll(0, data);
  padded[data.length] = 0x80;
  final bits = (prefixLength + data.length) * 8;
  padded.buffer.asByteData()
    ..setUint32(padded.length - 8, bits ~/ 0x100000000)
    ..setUint32(padded.length - 4, bits & 0xffffffff);
  final view = padded.buffer.asByteData();
  final w = Uint32List(64);
  out.setAll(0, state);
  for (var offset = 0; offset < padded.length; offset += 64) {
    for (var i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + 4 * i);
    }
    _compress(out, w, out);
  }
}

/// One SHA-256 compression: [state] and the block in `w[0..15]` into [out]
/// ([out] may be [state]). Overwrites `w[16..63]` with the message schedule.
void _compress(Uint32List state, Uint32List w, Uint32List out) {
  for (var i = 16; i < 64; i++) {
    final w15 = w[i - 15];
    final w2 = w[i - 2];
    final s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3);
    final s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10);
    w[i] = s1 + w[i - 7] + s0 + w[i - 16];
  }
  var a = state[0], b = state[1], c = state[2], d = state[3];
  var e = state[4], f = state[5], g = state[6], h = state[7];
  for (var i = 0; i < 64; i++) {
    final s1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & 0xffffffff;
    final ch = g ^ (e & (f ^ g));
    final t1 = h + s1 + ch + _k[i] + w[i];
    final s0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & 0xffffffff;
    final maj = (a & b) | (c & (a | b));
    h = g;
    g = f;
    f = e;
    e = (d + t1) & 0xffffffff;
    d = c;
    c = b;
    b = a;
    a = (t1 + s0 + maj) & 0xffffffff;
  }
  out[0] = state[0] + a;
  out[1] = state[1] + b;
  out[2] = state[2] + c;
  out[3] = state[3] + d;
  out[4] = state[4] + e;
  out[5] = state[5] + f;
  out[6] = state[6] + g;
  out[7] = state[7] + h;
}

/// PBKDF2 with HMAC-SHA1 (RFC 8018): [length] bytes from [password] and
/// [salt] after [iterations] rounds. Only for what a protocol fixes it for:
/// a security key's code application derives its access key this way, with
/// 1000 rounds (openspec: add-security-key-codes, decision 8). Nothing of
/// Kemlock's own is protected by it.
Uint8List pbkdf2Sha1(List<int> password, List<int> salt, int iterations, int length) {
  if (iterations < 1) throw ArgumentError.value(iterations, 'iterations', 'must be at least 1');
  if (length < 1) throw ArgumentError.value(length, 'length', 'must be at least 1');
  final hmac = Hmac(sha1, password);
  final out = Uint8List(length);
  for (var block = 1, pos = 0; pos < length; block++) {
    var u = hmac.convert([...salt, block >> 24 & 0xff, block >> 16 & 0xff, block >> 8 & 0xff, block & 0xff]).bytes;
    final t = Uint8List.fromList(u);
    for (var round = 1; round < iterations; round++) {
      u = hmac.convert(u).bytes;
      for (var i = 0; i < t.length; i++) {
        t[i] ^= u[i];
      }
    }
    for (var i = 0; i < t.length && pos < length; i++, pos++) {
      out[pos] = t[i];
    }
  }
  return out;
}
