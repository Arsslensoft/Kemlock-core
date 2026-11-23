// bcrypt_pbkdf, the key derivation of protected OpenSSH private keys,
// ported from OpenBSD's `bcrypt_pbkdf.c` and the parts of `blowfish.c` it
// uses. pointycastle's Blowfish keeps its key schedule private, and bcrypt
// needs the salted "expensive" one, so Blowfish is written out here.
//
// Blowfish starts from the hexadecimal digits of pi: 18 words for P and
// 4 x 256 for the S-boxes. They are worked out once, with Machin's formula,
// instead of being pasted in as 1,042 constants; the tests check the first
// and last words against the published tables.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

const _mask32 = 0xffffffff;

/// P (words 0 to 17) then S0 to S3 (from word 18): the 1,042 words of pi's
/// fraction after "3.".
final Uint32List blowfishInitialState = _piFraction(18 + 1024);

/// The first [words] 32-bit words of pi's fractional part, from
/// pi = 16 arctan(1/5) - 4 arctan(1/239) in fixed point, with 64 guard
/// bits for the rounding of each term.
Uint32List _piFraction(int words) {
  final bits = words * 32 + 64;
  final one = BigInt.one << bits;
  BigInt arctanInverse(int x) {
    final x2 = BigInt.from(x * x);
    var power = one ~/ BigInt.from(x);
    var sum = power;
    for (var n = 3, sign = -1; power > BigInt.zero; n += 2, sign = -sign) {
      power ~/= x2;
      final term = power ~/ BigInt.from(n);
      sum = sign < 0 ? sum - term : sum + term;
    }
    return sum;
  }

  final pi = arctanInverse(5) * BigInt.from(16) - arctanInverse(239) * BigInt.from(4);
  var fraction = (pi - (BigInt.from(3) << bits)) >> 64;
  final out = Uint32List(words);
  final mask = BigInt.from(_mask32);
  for (var i = words - 1; i >= 0; i--) {
    out[i] = (fraction & mask).toInt();
    fraction >>= 32;
  }
  return out;
}

class _Blowfish {
  _Blowfish() {
    p.setAll(0, Uint32List.sublistView(blowfishInitialState, 0, 18));
    s.setAll(0, Uint32List.sublistView(blowfishInitialState, 18));
  }

  final p = Uint32List(18);
  final s = Uint32List(1024);

  int _f(int x) =>
      ((((s[x >>> 24] + s[256 + ((x >>> 16) & 0xff)]) & _mask32) ^ s[512 + ((x >>> 8) & 0xff)]) + s[768 + (x & 0xff)]) & _mask32;

  /// Encrypts the block in `data[i]`, `data[i + 1]` in place.
  void encipher(Uint32List data, int i) {
    var l = data[i] ^ p[0];
    var r = data[i + 1];
    for (var round = 1; round <= 16; round += 2) {
      r ^= _f(l) ^ p[round];
      l ^= _f(r) ^ p[round + 1];
    }
    data[i] = r ^ p[17];
    data[i + 1] = l;
  }

  /// Blowfish_expandstate: the key schedule, salted with [data].
  void expand(Uint8List data, Uint8List key) {
    final keyStream = _Stream(key);
    for (var i = 0; i < 18; i++) {
      p[i] ^= keyStream.next();
    }
    final dataStream = _Stream(data);
    final block = Uint32List(2);
    void fill(Uint32List table, int length) {
      for (var i = 0; i < length; i += 2) {
        block[0] ^= dataStream.next();
        block[1] ^= dataStream.next();
        encipher(block, 0);
        table[i] = block[0];
        table[i + 1] = block[1];
      }
    }

    fill(p, 18);
    fill(s, 1024);
  }

  /// Blowfish_expand0state: the plain key schedule.
  void expand0(Uint8List key) {
    final keyStream = _Stream(key);
    for (var i = 0; i < 18; i++) {
      p[i] ^= keyStream.next();
    }
    final block = Uint32List(2);
    for (var i = 0; i < 18; i += 2) {
      encipher(block, 0);
      p[i] = block[0];
      p[i + 1] = block[1];
    }
    for (var i = 0; i < 1024; i += 2) {
      encipher(block, 0);
      s[i] = block[0];
      s[i + 1] = block[1];
    }
  }
}

/// Blowfish_stream2word: big-endian words from [bytes], going round.
class _Stream {
  _Stream(this.bytes);

  final Uint8List bytes;
  int _pos = 0;

  int next() {
    var word = 0;
    for (var i = 0; i < 4; i++) {
      if (_pos >= bytes.length) _pos = 0;
      word = (word << 8) | bytes[_pos++];
    }
    return word;
  }
}

/// "OxychromaticBlowfishSwatDynamite", the text bcrypt encrypts.
final _magic = Uint8List.fromList('OxychromaticBlowfishSwatDynamite'.codeUnits);

/// bcrypt_hash: 32 bytes from the SHA-512 of the passphrase and of a salt.
Uint8List _bcryptHash(Uint8List sha2pass, Uint8List sha2salt) {
  final state = _Blowfish()..expand(sha2salt, sha2pass);
  for (var i = 0; i < 64; i++) {
    state
      ..expand0(sha2salt)
      ..expand0(sha2pass);
  }
  final stream = _Stream(_magic);
  final data = Uint32List.fromList([for (var i = 0; i < 8; i++) stream.next()]);
  for (var i = 0; i < 64; i++) {
    for (var block = 0; block < 8; block += 2) {
      state.encipher(data, block);
    }
  }
  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[4 * i] = data[i];
    out[4 * i + 1] = data[i] >>> 8;
    out[4 * i + 2] = data[i] >>> 16;
    out[4 * i + 3] = data[i] >>> 24;
  }
  return out;
}

/// bcrypt_pbkdf: [length] bytes from [passphrase] and [salt] after
/// [rounds] rounds, as OpenSSH derives the key and IV of a protected
/// private key. Throws an [ArgumentError] where OpenBSD's returns -1: an
/// empty passphrase or salt, no rounds, or more than 1024 bytes.
Uint8List bcryptPbkdf(List<int> passphrase, List<int> salt, int rounds, int length) {
  if (passphrase.isEmpty || salt.isEmpty || rounds < 1 || length < 1 || length > 1024) {
    throw ArgumentError('bcrypt_pbkdf: empty passphrase or salt, no rounds, or a bad length');
  }
  final stride = (length + 31) ~/ 32;
  var amount = (length + stride - 1) ~/ stride;
  final sha2pass = Uint8List.fromList(hash.sha512.convert(passphrase).bytes);
  final countSalt = Uint8List(salt.length + 4)..setAll(0, salt);
  final key = Uint8List(length);
  var left = length;
  for (var count = 1; left > 0; count++) {
    countSalt.buffer.asByteData().setUint32(salt.length, count);
    var tmp = _bcryptHash(sha2pass, Uint8List.fromList(hash.sha512.convert(countSalt).bytes));
    final out = Uint8List.fromList(tmp);
    for (var i = 1; i < rounds; i++) {
      tmp = _bcryptHash(sha2pass, Uint8List.fromList(hash.sha512.convert(tmp).bytes));
      for (var j = 0; j < 32; j++) {
        out[j] ^= tmp[j];
      }
    }
    // Spread the bytes out instead of putting them in order (OpenBSD's
    // "pbkdf2 deviation").
    if (amount > left) amount = left;
    var i = 0;
    for (; i < amount; i++) {
      final dest = i * stride + (count - 1);
      if (dest >= length) break;
      key[dest] = out[i];
    }
    left -= i;
  }
  return key;
}
