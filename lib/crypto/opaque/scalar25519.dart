// Scalars of the ristretto255 group: integers modulo the group order
// l = 2^252 + 27742317777372353535851937790883648493 (RFC 9496 section 4.4),
// as 32 little-endian bytes.
//
// A scalar is eleven limbs of 24 bits while it is worked on. The two
// operations that need the order, adding modulo l and then selecting, are the
// only ones: a product is built bit by bit, with every step run whatever the
// bit is and the result chosen by a mask, and a 64-byte hash is reduced the
// same way. So no step branches on a scalar, and the loops run for counts that
// are fixed (253 bits per product, 512 per reduction). That is slow, about a
// hundred milliseconds for an inversion, and it is run twice per sign-in.
// Dart makes no promise about the timing of `int` operations, and the runtime
// may leave copies of limbs in memory; the code can't wipe them.

library;

import 'dart:typed_data';

import '../bytes.dart';

const _limbs = 11;
const _limbMask = 0xffffff;

final BigInt _order = (BigInt.one << 252) + BigInt.parse('27742317777372353535851937790883648493');

/// The order as limbs.
final Int64List _orderLimbs = _limbsOfBigInt(_order);

/// The bits of l - 2, most significant first, the exponent of an inversion
/// (Fermat). The exponent is public.
final List<int> _inverseExponentBits = [for (var i = 252; i >= 0; i--) ((_order - BigInt.two) >> i).isOdd ? 1 : 0];

Int64List _limbsOfBigInt(BigInt value) {
  final l = Int64List(_limbs);
  var n = value;
  for (var i = 0; i < _limbs; i++) {
    l[i] = (n & BigInt.from(_limbMask)).toInt();
    n >>= 24;
  }
  return l;
}

/// Arithmetic on scalars of the ristretto255 group, as 32 little-endian bytes.
abstract final class Scalar25519 {
  /// The length of a scalar.
  static const length = 32;

  /// Whether [bytes] (32 little-endian bytes) are a canonical scalar: below
  /// l, which also needs the top three bits to be zero (RFC 9497 section 4.1,
  /// `DeserializeScalar`).
  static bool isCanonical(List<int> bytes) {
    if (bytes.length != length) return false;
    final a = _fromBytes(bytes);
    // a - l: a borrow out means a < l
    var borrow = 0;
    for (var i = 0; i < _limbs; i++) {
      final t = a[i] - _orderLimbs[i] - borrow;
      borrow = (t >> 24) & 1;
    }
    return borrow == 1;
  }

  /// 1 when the scalar is zero, else 0. [a] must be canonical.
  static int isZero(List<int> a) {
    var any = 0;
    for (final b in a) {
      any |= b;
    }
    return ((any - 1) >> 8) & 1;
  }

  /// The 64 little-endian bytes as a 512-bit integer, reduced modulo l
  /// (RFC 9497 `HashToScalar`'s last step, and RFC 8032's way of making a
  /// scalar from a hash). The result is canonical.
  static Uint8List reduce64(List<int> bytes) {
    if (bytes.length != 64) throw ArgumentError.value(bytes.length, 'bytes', 'expected 64 bytes');
    var r = Int64List(_limbs);
    final one = _limbsOfBigInt(BigInt.one);
    for (var i = 511; i >= 0; i--) {
      r = _addMod(r, r);
      final t = _addMod(r, one);
      final bit = (bytes[i >> 3] >> (i & 7)) & 1;
      r = _select(bit, t, r);
    }
    return _toBytes(r);
  }

  /// A uniformly random scalar, below l (RFC 9497 section 4.7.2): 64 random
  /// bytes reduced modulo l. It may be zero, with probability about 2^-252;
  /// [randomNonZero] retries.
  static Uint8List random() {
    final bytes = randomBytes(64);
    try {
      return reduce64(bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }

  /// A uniformly random non-zero scalar.
  static Uint8List randomNonZero() {
    while (true) {
      final s = random();
      if (isZero(s) == 0) return s;
    }
  }

  /// `a * b` modulo l. Both must be canonical.
  static Uint8List multiply(List<int> a, List<int> b) {
    _requireCanonical(a);
    _requireCanonical(b);
    return _toBytes(_mulMod(_fromBytes(a), _fromBytes(b)));
  }

  /// `a^-1` modulo l, as `a^(l-2)`. [a] must be canonical, and non-zero for a
  /// meaningful answer; zero gives zero.
  static Uint8List invert(List<int> a) {
    _requireCanonical(a);
    final x = _fromBytes(a);
    var r = _limbsOfBigInt(BigInt.one);
    for (final bit in _inverseExponentBits) {
      r = _mulMod(r, r);
      if (bit == 1) r = _mulMod(r, x);
    }
    return _toBytes(r);
  }
}

void _requireCanonical(List<int> bytes) {
  if (!Scalar25519.isCanonical(bytes)) throw ArgumentError('not a canonical scalar');
}

/// 33 bytes (the 32 given and a zero) as eleven limbs of 24 bits.
Int64List _fromBytes(List<int> bytes) {
  final l = Int64List(_limbs);
  for (var i = 0; i < 33; i++) {
    final v = i < bytes.length ? bytes[i] : 0;
    l[i ~/ 3] |= v << (8 * (i % 3));
  }
  return l;
}

Uint8List _toBytes(Int64List limbs) {
  final out = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    out[i] = (limbs[i ~/ 3] >> (8 * (i % 3))) & 0xff;
  }
  return out;
}

/// `(a + b) mod l` for a and b below l: add, subtract l, and keep the
/// difference unless it borrowed.
Int64List _addMod(Int64List a, Int64List b) {
  final s = Int64List(_limbs);
  var carry = 0;
  for (var i = 0; i < _limbs; i++) {
    final t = a[i] + b[i] + carry;
    s[i] = t & _limbMask;
    carry = t >> 24;
  }
  final d = Int64List(_limbs);
  var borrow = 0;
  for (var i = 0; i < _limbs; i++) {
    final t = s[i] - _orderLimbs[i] - borrow;
    d[i] = t & _limbMask;
    borrow = (t >> 24) & 1;
  }
  return _select(borrow, s, d);
}

/// [ifOne] when [condition] is 1, else [ifZero].
Int64List _select(int condition, Int64List ifOne, Int64List ifZero) {
  final mask = -condition;
  final out = Int64List(_limbs);
  for (var i = 0; i < _limbs; i++) {
    out[i] = ifZero[i] ^ (mask & (ifOne[i] ^ ifZero[i]));
  }
  return out;
}

/// `a * b mod l` by doubling and adding over the 253 bits of b, most
/// significant first: every step is done, and the bit only picks the result.
Int64List _mulMod(Int64List a, Int64List b) {
  var r = Int64List(_limbs);
  for (var i = 252; i >= 0; i--) {
    r = _addMod(r, r);
    final t = _addMod(r, a);
    final bit = (b[i ~/ 24] >> (i % 24)) & 1;
    r = _select(bit, t, r);
  }
  return r;
}
