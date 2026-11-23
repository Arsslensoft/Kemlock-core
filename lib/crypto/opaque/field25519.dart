// Arithmetic in the field of integers modulo p = 2^255 - 19, the base field of
// Curve25519 and so of ristretto255 (RFC 9496).
//
// An element is ten signed limbs in radix 2^25.5, the representation of
// ref10 and SUPERCOP (limb i is 26 bits wide for even i and 25 for odd i),
// held in an Int64List. A product of two limbs is under 2^52, and ten of them,
// with the 19 and 2 factors, stay under 2^63, so Dart's 64-bit `int` never
// overflows (on the VM and under dart2wasm; not under dart2js, which has no
// 64-bit integers and is not a target). Every operation carries its result back
// to tight limbs, so any result may be an operand.
//
// Constant time, as far as Dart integers allow: no operation branches on the
// value of an element, indexes memory by one or exits a loop early; the loops
// run for counts fixed by the representation, and a choice between two values
// is made with a mask (`select`). The comparison functions return 0 or 1 as an
// `int`, not a `bool`, so the caller can keep combining them with `|` and
// masks. Dart makes no promise about the timing of `int` multiplication or
// shifts, and a JIT or the garbage collector may leave copies of limbs in
// memory; the code can't wipe them. That is the limit of "constant time" here.

library;

import 'dart:typed_data';

/// The width in bits of each limb.
const _width = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25];

/// The bit at which each limb starts: ceil(25.5 * i).
const _offset = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230];

/// An element of GF(2^255 - 19).
final class Fe {
  Fe._(this._l);

  /// A small non-negative integer, under 2^25.
  factory Fe.small(int value) {
    if (value < 0 || value >= (1 << 25)) throw ArgumentError.value(value, 'value', 'does not fit one limb');
    final l = Int64List(10)..[0] = value;
    return Fe._(l);
  }

  /// The 32 little-endian bytes as an integer of 255 bits: the top bit of the
  /// last byte is ignored, and a value of p or more is accepted and acts as
  /// its residue, as RFC 7748 and RFC 9496 section 4.3.4 read field elements.
  factory Fe.fromBytes(List<int> bytes) {
    if (bytes.length != 32) throw ArgumentError.value(bytes.length, 'bytes', 'a field element is 32 bytes');
    final l = Int64List(10);
    for (var i = 0; i < 10; i++) {
      var limb = 0;
      for (var k = 0; k < _width[i]; k++) {
        final bit = _offset[i] + k;
        if (bit < 255) limb |= ((bytes[bit >> 3] >> (bit & 7)) & 1) << k;
      }
      l[i] = limb;
    }
    return Fe._(l);
  }

  /// A public constant, from its integer value. Not for secrets: [BigInt] is
  /// not constant-time.
  factory Fe.fromBigInt(BigInt value) {
    final p = (BigInt.one << 255) - BigInt.from(19);
    var n = value % p;
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = (n & BigInt.from(0xff)).toInt();
      n >>= 8;
    }
    return Fe.fromBytes(bytes);
  }

  final Int64List _l;

  static final Fe zero = Fe.small(0);
  static final Fe one = Fe.small(1);

  Fe operator +(Fe other) {
    final h = Int64List(10);
    for (var i = 0; i < 10; i++) {
      h[i] = _l[i] + other._l[i];
    }
    return Fe._(_carry(h));
  }

  Fe operator -(Fe other) {
    final h = Int64List(10);
    for (var i = 0; i < 10; i++) {
      h[i] = _l[i] - other._l[i];
    }
    return Fe._(_carry(h));
  }

  Fe operator -() {
    final h = Int64List(10);
    for (var i = 0; i < 10; i++) {
      h[i] = -_l[i];
    }
    return Fe._(_carry(h));
  }

  /// The product. Limb `i` of one times limb `j` of the other has weight
  /// 2^(ceil(25.5 i) + ceil(25.5 j)), which is that of limb `i + j`, doubled
  /// when both indices are odd, and, from limb 10 up, wraps to limb `i + j - 10`
  /// times 19 because 2^255 = 19 (mod p).
  Fe operator *(Fe other) {
    final f = _l;
    final g = other._l;
    final h = Int64List(10);
    for (var i = 0; i < 10; i++) {
      for (var j = 0; j < 10; j++) {
        var t = f[i] * g[j];
        if ((i & j & 1) == 1) t *= 2;
        final k = i + j;
        if (k >= 10) {
          h[k - 10] += t * 19;
        } else {
          h[k] += t;
        }
      }
    }
    return Fe._(_carry(h));
  }

  /// This element squared.
  Fe square() => this * this;

  /// This element squared [times] times.
  Fe squareTimes(int times) {
    var r = this;
    for (var i = 0; i < times; i++) {
      r = r.square();
    }
    return r;
  }

  /// This element to the power (p - 5) / 8 = 2^252 - 3, by the addition chain
  /// of ref10's `fe_pow22523`. The exponent is public, so the chain is too.
  Fe pow22523() {
    final z = this;
    var t0 = z.square(); // z^2
    var t1 = t0.square().square(); // z^8
    t1 = z * t1; // z^9
    t0 = t0 * t1; // z^11
    t0 = t0.square(); // z^22
    t0 = t1 * t0; // z^31 = z^(2^5 - 1)
    t1 = t0.squareTimes(5);
    t0 = t1 * t0; // z^(2^10 - 1)
    t1 = t0.squareTimes(10);
    t1 = t1 * t0; // z^(2^20 - 1)
    var t2 = t1.squareTimes(20);
    t1 = t2 * t1; // z^(2^40 - 1)
    t1 = t1.squareTimes(10);
    t0 = t1 * t0; // z^(2^50 - 1)
    t1 = t0.squareTimes(50);
    t1 = t1 * t0; // z^(2^100 - 1)
    t2 = t1.squareTimes(100);
    t1 = t2 * t1; // z^(2^200 - 1)
    t1 = t1.squareTimes(50);
    t0 = t1 * t0; // z^(2^250 - 1)
    t0 = t0.squareTimes(2); // z^(2^252 - 4)
    return t0 * z; // z^(2^252 - 3)
  }

  /// The canonical 32-byte little-endian encoding: the residue between 0 and
  /// p - 1, found by a fixed sequence of carries, with no comparison to p.
  Uint8List toBytes() {
    final h = Int64List.fromList(_l);
    var q = (19 * h[9] + (1 << 24)) >> 25;
    for (var i = 0; i < 10; i++) {
      q = (h[i] + q) >> _width[i];
    }
    // q is 1 when the value is p or more, else 0: add 19q and drop 2^255 q
    h[0] += 19 * q;
    for (var i = 0; i < 9; i++) {
      final c = h[i] >> _width[i];
      h[i + 1] += c;
      h[i] -= c << _width[i];
    }
    h[9] -= (h[9] >> 25) << 25;
    final out = Uint8List(32);
    for (var i = 0; i < 10; i++) {
      for (var k = 0; k < _width[i]; k++) {
        final bit = _offset[i] + k;
        out[bit >> 3] |= ((h[i] >> k) & 1) << (bit & 7);
      }
    }
    return out;
  }

  /// 1 when the canonical encoding is odd ("negative" in RFC 9496), else 0.
  int get isNegative => toBytes()[0] & 1;

  /// 1 when this element is zero, else 0.
  int get isZero => eq(zero);

  /// 1 when this element and [other] are equal, else 0.
  int eq(Fe other) {
    final a = toBytes();
    final b = other.toBytes();
    var difference = 0;
    for (var i = 0; i < 32; i++) {
      difference |= a[i] ^ b[i];
    }
    // difference is 0..255: 0 gives 1, the rest give 0
    return ((difference - 1) >> 8) & 1;
  }

  /// The non-negative one of this element and its negation (RFC 9496 CT_ABS).
  Fe abs() => Fe.select(isNegative, -this, this);

  /// [ifOne] when [condition] is 1, else [ifZero]; [condition] must be 0 or 1.
  static Fe select(int condition, Fe ifOne, Fe ifZero) {
    final mask = -condition;
    final h = Int64List(10);
    for (var i = 0; i < 10; i++) {
      h[i] = ifZero._l[i] ^ (mask & (ifOne._l[i] ^ ifZero._l[i]));
    }
    return Fe._(h);
  }
}

/// Carries [h] back to tight limbs (|limb| about 2^25 or 2^24), in ref10's
/// order, so that no step overflows or leaves a limb out of range.
Int64List _carry(Int64List h) {
  var c = (h[0] + (1 << 25)) >> 26;
  h[1] += c;
  h[0] -= c << 26;
  c = (h[4] + (1 << 25)) >> 26;
  h[5] += c;
  h[4] -= c << 26;
  c = (h[1] + (1 << 24)) >> 25;
  h[2] += c;
  h[1] -= c << 25;
  c = (h[5] + (1 << 24)) >> 25;
  h[6] += c;
  h[5] -= c << 25;
  c = (h[2] + (1 << 25)) >> 26;
  h[3] += c;
  h[2] -= c << 26;
  c = (h[6] + (1 << 25)) >> 26;
  h[7] += c;
  h[6] -= c << 26;
  c = (h[3] + (1 << 24)) >> 25;
  h[4] += c;
  h[3] -= c << 25;
  c = (h[7] + (1 << 24)) >> 25;
  h[8] += c;
  h[7] -= c << 25;
  c = (h[4] + (1 << 25)) >> 26;
  h[5] += c;
  h[4] -= c << 26;
  c = (h[8] + (1 << 25)) >> 26;
  h[9] += c;
  h[8] -= c << 26;
  c = (h[9] + (1 << 24)) >> 25;
  h[0] += c * 19;
  h[9] -= c << 25;
  c = (h[0] + (1 << 25)) >> 26;
  h[1] += c;
  h[0] -= c << 26;
  return h;
}
