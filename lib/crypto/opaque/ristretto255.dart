// The ristretto255 prime-order group, RFC 9496, on the Curve25519 points of
// field25519.dart: encode, decode, equality, the element derivation function
// and addition and scalar multiplication on the internal representation.
//
// A point is held as extended twisted Edwards coordinates (x, y, z, t) with
// x * y = z * t. Addition is the unified formula of Hisil, Wong, Carter and
// Dawson (2008, "add-2008-hwcd-3" for a = -1), which is complete on this curve,
// so it also doubles and has no exceptional inputs: no branch on whether two
// points are equal, opposite or the identity. Scalar multiplication is
// double-and-add over all 256 bits of the scalar with a masked choice, so its
// operations do not depend on the scalar. Dart makes no promise about the
// timing of `int` operations and can't wipe limbs; see field25519.dart.
//
// Decoding refuses an encoding with a non-canonical or negative field element,
// a non-square, a negative t or a y of zero (RFC 9496 section 4.3.1). Those
// branches depend on the peer's bytes, which are public.

library;

import 'dart:typed_data';

import 'field25519.dart';

// The implementation constants of RFC 9496 section 4.1.
final Fe _d = Fe.fromBigInt(BigInt.parse('37095705934669439343138083508754565189542113879843219016388785533085940283555'));
final Fe _d2 = _d + _d;
final Fe _sqrtM1 = Fe.fromBigInt(BigInt.parse('19681161376707505956807079304988542015446066515923890162744021073123829784752'));
final Fe _sqrtAdMinusOne = Fe.fromBigInt(BigInt.parse('25063068953384623474111414158702152701244531502492656460079210482610430750235'));
final Fe _invsqrtAMinusD = Fe.fromBigInt(BigInt.parse('54469307008909316920995813868745141605393597292927456921205312896311721017578'));
final Fe _oneMinusDSq = Fe.fromBigInt(BigInt.parse('1159843021668779879193775521855586647937357759715417654439879720876111806838'));
final Fe _dMinusOneSq = Fe.fromBigInt(BigInt.parse('40440834346308536858101042469323190826248399146238708352240133220865137265952'));

/// SQRT_RATIO_M1(u, v) of RFC 9496 section 4.2:
///
/// - (1, +sqrt(u/v)) if u and v are nonzero and u/v is square;
/// - (1, 0) if u is zero;
/// - (0, 0) if v is zero and u is not;
/// - (0, +sqrt(SQRT_M1 * (u/v))) if u and v are nonzero and u/v is not square.
///
/// `wasSquare` is 1 or 0, and `root` is the non-negative root. Exposed for the
/// RFC's vectors; the group needs nothing else of it.
({int wasSquare, Fe root}) sqrtRatioM1(Fe u, Fe v) {
  final v3 = v.square() * v;
  final v7 = v3.square() * v;
  var r = (u * v3) * (u * v7).pow22523();
  final check = v * r.square();
  final correctSign = check.eq(u);
  final flippedSign = check.eq(-u);
  final flippedSignI = check.eq(-u * _sqrtM1);
  final rPrime = _sqrtM1 * r;
  r = Fe.select(flippedSign | flippedSignI, rPrime, r);
  r = r.abs();
  return (wasSquare: correctSign | flippedSign, root: r);
}

/// An element of the ristretto255 group.
final class RistrettoPoint {
  RistrettoPoint._(this._x, this._y, this._z, this._t);

  final Fe _x;
  final Fe _y;
  final Fe _z;
  final Fe _t;

  /// The length of an encoded element.
  static const encodedLength = 32;

  /// The identity element.
  static final RistrettoPoint identity = RistrettoPoint._(Fe.zero, Fe.one, Fe.one, Fe.zero);

  /// The canonical generator, whose encoding RFC 9496 section 4 gives.
  static final RistrettoPoint generator = decode(_hexBytes('e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76'))!;

  /// Decodes 32 bytes (RFC 9496 section 4.3.1), or gives null when they are
  /// not the canonical encoding of an element.
  static RistrettoPoint? decode(List<int> bytes) {
    if (bytes.length != encodedLength) return null;
    final s = Fe.fromBytes(bytes);
    // A non-canonical value, one of p or more or with the top bit set, does not
    // survive the trip back to bytes. Public input, so a branch is fine.
    if (!_sameBytes(s.toBytes(), bytes) || s.isNegative == 1) return null;
    final ss = s.square();
    final u1 = Fe.one - ss;
    final u2 = Fe.one + ss;
    final u2Sqr = u2.square();
    final v = -(_d * u1.square()) - u2Sqr;
    final (:wasSquare, root: invsqrt) = sqrtRatioM1(Fe.one, v * u2Sqr);
    final denX = invsqrt * u2;
    final denY = invsqrt * denX * v;
    final x = ((s + s) * denX).abs();
    final y = u1 * denY;
    final t = x * y;
    if (wasSquare == 0 || t.isNegative == 1 || y.isZero == 1) return null;
    return RistrettoPoint._(x, y, Fe.one, t);
  }

  /// The element derivation function of RFC 9496 section 4.3.4 on 64 bytes:
  /// the two halves are mapped (MAP) and added.
  static RistrettoPoint fromUniformBytes(List<int> bytes) {
    if (bytes.length != 64) throw ArgumentError.value(bytes.length, 'bytes', 'expected 64 bytes');
    return _map(bytes.sublist(0, 32)) + _map(bytes.sublist(32, 64));
  }

  /// The encoding of this element (RFC 9496 section 4.3.2), 32 bytes.
  Uint8List encode() {
    final u1 = (_z + _y) * (_z - _y);
    final u2 = _x * _y;
    // Ignore was_square: it is always square here
    final invsqrt = sqrtRatioM1(Fe.one, u1 * u2.square()).root;
    final den1 = invsqrt * u1;
    final den2 = invsqrt * u2;
    final zInv = den1 * den2 * _t;
    final ix0 = _x * _sqrtM1;
    final iy0 = _y * _sqrtM1;
    final enchantedDenominator = den1 * _invsqrtAMinusD;
    final rotate = (_t * zInv).isNegative;
    final x = Fe.select(rotate, iy0, _x);
    var y = Fe.select(rotate, ix0, _y);
    final denInv = Fe.select(rotate, enchantedDenominator, den2);
    y = Fe.select((x * zInv).isNegative, -y, y);
    return (denInv * (_z - y)).abs().toBytes();
  }

  /// 1 when [other] is the same element, else 0 (RFC 9496 section 4.3.3).
  int equals(RistrettoPoint other) => (_x * other._y).eq(_y * other._x) | (_y * other._y).eq(_x * other._x);

  /// Whether this is the identity element.
  bool get isIdentity => equals(identity) == 1;

  /// The sum of two elements.
  RistrettoPoint operator +(RistrettoPoint other) {
    final a = (_y - _x) * (other._y - other._x);
    final b = (_y + _x) * (other._y + other._x);
    final c = _t * _d2 * other._t;
    final dd = _z * other._z;
    final d = dd + dd;
    final e = b - a;
    final f = d - c;
    final g = d + c;
    final h = b + a;
    return RistrettoPoint._(e * f, g * h, f * g, e * h);
  }

  /// The opposite element.
  RistrettoPoint operator -() => RistrettoPoint._(-_x, _y, _z, -_t);

  /// This element times the scalar given as 32 little-endian bytes (below the
  /// group order, though only its 256 bits matter). For every bit, most
  /// significant first, it doubles and adds, and the bit chooses which result
  /// goes on, by a mask, so what the code does doesn't depend on the scalar.
  RistrettoPoint multiply(List<int> scalar) {
    if (scalar.length != 32) throw ArgumentError.value(scalar.length, 'scalar', 'expected 32 bytes');
    var acc = identity;
    for (var i = 255; i >= 0; i--) {
      acc = acc + acc;
      final bit = (scalar[i >> 3] >> (i & 7)) & 1;
      acc = _select(bit, acc + this, acc);
    }
    return acc;
  }
}

/// MAP of RFC 9496 section 4.3.4 on 32 bytes, whose top bit is masked.
RistrettoPoint _map(List<int> bytes) {
  final masked = Uint8List.fromList(bytes);
  masked[31] &= 0x7f;
  final t = Fe.fromBytes(masked);
  final r = _sqrtM1 * t.square();
  final u = (r + Fe.one) * _oneMinusDSq;
  final v = (-Fe.one - r * _d) * (r + _d);
  final (:wasSquare, root: s0) = sqrtRatioM1(u, v);
  final sPrime = -(s0 * t).abs();
  final s = Fe.select(wasSquare, s0, sPrime);
  final c = Fe.select(wasSquare, -Fe.one, r);
  final n = c * (r - Fe.one) * _dMinusOneSq - v;
  final w0 = (s + s) * v;
  final w1 = n * _sqrtAdMinusOne;
  final w2 = Fe.one - s.square();
  final w3 = Fe.one + s.square();
  return RistrettoPoint._(w0 * w3, w2 * w1, w1 * w3, w0 * w2);
}

RistrettoPoint _select(int condition, RistrettoPoint ifOne, RistrettoPoint ifZero) => RistrettoPoint._(
  Fe.select(condition, ifOne._x, ifZero._x),
  Fe.select(condition, ifOne._y, ifZero._y),
  Fe.select(condition, ifOne._z, ifZero._z),
  Fe.select(condition, ifOne._t, ifZero._t),
);

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

Uint8List _hexBytes(String hex) =>
    Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);
