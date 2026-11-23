@Tags(['wasm'])
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/opaque/field25519.dart';
import 'package:test/test.dart';

final _p = (BigInt.one << 255) - BigInt.from(19);

BigInt _toBig(Fe e) {
  var n = BigInt.zero;
  final b = e.toBytes();
  for (var i = 31; i >= 0; i--) {
    n = (n << 8) | BigInt.from(b[i]);
  }
  return n;
}

Uint8List _bytesOf(BigInt n) {
  final out = Uint8List(32);
  var v = n;
  for (var i = 0; i < 32; i++) {
    out[i] = (v & BigInt.from(0xff)).toInt();
    v >>= 8;
  }
  return out;
}

// The field arithmetic is checked against BigInt, which is exact and not
// constant-time, on values worked out by Dart's Random with a fixed seed.
void main() {
  final random = Random(2026);
  BigInt randomBelowP() {
    var n = BigInt.zero;
    for (var i = 0; i < 32; i++) {
      n = (n << 8) | BigInt.from(random.nextInt(256));
    }
    return n % _p;
  }

  Fe fe(BigInt n) => Fe.fromBytes(_bytesOf(n));

  final edges = [
    BigInt.zero,
    BigInt.one,
    BigInt.from(2),
    _p - BigInt.one,
    _p - BigInt.from(2),
    (BigInt.one << 254),
    (BigInt.one << 255) - BigInt.from(20),
    BigInt.parse('57896044618658097711785492504343953926634992332820282019728792003956564819948'),
  ];
  final values = [...edges, for (var i = 0; i < 40; i++) randomBelowP()];

  test('bytes round-trip for every value below p', () {
    for (final n in values) {
      expect(_toBig(fe(n)), n);
      expect(fe(n).toBytes(), _bytesOf(n));
    }
  });

  test('a value of p or more reads as its residue, and the top bit is ignored', () {
    for (final extra in [0, 1, 5, 18]) {
      expect(_toBig(fe(_p + BigInt.from(extra))), BigInt.from(extra));
    }
    final withTopBit = _bytesOf(BigInt.from(7))..[31] |= 0x80;
    expect(_toBig(Fe.fromBytes(withTopBit)), BigInt.from(7));
    expect(() => Fe.fromBytes(Uint8List(31)), throwsArgumentError);
  });

  test('adds, subtracts and negates modulo p', () {
    for (var i = 0; i < values.length - 1; i++) {
      final a = values[i];
      final b = values[values.length - 1 - i];
      expect(_toBig(fe(a) + fe(b)), (a + b) % _p, reason: '$a + $b');
      expect(_toBig(fe(a) - fe(b)), (a - b) % _p, reason: '$a - $b');
      expect(_toBig(-fe(a)), (_p - a) % _p, reason: '-$a');
    }
  });

  test('multiplies and squares modulo p', () {
    for (var i = 0; i < values.length; i++) {
      final a = values[i];
      final b = values[(i * 7 + 3) % values.length];
      expect(_toBig(fe(a) * fe(b)), (a * b) % _p, reason: '$a * $b');
      expect(_toBig(fe(a).square()), (a * a) % _p, reason: '$a squared');
    }
    expect(_toBig(fe(values[10]).squareTimes(5)), values[10].modPow(BigInt.from(32), _p));
  });

  test('chains of operations keep their limbs in range', () {
    // Many additions and subtractions between multiplications, as the group formulas have
    var a = fe(values[12]);
    var expected = values[12];
    for (var i = 0; i < 60; i++) {
      final b = values[(i * 5) % values.length];
      a = (a * fe(b) + fe(b)) - a;
      expected = (((expected * b) + b) - expected) % _p;
    }
    expect(_toBig(a), expected);
  });

  test('raises to the power (p - 5) / 8', () {
    final exponent = (_p - BigInt.from(5)) ~/ BigInt.from(8);
    for (final n in values.skip(1)) {
      expect(_toBig(fe(n).pow22523()), n.modPow(exponent, _p), reason: '$n');
    }
  });

  test('compares, and finds the sign, zero and absolute value', () {
    expect(fe(BigInt.from(5)).eq(fe(BigInt.from(5))), 1);
    expect(fe(BigInt.from(5)).eq(fe(BigInt.from(6))), 0);
    expect(fe(_p + BigInt.from(5)).eq(fe(BigInt.from(5))), 1, reason: 'equal by residue');
    expect(Fe.zero.isZero, 1);
    expect(fe(_p).isZero, 1);
    expect(Fe.one.isZero, 0);
    expect(fe(BigInt.from(3)).isNegative, 1);
    expect(fe(BigInt.from(4)).isNegative, 0);
    expect(_toBig(fe(BigInt.from(3)).abs()), _p - BigInt.from(3), reason: '3 is odd, so negative: abs gives -3 mod p, which is even');
    expect(_toBig(fe(BigInt.from(4)).abs()), BigInt.from(4));
  });

  test('selects by a mask', () {
    final a = fe(values[11]);
    final b = fe(values[12]);
    expect(_toBig(Fe.select(1, a, b)), values[11]);
    expect(_toBig(Fe.select(0, a, b)), values[12]);
  });

  test('small constants and constants from integers', () {
    expect(_toBig(Fe.small(19)), BigInt.from(19));
    expect(_toBig(Fe.fromBigInt(_p + BigInt.from(3))), BigInt.from(3));
    expect(() => Fe.small(1 << 25), throwsArgumentError);
  });
}
