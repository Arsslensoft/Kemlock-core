@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/opaque/field25519.dart';
import 'package:kemlock_core/crypto/opaque/ristretto255.dart';
import 'package:kemlock_core/crypto/opaque/scalar25519.dart';
import 'package:test/test.dart';

import '../vectors.dart';

// RFC 9496 appendix A, copied by script from the RFC's text into
// test/fixtures/account/rfc/ristretto255_rfc9496.json: A.1 the multiples 0 to
// 15 of the generator, A.2 the encodings that must be rejected, A.3 the element
// derivation function on 64-byte strings, A.4 SQRT_RATIO_M1.
void main() {
  final vectors = jsonDecode(File('test/fixtures/account/rfc/ristretto255_rfc9496.json').readAsStringSync()) as Map<String, Object?>;
  final multiples = (vectors['multiples']! as List<Object?>).cast<String>();
  final invalid = (vectors['invalid']! as List<Object?>).cast<String>();

  Uint8List scalarOf(int n) => Uint8List(32)..[0] = n;

  group('A.1 multiples of the generator', () {
    test('adding the generator one more time gives each encoding', () {
      var point = RistrettoPoint.identity;
      for (var i = 0; i < multiples.length; i++) {
        expect(toHex(point.encode()), multiples[i], reason: 'B[$i]');
        point = point + RistrettoPoint.generator;
      }
    });

    test('scalar multiplication gives the same encodings', () {
      for (var i = 0; i < multiples.length; i++) {
        expect(toHex(RistrettoPoint.generator.multiply(scalarOf(i)).encode()), multiples[i], reason: 'B[$i]');
      }
    });

    test('decoding and encoding again gives the same bytes', () {
      for (var i = 0; i < multiples.length; i++) {
        expect(toHex(RistrettoPoint.decode(fromHex(multiples[i]))!.encode()), multiples[i], reason: 'B[$i]');
      }
    });

    test('the generator encodes as RFC 9496 section 4 says', () {
      expect(toHex(RistrettoPoint.generator.encode()), 'e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76');
    });

    test('the identity is the zero encoding and is found as such', () {
      expect(RistrettoPoint.decode(fromHex(multiples[0]))!.isIdentity, isTrue);
      expect(RistrettoPoint.generator.isIdentity, isFalse);
      expect(RistrettoPoint.generator.multiply(Uint8List(32)).isIdentity, isTrue);
    });
  });

  group('A.2 invalid encodings', () {
    test('every one is rejected', () {
      expect(invalid, hasLength(29));
      for (final (i, encoding) in invalid.indexed) {
        expect(RistrettoPoint.decode(fromHex(encoding)), isNull, reason: 'encoding $i: $encoding');
      }
    });

    test('a length other than 32 bytes is rejected', () {
      expect(RistrettoPoint.decode(Uint8List(31)), isNull);
      expect(RistrettoPoint.decode(Uint8List(33)), isNull);
    });
  });

  group('A.3 element derivation', () {
    test('maps each 64-byte string to its encoding', () {
      for (final v in objects(vectors['derivation'])) {
        expect(toHex(RistrettoPoint.fromUniformBytes(fromHex(v['input']! as String)).encode()), v['output'], reason: '${v['input']}');
      }
    });

    test('the four inputs that give one encoding do', () {
      final same = vectors['derivationSame']! as Map<String, Object?>;
      final inputs = (same['inputs']! as List<Object?>).cast<String>();
      expect(inputs, hasLength(4));
      for (final input in inputs) {
        expect(toHex(RistrettoPoint.fromUniformBytes(fromHex(input)).encode()), same['output'], reason: input);
      }
    });
  });

  group('A.4 SQRT_RATIO_M1', () {
    test('gives the RFC square, root and flag for each input', () {
      final cases = objects(vectors['sqrtRatio']);
      expect(cases, isNotEmpty);
      for (final v in cases) {
        final (:wasSquare, :root) = sqrtRatioM1(Fe.fromBytes(fromHex(v['u']! as String)), Fe.fromBytes(fromHex(v['v']! as String)));
        expect(wasSquare == 1, v['wasSquare'], reason: 'u=${v['u']} v=${v['v']}');
        expect(toHex(root.toBytes()), v['r'], reason: 'u=${v['u']} v=${v['v']}');
      }
    });
  });

  group('the group', () {
    test('has the order of RFC 9496: l times the generator is the identity', () {
      // l - 1 as 32 little-endian bytes: l = 2^252 + 27742317777372353535851937790883648493
      final lMinusOne = BigInt.one << 252;
      var n = lMinusOne + BigInt.parse('27742317777372353535851937790883648492');
      final bytes = Uint8List(32);
      for (var i = 0; i < 32; i++) {
        bytes[i] = (n & BigInt.from(0xff)).toInt();
        n >>= 8;
      }
      final almost = RistrettoPoint.generator.multiply(bytes);
      expect((almost + RistrettoPoint.generator).isIdentity, isTrue);
      expect(almost.equals(-RistrettoPoint.generator), 1);
    });

    test('addition is commutative and associative, and a point plus its negation is the identity', () {
      final a = RistrettoPoint.generator.multiply(scalarOf(3));
      final b = RistrettoPoint.generator.multiply(scalarOf(5));
      final c = RistrettoPoint.generator.multiply(scalarOf(11));
      expect((a + b).equals(b + a), 1);
      expect(((a + b) + c).equals(a + (b + c)), 1);
      expect((a + -a).isIdentity, isTrue);
      expect((a + b).equals(RistrettoPoint.generator.multiply(scalarOf(8))), 1);
    });

    test('scalar multiplication distributes over the group', () {
      final p = RistrettoPoint.generator.multiply(scalarOf(7));
      final twice = p.multiply(scalarOf(2));
      expect(twice.equals(p + p), 1);
      expect(p.multiply(scalarOf(6)).equals(RistrettoPoint.generator.multiply(scalarOf(42))), 1);
    });

    test('two points of one element are equal, though their coordinates are not the same', () {
      // B[2] by doubling and by adding are different representations of one element
      final byAdding = RistrettoPoint.generator + RistrettoPoint.generator;
      final byScalar = RistrettoPoint.generator.multiply(scalarOf(2));
      expect(byAdding.equals(byScalar), 1);
      expect(toHex(byAdding.encode()), toHex(byScalar.encode()));
    });

    test('a scalar of the wrong length is refused', () {
      expect(() => RistrettoPoint.generator.multiply(Uint8List(31)), throwsArgumentError);
      expect(() => RistrettoPoint.fromUniformBytes(Uint8List(32)), throwsArgumentError);
    });
  });

  group('scalars', () {
    final order = (BigInt.one << 252) + BigInt.parse('27742317777372353535851937790883648493');

    Uint8List bytesOf(BigInt n) {
      final out = Uint8List(32);
      var v = n;
      for (var i = 0; i < 32; i++) {
        out[i] = (v & BigInt.from(0xff)).toInt();
        v >>= 8;
      }
      return out;
    }

    BigInt bigOf(List<int> bytes) {
      var n = BigInt.zero;
      for (var i = bytes.length - 1; i >= 0; i--) {
        n = (n << 8) | BigInt.from(bytes[i]);
      }
      return n;
    }

    final samples = [
      BigInt.zero,
      BigInt.one,
      BigInt.from(2),
      order - BigInt.one,
      order - BigInt.from(2),
      BigInt.one << 251,
      order ~/ BigInt.from(3),
      order ~/ BigInt.from(7) + BigInt.from(12345),
    ];

    test('a scalar is canonical below the order, with the top three bits zero', () {
      expect(Scalar25519.isCanonical(bytesOf(order - BigInt.one)), isTrue);
      expect(Scalar25519.isCanonical(bytesOf(BigInt.zero)), isTrue);
      expect(Scalar25519.isCanonical(bytesOf(order)), isFalse);
      expect(Scalar25519.isCanonical(bytesOf(order + BigInt.one)), isFalse);
      expect(Scalar25519.isCanonical(bytesOf(BigInt.one << 255)), isFalse);
      expect(Scalar25519.isCanonical(Uint8List(31)), isFalse);
    });

    test('reduces 64 bytes modulo the order', () {
      final hash = Uint8List.fromList(List.generate(64, (i) => (i * 37 + 11) & 0xff));
      expect(bigOf(Scalar25519.reduce64(hash)), bigOf(hash) % order);
      final ones = Uint8List(64)..fillRange(0, 64, 0xff);
      expect(bigOf(Scalar25519.reduce64(ones)), bigOf(ones) % order);
      expect(bigOf(Scalar25519.reduce64(Uint8List(64))), BigInt.zero);
      expect(() => Scalar25519.reduce64(Uint8List(32)), throwsArgumentError);
    });

    test('multiplies modulo the order', () {
      for (final a in samples) {
        for (final b in samples) {
          expect(bigOf(Scalar25519.multiply(bytesOf(a), bytesOf(b))), (a * b) % order, reason: '$a * $b');
        }
      }
    });

    test('inverts modulo the order', () {
      for (final a in samples.skip(1)) {
        final inverse = Scalar25519.invert(bytesOf(a));
        expect(bigOf(inverse), a.modInverse(order), reason: '$a');
        expect(bigOf(Scalar25519.multiply(bytesOf(a), inverse)), BigInt.one);
      }
    });

    test('a random scalar is canonical, and a non-zero one is not zero', () {
      for (var i = 0; i < 5; i++) {
        expect(Scalar25519.isCanonical(Scalar25519.random()), isTrue);
        expect(Scalar25519.isZero(Scalar25519.randomNonZero()), 0);
      }
      expect(Scalar25519.isZero(Uint8List(32)), 1);
    });

    test('refuses an operand that is not canonical', () {
      expect(() => Scalar25519.multiply(bytesOf(order), bytesOf(BigInt.one)), throwsArgumentError);
      expect(() => Scalar25519.invert(bytesOf(order + BigInt.one)), throwsArgumentError);
    });
  });
}
