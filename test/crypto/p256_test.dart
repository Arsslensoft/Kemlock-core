@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

/// 0x04, x, y with x and y of [size] bytes, each holding a small number.
Uint8List _point(int size, int x, int y) => Uint8List(1 + 2 * size)
  ..[0] = 4
  ..[size] = x
  ..[2 * size] = y;

void main() {
  group('p256SharedSecret', () {
    test('gives both sides the same secret', () {
      final a = newP256KeyPair();
      final b = newP256KeyPair();
      expect(p256SharedSecret(a.d, b.point), p256SharedSecret(b.d, a.point));
      expect(p256SharedSecret(a.d, b.point), hasLength(32));
    });

    test('refuses a point that is not on P-256, which the library alone would multiply', () {
      final mine = newP256KeyPair();
      // (1, 1) is on no curve of this shape with P-256's b
      final off = _point(32, 1, 1);
      expect(EcCurve.p256.domain.curve.decodePoint(off), isNotNull, reason: 'pointycastle builds the point without checking it');

      expect(() => p256SharedSecret(mine.d, off), throwsArgumentError);
      expect(es256Verify(off, Uint8List(3), Uint8List(8)), isFalse);
    });

    test('refuses every encoding but the uncompressed one, and infinity', () {
      final mine = newP256KeyPair();
      final theirs = newP256KeyPair();
      final compressed = Uint8List.fromList([2 + (theirs.y.last & 1), ...theirs.x]);
      expect(EcCurve.p256.domain.curve.decodePoint(compressed), isNotNull);

      expect(() => p256SharedSecret(mine.d, compressed), throwsArgumentError);
      expect(() => p256SharedSecret(mine.d, Uint8List.fromList([0])), throwsArgumentError);
      expect(() => p256SharedSecret(mine.d, Uint8List(0)), throwsArgumentError);
      expect(() => p256SharedSecret(mine.d, theirs.point.sublist(0, 64)), throwsArgumentError);
      // A coordinate that is no field element
      final tooLarge = Uint8List.fromList([4, ...List.filled(32, 0xff), ...theirs.y]);
      expect(() => p256SharedSecret(mine.d, tooLarge), throwsArgumentError);
    });
  });

  group('pointOnCurve', () {
    test('takes a point of the curve and no other, on the brainpool curves too', () {
      for (final name in ['prime256v1', 'secp384r1', 'brainpoolp256r1', 'brainpoolp384r1']) {
        final domain = pc.ECDomainParameters(name);
        final size = (domain.curve.fieldSize + 7) ~/ 8;
        final good = (domain.G * BigInt.from(12345))!.getEncoded(false);

        expect(pointOnCurve(domain, good), isNotNull, reason: name);
        expect(pointOnCurve(domain, _point(size, 1, 1)), isNull, reason: name);
        // The same x with another y
        final moved = Uint8List.fromList(good)..[good.length - 1] ^= 1;
        expect(pointOnCurve(domain, moved), isNull, reason: name);
        expect(pointOnCurve(domain, (domain.G * BigInt.from(12345))!.getEncoded(true)), isNull, reason: name);
        expect(pointOnCurve(domain, good.sublist(1)), isNull, reason: name);
      }
    });
  });
}
