@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:test/test.dart';

// The ECDSA test vectors of RFC 6979, appendix A.2.5 (P-256) and A.2.6
// (P-384), for the hash each curve signs with: the private key x, the
// public point (Ux, Uy), and the signature (r, s) of "sample" and "test".

typedef _Vector = ({EcCurve curve, String x, String ux, String uy, Map<String, (String, String)> signatures});

const List<_Vector> _vectors = [
  (
    curve: EcCurve.p256,
    x: 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721',
    ux: '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6',
    uy: '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299',
    signatures: {
      'sample': (
        'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
        'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8',
      ),
      'test': (
        'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
        '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083',
      ),
    },
  ),
  (
    curve: EcCurve.p384,
    x: '6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5',
    ux: 'EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13',
    uy: '8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720',
    signatures: {
      'sample': (
        '94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46',
        '99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8',
      ),
      'test': (
        '8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB',
        'DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5',
      ),
    },
  ),
];

Uint8List _hex(String hex) => Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

BigInt _number(String hex) => BigInt.parse(hex, radix: 16);

void main() {
  for (final v in _vectors) {
    final key = ecMaterial(v.curve, _hex(v.x));
    final order = v.curve.domain.n;

    group('ECDSA ${v.curve.sshName}', () {
      test('the key of RFC 6979 has its public point', () {
        expect(key.point, [4, ..._hex(v.ux), ..._hex(v.uy)]);
      });

      for (final MapEntry(key: message, value: (r, s)) in v.signatures.entries) {
        test('signing "$message" gives the signature RFC 6979 lists, which verifies', () {
          final signature = ecdsaSign(key, utf8.encode(message));
          expect(signature.r, _number(r));
          expect(signature.s, _number(s));
          expect(ecdsaVerify(key.publicHalf, utf8.encode(message), signature.r, signature.s), isTrue);
        });
      }

      test('a signature does not verify over another message or under another key', () {
        final (r, s) = v.signatures['sample']!;
        expect(ecdsaVerify(key.publicHalf, utf8.encode('sample'), _number(r), _number(s)), isTrue);
        expect(ecdsaVerify(key.publicHalf, utf8.encode('samplf'), _number(r), _number(s)), isFalse);
        final other = ecMaterial(v.curve, Uint8List.fromList([1, 2, 3]));
        expect(ecdsaVerify(other.publicHalf, utf8.encode('sample'), _number(r), _number(s)), isFalse);
        expect(ecdsaVerify(key.publicHalf, utf8.encode('sample'), _number(s), _number(r)), isFalse);
      });

      test('r or s of zero, of the order or over it is rejected', () {
        final message = utf8.encode('sample');
        final (r, s) = (_number(v.signatures['sample']!.$1), _number(v.signatures['sample']!.$2));
        for (final bad in [BigInt.zero, -BigInt.one, order, order + BigInt.one, order + r, BigInt.one << (v.curve.size * 8 + 8)]) {
          expect(ecdsaVerify(key.publicHalf, message, bad, s), isFalse, reason: 'r = $bad');
          expect(ecdsaVerify(key.publicHalf, message, r, bad), isFalse, reason: 's = $bad');
        }
        // r + n and s + n are the same numbers modulo the order: a check
        // that reduced them first would accept these.
        expect(ecdsaVerify(key.publicHalf, message, r, order + s), isFalse);
      });

      test('a public point that is not on the curve is rejected', () {
        final (r, s) = (_number(v.signatures['sample']!.$1), _number(v.signatures['sample']!.$2));
        final point = Uint8List.fromList(key.point);
        point[point.length - 1] ^= 1;
        expect(ecdsaVerify(EcPublicHalf(v.curve, point), utf8.encode('sample'), r, s), isFalse);
        expect(ecdsaVerify(EcPublicHalf(v.curve, Uint8List.sublistView(key.point, 0, 10)), utf8.encode('sample'), r, s), isFalse);
        expect(ecdsaVerify(EcPublicHalf(v.curve, Uint8List(key.point.length)..[0] = 4), utf8.encode('sample'), r, s), isFalse);
      });
    });
  }

  group('RSA PKCS#1 v1.5', () {
    test('the padding is 00 01, ff bytes, 00 and the DigestInfo of the hash', () {
      final padded = emsaPkcs1(oidSha256, Uint8List(32), 64);
      expect(padded.sublist(0, 2), [0, 1]);
      expect(padded.sublist(2, 12), List.filled(10, 0xff));
      // RFC 8017 section 9.2, note 1: the DigestInfo prefix of SHA-256.
      expect(padded.sublist(12, 32), [
        0,
        0x30,
        0x31,
        0x30,
        0x0d,
        0x06,
        0x09,
        0x60,
        0x86,
        0x48,
        0x01,
        0x65,
        0x03,
        0x04,
        0x02,
        0x01,
        0x05,
        0x00,
        0x04,
        0x20,
      ]);
      expect(padded.sublist(32), Uint8List(32));
      expect(bigIntToBytes(bytesToBigInt(padded), 64), padded);
    });

    test('a key too small for the digest is refused', () {
      expect(() => emsaPkcs1(oidSha512, Uint8List(64), 64), throwsA(anything));
    });
  });
}
