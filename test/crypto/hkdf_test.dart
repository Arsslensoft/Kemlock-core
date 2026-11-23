@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/hkdf.dart';
import 'package:test/test.dart';

Uint8List _hex(String hex) => Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

String _toHex(List<int> bytes) => bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

/// The bytes from [first] to [last], as the RFC's longer inputs are.
String _run(int first, int last) => _toHex([for (var i = first; i <= last; i++) i]);

// The SHA-256 test cases of RFC 5869, appendix A.1 to A.3.
void main() {
  test('test case 1: basic', () {
    final prk = hkdfExtractSha256(_hex('000102030405060708090a0b0c'), _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'));
    expect(_toHex(prk), '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
    expect(
      _toHex(hkdfExpandSha256(prk, _hex('f0f1f2f3f4f5f6f7f8f9'), 42)),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  test('test case 2: longer inputs and outputs', () {
    final prk = hkdfExtractSha256(_hex(_run(0x60, 0xaf)), _hex(_run(0x00, 0x4f)));
    expect(_toHex(prk), '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244');
    expect(
      _toHex(hkdfExpandSha256(prk, _hex(_run(0xb0, 0xff)), 82)),
      'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
    );
  });

  test('test case 3: no salt and no info', () {
    final ikm = _hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    final prk = hkdfExtractSha256(const [], ikm);
    expect(_toHex(prk), '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04');
    const okm = '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8';
    expect(_toHex(hkdfExpandSha256(prk, const [], 42)), okm);
    expect(_toHex(hkdfSha256(ikm, salt: const [], info: const [], length: 42)), okm);
  });

  test('refuses more than 255 blocks', () {
    expect(() => hkdfExpandSha256(Uint8List(32), const [], 255 * 32 + 1), throwsArgumentError);
  });
}
