@TestOn('vm')
library;

// RSA PKCS#1 v1.5 for session keys.

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/rsa.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

/// The secret material of the RSA fixture key's packet [index] (0 the
/// primary key, 1 the encryption subkey).
RsaSecret _rsa(Uint8List key, int index) {
  final packets = readPackets(key).where((p) => p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey).toList();
  return unlockSecretKey(parseKeyPacket(packets[index])) as RsaSecret;
}

Uint8List _padding(int length, [int seed = 1]) => Uint8List.fromList([for (var i = 0; i < length; i++) ((i * 31 + seed) % 255) + 1]);

void main() {
  final key = _rsa(Keys.rsa, 1).material;
  final message = Uint8List.fromList([9, ...List.generate(32, (i) => i * 3), 0x12, 0x34]);
  final failed = throwsA(
    isA<PgpException>().having((e) => e.problem, 'problem', PgpProblem.damaged).having((e) => e.detail, 'detail', 'session key'),
  );

  test('a round trip with the RSA 3072 fixture', () {
    expect(key.bits, 3072);
    final padding = _padding(rsaPaddingLength(key.n, message.length));
    expect(padding.length, 384 - message.length - 3);
    final cipher = rsaEncryptPkcs1(key.n, key.e, message, padding);
    expect(rsaDecryptPkcs1(key, cipher), message);
    // Other padding, another cipher text, the same message
    final other = rsaEncryptPkcs1(key.n, key.e, message, _padding(padding.length, 7));
    expect(other, isNot(cipher));
    expect(rsaDecryptPkcs1(key, other), message);
  });

  test('a zero in the random padding does not end it', () {
    final padding = _padding(rsaPaddingLength(key.n, message.length))..[10] = 0;
    expect(rsaDecryptPkcs1(key, rsaEncryptPkcs1(key.n, key.e, message, padding)), message);
  });

  test('the padding must fit', () {
    expect(() => rsaEncryptPkcs1(key.n, key.e, message, _padding(5)), throwsArgumentError);
    expect(() => rsaEncryptPkcs1(key.n, key.e, Uint8List(380), _padding(1)), throwsArgumentError);
  });

  test('a wrong key, a short block and a zero padding byte give one and the same error', () {
    final padding = _padding(rsaPaddingLength(key.n, message.length));
    final cipher = rsaEncryptPkcs1(key.n, key.e, message, padding);

    // Another key of the same size
    expect(() => rsaDecryptPkcs1(_rsa(Keys.rsa, 0).material, cipher % _rsa(Keys.rsa, 0).material.n), failed);

    // Blocks built by hand, encrypted without the padding rules
    BigInt raw(List<int> block) => bytesToBigInt(block).modPow(key.e, key.n);
    final k = 384;
    final good = Uint8List(k)
      ..[1] = 2
      ..fillRange(2, k - message.length - 1, 0xaa)
      ..setAll(k - message.length, message);
    expect(rsaDecryptPkcs1(key, raw(good)), message);
    // A zero among the first eight padding bytes: the padding is too short
    expect(() => rsaDecryptPkcs1(key, raw(Uint8List.fromList(good)..[5] = 0)), failed);
    // No zero at all: the padding never ends
    expect(() => rsaDecryptPkcs1(key, raw(Uint8List.fromList(good)..fillRange(2, k, 0xaa))), failed);
    // Not 00 02 in front
    expect(() => rsaDecryptPkcs1(key, raw(Uint8List.fromList(good)..[1] = 1)), failed);
    expect(() => rsaDecryptPkcs1(key, raw(Uint8List.fromList(good)..[0] = 1)), failed);
    // A cipher text that is not below the modulus
    expect(() => rsaDecryptPkcs1(key, key.n), failed);
    expect(() => rsaDecryptPkcs1(key, key.n + BigInt.two), failed);
  });

  test('the private operation undoes the public one', () {
    final m = BigInt.parse('123456789abcdef', radix: 16);
    expect(rsaPrivate(key, m.modPow(key.e, key.n)), m);
  });
}
