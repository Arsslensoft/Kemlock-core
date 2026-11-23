@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

void main() {
  final accountId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ab');
  final kx1Private = Uint8List.fromList(List.generate(96, (i) => (i * 3 + 7) & 0xff));
  final sig1Private = Uint8List.fromList(List.generate(64, (i) => (i * 5 + 9) & 0xff));
  late KeyBundle bundle;
  late Uint8List signature;

  setUpAll(() async {
    bundle = KeyBundle(
      accountId: accountId,
      keyVersion: 2,
      kx1PublicKey: await Kx1.publicKeyOf(kx1Private),
      sig1PublicKey: await Sig1.publicKeyOf(sig1Private),
    );
    signature = await signBundle(bundle, sig1Private);
  });

  test('is the label, account id, key version, kx1 key and sig1 key', () {
    final bytes = bundle.bytes;
    expect(bytes, hasLength(17 + 16 + 4 + 1600 + 1984));
    expect(bytes.sublist(0, 17), utf8.encode('kemlock/v1/bundle'));
    expect(bytes.sublist(17, 33), accountId);
    expect(bytes.sublist(33, 37), [0, 0, 0, 2]);
    expect(bytes.sublist(37, 1637), bundle.kx1PublicKey);
    expect(bytes.sublist(1637), bundle.sig1PublicKey);
  });

  test('the fingerprint is SHA-512 of the label and the bundle', () {
    final expected = hash.sha512.convert([...utf8.encode('kemlock/v1/fingerprint'), ...bundle.bytes]).bytes;
    expect(bundle.fingerprint, expected);
    expect(bundle.fingerprint, hasLength(64));
  });

  group('the 60 digits', () {
    // Group i is the 40-bit big-endian number of bytes 5i to 5i+4, mod 100000,
    // worked out here with BigInt, not shifts.
    String expectedDigits(List<int> fingerprint) => [
      for (var i = 0; i < 12; i++)
        (BigInt.parse([for (var j = 0; j < 5; j++) fingerprint[5 * i + j].toRadixString(16).padLeft(2, '0')].join(), radix: 16) %
                BigInt.from(100000))
            .toString()
            .padLeft(5, '0'),
    ].join(' ');

    test('are 12 groups of 5 digits, from the first 60 of the 64 hash bytes', () {
      final digits = bundle.fingerprintDigits;
      expect(digits, expectedDigits(bundle.fingerprint));
      expect(digits, matches(RegExp(r'^(\d{5} ){11}\d{5}$')));
    });

    test('keep their leading zeros and use only the first 60 bytes', () {
      final fingerprint = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0, 0, 1, ...List.generate(54, (i) => i + 10)]);
      final digits = fingerprintDigitsOf(fingerprint);
      expect(digits.split(' ').take(2), ['00000', '00001']);
      expect(digits, expectedDigits(fingerprint));
      final lastFour = Uint8List.fromList(fingerprint)..fillRange(60, 64, 0xee);
      expect(fingerprintDigitsOf(lastFour), digits);
    });

    test('a known value: bytes 00 01 02 03 04 are 16909060, which is 09060 mod 100000', () {
      final fingerprint = Uint8List.fromList(List.generate(64, (i) => i));
      expect(fingerprintDigitsOf(fingerprint).split(' ').first, '09060');
    });

    test('a fingerprint that is not 64 bytes is refused', () {
      expect(() => fingerprintDigitsOf(Uint8List(63)), throwsA(isA<MalformedException>()));
    });
  });

  test('the QR comparison matches all 64 bytes', () {
    final fingerprint = bundle.fingerprint;
    expect(fingerprintsMatch(fingerprint, Uint8List.fromList(fingerprint)), isTrue);
    expect(fingerprintsMatch(fingerprint, Uint8List.fromList(fingerprint)..[63] ^= 1), isFalse);
    expect(fingerprintsMatch(fingerprint, fingerprint.sublist(0, 63)), isFalse);
  });

  test('is signed by its own sig1 key and verifies', () async {
    expect(await verifyBundle(bundle, signature), isTrue);
  });

  test('a bundle with a swapped key, account or version is refused', () async {
    final otherKx1 = await Kx1.publicKeyOf(Uint8List.fromList(kx1Private)..[0] ^= 1);
    final otherSig1 = await Sig1.publicKeyOf(Uint8List.fromList(sig1Private)..[0] ^= 1);
    final swapped = [
      KeyBundle(accountId: accountId, keyVersion: 2, kx1PublicKey: otherKx1, sig1PublicKey: bundle.sig1PublicKey),
      KeyBundle(accountId: accountId, keyVersion: 2, kx1PublicKey: bundle.kx1PublicKey, sig1PublicKey: otherSig1),
      KeyBundle(accountId: Uint8List(16), keyVersion: 2, kx1PublicKey: bundle.kx1PublicKey, sig1PublicKey: bundle.sig1PublicKey),
      KeyBundle(accountId: accountId, keyVersion: 3, kx1PublicKey: bundle.kx1PublicKey, sig1PublicKey: bundle.sig1PublicKey),
    ];
    for (final (i, other) in swapped.indexed) {
      expect(await verifyBundle(other, signature), isFalse, reason: 'case $i');
      expect(other.fingerprint, isNot(bundle.fingerprint), reason: 'case $i');
    }
  });

  test('parses its own bytes and refuses a wrong label, length or trailing bytes', () {
    final parsed = KeyBundle.parse(bundle.bytes);
    expect(parsed.bytes, bundle.bytes);
    expect(parsed.keyVersion, 2);
    expect(() => KeyBundle.parse([...bundle.bytes, 0]), throwsA(isA<MalformedException>()));
    expect(() => KeyBundle.parse(bundle.bytes.sublist(0, bundle.bytes.length - 1)), throwsA(isA<MalformedException>()));
    expect(() => KeyBundle.parse(Uint8List.fromList(bundle.bytes)..[0] = 0x4b), throwsA(isA<MalformedException>()));
  });

  test('refuses keys and an account id of the wrong length', () {
    expect(
      () => KeyBundle(accountId: Uint8List(15), keyVersion: 1, kx1PublicKey: bundle.kx1PublicKey, sig1PublicKey: bundle.sig1PublicKey),
      throwsA(isA<MalformedException>()),
    );
    expect(
      () => KeyBundle(accountId: accountId, keyVersion: 1, kx1PublicKey: Uint8List(1599), sig1PublicKey: bundle.sig1PublicKey),
      throwsA(isA<MalformedException>()),
    );
    expect(
      () => KeyBundle(accountId: accountId, keyVersion: 1, kx1PublicKey: bundle.kx1PublicKey, sig1PublicKey: Uint8List(1983)),
      throwsA(isA<MalformedException>()),
    );
  });
}
