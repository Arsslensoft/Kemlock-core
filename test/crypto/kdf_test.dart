@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/kdf.dart';
import 'package:kemlock_core/crypto/pbkdf2.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:test/test.dart';

void main() {
  final password = utf8.encode('correct horse');
  final salt = utf8.encode('battery staple');

  test('scryptInBackground gives what scrypt gives', () async {
    expect(await scryptInBackground(password, salt, n: 1024, r: 8, p: 1), scrypt(password, salt, n: 1024, r: 8, p: 1));
    expect(await scryptInBackground(password, salt, n: 16, r: 2, p: 3, length: 70), scrypt(password, salt, n: 16, r: 2, p: 3, length: 70));
  });

  test('pbkdf2Sha256InBackground gives what pbkdf2Sha256 gives', () async {
    expect(await pbkdf2Sha256InBackground(password, salt, 1000, 32), pbkdf2Sha256(password, salt, 1000, 32));
  });

  test('runs several at once', () async {
    final keys = await Future.wait([for (var n = 16; n <= 256; n *= 2) scryptInBackground(password, salt, n: n, r: 8, p: 1)]);
    expect(keys.map((k) => k.length), everyElement(32));
    expect(keys.toSet().length, keys.length);
  });

  test('passes argument errors back', () async {
    await expectLater(scryptInBackground(password, salt, n: 1000, r: 8, p: 1), throwsArgumentError);
    await expectLater(pbkdf2Sha256InBackground(password, salt, 0, 32), throwsArgumentError);
  });
}
