@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/pbkdf2.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  test('gives the RFC 7914 section 11 known answers', () {
    expect(
      toHex(pbkdf2Sha256(utf8.encode('passwd'), utf8.encode('salt'), 1, 64)),
      '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc'
      '49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783',
    );
    expect(
      toHex(pbkdf2Sha256(utf8.encode('Password'), utf8.encode('NaCl'), 80000, 64)),
      '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56'
      'a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d',
    );
  });

  test("matches WebCrypto's deriveBits, up to the QR export's 200,000 rounds", () {
    for (final v in objects(readVectors('pbkdf2.json'))) {
      final out = pbkdf2Sha256(
        utf8.encode(v['password']! as String),
        fromHex(v['salt']! as String),
        v['iterations']! as int,
        v['length']! as int,
      );
      expect(toHex(out), v['output'], reason: '"${v['password']}", ${v['iterations']} rounds, ${v['length']} bytes');
    }
  });

  test('pbkdf2Sha1 gives the RFC 6070 known answers', () {
    String derive(String password, String salt, int rounds, int length) =>
        toHex(pbkdf2Sha1(utf8.encode(password), utf8.encode(salt), rounds, length));
    expect(derive('password', 'salt', 1, 20), '0c60c80f961f0e71f3a9b524af6012062fe037a6');
    expect(derive('password', 'salt', 2, 20), 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
    expect(derive('password', 'salt', 4096, 20), '4b007901b765489abead49d926f721d065a429c1');
    expect(
      derive('passwordPASSWORDpassword', 'saltSALTsaltSALTsaltSALTsaltSALTsalt', 4096, 25),
      '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
    );
    expect(derive('pass\x00word', 'sa\x00lt', 4096, 16), '56fa6aa75548099dcc37d7f03425e0c3');
    expect(() => pbkdf2Sha1([1], [2], 0, 20), throwsArgumentError);
    expect(() => pbkdf2Sha1([1], [2], 1, 0), throwsArgumentError);
  });

  test('refuses no rounds and an empty key', () {
    expect(() => pbkdf2Sha256([1], [2], 0, 32), throwsArgumentError);
    expect(() => pbkdf2Sha256([1], [2], 1, 0), throwsArgumentError);
  });
}
