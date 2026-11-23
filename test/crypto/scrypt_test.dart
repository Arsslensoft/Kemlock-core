@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  // RFC 7914 section 12, but for the fourth vector (N=2^20, 1 GiB).
  test('gives the RFC 7914 known answers', () {
    expect(
      toHex(scrypt([], [], n: 16, r: 1, p: 1, length: 64)),
      '77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442'
      'fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906',
    );
    expect(
      toHex(scrypt(utf8.encode('password'), utf8.encode('NaCl'), n: 1024, r: 8, p: 16, length: 64)),
      'fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162'
      '2eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640',
    );
    expect(
      toHex(scrypt(utf8.encode('pleaseletmein'), utf8.encode('SodiumChloride'), n: 16384, r: 8, p: 1, length: 64)),
      '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2'
      'd5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
    );
  });

  test("matches noble's scrypt, up to the vault's N=2^17 with a non-ASCII password", () {
    for (final v in objects(readVectors('scrypt.json'))) {
      final out = scrypt(
        utf8.encode(v['password']! as String),
        fromHex(v['salt']! as String),
        n: v['N']! as int,
        r: v['r']! as int,
        p: v['p']! as int,
        length: v['dkLen']! as int,
      );
      expect(toHex(out), v['output'], reason: '"${v['password']}", N=${v['N']}, r=${v['r']}, p=${v['p']}');
    }
  });

  test('refuses the parameters noble refuses', () {
    expect(() => scrypt([], [], n: 1, r: 1, p: 1), throwsArgumentError);
    expect(() => scrypt([], [], n: 24, r: 1, p: 1), throwsArgumentError);
    expect(() => scrypt([], [], n: 16, r: 0, p: 1), throwsArgumentError);
    expect(() => scrypt([], [], n: 16, r: 1, p: 0), throwsArgumentError);
    expect(() => scrypt([], [], n: 16, r: 1, p: 1, length: 0), throwsArgumentError);
    // 128 * r * (N + p + 1) over noble's 1 GiB limit
    expect(() => scrypt([], [], n: 1 << 21, r: 8, p: 1), throwsArgumentError);
  });
}
