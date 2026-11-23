@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keccak.dart';
import 'package:test/test.dart';

import 'vectors.dart';

void main() {
  test('gives the FIPS 202 known answers', () {
    expect(toHex(sha3_256([])), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
    expect(toHex(sha3_256(utf8.encode('abc'))), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
    expect(
      toHex(sha3_512([])),
      'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6'
      '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
    );
    expect(toHex(shake128([], 32)), '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26');
    expect(
      toHex(shake256([], 64)),
      '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
      'd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be',
    );
  });

  group("matches noble's", () {
    final vectors = readVectors('keccak.json')! as Map<String, Object?>;
    final inputs = (vectors['inputs']! as Map<String, Object?>).map((length, hex) => MapEntry(length, fromHex(hex! as String)));

    for (final (name, hash) in [('sha3_256', sha3_256), ('sha3_512', sha3_512)]) {
      test(name, () {
        for (final v in objects(vectors[name])) {
          expect(toHex(hash(inputs['${v['input']}']!)), v['output'], reason: '${v['input']} bytes in');
        }
      });
    }

    for (final (name, shake) in [('shake128', shake128), ('shake256', shake256)]) {
      test(name, () {
        for (final v in objects(vectors[name])) {
          final out = shake(inputs['${v['input']}']!, v['outLength']! as int);
          expect(toHex(out), v['output'], reason: '${v['input']} bytes in, ${v['outLength']} out');
        }
      });
    }
  });

  test('absorbs and squeezes in pieces as in one go', () {
    final input = Uint8List.fromList(List.generate(700, (i) => i * 7));
    for (final make in [Keccak.sha3_256, Keccak.sha3_512, Keccak.shake128, Keccak.shake256]) {
      final whole = (make()..update(input)).squeeze(500);

      final sponge = make();
      for (var i = 0; i < input.length; i += 61) {
        sponge.update(input.sublist(i, i + 61 > input.length ? input.length : i + 61));
      }
      final pieces = <int>[];
      for (final n in [1, 167, 168, 0, 164]) {
        pieces.addAll(sponge.squeeze(n));
      }

      expect(pieces, whole);
    }
  });

  test('refuses more input once output has been read', () {
    final sponge = Keccak.shake128()
      ..update([1])
      ..squeeze(1);
    expect(() => sponge.update([2]), throwsStateError);
  });

  // NIST's SP 800-185 example values: the cSHAKE256 outputs from
  // cSHAKE_samples.pdf (csrc.nist.gov, Cryptographic Standards and
  // Guidelines, examples), as BouncyCastle's CSHAKETest copies them; the
  // KMAC256 tags of KMAC_samples.pdf as BouncyCastle's KMACTest and
  // pycryptodome's test_KMAC.py both copy them.
  group('SP 800-185', () {
    final short = [0, 1, 2, 3];
    final long = List.generate(200, (i) => i); // 00 to C7
    final emailSignature = utf8.encode('Email Signature');
    final tagged = utf8.encode('My Tagged Application');
    final key = List.generate(32, (i) => 0x40 + i); // 40 to 5F

    test('cSHAKE256 gives samples #3 and #4', () {
      expect(
        toHex(cshake256(short, 64, customization: emailSignature)),
        'd008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd1'
        '64020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c',
      );
      expect(
        toHex(cshake256(long, 64, customization: emailSignature)),
        '07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac864302730917'
        '27f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb',
      );
    });

    test('cSHAKE256 with no name and no customization is SHAKE256', () {
      expect(cshake256(long, 100), shake256(long, 100));
      expect(cshake256(long, 64, name: [0x4e]), isNot(shake256(long, 64)));
    });

    test('KMAC256 gives samples #4, #5 and #6', () {
      expect(
        toHex(kmac256(key, short, 64, customization: tagged)),
        '20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7'
        'f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd',
      );
      expect(
        toHex(kmac256(key, long, 64)),
        '75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691'
        '589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69',
      );
      expect(
        toHex(kmac256(key, long, 64, customization: tagged)),
        'b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9'
        '70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965',
      );
    });

    test('a KMAC256 tag depends on its length', () {
      // L goes into the input, so a shorter tag is not a prefix of a longer one.
      expect(kmac256(key, short, 32), isNot(kmac256(key, short, 64).sublist(0, 32)));
    });
  });
}
