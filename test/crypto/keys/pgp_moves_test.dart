@TestOn('vm')
library;

// Pins what four functions of the OpenPGP key code give for fixed inputs,
// before the message code moves them to files of their own (`s2k.dart`,
// `rsa.dart`) and builds on them: a move must not change one byte.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

Uint8List _counting(int length, [int from = 0]) => Uint8List.fromList([for (var i = 0; i < length; i++) (from + i) & 0xff]);

void main() {
  test('iteratedSaltedS2k', () {
    final passphrase = utf8.encode('fixture passphrase');
    expect(_hex(iteratedSaltedS2k(passphrase, _counting(8), 0x60)), '78ff373320dc8edafae574db451e5cd59c25b802d6d58242e3bbc6bb5d0205e3');
    // A count below the salt and passphrase still hashes them once
    expect(_hex(iteratedSaltedS2k(passphrase, _counting(8, 100), 0)), '85d06b2b0ec4611aa663cb922352c60699d68f5c09e35ad49f67f1929a7d1417');
    expect(
      _hex(iteratedSaltedS2k(passphrase, _counting(8, 200), defaultS2kCount)),
      'a97396edd135a17b45caf093ee9a7bcb6d1c2c9a2ed054775b6e9993a72f2a7e',
    );
  });

  test('cfb', () {
    final key = _counting(32);
    final iv = _counting(16, 64);
    final data = _counting(37, 128);
    final encrypted = cfb(true, key, iv, data);
    expect(_hex(encrypted), '23ff5dbc13df3c681bf2e84c01d63fd88f84640d3f88054a1731cd2cc8058d9df0a927f1e3');
    expect(cfb(false, key, iv, encrypted), data);
  });

  test('signRsa', () async {
    final key = await readPkcs8(keyFixture('openssl/rsa2048.pkcs8.der')) as RsaMaterial;
    final signature = signRsa(key, hash.sha512.convert(utf8.encode('a digest to sign')).bytes);
    expect(signature.length, 258);
    expect(_hex(hash.sha256.convert(signature).bytes), '2c27723e9d6eccad7d53b54386aa4138a14b338916546335145bf1111ed08698');
  });

  test('makeSignature', () async {
    final packets = readPackets(keyFixture('gnupg/ed25519.secret.gpg'));
    final signer = parseKeyPacket(packets.first);
    // An EdDSA secret is one MPI: the seed
    final seed = Uint8List(32)..setAll(0, signer.plainSecret!.sublist(2));
    final body = await makeSignature(
      type: 0x00,
      signer: signer,
      data: utf8.encode('the data that is signed'),
      hashed: [
        ...subpacket(33, [4, ...signer.fingerprint]),
        ...subpacket(2, [0x65, 0x00, 0x00, 0x00]),
      ],
      sign: (digest) => signEdDsa(seed, digest),
    );
    expect(
      _hex(body),
      '0400160a001d1621041fcda135ee42400ec2b77ce677249abe661cf8db050265000000000a091077249abe661cf8dbaf8800ff7c43225c96035f91beb8817ad4ce3d6ccd6b79029807b3c36cc637177cd9598700fd15c49849ab455b18139680119df65d75a6ea4b8a900ef26b60230b1113791c09',
    );
    final signature = parseSignature(body);
    expect(signature.created, 0x65000000);
    expect(await verifySignature(signature, signer, utf8.encode('the data that is signed')), isTrue);
  });
}
