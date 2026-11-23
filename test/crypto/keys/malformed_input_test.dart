@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openssh.dart';
import 'package:kemlock_core/crypto/keys/pbes2.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:kemlock_core/crypto/keys/x509.dart';
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// Every reader in crypto/keys, fed what a damaged or hostile file holds:
// the fixtures cut at every byte (so at every field), with a byte set to
// 0xff at every position (which turns each length it lands on into one
// past the end), more than 1 MB, and random bytes. Each must end in a
// KeyFormatException, or for a cut that leaves a whole shorter key, read
// it; nothing may throw anything else.

const _passphrase = 'fixture passphrase';

/// Runs [read]; returns whether it threw a [KeyFormatException]. Anything
/// else it throws fails the test, naming [what].
Future<bool> _keyErrorOrValue(String what, FutureOr<Object?> Function() read) async {
  Object? other;
  StackTrace? stack;
  try {
    await read();
    return false;
  } on KeyFormatException {
    return true;
  } on Object catch (e, s) {
    other = e;
    stack = s;
  }
  fail('$what threw ${other.runtimeType}, not a KeyFormatException: $other\n$stack');
}

Uint8List _pem(String path) => readPemBlocks(keyFixtureText(path)).single.decode();

Uint8List _armored(String path) => readArmor(readPemBlocks(keyFixtureText(path)).single);

typedef _Case = ({String name, Uint8List input, FutureOr<Object?> Function(Uint8List) read, bool prefixMayBeAKey});

List<_Case> _cases() {
  _Case c(String name, Uint8List input, FutureOr<Object?> Function(Uint8List) read, {bool prefixMayBeAKey = false}) =>
      (name: name, input: input, read: read, prefixMayBeAKey: prefixMayBeAKey);
  Future<Object?> facade(Uint8List b) => readPrivateKey(b, passphrase: _passphrase);
  return [
    // DER through the facade, and each DER reader on its own.
    for (final file in [
      'openssl/rsa2048.pkcs8.der',
      'openssl/p256.pkcs8.der',
      'openssl/ed25519.pkcs8.der',
      'openssl/x25519.pkcs8.der',
      'openssl/ed448.pkcs8.der',
      'openssl/ml-kem-768.both.der',
      'openssl/ml-dsa-65.both.der',
    ]) ...[c('readPrivateKey $file', keyFixture(file), facade), c('readPkcs8 $file', keyFixture(file), readPkcs8)],
    c('readPrivateKey ml-kem-1024 seed', _pem('openssl/ml-kem-1024.seed.pem'), facade),
    c('readPrivateKey ml-dsa-65 expanded', _pem('openssl/ml-dsa-65.expanded.pem'), facade),
    c('readPkcs1 rsa2048', keyFixture('openssl/rsa2048.traditional.der'), readPkcs1),
    c('readPrivateKey PKCS#1', keyFixture('openssl/rsa2048.traditional.der'), facade),
    c('readSec1 p384', keyFixture('openssl/p384.traditional.der'), readSec1),
    c('readPrivateKey SEC1', keyFixture('openssl/p256.traditional.der'), facade),
    c('readSpki p256', keyFixture('openssl/p256.spki.der'), readSpki),
    c('readSpki rsa2048', keyFixture('openssl/rsa2048.spki.der'), readSpki),
    c('readSpki ml-kem-768', keyFixture('openssl/ml-kem-768.spki.der'), readSpki),
    c('decryptPkcs8 p384', keyFixture('openssl/p384.pbes2-default.der'), (b) => decryptPkcs8(b, _passphrase)),
    c('readPrivateKey PBES2', keyFixture('openssl/p384.pbes2-default.der'), facade),
    // OpenSSH: plain keys with a passphrase given (it isn't used), and
    // protected ones without, so a cut never reaches bcrypt.
    for (final name in ['ed25519', 'ecdsa256', 'ecdsa384', 'rsa3072']) ...[
      c('readOpenSsh $name', _pem('openssh/$name'), (b) => readOpenSsh(b, _passphrase)),
      c('readPrivateKey OpenSSH $name', _pem('openssh/$name'), facade),
      c('readOpenSsh $name.protected', _pem('openssh/$name.protected'), (b) => readOpenSsh(b, null)),
    ],
    // OpenPGP: a cut between packets can leave a whole key.
    for (final file in ['gnupg/ed25519.secret.gpg', 'gnupg/rsa3072-protected.secret.gpg', 'gnupg/ed25519-two-uids.secret.gpg'])
      if (!file.contains('two-uids')) ...[
        c('readPrivateKey $file', keyFixture(file), facade, prefixMayBeAKey: true),
        c('readPackets $file', keyFixture(file), readPackets, prefixMayBeAKey: true),
        c('readTransferableKey $file', keyFixture(file), readTransferableKey, prefixMayBeAKey: true),
        c('verifyPgpSelfSignatures $file', keyFixture(file), verifyPgpSelfSignatures, prefixMayBeAKey: true),
      ],
    c('readTransferableKey v6', _armored('rfc9580/v6-secret.asc'), readTransferableKey, prefixMayBeAKey: true),
    c('verifyPgpSelfSignatures v6', _armored('rfc9580/v6-locked-secret.asc'), verifyPgpSelfSignatures, prefixMayBeAKey: true),
    c('readPgpKeyInfo generated RSA', _armored('kemlock/pgp-rsa4096.public.asc'), readPgpKeyInfo, prefixMayBeAKey: true),
    // Other people's public keys, each signature of their own checked as they are read.
    c('readPublicKeys gnupg/ed25519.public.gpg', keyFixture('gnupg/ed25519.public.gpg'), readPublicKeys, prefixMayBeAKey: true),
    c('readPublicKeys contacts/two-keys.public.gpg', keyFixture('contacts/two-keys.public.gpg'), readPublicKeys, prefixMayBeAKey: true),
    c(
      'readPublicKeys contacts/rsa3072-certified-photo',
      _armored('contacts/rsa3072-certified-photo.public.asc'),
      readPublicKeys,
      prefixMayBeAKey: true,
    ),
    c('readPublicKeys v6', _armored('rfc9580/v6-public.asc'), readPublicKeys, prefixMayBeAKey: true),
  ];
}

void main() {
  final cases = _cases();

  group('cut at every byte', () {
    for (final k in cases) {
      test(k.name, () async {
        for (var length = 0; length < k.input.length; length++) {
          final failed = await _keyErrorOrValue('${k.name} cut to $length bytes', () => k.read(Uint8List.sublistView(k.input, 0, length)));
          if (!k.prefixMayBeAKey) expect(failed, isTrue, reason: '${k.name} read a key from its first $length bytes');
        }
      });
    }
  });

  group('a byte set to 0xff at every position', () {
    for (final k in cases) {
      test(k.name, () async {
        for (var i = 0; i < k.input.length; i++) {
          if (k.input[i] == 0xff) continue;
          final changed = Uint8List.fromList(k.input)..[i] = 0xff;
          await _keyErrorOrValue('${k.name} with byte $i set to 0xff', () => k.read(changed));
        }
      });
    }
  });

  group('lengths past the end', () {
    test('DER: a length of 2^32 - 1 for the whole key, and for its private key', () async {
      final der = keyFixture('openssl/ed25519.pkcs8.der');
      final huge = Uint8List.fromList([0x30, 0x84, 0xff, 0xff, 0xff, 0xff, ...der.sublist(2)]);
      expect(await _keyErrorOrValue('outer', () => readPkcs8(huge)), isTrue);
      // The OCTET STRING of the private key is at offset 14 (04 22 ...).
      final inner = Uint8List.fromList(der)..[15] = 0x7f;
      expect(await _keyErrorOrValue('inner', () => readPkcs8(inner)), isTrue);
    });

    test('OpenSSH: each 32-bit length of the header set to 2^32 - 1', () async {
      final blob = _pem('openssh/ed25519');
      // The cipher name, KDF name, KDF options, key count and public key
      // lengths follow the 15-byte magic.
      var offset = 15;
      for (var field = 0; field < 5; field++) {
        final changed = Uint8List.fromList(blob)..setAll(offset, [0xff, 0xff, 0xff, 0xff]);
        expect(await _keyErrorOrValue('field $field', () => readOpenSsh(changed, null)), isTrue, reason: 'field $field');
        final length = blob.buffer.asByteData(blob.offsetInBytes).getUint32(offset);
        offset += 4 + (field == 3 ? 0 : length);
      }
    });

    test('OpenPGP: a packet length, a subpacket length and an MPI bit count past the end', () async {
      final data = keyFixture('gnupg/ed25519.secret.gpg');
      final first = readPackets(data).first;
      // A new-format header with a 4-byte length, for the first packet.
      final packet = Uint8List.fromList([0xc5, 0xff, 0x7f, 0xff, 0xff, 0xff, ...first.body]);
      expect(await _keyErrorOrValue('packet', () => readPackets(packet)), isTrue);
      // The primary key's MPI bit count (after version, time, algorithm and
      // the 10-byte curve OID) set to 65535.
      final mpi = Uint8List.fromList(data)..setAll(first.encoded.length - first.body.length + 16, [0xff, 0xff]);
      expect(await _keyErrorOrValue('MPI', () => readTransferableKey(mpi)), isTrue);
      // The hashed subpacket area of the first signature claiming 65535 bytes.
      final packets = readPackets(data);
      final sigAt = packets.takeWhile((p) => p.tag != PgpTag.signature).fold(0, (n, p) => n + p.encoded.length);
      final signature = packets.firstWhere((p) => p.tag == PgpTag.signature);
      final headerLength = signature.encoded.length - signature.body.length;
      final subpackets = Uint8List.fromList(data)..setAll(sigAt + headerLength + 4, [0xff, 0xff]);
      expect(await _keyErrorOrValue('subpackets', () => readTransferableKey(subpackets)), isTrue);
    });
  });

  group('text cut short', () {
    for (final file in [
      'openssl/p256.pkcs8.pem',
      'openssl/x25519.pbes2-sha256-aes128.pem',
      'openssh/ecdsa256',
      'gnupg/ed25519.secret.asc',
      'rfc9580/v6-secret.asc',
    ]) {
      test(file, () async {
        final text = keyFixtureText(file);
        final end = text.lastIndexOf('-----END ');
        for (var length = 0; length < text.length; length += 3) {
          final cut = text.substring(0, length);
          final failed = await _keyErrorOrValue('$file cut to $length characters', () => readPrivateKey(cut, passphrase: _passphrase));
          if (length < end) expect(failed, isTrue, reason: '$file read from its first $length characters');
          await _keyErrorOrValue('readPemBlocks $file cut to $length', () => readPemBlocks(cut));
        }
      });
    }
  });

  test('more than 1 MB, as bytes and as text, whatever it starts with', () async {
    for (final start in [
      keyFixture('openssl/p256.pkcs8.der'),
      utf8.encode(keyFixtureText('openssh/ed25519')),
      keyFixture('gnupg/rsa3072.secret.gpg'),
    ]) {
      final big = Uint8List(maxKeyInputLength + 1)..setAll(0, start);
      await expectLater(readPrivateKey(big), throwsKeyProblem(KeyProblem.tooLarge));
      await expectLater(readPrivateKey(latin1.decode(big)), throwsKeyProblem(KeyProblem.tooLarge));
    }
    // Exactly 1 MB is read (and found not to be a key).
    await expectLater(readPrivateKey(Uint8List(maxKeyInputLength)), throwsKeyProblem(KeyProblem.unrecognized));
  });

  group('random bytes', () {
    final random = Random(410);
    Uint8List bytes(int n) => Uint8List.fromList([for (var i = 0; i < n; i++) random.nextInt(256)]);
    final prefixes = <String, List<int>>{
      'nothing': [],
      'a DER sequence': [0x30, 0x82, 0x01, 0x00],
      'a PKCS#8 start': [0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30],
      'the OpenSSH magic': 'openssh-key-v1\x00'.codeUnits,
      'an old-format secret key packet': [0x95, 0x01, 0x00, 0x04],
      'a new-format secret key packet': [0xc5, 0xc0, 0x00, 0x06],
    };

    for (final MapEntry(key: name, value: prefix) in prefixes.entries) {
      test('after $name, through every reader', () async {
        for (var i = 0; i < 150; i++) {
          final input = Uint8List.fromList([...prefix, ...bytes(random.nextInt(700))]);
          for (final k in cases) {
            await _keyErrorOrValue('${k.name} on random input $i', () => k.read(input));
          }
          expect(await _keyErrorOrValue('readPrivateKey on random input $i', () => readPrivateKey(input)), isTrue);
        }
      });
    }

    test('as base64 inside each kind of block', () async {
      for (final label in [
        'PRIVATE KEY',
        'ENCRYPTED PRIVATE KEY',
        'RSA PRIVATE KEY',
        'EC PRIVATE KEY',
        'OPENSSH PRIVATE KEY',
        'PGP PRIVATE KEY BLOCK',
      ]) {
        for (var i = 0; i < 100; i++) {
          final text = writePem(label, bytes(random.nextInt(600)));
          expect(await _keyErrorOrValue('$label $i', () => readPrivateKey(text, passphrase: _passphrase)), isTrue, reason: '$label $i');
        }
      }
    });

    test('as text', () async {
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-: \n';
      for (var i = 0; i < 300; i++) {
        final text = String.fromCharCodes([
          for (var j = 0; j < random.nextInt(800); j++) alphabet.codeUnitAt(random.nextInt(alphabet.length)),
        ]);
        await _keyErrorOrValue('text $i', () => readPrivateKey(text));
      }
    });

    test('as an ML-DSA-65 secret key, which only ever gives an ArgumentError', () {
      for (var i = 0; i < 50; i++) {
        expect(() => MlDsa65.publicKeyOf(bytes(MlDsa65.secretKeyLength)), throwsArgumentError);
      }
    });
  });

  test('two keys in one file: the first is read, and kept on its own', () async {
    final first = keyFixture('gnupg/ed25519.secret.gpg');
    final both = Uint8List.fromList([...first, ...keyFixture('gnupg/rsa3072.secret.gpg')]);
    final key = await readPrivateKey(both);
    expect(key.private, first);
  });

  // The certificate reader of `x509.dart`, which a security key's slot or a
  // picked file feeds: the key format error, and nothing else.
  group('a certificate', () {
    const certificates = ['rsa2048.selfsigned', 'p256.selfsigned', 'p256.names', 'p256.issued', 'ed25519.selfsigned'];
    Uint8List certificate(String name) => keyFixture('openssl/x509/$name.der');

    test('cut at every byte', () async {
      for (final name in certificates) {
        final whole = certificate(name);
        for (var length = 0; length < whole.length; length++) {
          final cut = Uint8List.sublistView(whole, 0, length);
          expect(await _keyErrorOrValue('$name cut at $length', () => readCertificate(cut)), isTrue, reason: '$name cut at $length');
        }
      }
    });

    test('with a byte set to 0xff at every position', () async {
      for (final name in certificates) {
        final whole = certificate(name);
        for (var at = 0; at < whole.length; at++) {
          final damaged = Uint8List.fromList(whole)..[at] = 0xff;
          await _keyErrorOrValue('$name with 0xff at $at', () => readCertificate(damaged));
        }
      }
    });

    test('with bytes after it', () async {
      final trailing = Uint8List.fromList([...certificate('p256.selfsigned'), 0]);
      expect(await _keyErrorOrValue('trailing', () => readCertificate(trailing)), isTrue);
      final twice = Uint8List.fromList([...certificate('p256.selfsigned'), ...certificate('p256.selfsigned')]);
      expect(await _keyErrorOrValue('twice', () => readCertificate(twice)), isTrue);
    });

    test('that is a request, a private key or a public key', () async {
      for (final path in [
        'openssl/x509/p256.request.der',
        'openssl/p256.pkcs8.der',
        'openssl/rsa2048.traditional.der',
        'openssl/p256.spki.der',
      ]) {
        expect(await _keyErrorOrValue(path, () => readCertificate(keyFixture(path))), isTrue, reason: path);
      }
    });

    test('that is random bytes, or more than 1 MB', () async {
      final random = Random(7);
      for (var i = 0; i < 300; i++) {
        final bytes = Uint8List.fromList([for (var j = 0; j < random.nextInt(700); j++) random.nextInt(256)]);
        expect(await _keyErrorOrValue('random $i', () => readCertificate(bytes)), isTrue);
      }
      final huge = Uint8List(maxKeyInputLength + 1)..setAll(0, certificate('p256.selfsigned'));
      await expectLater(
        () => readCertificate(huge),
        throwsA(isA<KeyFormatException>().having((e) => e.problem, 'problem', KeyProblem.tooLarge)),
      );
    });
  });
}
