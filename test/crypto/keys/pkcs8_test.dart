@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The keys in test/fixtures/keys/openssl were made by OpenSSL 3.6.1
// (tool/keys/make_fixtures.sh); `<name>.pkcs8.der` and `<name>.spki.der`
// are what `openssl pkey` wrote for the private and public halves.

typedef _Known = ({String name, KeyKind kind, String algorithm, int? bits});

const List<_Known> _known = [
  (name: 'rsa2048', kind: KeyKind.signing, algorithm: 'rsa', bits: 2048),
  (name: 'p256', kind: KeyKind.signing, algorithm: 'ecdsa-p256', bits: null),
  (name: 'p384', kind: KeyKind.signing, algorithm: 'ecdsa-p384', bits: null),
  (name: 'ed25519', kind: KeyKind.signing, algorithm: 'ed25519', bits: null),
  (name: 'x25519', kind: KeyKind.exchange, algorithm: 'x25519', bits: null),
];

void main() {
  group('reads the keys OpenSSL wrote', () {
    for (final k in _known) {
      final pkcs8 = keyFixture('openssl/${k.name}.pkcs8.der');
      final spki = keyFixture('openssl/${k.name}.spki.der');

      void expectKey(ParsedKey key) {
        expect(key.kind, k.kind);
        expect(key.algorithm, k.algorithm);
        expect(key.bits, k.bits);
        expect(key.private, pkcs8);
        expect(key.public, spki, reason: 'the public half OpenSSL derives');
        expect(key.comment, isNull);
      }

      test('${k.name}: PKCS#8 PEM, as pasted text and as file bytes', () async {
        expectKey(await readPrivateKey(keyFixtureText('openssl/${k.name}.pkcs8.pem')));
        expectKey(await readPrivateKey(keyFixture('openssl/${k.name}.pkcs8.pem')));
      });

      test('${k.name}: PKCS#8 DER', () async {
        expectKey(await readPrivateKey(pkcs8));
      });

      if (k.name.startsWith('rsa') || k.name.startsWith('p')) {
        test('${k.name}: ${k.name.startsWith('rsa') ? 'PKCS#1' : 'SEC1'}, PEM and DER, giving the PKCS#8 OpenSSL converts it to', () async {
          expectKey(await readPrivateKey(keyFixtureText('openssl/${k.name}.traditional.pem')));
          expectKey(await readPrivateKey(keyFixture('openssl/${k.name}.traditional.der')));
        });
      }

      test('${k.name}: the public half as OpenSSL writes it, and its SHA-256', () async {
        final key = await readPrivateKey(pkcs8);
        expect(publicKeyPem(key), keyFixtureText('openssl/${k.name}.spki.pem'));
        final fingerprint = keyFingerprint(key)!;
        expect(fingerprint.bytes, sha256.convert(spki).bytes);
        expect(fingerprint.text, 'SHA256:${base64.encode(fingerprint.bytes).replaceAll('=', '')}');
      });

      test('${k.name}: exports the PKCS#8 PEM it read, byte for byte', () async {
        final key = await readPrivateKey(pkcs8);
        expect(exportPkcs8Pem(key), keyFixtureText('openssl/${k.name}.pkcs8.pem'));
      });

      test('${k.name}: the writer gives the same DER as OpenSSL', () async {
        final material = await readPkcs8(pkcs8);
        expect(writePkcs8(material), pkcs8);
        expect(writeSpki(material.publicHalf!), spki);
        expect(writeSpki(readSpki(spki)!), spki);
      });
    }

    test('a SEC1 file with an EC PARAMETERS block in front', () async {
      final key = await readPrivateKey(keyFixtureText('openssl/p256.sec1-with-params.pem'));
      expect(key.algorithm, 'ecdsa-p256');
      expect(key.private, keyFixture('openssl/p256.pkcs8.der'));
      expect(key.public, keyFixture('openssl/p256.spki.der'));
    });

    test('PEM whose line breaks were lost or changed on the way', () async {
      final pem = keyFixtureText('openssl/ed25519.pkcs8.pem');
      final expected = keyFixture('openssl/ed25519.pkcs8.der');
      expect((await readPrivateKey(pem.replaceAll('\n', ' '))).private, expected);
      expect((await readPrivateKey(pem.replaceAll('\n', '\r\n'))).private, expected);
      expect((await readPrivateKey('  Here is my key:\n\n$pem\nThanks')).private, expected);
    });

    test('the base64 of a DER key without its PEM markers', () async {
      final body = keyFixtureText('openssl/p384.pkcs8.pem').split('\n').where((l) => !l.startsWith('-----')).join('\n');
      expect((await readPrivateKey(body)).private, keyFixture('openssl/p384.pkcs8.der'));
    });
  });

  group('keeps a key of an algorithm it does not know as it was given', () {
    test('Ed448, under its identifier', () async {
      final key = await readPrivateKey(keyFixtureText('openssl/ed448.pkcs8.pem'));
      expect(key.kind, KeyKind.other);
      expect(key.algorithm, '1.3.101.113');
      expect(key.public, isNull);
      expect(key.private, keyFixture('openssl/ed448.pkcs8.der'));
      expect(keyFingerprint(key), isNull);
      expect(publicKeyPem(key), isNull);
      expect(exportPkcs8Pem(key), keyFixtureText('openssl/ed448.pkcs8.pem'));
    });

    test('ECDSA on P-521, under the curve, from PKCS#8 and from SEC1', () async {
      for (final file in ['p521.pkcs8.pem', 'p521.traditional.pem', 'p521.traditional.der']) {
        final key = await readPrivateKey(keyFixture('openssl/$file'));
        expect(key.kind, KeyKind.other, reason: file);
        expect(key.algorithm, '1.3.132.0.35', reason: file);
        expect(key.public, isNull, reason: file);
        expect(key.private, keyFixture('openssl/p521.pkcs8.der'), reason: file);
      }
    });
  });

  group('refuses, and says why', () {
    test('a public key alone, in PEM and DER', () async {
      for (final file in ['p256.spki.pem', 'p256.spki.der', 'rsa2048.spki.pem', 'ed25519.spki.der']) {
        await expectLater(readPrivateKey(keyFixture('openssl/$file')), throwsKeyProblem(KeyProblem.publicKeyOnly), reason: file);
      }
    });

    test('a certificate', () async {
      await expectLater(readPrivateKey(keyFixtureText('openssl/p256.cert.pem')), throwsKeyProblem(KeyProblem.publicKeyOnly));
      final der = readPemBlocks(keyFixtureText('openssl/p256.cert.pem')).single.decode();
      await expectLater(readPrivateKey(der), throwsKeyProblem(KeyProblem.publicKeyOnly));
    });

    test('a legacy PEM encrypted with DEK-Info', () async {
      await expectLater(
        readPrivateKey(keyFixtureText('openssl/rsa2048.legacy-aes128.pem')),
        throwsKeyProblem(KeyProblem.legacyPemEncryption),
      );
    });

    test('half a PEM block, pasted', () async {
      final pem = keyFixtureText('openssl/rsa2048.pkcs8.pem');
      await expectLater(readPrivateKey(pem.substring(0, pem.length ~/ 2)), throwsKeyProblem(KeyProblem.damaged));
      await expectLater(readPrivateKey(pem.substring(pem.length ~/ 2)), throwsKeyProblem(KeyProblem.damaged));
    });

    test('a PEM block with its middle cut out', () async {
      final lines = keyFixtureText('openssl/rsa2048.pkcs8.pem').split('\n');
      final cut = [...lines.take(5), ...lines.skip(10)].join('\n');
      await expectLater(readPrivateKey(cut), throwsKeyProblem(KeyProblem.damaged));
    });

    test('an RSA key whose numbers do not belong together', () async {
      final material = readPkcs1(keyFixture('openssl/rsa2048.traditional.der'));
      final m = material;
      final broken = writePkcs1(RsaMaterial(n: m.n, e: m.e, d: m.d + BigInt.two, p: m.p, q: m.q, dp: m.dp, dq: m.dq, qinv: m.qinv));
      await expectLater(readPrivateKey(writePem('RSA PRIVATE KEY', broken)), throwsKeyProblem(KeyProblem.damaged));
    });

    test('an EC key whose public point is not its own', () async {
      final sec1 = keyFixture('openssl/p256.traditional.der');
      final other = keyFixture('openssl/p256.spki.der');
      // The public point is the last 65 bytes of both; flip a bit in it.
      final broken = Uint8List.fromList(sec1)..[sec1.length - 1] ^= 1;
      expect(other.sublist(other.length - 65), sec1.sublist(sec1.length - 65));
      await expectLater(readPrivateKey(broken), throwsKeyProblem(KeyProblem.damaged));
    });

    test('text that is not a key', () async {
      await expectLater(readPrivateKey('hello, this is not a key'), throwsKeyProblem(KeyProblem.unrecognized));
      await expectLater(readPrivateKey(''), throwsKeyProblem(KeyProblem.unrecognized));
      await expectLater(
        readPrivateKey(utf8.encode('-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n')),
        throwsKeyProblem(KeyProblem.unrecognized),
      );
    });
  });

  group('DER', () {
    test('reads and writes object identifiers', () {
      for (final oid in ['1.2.840.113549.1.1.1', '1.3.101.112', '2.16.840.1.101.3.4.3.18', '1.3.6.1.4.1.11591.15.1', '2.999.1']) {
        final encoded = derOid(oid);
        expect(DerReader(encoded).oid(), oid);
      }
      expect(derOid('1.2.840.10045.3.1.7'), [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    });

    test('writes integers with a zero byte when the top bit is set, and reads them back', () {
      expect(derInteger(BigInt.zero), [0x02, 0x01, 0x00]);
      expect(derInteger(BigInt.from(127)), [0x02, 0x01, 0x7f]);
      expect(derInteger(BigInt.from(128)), [0x02, 0x02, 0x00, 0x80]);
      expect(derInteger(BigInt.from(65537)), [0x02, 0x03, 0x01, 0x00, 0x01]);
      final big = BigInt.two.pow(2048) - BigInt.one;
      expect(DerReader(derInteger(big)).integer(), big);
    });

    test('writes long lengths in the fewest bytes', () {
      expect(derOctetString(Uint8List(127)).sublist(0, 2), [0x04, 0x7f]);
      expect(derOctetString(Uint8List(128)).sublist(0, 3), [0x04, 0x81, 0x80]);
      expect(derOctetString(Uint8List(256)).sublist(0, 4), [0x04, 0x82, 0x01, 0x00]);
      expect(derOctetString(Uint8List(70000)).sublist(0, 5), [0x04, 0x83, 0x01, 0x11, 0x70]);
    });

    test('refuses BER lengths, lengths past the end, negative integers and trailing bytes', () {
      Matcher damaged() => throwsKeyProblem(KeyProblem.damaged);
      expect(() => DerReader(Uint8List.fromList([0x30, 0x80, 0x00, 0x00])).read(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x04, 0x81, 0x05, 1, 2, 3, 4, 5])).read(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x04, 0x05, 1, 2])).read(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x04, 0x85, 1, 1, 1, 1, 1])).read(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x02, 0x01, 0xff])).integer(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x02, 0x00])).integer(), damaged());
      expect(() => readSequence(Uint8List.fromList([0x30, 0x00, 0x00])), damaged());
      expect(() => DerReader(Uint8List.fromList([0x06, 0x02, 0x80, 0x01])).oid(), damaged());
      expect(() => DerReader(Uint8List.fromList([0x06, 0x01, 0x81])).oid(), damaged());
    });
  });

  group('PEM', () {
    test('writes 64-character lines and reads them back', () {
      final bytes = Uint8List.fromList(List.generate(200, (i) => i));
      final pem = writePem('PRIVATE KEY', bytes);
      final lines = pem.split('\n');
      expect(lines.first, '-----BEGIN PRIVATE KEY-----');
      expect(lines[1], hasLength(64));
      expect(pem, endsWith('-----END PRIVATE KEY-----\n'));
      expect(readPemBlocks(pem).single.decode(), bytes);
    });

    test('reads RFC 1421 headers', () {
      final block = readPemBlocks(keyFixtureText('openssl/rsa2048.legacy-aes128.pem')).single;
      expect(block.label, 'RSA PRIVATE KEY');
      expect(block.headers['Proc-Type'], '4,ENCRYPTED');
      expect(block.headers['DEK-Info'], startsWith('AES-128-CBC,'));
    });

    test('refuses a body that is not base64', () {
      expect(
        () => readPemBlocks('-----BEGIN PRIVATE KEY-----\nnot*base64\n-----END PRIVATE KEY-----').single.decode(),
        throwsKeyProblem(KeyProblem.damaged),
      );
    });
  });
}
