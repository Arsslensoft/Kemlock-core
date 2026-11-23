@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/pbes2.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The encrypted keys in test/fixtures/keys/openssl were made by
// `openssl pkcs8 -topk8` from the plain keys beside them, with the
// passphrase below; kemlock/p256.pbes2.pem was written by
// tool/keys/write_samples.dart, and NOTES.md records `openssl pkey`
// opening it.

const _passphrase = 'fixture passphrase';

const _encrypted = [
  (file: 'rsa2048.pbes2-sha1-aes128.pem', plain: 'rsa2048', scheme: 'PBKDF2-HMAC-SHA-1, AES-128-CBC'),
  (file: 'p256.pbes2-sha256-aes256.pem', plain: 'p256', scheme: 'PBKDF2-HMAC-SHA-256, AES-256-CBC'),
  (file: 'ed25519.pbes2-sha512-aes256.pem', plain: 'ed25519', scheme: 'PBKDF2-HMAC-SHA-512, AES-256-CBC'),
  (file: 'x25519.pbes2-sha256-aes128.pem', plain: 'x25519', scheme: 'PBKDF2-HMAC-SHA-256, AES-128-CBC'),
  (file: 'p384.pbes2-default.der', plain: 'p384', scheme: "OpenSSL's defaults, in DER"),
  (file: 'p256.pbes2-sha256-aes192-100000.pem', plain: 'p256', scheme: 'AES-192-CBC, 100,000 rounds'),
];

void main() {
  group('opens the keys OpenSSL encrypted', () {
    for (final e in _encrypted) {
      test('${e.plain}: ${e.scheme}', () async {
        final key = await readPrivateKey(keyFixture('openssl/${e.file}'), passphrase: _passphrase);
        expect(key.private, keyFixture('openssl/${e.plain}.pkcs8.der'));
        expect(key.public, keyFixture('openssl/${e.plain}.spki.der'));
      });

      test('${e.plain}: ${e.scheme}, asks for the passphrase and refuses a wrong one', () async {
        final file = keyFixture('openssl/${e.file}');
        await expectLater(readPrivateKey(file), throwsKeyProblem(KeyProblem.passphraseNeeded));
        await expectLater(readPrivateKey(file, passphrase: 'fixture passphrasf'), throwsKeyProblem(KeyProblem.wrongPassphrase));
        await expectLater(readPrivateKey(file, passphrase: ''), throwsKeyProblem(KeyProblem.wrongPassphrase));
      });
    }
  });

  group('refuses the schemes it does not read, by name', () {
    for (final (file, name) in [
      ('p256.pbes2-scrypt.pem', 'scrypt'),
      ('p256.pbes2-des3.pem', 'des-ede3-cbc'),
      ('rsa2048.pbes1-sha1-3des.pem', 'pbeWithSHAAnd3-KeyTripleDES-CBC'),
    ]) {
      test(name, () async {
        await expectLater(
          readPrivateKey(keyFixtureText('openssl/$file'), passphrase: _passphrase),
          throwsKeyProblem(KeyProblem.unsupportedCipher, name),
        );
        // Before asking for a passphrase, too.
        await expectLater(readPrivateKey(keyFixtureText('openssl/$file')), throwsKeyProblem(KeyProblem.unsupportedCipher, name));
      });
    }
  });

  group('writes', () {
    test('a key that it reads back with the passphrase', () async {
      final key = await readPrivateKey(keyFixture('openssl/ed25519.pkcs8.der'));
      final pem = exportPkcs8Pem(key, passphrase: 'another passphrase', iterations: 1000);
      expect(pem, startsWith('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'));
      final back = await readPrivateKey(pem, passphrase: 'another passphrase');
      expect(back.private, key.private);
      await expectLater(readPrivateKey(pem, passphrase: _passphrase), throwsKeyProblem(KeyProblem.wrongPassphrase));
    });

    test('PBES2 with PBKDF2-HMAC-SHA-256, 600,000 rounds and AES-256-CBC, the shape OpenSSL writes', () async {
      final key = await readPrivateKey(keyFixture('openssl/p256.pkcs8.der'));
      final der = readPemBlocks(exportPkcs8Pem(key, passphrase: _passphrase)).single.decode();
      final r = readSequence(der);
      final scheme = r.sequence();
      expect(scheme.oid(), '1.2.840.113549.1.5.13');
      final params = scheme.sequence();
      final kdf = params.sequence();
      expect(kdf.oid(), '1.2.840.113549.1.5.12');
      final pbkdf2 = kdf.sequence();
      expect(pbkdf2.octetString(), hasLength(16));
      expect(pbkdf2.smallInteger(), 600000);
      final prf = pbkdf2.sequence();
      expect(prf.oid(), '1.2.840.113549.2.9');
      prf.readNull();
      final cipher = params.sequence();
      expect(cipher.oid(), '2.16.840.1.101.3.4.1.42');
      expect(cipher.octetString(), hasLength(16));
      expect(r.octetString().length % 16, 0);
    });

    test('a fresh salt and IV each time', () async {
      final key = await readPrivateKey(keyFixture('openssl/x25519.pkcs8.der'));
      final a = exportPkcs8Pem(key, passphrase: _passphrase, iterations: 1000);
      final b = exportPkcs8Pem(key, passphrase: _passphrase, iterations: 1000);
      expect(a, isNot(b));
    });

    test('the key Kemlock wrote that `openssl pkey` opened (NOTES.md)', () async {
      final key = await readPrivateKey(keyFixtureText('kemlock/p256.pbes2.pem'), passphrase: _passphrase);
      expect(key.private, keyFixture('openssl/p256.pkcs8.der'));
    });
  });

  test('refuses a file that asks for more rounds than it runs, without running them', () {
    Uint8List withRounds(int rounds) => derSequence([
      derSequence([
        derOid('1.2.840.113549.1.5.13'),
        derSequence([
          derSequence([
            derOid('1.2.840.113549.1.5.12'),
            derSequence([derOctetString(Uint8List(16)), derSmallInteger(rounds)]),
          ]),
          derSequence([derOid('2.16.840.1.101.3.4.1.42'), derOctetString(Uint8List(16))]),
        ]),
      ]),
      derOctetString(Uint8List(32)),
    ]);
    expect(() => decryptPkcs8(withRounds(maxPbkdf2Iterations + 1), _passphrase), throwsKeyProblem(KeyProblem.unsupportedCipher));
    expect(() => decryptPkcs8(withRounds(0), _passphrase), throwsKeyProblem(KeyProblem.damaged));
    // One round over zeros: the padding comes out wrong.
    expect(() => decryptPkcs8(withRounds(1), _passphrase), throwsKeyProblem(KeyProblem.wrongPassphrase));
  });
}
