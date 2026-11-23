@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// openssl/ml-kem-768.*, ml-kem-1024.* and ml-dsa-65.* are one key each that
// OpenSSL 3.6.1 made from the seed in <name>.seed.hex and wrote in its three
// PKCS#8 forms: both (its default, seed-priv), seed (seed-only) and
// expanded (priv-only), with the SPKI `openssl pkey -pubout` gave.

const _keys = [
  (name: 'ml-kem-768', parameters: PqParameters.mlKem768, kind: KeyKind.exchange),
  (name: 'ml-kem-1024', parameters: PqParameters.mlKem1024, kind: KeyKind.exchange),
  (name: 'ml-dsa-65', parameters: PqParameters.mlDsa65, kind: KeyKind.signing),
];

Uint8List _pem(String file) => readPemBlocks(keyFixtureText('openssl/$file')).single.decode();

void main() {
  for (final k in _keys) {
    group(k.name, () {
      final spki = keyFixture('openssl/${k.name}.spki.der');

      for (final form in PqForm.values) {
        test('reads the ${form.name} form, keeping it as given, with the public half OpenSSL derives', () async {
          final pkcs8 = _pem('${k.name}.${form.name}.pem');
          final key = await readPrivateKey(keyFixtureText('openssl/${k.name}.${form.name}.pem'));
          expect(key.kind, k.kind);
          expect(key.algorithm, k.name);
          expect(key.bits, isNull);
          expect(key.private, pkcs8);
          expect(key.public, spki);
          expect(publicKeyPem(key), keyFixtureText('openssl/${k.name}.spki.pem'));
          expect(key.hasSshForm, isFalse);
        });

        test('writes the ${form.name} form as OpenSSL does, from the seed', () {
          final seed = fromHex(keyFixtureText('openssl/${k.name}.seed.hex').trim());
          final material = pqMaterial(k.parameters, seed: seed);
          expect(writePkcs8(material, pqForm: form), _pem('${k.name}.${form.name}.pem'));
        });
      }

      test('reads DER, and the SPKI back', () async {
        final key = await readPrivateKey(keyFixture('openssl/${k.name}.both.der'));
        expect(key.private, keyFixture('openssl/${k.name}.both.der'));
        final half = readSpki(spki)!;
        expect(half.algorithm.id, k.name);
        expect(writeSpki(half), spki);
      });

      test("reads OpenSSL's older bare forms, the seed or the expanded key alone", () async {
        final material = pqMaterial(k.parameters, seed: fromHex(keyFixtureText('openssl/${k.name}.seed.hex').trim()));
        for (final bare in [material.seed!, material.expanded]) {
          final pkcs8 = derSequence([
            derSmallInteger(0),
            derSequence([derOid(k.parameters.oid)]),
            derOctetString(bare),
          ]);
          expect((await readPrivateKey(pkcs8)).public, spki);
        }
      });

      test('refuses a seed and an expanded key that are not the same key', () async {
        final other = k.parameters.keygen(Uint8List(k.parameters.seedLength));
        final seed = fromHex(keyFixtureText('openssl/${k.name}.seed.hex').trim());
        final pkcs8 = derSequence([
          derSmallInteger(0),
          derSequence([derOid(k.parameters.oid)]),
          derOctetString(derSequence([derOctetString(seed), derOctetString(other.secretKey)])),
        ]);
        await expectLater(readPrivateKey(pkcs8), throwsKeyProblem(KeyProblem.damaged));
      });

      test('refuses an expanded key that fails its own checks', () async {
        final info = readSequence(_pem('${k.name}.expanded.pem'))
          ..smallInteger()
          ..sequence();
        final expanded = DerReader(info.octetString()).octetString();
        final broken = Uint8List.fromList(expanded)..[expanded.length - 40] ^= 1;
        final pkcs8 = derSequence([
          derSmallInteger(0),
          derSequence([derOid(k.parameters.oid)]),
          derOctetString(derOctetString(broken)),
        ]);
        await expectLater(readPrivateKey(pkcs8), throwsKeyProblem(KeyProblem.damaged));
      });
    });
  }

  test('keeps ML-KEM-512 as a key of an algorithm it does not know', () async {
    final key = await readPrivateKey(keyFixtureText('openssl/ml-kem-512.both.pem'));
    expect(key.kind, KeyKind.other);
    expect(key.algorithm, '2.16.840.1.101.3.4.4.1');
    expect(key.public, isNull);
  });
}
