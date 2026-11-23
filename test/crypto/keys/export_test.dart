@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart' show KeyPacket, parseKeyPacket;
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart' show protectSecretKeyPacket;
import 'package:test/test.dart';

import 'fixtures.dart';

// exportPrivateKey picks the form by kind (design decision 5); each export
// re-imports, with the passphrase, to the key it came from.

const _passphrase = 'export passphrase';

void main() {
  final cases = [
    (file: 'openssh/ed25519', header: '-----BEGIN OPENSSH PRIVATE KEY-----'),
    (file: 'openssl/p256.pkcs8.der', header: '-----BEGIN ENCRYPTED PRIVATE KEY-----'),
    (file: 'openssl/ml-kem-768.both.der', header: '-----BEGIN ENCRYPTED PRIVATE KEY-----'),
    (file: 'openssl/ed448.pkcs8.der', header: '-----BEGIN ENCRYPTED PRIVATE KEY-----'),
    (file: 'gnupg/ed25519.secret.gpg', header: '-----BEGIN PGP PRIVATE KEY BLOCK-----'),
  ];

  for (final c in cases) {
    test('${c.file}: in its kind\'s form, protected, and back to the same key', () async {
      final key = await readPrivateKey(keyFixture(c.file));
      final exported = await exportPrivateKey(key, passphrase: _passphrase, comment: 'laptop');
      expect(exported, startsWith('${c.header}\n'));
      final back = await readPrivateKey(exported, passphrase: _passphrase);
      expect(back.kind, key.kind);
      expect(back.algorithm, key.algorithm);
      expect(back.public, key.public);
      if (key.kind == KeyKind.pgp) {
        expect(back.pgp!.protected, isTrue);
      } else {
        expect(back.private, key.private);
        await expectLater(readPrivateKey(exported), throwsKeyProblem(KeyProblem.passphraseNeeded));
      }
      if (key.kind == KeyKind.ssh) expect(back.comment, 'laptop');
    });

    test('${c.file}: unprotected only when the passphrase is null, never when it is empty', () async {
      final key = await readPrivateKey(keyFixture(c.file));
      final plain = await exportPrivateKey(key);
      expect((await readPrivateKey(plain)).private, key.private);
      await expectLater(exportPrivateKey(key, passphrase: ''), throwsArgumentError);
    });
  }

  // openspec: add-post-quantum-pgp, task 4.5
  group('post-quantum PGP keys', () {
    for (final name in ['pq-standard', 'pq-gnupg']) {
      test('$name: exported with a passphrase and imported back, the same key', () async {
        final key = await readPrivateKey(keyFixtureText('kemlock/pgp-$name.unprotected.asc'));
        final exported = exportPgpSecretKey(key, passphrase: _passphrase);
        final back = await readPrivateKey(exported);
        expect(back.pgp!.protected, isTrue);
        expect(back.public, key.public);
        expect(back.pgp!.primary.fingerprintHex, key.pgp!.primary.fingerprintHex);
        expect(back.pgp!.subkeys.single.fingerprintHex, key.pgp!.subkeys.single.fingerprintHex);
        expect(await verifyPgpSelfSignatures(back.private), isTrue);
        // A version 6 key without the CRC-24 line, the others with it
        expect(exported.contains(RegExp(r'^=', multiLine: true)), name != 'pq-standard');
      });
    }

    test("a version 4 key's armor is byte for byte what it was", () async {
      for (final name in ['ed25519', 'rsa4096']) {
        final key = await readPrivateKey(keyFixtureText('kemlock/pgp-$name.unprotected.asc'));
        expect(exportPgpSecretKey(key), keyFixtureText('kemlock/pgp-$name.unprotected.asc'));
        expect(publicKeyPem(key), keyFixtureText('kemlock/pgp-$name.public.asc'));
      }
    });
  });

  // A GnuPG stub holds no secret, so it protects none: a key keeps its own passphrase only when every secret part
  // it holds is behind one
  group('a PGP key with a part that is not protected', () {
    KeyPacket packet(Uint8List key, int index) => parseKeyPacket(readPackets(key)[index]);
    int indexOfSubkey(Uint8List key) => readPackets(key).indexWhere((p) => p.tag == PgpTag.secretSubkey);

    test('a stub and a subkey in the clear: the subkey gets the export passphrase, and the stub stays as it was', () async {
      // `gpg --export-secret-subkeys` of a key with no passphrase
      final stub = File('test/fixtures/pgp/gnupg/ed25519.stub.secret.gpg').readAsBytesSync();
      final key = await readPrivateKey(stub);
      expect((key.pgp!.primary.stub, key.pgp!.subkeys.single.protected), (true, false));
      expect((key.pgp!.protected, key.pgp!.partlyProtected), (false, false));

      final back = await readPrivateKey(exportPgpSecretKey(key, passphrase: _passphrase));
      expect(back.pgp!.protected, isTrue);
      expect(readPackets(back.private).first.encoded, readPackets(key.private).first.encoded);
      final subkey = packet(back.private, indexOfSubkey(back.private));
      expect(() => unlockSecretKey(subkey), throwsA(isA<PgpException>().having((e) => e.problem, 'problem', PgpProblem.passphraseNeeded)));
      expect(unlockSecretKey(subkey, passphrase: _passphrase), isA<PgpSecret>());
      expect(await verifyPgpSelfSignatures(back.private), isTrue);
      // Without a passphrase it goes out as it is, which the person chose
      expect(await readPrivateKey(exportPgpSecretKey(key)), isA<ParsedKey>().having((k) => k.private, 'private', key.private));
    });

    test('a stub and a protected subkey keep their own passphrase, byte for byte', () async {
      final key = await readPrivateKey(keyFixtureText('gnupg/editing/protected.stub.secret.asc'));
      expect((key.pgp!.primary.stub, key.pgp!.protected), (true, true));

      expect(exportPgpSecretKey(key, passphrase: _passphrase), exportPgpSecretKey(key));
      expect((await readPrivateKey(exportPgpSecretKey(key, passphrase: _passphrase))).private, key.private);
    });

    test('a part behind its own passphrase keeps it, and the part in the clear gets the export passphrase', () async {
      final plain = keyFixture('gnupg/ed25519.secret.gpg');
      final mixed = Uint8List.fromList([
        for (final p in readPackets(plain))
          ...(p.tag == PgpTag.secretKey ? protectSecretKeyPacket(p, 'its own', s2kCount: 0x60) : p.encoded),
      ]);
      final key = await readPrivateKey(mixed);
      expect((key.pgp!.protected, key.pgp!.partlyProtected), (false, true));

      final back = await readPrivateKey(exportPgpSecretKey(key, passphrase: _passphrase));
      expect(back.pgp!.protected, isTrue);
      expect(readPackets(back.private).first.encoded, readPackets(mixed).first.encoded);
      expect(unlockSecretKey(packet(back.private, 0), passphrase: 'its own'), isA<PgpSecret>());
      expect(unlockSecretKey(packet(back.private, indexOfSubkey(back.private)), passphrase: _passphrase), isA<PgpSecret>());
    });
  });
}
