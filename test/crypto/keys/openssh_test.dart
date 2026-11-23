@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/bcrypt_pbkdf.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openssh.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// The keys in test/fixtures/keys/openssh were made by ssh-keygen from
// OpenSSH 10.2 (tool/keys/make_fixtures.sh), and fingerprints.txt is what
// `ssh-keygen -l` printed for each .pub file. The kemlock/*.openssh files
// were written by tool/keys/write_samples.dart and opened by
// `ssh-keygen -y` (NOTES.md).

const _passphrase = 'fixture passphrase';

const _keys = [
  (name: 'ed25519', algorithm: 'ed25519', bits: null),
  (name: 'ecdsa256', algorithm: 'ecdsa-p256', bits: null),
  (name: 'ecdsa384', algorithm: 'ecdsa-p384', bits: null),
  (name: 'rsa3072', algorithm: 'rsa', bits: 3072),
];

/// Comment to fingerprint, from what `ssh-keygen -l` printed.
final Map<String, String> _fingerprints = {
  for (final line in const LineSplitter().convert(keyFixtureText('openssh/fingerprints.txt')))
    line.substring(line.indexOf(' ', line.indexOf('SHA256:')) + 1, line.lastIndexOf(' (')): line.split(' ')[1],
};

void main() {
  group('reads the keys ssh-keygen made', () {
    for (final k in _keys) {
      for (final protected in [false, true]) {
        final file = protected ? '${k.name}.protected' : k.name;
        test('$file: kind, algorithm, comment, fingerprint and public line', () async {
          final key = await readPrivateKey(keyFixture('openssh/$file'), passphrase: protected ? _passphrase : null);
          final pub = keyFixtureText('openssh/$file.pub').trim();
          final comment = pub.split(' ').skip(2).join(' ');
          expect(key.kind, KeyKind.ssh);
          expect(key.algorithm, k.algorithm);
          expect(key.bits, k.bits);
          expect(key.comment, comment);
          expect(keyFingerprint(key)!.text, _fingerprints[comment], reason: 'what ssh-keygen -l printed');
          expect(sshPublicKeyLine(key), pub);
          expect(sshPublicKeyLine(key, comment: 'laptop'), '${pub.split(' ').take(2).join(' ')} laptop');
        });
      }

      test('${k.name}.protected: asks for the passphrase and refuses a wrong one', () async {
        final file = keyFixture('openssh/${k.name}.protected');
        await expectLater(readPrivateKey(file), throwsKeyProblem(KeyProblem.passphraseNeeded));
        await expectLater(readPrivateKey(file, passphrase: 'fixture passphrasf'), throwsKeyProblem(KeyProblem.wrongPassphrase));
        await expectLater(readPrivateKey(file, passphrase: ''), throwsKeyProblem(KeyProblem.wrongPassphrase));
      });

      test('${k.name}: the PKCS#8 it keeps is the key `openssl pkey -check` called valid (NOTES.md)', () async {
        final key = await readPrivateKey(keyFixture('openssh/${k.name}'));
        expect(exportPkcs8Pem(key), keyFixtureText('kemlock/${k.name}.from-openssh.pkcs8.pem'));
      });
    }

    for (final cipher in ['aes128-ctr', 'aes192-ctr', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc']) {
      test('a key protected with $cipher', () async {
        final key = await readPrivateKey(keyFixtureText('openssh/ed25519.$cipher'), passphrase: _passphrase);
        expect(sshPublicKeyLine(key), keyFixtureText('openssh/ed25519.$cipher.pub').trim());
        await expectLater(
          readPrivateKey(keyFixtureText('openssh/ed25519.$cipher'), passphrase: 'x'),
          throwsKeyProblem(KeyProblem.wrongPassphrase),
        );
      });
    }

    test('a key protected with 4 rounds of bcrypt instead of 16', () async {
      final key = await readPrivateKey(keyFixtureText('openssh/ed25519.rounds4'), passphrase: _passphrase);
      expect(sshPublicKeyLine(key), keyFixtureText('openssh/ed25519.rounds4.pub').trim());
    });

    test('a pasted key whose line breaks were lost', () async {
      final key = await readPrivateKey(keyFixtureText('openssh/ecdsa256').replaceAll('\n', ' '));
      expect(sshPublicKeyLine(key), keyFixtureText('openssh/ecdsa256.pub').trim());
    });
  });

  group('refuses, and says why', () {
    for (final cipher in ['chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com']) {
      test('the cipher $cipher, by name', () async {
        await expectLater(
          readPrivateKey(keyFixtureText('openssh/ed25519.$cipher'), passphrase: _passphrase),
          throwsKeyProblem(KeyProblem.unsupportedCipher, cipher),
        );
      });
    }

    test('an ECDSA P-521 key, by its type', () async {
      await expectLater(
        readPrivateKey(keyFixtureText('openssh/ecdsa521')),
        throwsKeyProblem(KeyProblem.unsupportedKeyType, 'ecdsa-sha2-nistp521'),
      );
    });

    test('a .pub file and a certificate', () async {
      for (final file in ['ed25519.pub', 'rsa3072.pub', 'ecdsa384.pub', 'ed25519-cert.pub']) {
        await expectLater(readPrivateKey(keyFixture('openssh/$file')), throwsKeyProblem(KeyProblem.publicKeyOnly), reason: file);
      }
      // An authorized_keys line with options in front.
      final line = 'from="10.0.0.1",no-pty ${keyFixtureText('openssh/ed25519.pub')}';
      await expectLater(readPrivateKey(line), throwsKeyProblem(KeyProblem.publicKeyOnly));
    });

    test('a PuTTY key', () async {
      const ppk =
          'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: fixture\nPublic-Lines: 2\n'
          'AAAAC3NzaC1lZDI1NTE5AAAAIDpNQWFm69PLYUk8LUN03v98\nAAAA\nPrivate-Lines: 1\nAAAA\nPrivate-MAC: 00\n';
      await expectLater(readPrivateKey(ppk), throwsKeyProblem(KeyProblem.puttyKey));
      await expectLater(readPrivateKey(utf8.encode(ppk)), throwsKeyProblem(KeyProblem.puttyKey));
    });

    test('a key whose public half was swapped for another', () async {
      // The public key blob of ecdsa256.protected spliced into ecdsa256.
      final plain = readPemBlocks(keyFixtureText('openssh/ecdsa256')).single.decode();
      final other = readPemBlocks(keyFixtureText('openssh/ecdsa256.protected')).single.decode();
      final r = SshReader(Uint8List.sublistView(plain, 15));
      final head = [r.text(), r.text(), r.string(), r.uint32()];
      r.string();
      final private = r.string();
      final o = SshReader(Uint8List.sublistView(other, 15))
        ..text()
        ..text()
        ..string()
        ..uint32();
      final w = SshWriter()
        ..raw(plain.sublist(0, 15))
        ..text(head[0] as String)
        ..text(head[1] as String)
        ..string(head[2] as Uint8List)
        ..uint32(1)
        ..string(o.string())
        ..string(private);
      await expectLater(readPrivateKey(w.bytes), throwsKeyProblem(KeyProblem.damaged));
    });
  });

  group('writes', () {
    test('a plain key, in the form ssh-keygen writes, that it reads back', () async {
      for (final k in _keys) {
        final key = await readPrivateKey(keyFixture('openssh/${k.name}'));
        final file = await exportOpenSsh(key);
        expect(file, startsWith('-----BEGIN OPENSSH PRIVATE KEY-----\n'));
        expect(file.split('\n')[1], hasLength(70));
        final blob = readPemBlocks(file).single.decode();
        final r = SshReader(Uint8List.sublistView(blob, 15));
        expect([r.text(), r.text(), r.string(), r.uint32()], ['none', 'none', isEmpty, 1]);
        final back = await readPrivateKey(file);
        expect(back.private, key.private);
        expect(back.comment, key.comment);
      }
    });

    test('a protected key with aes256-ctr and 16 rounds of bcrypt, with the comment given', () async {
      final key = await readPrivateKey(keyFixture('openssh/ed25519'));
      final file = await exportOpenSsh(key, passphrase: 'another passphrase', comment: 'laptop');
      final blob = readPemBlocks(file).single.decode();
      final r = SshReader(Uint8List.sublistView(blob, 15));
      expect(r.text(), 'aes256-ctr');
      expect(r.text(), 'bcrypt');
      final options = SshReader(r.string());
      expect(options.string(), hasLength(16));
      expect(options.uint32(), 16);
      final back = await readPrivateKey(file, passphrase: 'another passphrase');
      expect(back.private, key.private);
      expect(back.comment, 'laptop');
      await expectLater(readPrivateKey(file, passphrase: _passphrase), throwsKeyProblem(KeyProblem.wrongPassphrase));
    });

    test('the keys ssh-keygen -y opened with the passphrase (NOTES.md)', () async {
      for (final k in _keys) {
        final key = await readPrivateKey(keyFixtureText('kemlock/${k.name}.openssh'), passphrase: _passphrase);
        expect(sshPublicKeyLine(key), keyFixtureText('openssh/${k.name}.pub').trim());
      }
    });

    test('nothing for a key with no SSH form', () async {
      final key = await readPrivateKey(keyFixture('openssl/x25519.pkcs8.der'));
      expect(key.hasSshForm, isFalse);
      expect(sshPublicKeyLine(key), isNull);
      await expectLater(exportOpenSsh(key), throwsArgumentError);
    });

    test('a signing key with an SSH form, kept as an SSH key, gets the SSH fingerprint', () async {
      final key = await readPrivateKey(keyFixture('openssl/ed25519.pkcs8.der'));
      expect(key.kind, KeyKind.signing);
      expect(key.hasSshForm, isTrue);
      final ssh = key.withKind(KeyKind.ssh);
      expect(keyFingerprint(ssh)!.text, isNot(keyFingerprint(key)!.text));
      expect(sshPublicKeyLine(ssh), startsWith('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI'));
    });
  });

  group('bcrypt_pbkdf', () {
    test("starts Blowfish from pi's digits", () {
      expect(blowfishInitialState[0], 0x243f6a88); // P[0]
      expect(blowfishInitialState[17], 0x8979fb1b); // P[17]
      expect(blowfishInitialState[18], 0xd1310ba6); // S0[0]
      expect(blowfishInitialState[18 + 1023], 0x3ac372e6); // S3[255]
    });

    test('gives the known answers of other implementations', () {
      expect(
        toHex(bcryptPbkdf(utf8.encode('password'), utf8.encode('salt'), 4, 32)),
        '5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9',
      );
      expect(toHex(bcryptPbkdf(utf8.encode('password'), [0], 4, 16)), 'c12b566235eee04c212598970a579a67');
      expect(toHex(bcryptPbkdf([0], utf8.encode('salt'), 4, 16)), '6051be18c2f4f82cbf0efee5471b4bb9');
    });

    test('refuses what OpenBSD refuses', () {
      expect(() => bcryptPbkdf([], [1], 1, 16), throwsArgumentError);
      expect(() => bcryptPbkdf([1], [], 1, 16), throwsArgumentError);
      expect(() => bcryptPbkdf([1], [1], 0, 16), throwsArgumentError);
      expect(() => bcryptPbkdf([1], [1], 1, 1025), throwsArgumentError);
    });
  });
}
