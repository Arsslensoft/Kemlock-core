@TestOn('vm')
library;

// The packets that carry a session key, against the keys GnuPG showed
// with --show-session-key and RFC 9580's samples.

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/modes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/s2k.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/session_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'modes_test.dart' show packetBody;
import 'stream_test.dart' show throwsPgp;

/// The body of the first packet of a message.
Uint8List _firstPacket(Uint8List message) => PacketReader(PgpReader.bytes(message)).next()!.body.rest(max: message.length);

/// The encryption subkey of a fixture key.
KeyPacket _subkey(Uint8List key, {String? name}) =>
    readPackets(key)
        .where((p) => p.tag == PgpTag.secretSubkey || p.tag == PgpTag.publicSubkey)
        .map(parseKeyPacket)
        .firstWhere((k) => name == null ? k.algorithm != 22 : k.name == name);

String _keyId(KeyPacket key) => hexOf(key.keyId).toUpperCase();

void main() {
  group('to a key, as GnuPG wrote it', () {
    for (final (file, key, passphrase) in [
      ('to-ed25519.seipd.gpg', () => Keys.ed, null),
      ('to-ed25519.ocb.gpg', () => Keys.ed, null),
      ('to-rsa3072.seipd.gpg', () => Keys.rsa, null),
      ('to-rsa3072.ocb.gpg', () => Keys.rsa, null),
      ('to-kemlock-ed25519.gpg', () => Keys.kemlockEd, null),
      ('to-kemlock-rsa4096.gpg', () => Keys.kemlockRsa, null),
      ('to-protected-ed25519.gpg', () => Keys.edProtected, fixturePassphrase),
      ('to-protected-rsa3072.gpg', () => Keys.rsaProtected, fixturePassphrase),
      ('aes128.gpg', () => Keys.ed, null),
      ('aes192.gpg', () => Keys.ed, null),
      ('to-rsa1024.gpg', () => Keys.rsa1024, null),
    ]) {
      test('$file: the session key --show-session-key printed', () async {
        final pkesk = parsePkesk(packetBody('gnupg/$file', 1));
        final subkey = _subkey(key());
        expect(pkesk.version, 3);
        expect(pkesk.hidden, isFalse);
        expect(pkesk.keyIdHex, _keyId(subkey));
        expect(pkesk.isFor(subkey), isTrue);
        final session = await openPkesk(pkesk, subkey, unlockSecretKey(subkey, passphrase: passphrase));
        final recorded = gnupgSessionKey(file);
        expect(session.cipher, recorded.cipher);
        expect(hexOf(session.key), hexOf(recorded.key));
      });
    }

    test('a zero key ID is reported as hidden', () async {
      final pkesk = parsePkesk(packetBody('gnupg/hidden.gpg', 1));
      expect(pkesk.hidden, isTrue);
      expect(pkesk.keyIdHex, isNull);
      final subkey = _subkey(Keys.ed);
      expect(pkesk.isFor(subkey), isFalse);
      final session = await openPkesk(pkesk, subkey, unlockSecretKey(subkey));
      expect(hexOf(session.key), hexOf(gnupgSessionKey('hidden.gpg').key));
    });

    test('another key, and a changed packet, give the one error', () async {
      final pkesk = parsePkesk(packetBody('gnupg/to-ed25519.seipd.gpg', 1));
      final other = _subkey(Keys.kemlockEd);
      await expectLater(openPkesk(pkesk, other, unlockSecretKey(other)), throwsPgp(PgpProblem.damaged, 'session key'));
      final rsaPkesk = parsePkesk(packetBody('gnupg/to-rsa3072.seipd.gpg', 1));
      final rsaOther = _subkey(Keys.rsaProtected);
      await expectLater(
        openPkesk(rsaPkesk, rsaOther, unlockSecretKey(rsaOther, passphrase: fixturePassphrase)),
        throwsPgp(PgpProblem.damaged, 'session key'),
      );
      // An RSA packet given a Curve25519 key
      final subkey = _subkey(Keys.ed);
      await expectLater(openPkesk(rsaPkesk, subkey, unlockSecretKey(subkey)), throwsPgp(PgpProblem.damaged, 'session key'));
    });

    test('a cipher Kemlock does not read is named', () async {
      final pkesk = parsePkesk(packetBody('gnupg/cast5.gpg', 1));
      final subkey = _subkey(Keys.ed);
      await expectLater(openPkesk(pkesk, subkey, unlockSecretKey(subkey)), throwsPgp(PgpProblem.unsupported, 'CAST5'));
    });
  });

  group('RFC 9580', () {
    test('A.8.1: a version 6 PKESK to X25519', () async {
      final pkesk = parsePkesk(packetBody('rfc9580/a8-x25519-ocb.asc', 1));
      expect((pkesk.version, pkesk.algorithm), (6, 25));
      expect(hexOf(pkesk.fingerprint!).toUpperCase(), '12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885');
      expect(pkesk.keyIdHex, '12C83F1E706F6308');
      final subkey = _subkey(Keys.v6);
      expect(pkesk.isFor(subkey), isTrue);
      final session = await openPkesk(pkesk, subkey, unlockSecretKey(subkey));
      expect(session.cipher, isNull);
      expect(hexOf(session.key), 'dd708f6fa1ed65114d68d2343e7c2f1d');
    });

    for (final (file, mode, key) in [
      ('rfc9580/a9-skesk6-eax.asc', aeadEax, '3881bafe985412459b86c36f98cb9a5e'),
      ('rfc9580/a10-skesk6-ocb.asc', aeadOcb, '28e79ab82397d3c63de24ac217d7b791'),
      ('rfc9580/a11-skesk6-gcm.asc', aeadGcm, '1936fc8568980274bb900d8319360c77'),
    ]) {
      test('$file: a version 6 SKESK', () {
        final skesk = parseSkesk(packetBody(file, 3));
        expect((skesk.version, skesk.cipher, skesk.aead), (6, cipherAes128, mode));
        expect(hexOf(openSkesk(skesk, utf8.encode('password')).key), key);
        expect(() => openSkesk(skesk, utf8.encode('passwore')), throwsPgp(PgpProblem.wrongPassphrase));
      });
    }
  });

  group('to a passphrase, as GnuPG wrote it', () {
    test('version 5, the OCB form', () {
      final skesk = parseSkesk(packetBody('gnupg/sym-ocb.gpg', 3));
      expect((skesk.version, skesk.cipher, skesk.aead), (5, cipherAes256, aeadOcb));
      final session = openSkesk(skesk, utf8.encode(fixturePassphrase));
      expect(hexOf(session.key), hexOf(gnupgSessionKey('sym-ocb.gpg').key));
      expect(() => openSkesk(skesk, utf8.encode('wrong')), throwsPgp(PgpProblem.wrongPassphrase));
    });

    test('version 4 holding an encrypted session key', () {
      final skesk = parseSkesk(packetBody('gnupg/sym-and-key.gpg', 3));
      expect(skesk.version, 4);
      expect(skesk.encrypted, hasLength(33));
      final session = openSkesk(skesk, utf8.encode(fixturePassphrase));
      final recorded = gnupgSessionKey('sym-and-key.gpg');
      expect((session.cipher, hexOf(session.key)), (recorded.cipher, hexOf(recorded.key)));
      // Garbage seldom starts with the octet of a cipher of the right size
      expect(() => openSkesk(skesk, utf8.encode('wrong')), throwsPgp(PgpProblem.wrongPassphrase));
    });

    test('CAST5 and Argon2 are named, whatever the passphrase', () {
      final cast5 = parseSkesk(packetBody('gnupg/sym-cast5.gpg', 3));
      expect(cast5.unsupportedName, 'CAST5');
      expect(() => openSkesk(cast5, utf8.encode(fixturePassphrase)), throwsPgp(PgpProblem.unsupported, 'CAST5'));
      // Shaped like the SKESK of RFC 9580 A.12.1: version 4, AES-128, Argon2
      final argon2 = parseSkesk(unhex('0407040c6b4c8b6a5c2b3d8a7f4e1b2c3d0104150cd7a1ee5dcf8a1f0c1c3a4b5a6c7d8e9f'));
      expect(argon2.unsupportedName, 'Argon2');
      expect(() => openSkesk(argon2, utf8.encode('password')), throwsPgp(PgpProblem.unsupported, 'Argon2'));
    });

    test('unknown versions are named', () {
      expect(() => parseSkesk(Uint8List.fromList([7, 9, 0, 2])), throwsPgp(PgpProblem.unsupported, 'SKESK version 7'));
      expect(() => parsePkesk(Uint8List.fromList([2, 0, 0, 0, 0, 0, 0, 0, 0, 1])), throwsPgp(PgpProblem.unsupported, 'PKESK version 2'));
      expect(() => parsePkesk(Uint8List.fromList([3, 1, 2])), throwsPgp(PgpProblem.damaged));
    });
  });

  group('writing', () {
    final sessionKey = Uint8List.fromList(List.generate(32, (i) => 255 - i));

    test('a PKESK written to each kind of key reads back', () async {
      for (final key in [Keys.ed, Keys.rsa, Keys.kemlockEd, Keys.kemlockRsa]) {
        final subkey = _subkey(key);
        final random = Uint8List.fromList(List.generate(pkeskRandomLength(subkey, 32), (i) => (i * 7 + 1) % 256));
        final body = await writePkesk3(subkey, cipherAes256, sessionKey, random);
        final pkesk = parsePkesk(body);
        expect((pkesk.version, pkesk.algorithm, pkesk.keyIdHex), (3, subkey.algorithm, _keyId(subkey)));
        final session = await openPkesk(pkesk, subkey, unlockSecretKey(subkey));
        expect(session.cipher, cipherAes256);
        expect(session.key, sessionKey);
        // The randomness is all that varies
        expect(await writePkesk3(subkey, cipherAes256, sessionKey, random), body);
      }
    });

    test('the ECDH packet has the shape GnuPG writes', () async {
      final subkey = _subkey(Keys.ed);
      final body = await writePkesk3(subkey, cipherAes256, sessionKey, Uint8List.fromList(List.generate(32, (i) => i)));
      final gnupg = packetBody('gnupg/to-ed25519.seipd.gpg', 1);
      expect(body.length, gnupg.length);
      // Version, key ID, algorithm, the MPI's bit count and the 0x40
      expect(body.sublist(0, 13), gnupg.sublist(0, 13));
      expect(body[13 + 32], 48);
    });

    // openspec: add-post-quantum-pgp, task 6.1
    test('to post-quantum keys, version 3 and 6 packets read back', () async {
      for (final (file, versions) in [
        ('keys/rfc9980/a1-secret.asc', [3, 6]),
        ('keys/rfc9980/a2-secret.asc', [3, 6]),
        ('keys/kemlock/pgp-pq-standard.unprotected.asc', [3, 6]),
        ('keys/gnupg/pqc/ky768-cv25519.secret.asc', [3]),
        ('keys/gnupg/pqc/pqc.secret.asc', [3]),
        ('keys/gnupg/pqc/ky1024-bp384.secret.asc', [3]),
      ]) {
        final subkey = _subkey(binaryKey(file));
        final secret = unlockSecretKey(subkey);
        final random = Uint8List.fromList(List.generate(pkeskRandomLength(subkey, 32), (i) => (i * 5 + 3) % 256));
        for (final version in versions) {
          final body = version == 3
              ? await writePkesk3(subkey, cipherAes256, sessionKey, random)
              : await writePkesk6(subkey, sessionKey, random);
          final pkesk = parsePkesk(body);
          expect((pkesk.version, pkesk.algorithm, pkesk.isFor(subkey)), (version, subkey.algorithm, true), reason: file);
          final session = await openPkesk(pkesk, subkey, secret);
          expect(session.cipher, version == 3 ? cipherAes256 : null);
          expect(session.key, sessionKey);
          expect(
            version == 3 ? await writePkesk3(subkey, cipherAes256, sessionKey, random) : await writePkesk6(subkey, sessionKey, random),
            body,
          );
        }
      }
    });

    test('a Kyber packet has the shape GnuPG writes', () async {
      for (final (key, message) in [
        ('ky768-cv25519', 'ky768-cv25519.message.gpg'),
        ('pqc', 'pqc.message.gpg'),
        ('ky1024-bp384', 'ky1024-bp384.message.gpg'),
      ]) {
        final subkey = _subkey(binaryKey('keys/gnupg/pqc/$key.secret.asc'));
        final body = await writePkesk3(
          subkey,
          cipherAes256,
          sessionKey,
          Uint8List.fromList(List.generate(pkeskRandomLength(subkey, 32), (i) => i + 1)),
        );
        final gnupg = parsePkesk(_firstPacket(binaryKey('keys/gnupg/pqc/$message')));
        final ours = parsePkesk(body);
        expect(ours.material.length, gnupg.material.length, reason: key);
        // The point's bit count, which the random point sets, counts as
        // many bytes, and the ML-KEM ciphertext has the same count
        int bytesOf(Uint8List m) => ((m[0] << 8 | m[1]) + 7) >> 3;
        expect(bytesOf(ours.material), bytesOf(gnupg.material), reason: key);
        final at = 2 + ((gnupg.material[0] << 8 | gnupg.material[1]) + 7) ~/ 8;
        expect(ours.material.sublist(at, at + 4), gnupg.material.sublist(at, at + 4), reason: key);
      }
    });

    test('a key it cannot write to is named', () async {
      await expectLater(
        writePkesk3(_subkey(Keys.brainpool, name: 'brainpoolP256r1'), cipherAes256, sessionKey, Uint8List(32)),
        throwsPgp(PgpProblem.unsupported, 'brainpoolP256r1'),
      );
    });

    test('an SKESK names the S2K, and its key is the session key', () {
      final s2k = S2k.iterated(hashSha256, Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]), 0x60);
      final body = writeSkesk4(cipherAes256, s2k);
      expect(body, [4, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0x60]);
      final skesk = parseSkesk(body);
      final session = openSkesk(skesk, utf8.encode('correct horse'));
      expect(session.cipher, cipherAes256);
      expect(session.key, s2k.derive(utf8.encode('correct horse'), 32));
    });
  });
}
