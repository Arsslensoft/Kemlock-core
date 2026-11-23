@TestOn('vm')
library;

// Passphrase hashing, against the files `gpg -c` wrote with each S2K and
// hash, and RFC 9580's samples.

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/modes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/s2k.dart';
import 'package:kemlock_core/crypto/keys/openpgp/session_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart' as writer;
import 'package:test/test.dart';

import 'fixtures.dart';
import 'modes_test.dart' show packetBody;
import 'stream_test.dart' show throwsPgp;

final _passphrase = utf8.encode(fixturePassphrase);

void main() {
  group('the key opens the file gpg -c made', () {
    for (final (name, type, hashId) in [
      ('sym-s2k0', S2k.simple, hashSha1),
      ('sym-s2k1', S2k.salted, hashSha1),
      ('sym-s2k3-SHA1', S2k.iteratedSalted, hashSha1),
      ('sym-s2k3-SHA224', S2k.iteratedSalted, hashSha224),
      ('sym-s2k3-SHA256', S2k.iteratedSalted, hashSha256),
      ('sym-s2k3-SHA384', S2k.iteratedSalted, hashSha384),
      ('sym-s2k3-SHA512', S2k.iteratedSalted, hashSha512),
      ('sym-default', S2k.iteratedSalted, hashSha512),
      ('sym-aes128', S2k.iteratedSalted, hashSha1),
    ]) {
      test('$name.gpg', () {
        final skesk = parseSkesk(packetBody('gnupg/$name.gpg', 3));
        expect((skesk.version, skesk.s2k.type, skesk.s2k.hashAlgorithm), (4, type, hashId));
        expect(skesk.encrypted, isNull);
        expect(skesk.unsupportedName, isNull);

        final recorded = gnupgSessionKey('$name.gpg');
        expect(skesk.cipher, recorded.cipher);
        final key = skesk.s2k.derive(_passphrase, cipherKeyLength(skesk.cipher));
        // In these files the passphrase's key is the session key GnuPG showed
        expect(hexOf(key), hexOf(recorded.key));

        // And the data proves it: the prefix repeats and the MDC matches
        final seipd = packetBody('gnupg/$name.gpg', 18);
        expect(seipd[0], 1);
        final plain = PgpReader(Seipd1Reader(key, BytesSource(Uint8List.sublistView(seipd, 1)))).rest(max: 1 << 20);
        expect(plain, isNotEmpty);
        final wrong = skesk.s2k.derive(utf8.encode('another passphrase'), key.length);
        expect(
          () =>
              PgpReader(Seipd1Reader(wrong, BytesSource(Uint8List.sublistView(seipd, 1)), wrongKeyIs: PgpProblem.wrongPassphrase))
                  .rest(max: 1 << 20),
          throwsPgp(PgpProblem.wrongPassphrase),
        );
      });
    }
  });

  test('a key longer than the digest takes a second pass over a zero byte', () {
    final skesk = parseSkesk(packetBody('gnupg/sym-s2k3-SHA1.gpg', 3));
    final long = skesk.s2k.derive(_passphrase, 32);
    final short = skesk.s2k.derive(_passphrase, 20);
    expect(long.sublist(0, 20), short);
    expect(long.sublist(20), isNot(short.sublist(0, 12)));
    // Three passes for 64 bytes of SHA-224
    final s2k = S2k.iterated(hashSha224, Uint8List(8), 0x60);
    expect(s2k.derive(_passphrase, 64).sublist(0, 28), s2k.derive(_passphrase, 28));
    expect(s2k.derive(_passphrase, 64).sublist(0, 56), s2k.derive(_passphrase, 56));
  });

  test('the samples of RFC 9580 A.9 to A.11 (count octet 255)', () {
    for (final (file, key) in [
      ('rfc9580/a9-skesk6-eax.asc', '154967e590aa1f923e1c0ac64c88f23d'),
      ('rfc9580/a10-skesk6-ocb.asc', 'e80de243a362d93b9dc607ede96a7356'),
      ('rfc9580/a11-skesk6-gcm.asc', '250281715bba7828ef71ef64c4784753'),
    ]) {
      final skesk = parseSkesk(packetBody(file, 3));
      expect((skesk.version, skesk.s2k.type, skesk.s2k.hashAlgorithm, skesk.s2k.codedCount), (6, S2k.iteratedSalted, hashSha256, 255));
      expect(hexOf(skesk.s2k.derive(utf8.encode('password'), 16)), key, reason: file);
    }
  });

  test('what moved here gives what it gave', () {
    // The function a key's export calls, now from this file
    final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
    expect(writer.iteratedSaltedS2k(_passphrase, salt, 0x60), iteratedSaltedS2k(_passphrase, salt, 0x60));
    expect(iteratedSaltedS2k(_passphrase, salt, 0x60), S2k.iterated(hashSha256, salt, 0x60).derive(_passphrase, 32));
  });

  test('specifiers are written as they are read', () {
    final s2k = S2k.iterated(hashSha256, Uint8List.fromList([9, 8, 7, 6, 5, 4, 3, 2]), 0xf0);
    expect(s2k.encoded, [3, 8, 9, 8, 7, 6, 5, 4, 3, 2, 0xf0]);
    final read = S2k.read(PgpReader.bytes(s2k.encoded));
    expect((read.type, read.hashAlgorithm, read.codedCount), (3, 8, 0xf0));
    expect(read.salt, s2k.salt);
  });

  test('Argon2, a stub and an unknown type or hash', () {
    final argon2 = S2k.read(PgpReader.bytes(Uint8List.fromList([4, ...List.filled(16, 7), 1, 4, 21])));
    expect(argon2.unsupportedName, 'Argon2');
    expect(() => argon2.derive(_passphrase, 32), throwsPgp(PgpProblem.unsupported, 'Argon2'));

    final stub = S2k.read(PgpReader.bytes(Uint8List.fromList([101, 0, 0x47, 0x4e, 0x55, 1])));
    expect(stub.type, S2k.gnu);
    expect(() => stub.derive(_passphrase, 32), throwsPgp(PgpProblem.unsupported));

    expect(() => S2k.read(PgpReader.bytes(Uint8List.fromList([2, 8]))), throwsPgp(PgpProblem.unsupported, 'S2K type 2'));
    final md5 = S2k.read(PgpReader.bytes(Uint8List.fromList([0, 1])));
    expect(md5.unsupportedName, 'MD5');
    expect(() => md5.derive(_passphrase, 16), throwsPgp(PgpProblem.unsupported, 'MD5'));
    expect(() => S2k.read(PgpReader.bytes(Uint8List.fromList([3, 8, 1, 2]))), throwsPgp(PgpProblem.damaged));
  });
}
