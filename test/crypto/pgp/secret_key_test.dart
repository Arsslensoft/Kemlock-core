@TestOn('vm')
library;

// The secret part of key packets: parsed, and unlocked with a passphrase.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/openpgp/ecdh.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/modes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/rsa.dart';
import 'package:kemlock_core/crypto/keys/openpgp/s2k.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

import 'fixtures.dart';
import 'stream_test.dart' show throwsPgp;

List<KeyPacket> _keyPackets(Uint8List key) => [
  for (final p in readPackets(key))
    if (const {PgpTag.secretKey, PgpTag.secretSubkey, PgpTag.publicKey, PgpTag.publicSubkey}.contains(p.tag)) parseKeyPacket(p),
];

/// Checks that [secret] is the secret half of [key]'s public part.
Future<void> _expectBelongs(KeyPacket key, PgpSecret secret) async {
  switch (secret) {
    case Ed25519Secret(:final seed):
      final public = (await ed25519Material(seed)).publicKey;
      final material = key.publicMaterial;
      // Algorithm 22: a curve OID, then an MPI of 0x40 and the point; 27: the point
      expect(material.sublist(material.length - 32), public);
      expect(key.algorithm, anyOf(22, 27));
    case X25519Secret(secret: final scalar):
      final public = await x25519Public(scalar);
      expect(key.algorithm == 25 ? key.publicMaterial : EcdhPublic.of(key).point, public);
    case RsaSecret(:final material):
      expect(material.bits, key.bits);
      expect(material.n, material.p * material.q);
      final m = BigInt.from(0x1234567);
      expect(rsaPrivate(material, m.modPow(material.e, material.n)), m);
      // OpenPGP keeps p below q
      expect(material.p < material.q, isTrue);
    case MlDsaEd25519Secret(:final ed25519Seed, :final mlDsaSeed):
      expect(key.publicMaterial.sublist(0, 32), (await ed25519Material(ed25519Seed)).publicKey);
      expect(key.publicMaterial.sublist(32), MlDsa65.keygen(mlDsaSeed).publicKey);
    case MlKemX25519Secret(:final x25519, :final mlKemSeed):
      expect(key.publicMaterial.sublist(0, 32), await x25519Public(x25519));
      expect(key.publicMaterial.sublist(32), MlKem768.keygen(mlKemSeed).publicKey);
    case KyberSecret(:final ecc, :final mlKemSecretKey):
      expect(_kyberPoint(key), await _eccPublic(key, ecc));
      // The decapsulation key holds the encapsulation key after its first
      // 384 * k bytes
      final public = _kyberMlKem(key);
      final k = public.length == MlKem768.publicKeyLength ? 3 : 4;
      expect(mlKemSecretKey.sublist(384 * k, 384 * k + public.length), public);
  }
}

/// The MPI of a Kyber key's ECC point, and where it ends.
(Uint8List, int) _kyberPointMpi(KeyPacket key) {
  final m = key.publicMaterial;
  final at = 1 + m[0];
  final end = at + 2 + ((m[at] << 8 | m[at + 1]) + 7) ~/ 8;
  return (m.sublist(at + 2, end), end);
}

/// A Kyber key's ECC point, without X25519's 0x40.
Uint8List _kyberPoint(KeyPacket key) {
  final (point, _) = _kyberPointMpi(key);
  return point[0] == 0x40 ? point.sublist(1) : point;
}

/// A Kyber key's ML-KEM public key.
Uint8List _kyberMlKem(KeyPacket key) {
  final m = key.publicMaterial;
  final (_, at) = _kyberPointMpi(key);
  final length = m[at] << 24 | m[at + 1] << 16 | m[at + 2] << 8 | m[at + 3];
  return m.sublist(at + 4, at + 4 + length);
}

/// The public point of the ECC secret of a Kyber key.
Future<Uint8List> _eccPublic(KeyPacket key, Uint8List ecc) async {
  if (key.name == 'ky768_cv25519') return x25519Public(ecc);
  final domain = pc.ECDomainParameters(key.name == 'ky768_bp256' ? 'brainpoolp256r1' : 'brainpoolp384r1');
  return (domain.G * bytesToBigInt(ecc))!.getEncoded(false);
}

void main() {
  group('unprotected material', () {
    for (final (name, key, kinds) in [
      ('gnupg/ed25519.secret.gpg', () => Keys.ed, [Ed25519Secret, X25519Secret]),
      ('gnupg/rsa3072.secret.gpg', () => Keys.rsa, [RsaSecret, RsaSecret]),
      ('kemlock/pgp-ed25519.unprotected.asc', () => Keys.kemlockEd, [Ed25519Secret, X25519Secret]),
      ('kemlock/pgp-rsa4096.unprotected.asc', () => Keys.kemlockRsa, [RsaSecret, RsaSecret]),
      ('rfc9580/v6-secret.asc', () => Keys.v6, [Ed25519Secret, X25519Secret]),
      ('pgp/gnupg/signing-subkey.secret.asc', () => Keys.signingSubkey, [Ed25519Secret, Ed25519Secret, X25519Secret]),
      ('pgp/gnupg/rsa1024.secret.asc', () => Keys.rsa1024, [RsaSecret, RsaSecret]),
    ]) {
      test('$name: each packet gives the secret of its public part', () async {
        final packets = _keyPackets(key());
        expect(packets, hasLength(kinds.length));
        for (final (i, packet) in packets.indexed) {
          final secret = unlockSecretKey(packet);
          expect(secret.runtimeType, kinds[i]);
          await _expectBelongs(packet, secret);
          expect(needsPassphrase(packet), isFalse);
        }
      });
    }

    test('the sample key of RFC 9580 A.4 holds the RFC\'s X25519 secret', () {
      final secret = unlockSecretKey(_keyPackets(Keys.v6)[1]) as X25519Secret;
      expect(hexOf(secret.secret), '4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8');
    });

    test('a NIST P-256 key is refused by name', () {
      for (final packet in _keyPackets(Keys.nistp256)) {
        expect(() => unlockSecretKey(packet), throwsPgp(PgpProblem.unsupported, 'nistp256'));
      }
    });

    test('material that does not fit its public part is damaged', () {
      final ed = _keyPackets(Keys.ed);
      // An RSA key's numbers given the wrong primes
      final rsa = _keyPackets(Keys.rsa);
      final other = rsa[1].plainSecret!;
      expect(() => parseSecretMaterial(rsa[0], other), throwsPgp(PgpProblem.damaged));
      expect(() => parseSecretMaterial(ed[0], Uint8List.fromList([0, 8, 1, 2])), throwsPgp(PgpProblem.damaged));
      expect(() => parseSecretMaterial(ed[0], Uint8List(0)), throwsPgp(PgpProblem.damaged));
    });

    test('a public key packet holds no secret', () {
      expect(() => unlockSecretKey(_keyPackets(Keys.edPublic).first), throwsPgp(PgpProblem.noSecretHere));
    });
  });

  group('protected by a passphrase', () {
    test('the keys GnuPG protected (usage 254, AES-128, SHA-1) unlock', () async {
      for (final key in [Keys.edProtected, Keys.rsaProtected]) {
        final before = Uint8List.fromList(key);
        for (final packet in _keyPackets(key)) {
          expect(packet.packet.body.sublist(packet.publicBody.length, packet.publicBody.length + 4), [254, 7, 3, 2]);
          expect(needsPassphrase(packet), isTrue);
          await _expectBelongs(packet, unlockSecretKey(packet, passphrase: fixturePassphrase));
          expect(() => unlockSecretKey(packet), throwsPgp(PgpProblem.passphraseNeeded));
          expect(() => unlockSecretKey(packet, passphrase: 'Fixture passphrase'), throwsPgp(PgpProblem.wrongPassphrase));
          expect(() => unlockSecretKey(packet, passphrase: ''), throwsPgp(PgpProblem.wrongPassphrase));
        }
        expect(key, before, reason: 'the stored bytes are not modified');
      }
    });

    test('the keys Kemlock exports (usage 254, AES-256, SHA-256) unlock to their unprotected twins', () async {
      for (final name in ['pgp-ed25519', 'pgp-rsa4096']) {
        final locked = _keyPackets(binaryKey('keys/kemlock/$name.secret.asc'));
        final plain = _keyPackets(binaryKey('keys/kemlock/$name.unprotected.asc'));
        expect(locked, hasLength(2));
        for (final (i, packet) in locked.indexed) {
          expect(packet.packet.body.sublist(packet.publicBody.length, packet.publicBody.length + 4), [254, 9, 3, 8]);
          final secret = unlockSecretKey(packet, passphrase: fixturePassphrase);
          await _expectBelongs(packet, secret);
          final twin = unlockSecretKey(plain[i]);
          switch ((secret, twin)) {
            case (Ed25519Secret(seed: final a), Ed25519Secret(seed: final b)):
              expect(a, b);
            case (X25519Secret(secret: final a), X25519Secret(secret: final b)):
              expect(a, b);
            case (RsaSecret(material: final a), RsaSecret(material: final b)):
              expect((a.d, a.p, a.q), (b.d, b.p, b.q));
            default:
              fail('$name: the kinds differ');
          }
          expect(() => unlockSecretKey(packet, passphrase: 'wrong'), throwsPgp(PgpProblem.wrongPassphrase));
        }
      }
    });

    test('a key Kemlock protects now unlocks, in versions 4 and 6', () async {
      for (final key in [Keys.ed, Keys.v6]) {
        final protected = protectPgpKey(key, 'correct horse', s2kCount: 0x60);
        for (final packet in _keyPackets(protected)) {
          await _expectBelongs(packet, unlockSecretKey(packet, passphrase: 'correct horse'));
          expect(() => unlockSecretKey(packet, passphrase: 'incorrect horse'), throwsPgp(PgpProblem.wrongPassphrase));
        }
      }
    });

    test('the locked sample key of RFC 9580 A.5 is refused: Argon2', () {
      for (final packet in _keyPackets(binaryKey('keys/rfc9580/v6-locked-secret.asc'))) {
        // Named whether or not a passphrase is given, so none is asked for
        expect(() => unlockSecretKey(packet), throwsPgp(PgpProblem.unsupported, 'Argon2'));
        expect(() => unlockSecretKey(packet, passphrase: 'correct horse battery staple'), throwsPgp(PgpProblem.unsupported, 'Argon2'));
        expect(needsPassphrase(packet), isFalse);
      }
    });

    test('the protected Sequoia key opens to its unprotected twin', () async {
      final plain = _keyPackets(binaryKey('keys/sequoia/pqc/standard.secret.asc'));
      final locked = _keyPackets(binaryKey('keys/sequoia/pqc/standard-protected.secret.asc'));
      expect(locked, hasLength(3));
      for (final (i, packet) in locked.indexed) {
        expect(needsPassphrase(packet), isTrue);
        final secret = await unlockSecretKeyAsync(packet, passphrase: fixturePassphrase);
        await _expectBelongs(packet, secret);
        final twin = unlockSecretKey(plain[i]);
        switch ((secret, twin)) {
          case (final MlDsaEd25519Secret a, final MlDsaEd25519Secret b):
            expect([a.ed25519Seed, a.mlDsaSeed], [b.ed25519Seed, b.mlDsaSeed]);
          case (final MlKemX25519Secret a, final MlKemX25519Secret b):
            expect([a.x25519, a.mlKemSeed], [b.x25519, b.mlKemSeed]);
          default:
            fail('${secret.runtimeType} against ${twin.runtimeType}');
        }
        expect(() => unlockSecretKey(packet, passphrase: 'Fixture passphrase'), throwsPgp(PgpProblem.wrongPassphrase));
      }
    });

    test('the Kyber keys GnuPG exported in its own form open, the protected ones with their passphrases', () async {
      for (final name in ['ky768-cv25519', 'pqc', 'ky1024-bp384']) {
        final plain = _keyPackets(binaryKey('keys/gnupg/pqc/$name.secret.asc')).last;
        expect(plain.version, 5);
        expect(needsPassphrase(plain), isFalse, reason: name);
        await _expectBelongs(plain, unlockSecretKey(plain));

        final locked = _keyPackets(binaryKey('keys/gnupg/pqc/$name-protected.secret.asc')).last;
        expect(needsPassphrase(locked), isTrue, reason: name);
        expect(() => unlockSecretKey(locked), throwsPgp(PgpProblem.passphraseNeeded));
        expect(() => unlockSecretKey(locked, passphrase: 'Fixture passphrase'), throwsPgp(PgpProblem.wrongPassphrase));
        await _expectBelongs(locked, await unlockSecretKeyAsync(locked, passphrase: fixturePassphrase));
      }
    });

    test('a wrong passphrase is told apart from a damaged key', () {
      final packet = _keyPackets(binaryKey('keys/sequoia/pqc/standard-protected.secret.asc')).first;
      expect(() => unlockSecretKey(packet, passphrase: 'wrong'), throwsPgp(PgpProblem.wrongPassphrase));
      final agent = _keyPackets(binaryKey('keys/gnupg/pqc/ky768-cv25519-protected.secret.asc')).last;
      final body = Uint8List.fromList(agent.packet.body);
      // The last closing parenthesis of gpg-agent's form, which no tag covers
      body[body.length - 1] = 0x28;
      final damaged = parseKeyPacket(readPackets(writePacket(PgpTag.secretSubkey, body)).single);
      expect(() => unlockSecretKey(damaged, passphrase: fixturePassphrase), throwsPgp(PgpProblem.damaged));
    });

    test('an Argon2 key opens when it asks for no more memory than the cap', () async {
      // The unlocked sample key of RFC 9580 A.4, protected here with Argon2
      // (t = 1, p = 1, 2^10 KiB) and OCB as RFC 9580 section 5.5.3 says
      for (final (i, key) in _keyPackets(Keys.v6).indexed) {
        final salt = Uint8List.fromList(List.generate(16, (j) => j + i));
        final s2k = [4, ...salt, 1, 1, 10];
        final derived = await deriveArgon2(S2k.read(PgpReader.bytes(Uint8List.fromList(s2k))), utf8.encode('correct horse'), 32);
        final tag = key.packet.tag;
        final kek = hkdfSha256(derived, info: [0xc0 | tag, 6, 9, 2], length: 32);
        final nonce = Uint8List(15)..[0] = i;
        final sealed = Ocb(kek).seal(nonce, key.plainSecret!, Uint8List.fromList([0xc0 | tag, ...key.publicBody]));
        final body = [...key.publicBody, 253, 3 + s2k.length + nonce.length, 9, 2, s2k.length, ...s2k, ...nonce, ...sealed];
        final locked = parseKeyPacket(readPackets(writePacket(tag, body)).single);
        // The synchronous unlock still names it; the asynchronous one opens it
        expect(() => unlockSecretKey(locked, passphrase: 'correct horse'), throwsPgp(PgpProblem.unsupported, 'Argon2'));
        await _expectBelongs(locked, await unlockSecretKeyAsync(locked, passphrase: 'correct horse'));
        await expectLater(unlockSecretKeyAsync(locked, passphrase: 'correct horses'), throwsPgp(PgpProblem.wrongPassphrase));
        await expectLater(unlockSecretKeyAsync(locked), throwsPgp(PgpProblem.passphraseNeeded));
      }
    });

    test('the locked sample key of RFC 9580 A.5 asks for 2 GiB, over the cap, and is refused by name', () async {
      for (final packet in _keyPackets(binaryKey('keys/rfc9580/v6-locked-secret.asc'))) {
        await expectLater(
          unlockSecretKeyAsync(packet, passphrase: 'correct horse battery staple'),
          throwsPgp(PgpProblem.unsupported, 'Argon2 with 2 GiB'),
        );
      }
    });

    test('a stub of GnuPG has no secret here', () {
      final packets = _keyPackets(Keys.stub);
      expect(() => unlockSecretKey(packets[0]), throwsPgp(PgpProblem.noSecretHere));
      expect(() => unlockSecretKey(packets[0], passphrase: 'any'), throwsPgp(PgpProblem.noSecretHere));
      expect(needsPassphrase(packets[0]), isFalse);
      // Its subkey's secret is there
      expect(unlockSecretKey(packets[1]), isA<X25519Secret>());
    });
  });

  // The keys a change to a PGP key is tried on (openspec: add-pgp-key-editing)
  group('the keys a change is signed with', () {
    test('every packet of the unprotected ones gives its secret, no passphrase asked', () async {
      for (final name in [
        'keys/gnupg/editing/signing-subkey.secret.asc',
        'keys/gnupg/editing/signing-subkey.after.secret.asc',
        'keys/gnupg/editing/rsa3072-expiring.secret.asc',
        'keys/other/editing/direct-key.secret.asc',
      ]) {
        final packets = _keyPackets(binaryKey(name));
        expect(packets.length, greaterThan(1), reason: name);
        for (final packet in packets) {
          expect(needsPassphrase(packet), isFalse, reason: name);
          await _expectBelongs(packet, unlockSecretKey(packet));
        }
      }
    });

    test('the protected key opens with its passphrase, and tells a wrong one apart from damage', () async {
      final packets = _keyPackets(binaryKey('keys/gnupg/editing/protected.secret.asc'));
      for (final packet in packets) {
        expect(needsPassphrase(packet), isTrue);
        await _expectBelongs(packet, unlockSecretKey(packet, passphrase: fixturePassphrase));
        expect(() => unlockSecretKey(packet), throwsPgp(PgpProblem.passphraseNeeded));
        expect(() => unlockSecretKey(packet, passphrase: 'fixture passphrase '), throwsPgp(PgpProblem.wrongPassphrase));
      }
      // A flipped byte in the encrypted secret: the SHA-1 inside fails, as for a wrong passphrase, but
      // a cut-short packet is damaged
      final body = Uint8List.fromList(packets.first.packet.body);
      final cut = parseKeyPacket(readPackets(writePacket(PgpTag.secretKey, body.sublist(0, packets.first.publicBody.length + 4))).single);
      expect(() => unlockSecretKey(cut, passphrase: fixturePassphrase), throwsPgp(PgpProblem.damaged));
    });

    test('the stub primary of its subkeys-only export is refused by name, its subkey opens as in the whole key', () async {
      final stub = _keyPackets(binaryKey('keys/gnupg/editing/protected.stub.secret.asc'));
      final whole = _keyPackets(binaryKey('keys/gnupg/editing/protected.secret.asc'));
      expect(() => unlockSecretKey(stub.first, passphrase: fixturePassphrase), throwsPgp(PgpProblem.noSecretHere));
      expect(needsPassphrase(stub.first), isFalse);
      final a = unlockSecretKey(stub[1], passphrase: fixturePassphrase) as X25519Secret;
      final b = unlockSecretKey(whole[1], passphrase: fixturePassphrase) as X25519Secret;
      expect(a.secret, b.secret);
    });
  });

  // No other program at hand writes these forms with a hash Kemlock reads,
  // so the packets are built here, from the rules of RFC 9580 section 5.5.3.
  group('forms built by hand', () {
    final primary = _keyPackets(Keys.ed).first;
    final secret = primary.plainSecret!;
    final passphrase = utf8.encode('by hand');
    final salt = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
    final iv = Uint8List.fromList(List.generate(16, (i) => i + 1));
    int sum(List<int> bytes) => bytes.fold(0, (a, b) => (a + b) & 0xffff);
    final withChecksum = Uint8List.fromList([...secret, sum(secret) >> 8, sum(secret) & 0xff]);

    KeyPacket packet(List<int> protection) =>
        parseKeyPacket(readPackets(writePacket(PgpTag.secretKey, [...primary.publicBody, ...protection])).single);

    Future<void> expectUnlocks(KeyPacket key) async {
      await _expectBelongs(key, unlockSecretKey(key, passphrase: 'by hand'));
      expect(() => unlockSecretKey(key, passphrase: 'by foot'), throwsPgp(PgpProblem.wrongPassphrase));
      expect(() => unlockSecretKey(key), throwsPgp(PgpProblem.passphraseNeeded));
    }

    test('usage 255 with a checksum, AES-192 and Salted S2K over SHA-512', () async {
      final s2k = [1, 10, ...salt];
      final key = S2k.read(PgpReader.bytes(Uint8List.fromList(s2k))).derive(passphrase, 24);
      await expectUnlocks(packet([255, 8, ...s2k, ...iv, ...cfb(true, key, iv, withChecksum)]));
    });

    test('usage 254 with Simple S2K over SHA-384', () async {
      final s2k = [0, 9];
      final key = S2k.read(PgpReader.bytes(Uint8List.fromList(s2k))).derive(passphrase, 32);
      final plain = Uint8List.fromList([...secret, ...hash.sha1.convert(secret).bytes]);
      await expectUnlocks(packet([254, 9, ...s2k, ...iv, ...cfb(true, key, iv, plain)]));
    });

    test('a bare cipher octet: AES-128 under the MD5 of the passphrase', () async {
      final key = Uint8List.fromList(hash.md5.convert(passphrase).bytes);
      await expectUnlocks(packet([7, ...iv, ...cfb(true, key, iv, withChecksum)]));
    });

    test('usage 253: AEAD with OCB, the key through HKDF', () async {
      final s2k = [3, 8, ...salt, 0x60];
      final derived = S2k.read(PgpReader.bytes(Uint8List.fromList(s2k))).derive(passphrase, 32);
      final kek = hkdfSha256(derived, info: [0xc5, 4, 9, 2], length: 32);
      final nonce = Uint8List.fromList(List.generate(15, (i) => 100 + i));
      final sealed = Ocb(kek).seal(nonce, secret, Uint8List.fromList([0xc5, ...primary.publicBody]));
      await expectUnlocks(packet([253, 9, 2, ...s2k, ...nonce, ...sealed]));
      // The public part is bound in: another creation time, and it fails
      final moved = Uint8List.fromList([...primary.publicBody, 253, 9, 2, ...s2k, ...nonce, ...sealed])..[4] ^= 1;
      final other = parseKeyPacket(readPackets(writePacket(PgpTag.secretKey, moved)).single);
      expect(() => unlockSecretKey(other, passphrase: 'by hand'), throwsPgp(PgpProblem.wrongPassphrase));
    });

    test('an old cipher is refused by name before a passphrase is asked for', () {
      final key = packet([254, 3, 3, 2, ...salt, 0x60, ...iv.sublist(0, 8), ...List.filled(60, 1)]);
      expect(() => unlockSecretKey(key), throwsPgp(PgpProblem.unsupported, 'CAST5'));
      expect(needsPassphrase(key), isFalse);
    });

    test('a checksum that fits by luck and material that does not parse is a wrong passphrase', () {
      // An MPI that claims 65535 bits, and the checksum of its two bytes
      final key = Uint8List.fromList(hash.md5.convert(passphrase).bytes);
      final lucky = packet([
        7,
        ...iv,
        ...cfb(true, key, iv, Uint8List.fromList([0xff, 0xff, 0x01, 0xfe])),
      ]);
      expect(() => unlockSecretKey(lucky, passphrase: 'by hand'), throwsPgp(PgpProblem.wrongPassphrase));
    });
  });

  test('bigIntToBytes pads what an MPI dropped', () {
    // An Ed25519 seed that starts with a zero byte is a shorter MPI
    final key = _keyPackets(Keys.ed).first;
    final seed = Uint8List(32)..setAll(1, List.generate(31, (i) => i + 1));
    final mpi = [0, 248 - 7, ...seed.sublist(1)];
    final secret = parseSecretMaterial(key, Uint8List.fromList(mpi)) as Ed25519Secret;
    expect(secret.seed, seed);
    expect(bigIntToBytes(bytesToBigInt(seed), 32), seed);
  });
}
