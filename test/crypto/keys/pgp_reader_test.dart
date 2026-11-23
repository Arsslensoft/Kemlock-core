@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as c;
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart' show parseKeyPacket, parseSignature, readTransferableKey;
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart'
    show Subpacket, hashedKey, readSubpackets, subpacket, verifyBackSignature, verifyDigest, verifySelfSignatures, writeSubpackets;
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart' as pgp;
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The keys in test/fixtures/keys/gnupg were made and exported by GnuPG
// 2.5.24 (tool/keys/make_fixtures.sh); <name>.colons.txt is what
// `gpg --list-keys --with-subkey-fingerprints --with-colons` printed for
// each, and <name>.list.txt the same listing as people read it. The
// rfc9580 files are the sample version 6 keys of RFC 9580 appendix A.

/// One `pub` or `sub` line of GnuPG's colon listing and the `fpr` after it.
typedef _Listed = ({String fingerprint, String algorithm, DateTime created, DateTime? expires, String capabilities});

/// The keys and user IDs GnuPG listed, in its order.
({List<_Listed> keys, List<String> userIds}) _gpgListing(String name) {
  final keys = <_Listed>[];
  final userIds = <String>[];
  List<String>? pending;
  for (final line in const LineSplitter().convert(keyFixtureText('gnupg/$name.colons.txt'))) {
    final f = line.split(':');
    switch (f[0]) {
      case 'pub' || 'sub':
        pending = f;
      case 'fpr' when pending != null:
        final p = pending;
        DateTime time(String s) => DateTime.fromMillisecondsSinceEpoch(int.parse(s) * 1000, isUtc: true);
        keys.add((
          fingerprint: f[9],
          // Field 17 is the curve; RSA has its algorithm (1) and size.
          algorithm: p[3] == '1' ? 'rsa${p[2]}' : p[16],
          created: time(p[5]),
          expires: p[6].isEmpty ? null : time(p[6]),
          capabilities: p[11],
        ));
        pending = null;
      case 'uid':
        userIds.add(f[9]);
    }
  }
  return (keys: keys, userIds: userIds);
}

String _capabilities(PgpKey key) =>
    [if (key.canSign) 's', if (key.canCertify) 'c', if (key.canEncrypt) 'e', if (key.canAuthenticate) 'a'].join();

void _expectListed(PgpKey key, _Listed listed) {
  expect(key.fingerprintHex, listed.fingerprint);
  expect(key.algorithm, listed.algorithm);
  expect(key.created, listed.created);
  expect(key.expires, listed.expires);
  // GnuPG lists a key's own capabilities in lower case, then (on the
  // primary) the whole key's in upper case.
  expect(_capabilities(key).split('')..sort(), listed.capabilities.replaceAll(RegExp('[A-Z]'), '').split('')..sort());
}

const _keys = [
  (name: 'ed25519', protected: false),
  (name: 'ed25519-protected', protected: true),
  (name: 'rsa3072', protected: false),
  (name: 'rsa3072-protected', protected: true),
];

void main() {
  group('reads the secret keys GnuPG exported', () {
    for (final k in _keys) {
      test('${k.name}: fingerprints, user IDs and subkeys as gpg --list-keys printed them', () async {
        final key = await readPrivateKey(keyFixtureText('gnupg/${k.name}.secret.asc'));
        final listed = _gpgListing(k.name);
        expect(key.kind, KeyKind.pgp);
        expect(key.algorithm, 'pgp');
        final info = key.pgp!;
        expect(info.version, 4);
        expect(info.isSecret, isTrue);
        expect(info.protected, k.protected);
        _expectListed(info.primary, listed.keys.first);
        expect(info.userIds, listed.userIds);
        expect(info.subkeys, hasLength(listed.keys.length - 1));
        for (final (i, sub) in info.subkeys.indexed) {
          _expectListed(sub, listed.keys[i + 1]);
        }
        expect(info.primary.protected, k.protected);
        expect(info.subkeys.every((s) => s.protected == k.protected), isTrue);
      });

      test('${k.name}: keeps the binary key as given, and gives the public key gpg --export gave', () async {
        final binary = keyFixture('gnupg/${k.name}.secret.gpg');
        final fromArmor = await readPrivateKey(keyFixtureText('gnupg/${k.name}.secret.asc'));
        final fromBinary = await readPrivateKey(binary);
        expect(fromBinary.private, binary);
        expect(fromArmor.private, readArmor(readPemBlocks(keyFixtureText('gnupg/${k.name}.secret.asc')).single));
        expect(fromBinary.public, keyFixture('gnupg/${k.name}.public.gpg'));
        expect(fromArmor.public, keyFixture('gnupg/${k.name}.public.gpg'));
      });

      test('${k.name}: the fingerprint in groups of four, the armored public key, and the secret key exported as it came', () async {
        final key = await readPrivateKey(keyFixture('gnupg/${k.name}.secret.gpg'));
        final hex = _gpgListing(k.name).keys.first.fingerprint;
        expect(keyFingerprint(key)!.text, matches(r'^([0-9A-F]{4} ){9}[0-9A-F]{4}$'));
        expect(keyFingerprint(key)!.text.replaceAll(' ', ''), hex);
        final armoredPublic = publicKeyPem(key)!;
        expect(armoredPublic, startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----\n'));
        expect(readArmor(readPemBlocks(armoredPublic).single), keyFixture('gnupg/${k.name}.public.gpg'));
        final exported = exportPgpSecretKey(key);
        expect((await readPrivateKey(exported)).private, keyFixture('gnupg/${k.name}.secret.gpg'));
        expect(readPgpKeyInfo(key.public!).primary.fingerprintHex, hex);
        expect(readPgpKeyInfo(key.public!).isSecret, isFalse);
      });
    }

    test('a key with two user IDs', () async {
      final key = await readPrivateKey(keyFixtureText('gnupg/ed25519-two-uids.secret.asc'));
      final listed = _gpgListing('ed25519-two-uids');
      expect(key.pgp!.userIds.toSet(), listed.userIds.toSet());
      expect(key.pgp!.userIds, ['Fixture Ed25519 <ed25519@example.org>', 'Fixture Second <second@example.org>']);
      _expectListed(key.pgp!.primary, listed.keys.first);
    });
  });

  group('reads the version 6 keys of RFC 9580', () {
    const primary = 'CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9';
    const subkey = '12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885';

    test('the unlocked secret key, whose public key is the sample certificate', () async {
      final key = await readPrivateKey(keyFixtureText('rfc9580/v6-secret.asc'));
      final info = key.pgp!;
      expect(info.version, 6);
      expect(info.primary.fingerprintHex, primary);
      expect(info.primary.algorithm, 'ed25519');
      expect(info.primary.canCertify && info.primary.canSign, isTrue);
      expect(info.primary.created, DateTime.utc(2022, 11, 30, 16, 8, 3));
      expect(info.subkeys.single.fingerprintHex, subkey);
      expect(info.subkeys.single.algorithm, 'cv25519');
      expect(info.subkeys.single.canEncrypt, isTrue);
      expect(info.userIds, isEmpty);
      expect(info.protected, isFalse);
      expect(key.public, readArmor(readPemBlocks(keyFixtureText('rfc9580/v6-public.asc')).single));
      expect(keyFingerprint(key)!.bytes, hasLength(32));
    });

    test('the locked one, kept with its own protection', () async {
      final key = await readPrivateKey(keyFixtureText('rfc9580/v6-locked-secret.asc'));
      expect(key.pgp!.protected, isTrue);
      expect(key.pgp!.primary.fingerprintHex, primary);
      expect(key.pgp!.subkeys.single.fingerprintHex, subkey);
      expect(key.public, readArmor(readPemBlocks(keyFixtureText('rfc9580/v6-public.asc')).single));
    });
  });

  group('reads the post-quantum keys of RFC 9980', () {
    final values = jsonDecode(keyFixtureText('rfc9980/values.json')) as Map<String, Object?>;
    String fingerprint(String section, String which) => ((values[section]! as Map<String, Object?>)[which]! as String).toUpperCase();
    const userId = 'PQC user (Test Key) <pqc-test-key@example.com>';

    for (final (section, version, primaryName, subkeyName) in [
      ('a1', 6, 'ed25519', 'mlk768'),
      ('a2', 4, 'ed25519', 'mlk768'),
      ('a3', 6, 'mld65', 'mlk768'),
    ]) {
      test('${section.toUpperCase()}: names, fingerprints, flags and user ID as the RFC prints them', () async {
        final key = await readPrivateKey(keyFixtureText('rfc9980/$section-secret.asc'));
        final info = key.pgp!;
        expect(info.version, version);
        expect(info.primary.algorithm, primaryName);
        expect(info.primary.fingerprintHex, fingerprint(section, 'primaryFingerprint'));
        expect(info.primary.canCertify && info.primary.canSign, isTrue);
        expect(info.primary.usable, isTrue);
        expect(info.userIds, [userId]);
        final subkey = info.subkeys.single;
        expect(subkey.algorithm, subkeyName);
        expect(subkey.version, version);
        expect(subkey.fingerprintHex, fingerprint(section, 'subkeyFingerprint'));
        expect(subkey.canEncrypt && !subkey.canSign, isTrue);
        expect(subkey.usable, isTrue);
        expect(info.protected, isFalse);
        expect(key.public, readArmor(readPemBlocks(keyFixtureText('rfc9980/$section-public.asc')).single));
      });
    }

    for (final (section, primaryName, subkeyName, subkeyUsable) in [
      ('a4', 'mld87', 'mlk1024', false),
      ('a5', 'SLH-DSA-SHAKE-128s', 'mlk768', true),
      ('a6', 'SLH-DSA-SHAKE-128f', 'mlk768', true),
      ('a7', 'SLH-DSA-SHAKE-256s', 'mlk1024', false),
    ]) {
      test('${section.toUpperCase()}: read and named, and not of use', () async {
        final info = (await readPrivateKey(keyFixtureText('rfc9980/$section-secret.asc'))).pgp!;
        expect(info.primary.algorithm, primaryName);
        expect(info.primary.fingerprintHex, fingerprint(section, 'primaryFingerprint'));
        expect(info.primary.usable, isFalse);
        expect(info.subkeys.single.algorithm, subkeyName);
        expect(info.subkeys.single.fingerprintHex, fingerprint(section, 'subkeyFingerprint'));
        expect(info.subkeys.single.usable, subkeyUsable);
      });
    }

    test('a post-quantum key whose material is not the fixed size is damaged', () {
      // Version 6, created at 0, ML-KEM-768+X25519, a length one short
      final short = [6, 0, 0, 0, 0, 35, 0, 0, 0x04, 0xbf, ...Uint8List(1215)];
      expect(() => parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, short)).single), throwsKeyProblem(KeyProblem.damaged));
      // Version 4 knows its size only from the algorithm: cut short
      final cut = [4, 0, 0, 0, 0, 30, ...Uint8List(1983)];
      expect(() => parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, cut)).single), throwsKeyProblem(KeyProblem.damaged));
      // The right size reads
      final whole = [6, 0, 0, 0, 0, 35, 0, 0, 0x04, 0xc0, ...Uint8List(1216)];
      expect(parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, whole)).single).name, 'mlk768');
    });
  });

  group('reads the Kyber keys GnuPG 2.5 made', () {
    for (final name in ['ky768-cv25519', 'ky768-cv25519-protected', 'pqc', 'pqc-protected', 'ky1024-bp384', 'ky1024-bp384-protected']) {
      test('$name: as gpg --list-keys printed it, with the public key gpg --export gave', () async {
        final key = await readPrivateKey(keyFixtureText('gnupg/pqc/$name.secret.asc'));
        final listed = _gpgListing('pqc/$name');
        final info = key.pgp!;
        expect(info.version, 4);
        _expectListed(info.primary, listed.keys.first);
        expect(info.userIds, listed.userIds);
        final subkey = info.subkeys.single;
        _expectListed(subkey, listed.keys[1]);
        expect(subkey.version, 5);
        expect(subkey.fingerprint, hasLength(32));
        expect(subkey.usable, isTrue);
        expect(info.protected, name.endsWith('-protected'));
        expect(subkey.protected, name.endsWith('-protected'));
        expect(key.public, readArmor(readPemBlocks(keyFixtureText('gnupg/pqc/$name.public.asc')).single));
      });
    }

    test('a version 4 binding of a version 5 subkey verifies, hashed as GnuPG hashes it', () async {
      for (final name in ['ky768-cv25519', 'ky768-cv25519-protected', 'ky1024-bp384', 'ky1024-bp384-protected']) {
        expect(
          await verifySelfSignatures(readArmor(readPemBlocks(keyFixtureText('gnupg/pqc/$name.public.asc')).single)),
          isTrue,
          reason: name,
        );
      }
      // The pqc shortcut's primary key is ECDSA on brainpoolP384r1, whose
      // signatures Kemlock does not check, as for a nistp256 key
      expect(await verifySelfSignatures(readArmor(readPemBlocks(keyFixtureText('gnupg/pqc/pqc.public.asc')).single)), isFalse);
    });

    test('a version 5 primary key is still refused, by name', () {
      final packets = readPackets(readArmor(readPemBlocks(keyFixtureText('gnupg/pqc/ky768-cv25519.public.asc')).single));
      final subkey = packets.firstWhere((p) => p.tag == PgpTag.publicSubkey);
      expect(
        () => readTransferableKey(writePacket(PgpTag.publicKey, subkey.body)),
        throwsKeyProblem(KeyProblem.unsupportedKeyType, 'LibrePGP version 5 primary key'),
      );
    });
  });

  group('checks composite ML-DSA-65+Ed25519 signatures on keys', () {
    Uint8List binary(String file) => readArmor(readPemBlocks(keyFixtureText(file)).single);

    /// [key] with one byte changed in the first signature's [part]: its
    /// Ed25519 half (the first 64 bytes) or its ML-DSA-65 half.
    Uint8List changed(Uint8List key, {required bool mlDsa}) {
      final out = BytesBuilder();
      var done = false;
      for (final p in readPackets(key)) {
        if (p.tag != PgpTag.signature || done) {
          out.add(p.encoded);
          continue;
        }
        final body = Uint8List.fromList(p.body);
        final start = body.length - parseSignature(p.body).material.length;
        body[start + (mlDsa ? 64 + 1000 : 10)] ^= 0x01;
        out.add(writePacket(PgpTag.signature, body));
        done = true;
      }
      return out.toBytes();
    }

    for (final file in ['rfc9980/a3-public.asc', 'sequoia/pqc/standard.public.asc']) {
      test('$file: every self-signature, both parts', () async {
        expect(await verifySelfSignatures(binary(file)), isTrue);
      });

      test('$file: a byte changed in either part fails', () async {
        expect(await verifySelfSignatures(changed(binary(file), mlDsa: true)), isFalse);
        expect(await verifySelfSignatures(changed(binary(file), mlDsa: false)), isFalse);
      });
    }

    test('a composite signature over SHA-1 is refused, though both parts sign its digest', () async {
      final key = readTransferableKey(binary('rfc9980/a3-secret.asc'));
      final primary = parseKeyPacket(key.packets.first);
      final seeds = primary.plainSecret!;
      Future<bool> signedWith(int hashAlgorithm, List<int> Function(List<int>) digestOf) async {
        final salt = Uint8List(16);
        final hashed = [
          ...subpacket(2, [0, 0, 0, 1]),
          ...subpacket(27, [3]),
        ];
        final hashedPart = [6, 0x1f, 30, hashAlgorithm, 0, 0, 0, hashed.length, ...hashed];
        final trailer = [...hashedPart, 6, 0xff, 0, 0, 0, hashedPart.length];
        final digest = digestOf([...salt, ...hashedKey(primary), ...trailer]);
        final ed = await c.Ed25519().sign(digest, keyPair: await c.Ed25519().newKeyPairFromSeed(seeds.sublist(0, 32)));
        final mlDsa = MlDsa65.sign(MlDsa65.keygen(seeds.sublist(32, 64)).secretKey, digest);
        final body = Uint8List.fromList([...hashedPart, 0, 0, 0, 0, digest[0], digest[1], 16, ...salt, ...ed.bytes, ...mlDsa]);
        return verifyDigest(parseSignature(body), primary, digest);
      }

      expect(await signedWith(8, (d) => crypto.sha256.convert(d).bytes), isTrue);
      expect(await signedWith(2, (d) => crypto.sha1.convert(d).bytes), isFalse);
    });
  });

  group('checks the ECDSA keys and signatures GnuPG made', () {
    for (final (curve, hash) in [('nistp256', 'SHA-256'), ('nistp384', 'SHA-384')]) {
      final public = keyFixture('gnupg/ecdsa/$curve.public.gpg');
      final data = keyFixture('gnupg/ecdsa/data.txt');
      final signature = keyFixture('gnupg/ecdsa/$curve.data.sig');

      test('$curve: its self-signature is good, and bad with one byte changed', () async {
        expect(readPgpKeyInfo(public).primary.algorithm, curve);
        expect(await verifyPgpSelfSignatures(public), isTrue);
        final changed = Uint8List.fromList(public)..[public.length - 3] ^= 0x01;
        expect(await verifyPgpSelfSignatures(changed), isFalse);
      });

      test('$curve: its signature of a file, made with $hash, is good, and bad with one byte changed', () async {
        Future<pgp.SignatureVerdict> verdict(Uint8List signed, Uint8List sig) async => (await pgp.verify(
          signed: pgp.PgpData.bytes(sig),
          data: pgp.PgpData.bytes(signed),
          verifiers: [public],
          now: DateTime.utc(2026, 11, 18),
        )).signatures.single.verdict;

        expect(await verdict(data, signature), pgp.SignatureVerdict.good);
        expect(await verdict(Uint8List.fromList(data)..[0] ^= 0x01, signature), pgp.SignatureVerdict.bad);
        expect(await verdict(data, Uint8List.fromList(signature)..[signature.length - 3] ^= 0x01), pgp.SignatureVerdict.bad);
      });
    }
  });

  group('refuses', () {
    test('a public key, armored or binary', () async {
      await expectLater(readPrivateKey(keyFixtureText('gnupg/ed25519.public.asc')), throwsKeyProblem(KeyProblem.publicKeyOnly));
      await expectLater(readPrivateKey(keyFixture('gnupg/rsa3072.public.gpg')), throwsKeyProblem(KeyProblem.publicKeyOnly));
      await expectLater(readPrivateKey(keyFixtureText('rfc9580/v6-public.asc')), throwsKeyProblem(KeyProblem.publicKeyOnly));
    });

    test('an armored key cut in half', () async {
      final text = keyFixtureText('gnupg/rsa3072.secret.asc');
      final lines = text.split('\n');
      final half = [...lines.take(lines.length ~/ 2), ...lines.skip(lines.length - 3)].join('\n');
      await expectLater(readPrivateKey(half), throwsKeyProblem(KeyProblem.damaged));
    });

    test('a secret key whose checksum is wrong', () async {
      final binary = Uint8List.fromList(keyFixture('gnupg/ed25519.secret.gpg'));
      // The first packet's last byte is its checksum's low byte.
      final first = readPackets(binary).first;
      binary[first.encoded.length - 1] ^= 1;
      await expectLater(readPrivateKey(binary), throwsKeyProblem(KeyProblem.damaged));
    });
  });

  group('armor and packets', () {
    test('the CRC-24 of RFC 9580, as GnuPG wrote it', () {
      final text = keyFixtureText('gnupg/ed25519.public.asc');
      final checksum = RegExp(r'\n=([A-Za-z0-9+/]{4})\n').firstMatch(text)!.group(1)!;
      final crc = crc24(keyFixture('gnupg/ed25519.public.gpg'));
      expect(base64.encode([crc >> 16, (crc >> 8) & 0xff, crc & 0xff]), checksum);
    });

    test('writes packets with GnuPG headers and reads them back', () {
      for (final (tag, length, oldFormat) in [
        (6, 51, true),
        (6, 397, true),
        (13, 37, true),
        (2, 70000, true),
        (14, 100, false),
        (17, 300, false),
        (6, 9000, false),
      ]) {
        final packet = writePacket(tag, Uint8List(length), oldFormat: oldFormat);
        final read = readPackets(packet).single;
        expect((read.tag, read.body.length, read.oldFormat), (tag, length, oldFormat));
      }
      expect(writePacket(6, Uint8List(51), oldFormat: true).sublist(0, 2), [0x98, 51]);
      expect(writePacket(6, Uint8List(397), oldFormat: true).sublist(0, 3), [0x99, 0x01, 0x8d]);
    });
  });
  // test/fixtures/pgp/gnupg holds a key GnuPG made with a signing subkey,
  // and a signature that subkey made with --default-sig-expire 10y.
  group('what a signature over data and a signing subkey carry', () {
    test('the signature expiry and the critical bit', () {
      final packet = readPackets(File('test/fixtures/pgp/gnupg/message.txt.signing-subkey.sig').readAsBytesSync()).single;
      final signature = parseSignature(packet.body);
      expect(signature.signatureExpiry, 10 * 365 * 86400);
      // GnuPG marks it critical; it is a subpacket this app reads
      final at = _indexOf(packet.body, [5, 0x80 | 3]);
      expect(at, greaterThan(0));
      expect(signature.unknownCritical, isFalse);

      // The same bytes under a type nobody knows: critical, then not
      final unknown = Uint8List.fromList(packet.body)..[at + 1] = 0x80 | 99;
      expect(parseSignature(unknown).unknownCritical, isTrue);
      expect(parseSignature(unknown).signatureExpiry, isNull);
      expect(parseSignature(Uint8List.fromList(packet.body)..[at + 1] = 99).unknownCritical, isFalse);
    });

    test('the back-signature in a signing subkey\'s binding', () async {
      final text = File('test/fixtures/pgp/gnupg/signing-subkey.public.asc').readAsStringSync();
      final packets = readPackets(readArmor(readPemBlocks(text).single));
      // Primary key, user ID, its certification, then each subkey and its binding
      expect(packets.map((p) => p.tag), [6, 13, 2, 14, 2, 14, 2]);
      final primary = parseKeyPacket(packets[0]);
      final signing = parseKeyPacket(packets[3]);
      final signingBinding = parseSignature(packets[4].body);
      final encryption = parseKeyPacket(packets[5]);
      final encryptionBinding = parseSignature(packets[6].body);
      expect((signing.name, encryption.name), ('ed25519', 'cv25519'));

      expect(signingBinding.embedded, hasLength(1));
      expect(parseSignature(signingBinding.embedded.single).type, 0x19);
      expect(await verifyBackSignature(primary, signing, signingBinding), isTrue);

      // An encryption subkey needs none and has none
      expect(encryptionBinding.embedded, isEmpty);
      expect(await verifyBackSignature(primary, encryption, encryptionBinding), isFalse);
      // One subkey's back-signature does not bind another key
      expect(await verifyBackSignature(primary, encryption, signingBinding), isFalse);
      expect(await verifyBackSignature(signing, signing, signingBinding), isFalse);
    });
  });

  test('a version 3 revocation is not read as the key revoking itself: it names no issuer, and is checked by nothing', () {
    final key = keyFixture('gnupg/ed25519.public.gpg');
    final packets = readPackets(key);
    // Version 3, type 0x20, a time and a key ID, EdDSA and SHA-512, the hash's first two bytes, and one made-up MPI
    const v3 = [3, 5, 0x20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 22, 10, 0, 0, 0, 8, 0xff];
    final withV3 = Uint8List.fromList([
      ...packets.first.encoded,
      ...writePacket(PgpTag.signature, v3),
      for (final p in packets.skip(1)) ...p.encoded,
    ]);
    expect(parseSignature(Uint8List.fromList(v3)).type, 0x20);
    expect(readTransferableKey(withV3).info.primary.revoked, isFalse);
  });

  // A change to a key copies a self-signature's subpackets into the new one
  group('the subpackets of a self-signature', () {
    final files = [
      for (final dir in ['gnupg', 'gnupg/expiry', 'gnupg/editing', 'rfc9580', 'kemlock', 'other/editing'])
        for (final file in Directory('test/fixtures/keys/$dir').listSync().whereType<File>())
          if (RegExp(r'\.(secret|public)\.(asc|gpg)$').hasMatch(file.path)) file,
      for (final file in Directory('test/fixtures/pgp/gnupg').listSync().whereType<File>())
        if (RegExp(r'\.(secret|public)\.asc$').hasMatch(file.path)) file,
    ];

    test('read and written again give the same bytes, in every fixture key', () {
      var signatures = 0;
      final types = <int>{};
      for (final file in files) {
        final bytes = file.path.endsWith('.asc') ? readArmor(readPemBlocks(file.readAsStringSync()).first) : file.readAsBytesSync();
        for (final packet in readPackets(bytes)) {
          if (packet.tag != PgpTag.signature) continue;
          final signature = parseSignature(packet.body);
          if (signature.version == 3) continue;
          for (final area in [signature.hashedArea, signature.unhashedArea]) {
            final read = readSubpackets(area);
            types.addAll(read.map((s) => s.type));
            expect(writeSubpackets(read), area, reason: file.path);
          }
          signatures++;
        }
      }
      expect(files.length, greaterThan(30));
      expect(signatures, greaterThan(80));
      // What GnuPG, Sequoia and RFC 9580 put in a self-signature, the embedded back-signature too
      expect(types, containsAll([2, 9, 11, 16, 21, 22, 23, 25, 27, 30, 32, 33]));
    });

    test('the critical bit and the length forms survive', () {
      for (final data in [Uint8List(3), Uint8List(190), Uint8List(191), Uint8List(8382), Uint8List(8383), Uint8List(9000)]) {
        final written = writeSubpackets([Subpacket(20, data, critical: true), Subpacket(2, Uint8List(4))]);
        final read = readSubpackets(written);
        expect([for (final s in read) (s.type, s.critical, s.data.length)], [(20, true, data.length), (2, false, 4)]);
        expect(writeSubpackets(read), written);
      }
      expect(() => readSubpackets(Uint8List.fromList([5, 2, 0, 0])), throwsA(isA<KeyFormatException>()));
      expect(() => readSubpackets(Uint8List.fromList([0])), throwsA(isA<KeyFormatException>()));
    });
  });
}

/// Where [needle] first is in [bytes], or -1.
int _indexOf(List<int> bytes, List<int> needle) {
  for (var i = 0; i + needle.length <= bytes.length; i++) {
    var same = true;
    for (var j = 0; j < needle.length && same; j++) {
      same = bytes[i + j] == needle[j];
    }
    if (same) return i;
  }
  return -1;
}
