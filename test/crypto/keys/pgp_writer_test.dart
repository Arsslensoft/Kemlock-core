@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// kemlock/pgp-*.asc are keys Kemlock generated (tool/keys/write_samples.dart)
// that GnuPG 2.5.24 imported with all signatures good (NOTES.md), and
// tool/keys/gnupg_check.sh does the same for freshly generated keys.

const _passphrase = 'fixture passphrase';

/// The version 4 key types the generate sheet had before the post-quantum
/// ones, whose fixtures are `kemlock/pgp-<name>.*`.
const _classic = [PgpKeyType.ed25519, PgpKeyType.rsa4096];

/// The packets of a binary key.
List<KeyPacket> _keyPackets(Uint8List data) => [
  for (final p in readPackets(data))
    if (const {PgpTag.secretKey, PgpTag.secretSubkey, PgpTag.publicKey, PgpTag.publicSubkey}.contains(p.tag)) parseKeyPacket(p),
];

/// Bytes from a counter, the same every time, for keys made twice.
Uint8List Function(int) _counter([int start = 1]) {
  var next = start;
  return (n) => Uint8List.fromList([for (var i = 0; i < n; i++) (next++) & 0xff]);
}

Uint8List _armored(String text) => readArmor(readPemBlocks(text).single);

/// Opens the protected secret key packets of [data] the way GnuPG does and
/// returns their secret material, checking the SHA-1 inside.
List<Uint8List> _openProtected(Uint8List data, String passphrase) => [
  for (final packet in readPackets(data))
    if (packet.tag == PgpTag.secretKey || packet.tag == PgpTag.secretSubkey) _openPacket(parseKeyPacket(packet), passphrase),
];

Uint8List _openPacket(KeyPacket key, String passphrase) {
  final body = key.packet.body;
  var pos = key.publicBody.length;
  expect(body[pos++], 254, reason: 'S2K usage: CFB with SHA-1');
  if (key.version == 6) {
    expect(body[pos++], 1 + 1 + 11 + 16, reason: 'the count of the S2K parameters');
  }
  expect(body[pos++], 9, reason: 'AES-256');
  if (key.version == 6) expect(body[pos++], 11, reason: 'the length of the S2K specifier');
  expect(body.sublist(pos, pos + 2), [3, 8], reason: 'Iterated and Salted, SHA-256');
  final salt = body.sublist(pos + 2, pos + 10);
  final count = body[pos + 10];
  pos += 11;
  final iv = body.sublist(pos, pos + 16);
  pos += 16;
  final aesKey = iteratedSaltedS2k(passphrase.codeUnits, salt, count);
  final plain = cfb(false, aesKey, iv, body.sublist(pos));
  final secret = plain.sublist(0, plain.length - 20);
  expect(plain.sublist(plain.length - 20), hash.sha1.convert(secret).bytes, reason: 'the SHA-1 of the secret material');
  return secret;
}

void main() {
  group('generates', () {
    for (final type in _classic) {
      test('a ${type.name} key with the self-signatures it needs, in a background isolate', () async {
        final result = await generateKey(PgpKeyRequest(name: 'Ada Lovelace', email: 'ada@example.org', type: type)).result;
        final key = (result as KeyGenerated).key;
        expect(key.kind, KeyKind.pgp);
        expect(key.algorithm, 'pgp');
        final info = key.pgp!;
        expect(info.version, 4);
        expect(info.userIds, ['Ada Lovelace <ada@example.org>']);
        expect(info.protected, isFalse);
        expect(info.primary.algorithm, type == PgpKeyType.ed25519 ? 'ed25519' : 'rsa4096');
        expect(info.primary.canCertify && info.primary.canSign, isTrue);
        expect(info.primary.canEncrypt, isFalse);
        expect(info.primary.expires, isNull);
        final sub = info.subkeys.single;
        expect(sub.algorithm, type == PgpKeyType.ed25519 ? 'cv25519' : 'rsa4096');
        expect(sub.canEncrypt, isTrue);
        expect(sub.canSign, isFalse);
        expect(sub.created, info.primary.created);

        // Kemlock's reader checks the signatures, on the secret and the public key.
        expect(await verifyPgpSelfSignatures(key.private), isTrue);
        expect(await verifyPgpSelfSignatures(key.public!), isTrue);
        // Read back as an import would, the same key.
        final again = await readPrivateKey(key.private);
        expect(again.public, key.public);
        expect(again.pgp!.primary.fingerprintHex, info.primary.fingerprintHex);
      });
    }

    test('refuses an empty name or email, naming it', () {
      expect(
        () => generateKey(const PgpKeyRequest(name: ' ', email: 'ada@example.org')),
        throwsA(isA<ArgumentError>().having((e) => e.name, 'name', 'name')),
      );
      expect(
        () => generateKey(const PgpKeyRequest(name: 'Ada Lovelace', email: '')),
        throwsA(isA<ArgumentError>().having((e) => e.name, 'name', 'email')),
      );
    });
  });

  group('checks self-signatures', () {
    test('of the keys GnuPG made, and of RFC 9580 version 6 keys', () async {
      for (final file in [
        'gnupg/ed25519.secret.gpg',
        'gnupg/ed25519-protected.secret.gpg',
        'gnupg/rsa3072.public.gpg',
        'gnupg/rsa3072-protected.secret.gpg',
      ]) {
        expect(await verifyPgpSelfSignatures(keyFixture(file)), isTrue, reason: file);
      }
      expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('gnupg/ed25519-two-uids.secret.asc'))), isTrue);
      expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('rfc9580/v6-public.asc'))), isTrue);
      expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('rfc9580/v6-locked-secret.asc'))), isTrue);
    });

    test('of the keys Kemlock generated that GnuPG imported (NOTES.md)', () async {
      for (final type in _classic) {
        expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('kemlock/pgp-${type.name}.public.asc'))), isTrue);
        expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('kemlock/pgp-${type.name}.secret.asc'))), isTrue);
      }
    });

    test('and finds a signature that was changed, or a user ID that was', () async {
      for (final type in _classic) {
        final data = _armored(keyFixtureText('kemlock/pgp-${type.name}.public.asc'));
        final packets = readPackets(data);
        // The last byte of the certification's signature.
        final certification = packets.firstWhere((p) => p.tag == PgpTag.signature);
        final end = packets.takeWhile((p) => p != certification).fold(0, (n, p) => n + p.encoded.length) + certification.encoded.length;
        final badSignature = Uint8List.fromList(data)..[end - 1] ^= 1;
        expect(await verifyPgpSelfSignatures(badSignature), isFalse, reason: type.name);
        // One letter of the user ID.
        final uidAt = packets.takeWhile((p) => p.tag != PgpTag.userId).fold(0, (n, p) => n + p.encoded.length) + 2;
        final badUserId = Uint8List.fromList(data)..[uidAt] ^= 0x20;
        expect(await verifyPgpSelfSignatures(badUserId), isFalse, reason: type.name);
      }
    });
  });

  group('exports', () {
    test('a generated key protected with the passphrase, which opens to the same secret parts', () async {
      final key = await readPrivateKey(keyFixtureText('kemlock/pgp-ed25519.unprotected.asc'));
      final exported = exportPgpSecretKey(key, passphrase: 'another passphrase');
      final protected = await readPrivateKey(exported);
      expect(protected.pgp!.protected, isTrue);
      expect(protected.public, key.public);
      expect(await verifyPgpSelfSignatures(protected.private), isTrue);
      final plain = [
        for (final p in readPackets(key.private))
          if (p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey) parseKeyPacket(p).plainSecret!,
      ];
      expect(_openProtected(protected.private, 'another passphrase'), plain);
    });

    test('the secret keys GnuPG imported with the passphrase (NOTES.md) open to the unprotected ones', () async {
      for (final type in _classic) {
        final unprotected = _armored(keyFixtureText('kemlock/pgp-${type.name}.unprotected.asc'));
        final plain = [
          for (final p in readPackets(unprotected))
            if (p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey) parseKeyPacket(p).plainSecret!,
        ];
        expect(_openProtected(_armored(keyFixtureText('kemlock/pgp-${type.name}.secret.asc')), _passphrase), plain, reason: type.name);
      }
    });

    test('a version 6 key protected the version 6 way', () async {
      final key = await readPrivateKey(keyFixtureText('rfc9580/v6-secret.asc'));
      final protected = await readPrivateKey(exportPgpSecretKey(key, passphrase: _passphrase));
      expect(protected.pgp!.protected, isTrue);
      expect(protected.pgp!.version, 6);
      expect(protected.public, key.public);
      final plain = [
        for (final p in readPackets(key.private))
          if (p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey) parseKeyPacket(p).plainSecret!,
      ];
      expect(_openProtected(protected.private, _passphrase), plain);
    });

    test('a key protected by its own passphrase byte for byte, whatever passphrase is given', () async {
      final key = await readPrivateKey(keyFixture('gnupg/ed25519-protected.secret.gpg'));
      expect(_armored(exportPgpSecretKey(key, passphrase: 'ignored')), keyFixture('gnupg/ed25519-protected.secret.gpg'));
      final locked = await readPrivateKey(keyFixtureText('rfc9580/v6-locked-secret.asc'));
      expect(_armored(exportPgpSecretKey(locked, passphrase: 'ignored')), locked.private);
    });

    test('without a passphrase, unprotected', () async {
      final key = await readPrivateKey(keyFixtureText('kemlock/pgp-rsa4096.unprotected.asc'));
      expect(_armored(exportPgpSecretKey(key)), key.private);
    });

    test('one secret subkey packet protected on its own, in its header format, opens with the passphrase', () async {
      for (final path in [
        'kemlock/pgp-ed25519.unprotected.asc',
        'gnupg/editing/signing-subkey.secret.asc',
        'other/editing/direct-key.secret.asc',
      ]) {
        final key = await readPrivateKey(keyFixtureText(path));
        final subkey = readPackets(key.private).firstWhere((p) => p.tag == PgpTag.secretSubkey);
        final protected = readPackets(protectSecretKeyPacket(subkey, _passphrase, s2kCount: 0x60)).single;
        expect((protected.tag, protected.oldFormat), (subkey.tag, subkey.oldFormat), reason: path);
        final before = parseKeyPacket(subkey);
        final after = parseKeyPacket(protected);
        expect(after.publicBody, before.publicBody);
        expect(after.s2kUsage, 254);
        expect(_openProtected(protected.encoded, _passphrase), [before.plainSecret!]);
        // And as the key code opens it
        expect(needsPassphrase(after), isTrue);
        expect(unlockSecretKey(after, passphrase: _passphrase).runtimeType, unlockSecretKey(before).runtimeType);
        expect(() => unlockSecretKey(after, passphrase: 'wrong'), throwsA(isA<PgpException>()));
        expect(() => protectSecretKeyPacket(protected, _passphrase), throwsArgumentError);
      }
    });
  });

  // openspec: add-post-quantum-pgp, task 4.1
  group('version 6 and composite signatures', () {
    test('one made over a fixed key, time, salt and randomness verifies', () async {
      final primary = _keyPackets(_armored(keyFixtureText('rfc9980/a3-secret.asc'))).first;
      final secret = unlockSecretKey(primary) as MlDsaEd25519Secret;
      final salt = Uint8List.fromList(List.filled(32, 7));
      Future<Uint8List> make() => makeSignature(
        type: 0x1f,
        signer: primary,
        data: hashedKey(primary),
        hashed: [
          ...subpacket(2, [0x66, 0, 0, 0]),
          ...subpacket(33, [6, ...primary.fingerprint]),
        ],
        salt: salt,
        sign: (d) => signComposite(secret.ed25519Seed, secret.mlDsaSecretKey, d, randomness: Uint8List(32)),
      );
      final body = await make();
      final signature = parseSignature(body);
      expect(signature.version, 6);
      expect(signature.hashAlgorithm, 10);
      expect(signature.salt, salt);
      expect(signature.material, hasLength(64 + 3309));
      expect(await verifySignature(signature, primary, hashedKey(primary)), isTrue);
      // Deterministic: the same inputs give the same bytes
      expect(await make(), body);
    });

    test("RFC 9980's A.3 self-signatures: the Ed25519 parts bit for bit, and both sides' verify", () async {
      // Given each signature's hashed area and salt, the Ed25519 part comes
      // out bit for bit, so the digest is the RFC's. The RFC's ML-DSA parts
      // were made hedged, so ours, deterministic, differ: each verifies.
      final packets = readPackets(_armored(keyFixtureText('rfc9980/a3-secret.asc')));
      final primary = parseKeyPacket(packets.first);
      final secret = unlockSecretKey(primary) as MlDsaEd25519Secret;
      List<int> covered = hashedKey(primary);
      var checked = 0;
      for (final p in packets.skip(1)) {
        if (p.tag == PgpTag.userId) covered = [...hashedKey(primary), ...hashedUserId(p.body)];
        if (p.tag == PgpTag.secretSubkey) covered = [...hashedKey(primary), ...hashedKey(parseKeyPacket(p))];
        if (p.tag != PgpTag.signature) continue;
        final theirs = parseSignature(p.body);
        final ours = parseSignature(
          await makeSignature(
            type: theirs.type,
            signer: primary,
            data: covered,
            hashed: theirs.body.sublist(8, theirs.hashedEnd),
            hashAlgorithm: theirs.hashAlgorithm,
            salt: theirs.salt,
            sign: (d) => signComposite(secret.ed25519Seed, secret.mlDsaSecretKey, d, randomness: Uint8List(32)),
          ),
        );
        expect(ours.material.sublist(0, 64), theirs.material.sublist(0, 64), reason: 'type ${theirs.type}');
        expect(ours.material.sublist(64), isNot(theirs.material.sublist(64)));
        expect(await verifySignature(ours, primary, covered), isTrue);
        expect(await verifySignature(theirs, primary, covered), isTrue);
        checked++;
      }
      expect(checked, 3);
    });
  });

  // openspec: add-post-quantum-pgp, tasks 4.2 to 4.4
  group('post-quantum keys', () {
    test('the standard key: algorithms 30 and 35, its flags, a version 6 fingerprint and one user ID', () async {
      final key =
          (await generateKey(const PgpKeyRequest(name: 'Ada Lovelace', email: 'ada@example.org', type: PgpKeyType.pqStandard)).result)
              as KeyGenerated;
      final info = key.key.pgp!;
      expect(info.version, 6);
      expect(info.userIds, ['Ada Lovelace <ada@example.org>']);
      expect(info.primary.algorithm, 'mld65');
      expect(info.primary.fingerprint, hasLength(32));
      expect(info.primary.canCertify && info.primary.canSign && !info.primary.canEncrypt, isTrue);
      expect(info.primary.expires, isNull);
      final sub = info.subkeys.single;
      expect(sub.algorithm, 'mlk768');
      expect(sub.version, 6);
      expect(sub.canEncrypt && !sub.canSign, isTrue);
      await checkSelfSignatures(key.key.private);
      expect(await verifyPgpSelfSignatures(key.key.public!), isTrue);
      // The direct-key signature carries the features and preferences
      final direct = parseSignature(readPackets(key.key.public!).firstWhere((p) => p.tag == PgpTag.signature).body);
      expect(direct.type, 0x1f);
      expect(direct.version, 6);
      expect(direct.salt, hasLength(32));
      expect(direct.body.sublist(8, direct.hashedEnd), containsAllInOrder([2, 30, 0x09, 3, 11, 9, 7, 3, 39, 9, 2]));
    });

    test('the same seeds give the same key material', () async {
      Future<List<KeyPacket>> make() async => _keyPackets(
        await generatePgpKey(
          userId: 'Ada <ada@example.org>',
          type: PgpKeyType.pqStandard,
          created: DateTime.utc(2026, 11, 17),
          random: _counter(),
        ),
      );
      final (a, b) = (await make(), await make());
      for (var i = 0; i < 2; i++) {
        expect(a[i].publicBody, b[i].publicBody);
        expect(a[i].plainSecret, b[i].plainSecret);
      }
      final other = _keyPackets(await generatePgpKey(userId: 'Ada <ada@example.org>', type: PgpKeyType.pqStandard, random: _counter(2)));
      expect(other.first.publicBody, isNot(a.first.publicBody));
    });

    test('the standard key fixture reads, verifies, and is armored without the CRC line', () async {
      final key = await readPrivateKey(keyFixtureText('kemlock/pgp-pq-standard.unprotected.asc'));
      expect(key.pgp!.primary.algorithm, 'mld65');
      expect(key.pgp!.subkeys.single.algorithm, 'mlk768');
      expect(await verifyPgpSelfSignatures(key.private), isTrue);
      final text = keyFixtureText('kemlock/pgp-pq-standard.public.asc');
      expect(text, isNot(contains(RegExp(r'^=', multiLine: true))));
      expect(_armored(text), key.public);
      expect(publicKeyPem(key), text);
    });

    test("the GnuPG key reads back as GnuPG's own does, field for field", () async {
      final ours = (await makeKey(const PgpKeyRequest(name: 'Ada Lovelace', email: 'ada@example.org', type: PgpKeyType.pqGnupg))).pgp!;
      final theirs = (await readPrivateKey(keyFixtureText('gnupg/pqc/ky768-cv25519.secret.asc'))).pgp!;
      for (final (a, b) in [(ours.primary, theirs.primary), (ours.subkeys.single, theirs.subkeys.single)]) {
        expect(
          [a.version, a.algorithm, a.flags, a.fingerprint.length, a.protected, a.usable, a.expires],
          [b.version, b.algorithm, b.flags, b.fingerprint.length, b.protected, b.usable, b.expires],
        );
      }
      final ourPackets = _keyPackets(await generatePgpKey(userId: 'Ada <ada@example.org>', type: PgpKeyType.pqGnupg));
      final theirPackets = _keyPackets(_armored(keyFixtureText('gnupg/pqc/ky768-cv25519.secret.asc')));
      final (ourSub, theirSub) = (ourPackets.last, theirPackets.last);
      // The same layout: the curve, the point and the ML-KEM key's count
      expect(ourSub.publicBody.length, theirSub.publicBody.length);
      expect(ourSub.publicMaterial.sublist(0, 6), theirSub.publicMaterial.sublist(0, 6));
      expect(ourSub.publicMaterial.sublist(39, 43), theirSub.publicMaterial.sublist(39, 43));
      // The same S2K fields, and the same tokens in gpg-agent's form
      final at = ourSub.publicBody.length;
      expect(ourSub.packet.body.sublist(at, at + 9), theirSub.packet.body.sublist(at, at + 9));
      // The canonical S-expression's atoms that are names, each read by its length so the key's own
      // bytes are skipped whole: a random byte run such as `1:a` is no name.
      List<String> tokens(Uint8List agent) {
        final names = <String>[];
        var i = 0;
        while (i < agent.length) {
          var j = i;
          var length = 0;
          while (j < agent.length && agent[j] >= 0x30 && agent[j] <= 0x39) {
            length = length * 10 + agent[j] - 0x30;
            j++;
          }
          if (j == i || j >= agent.length || agent[j] != 0x3a) {
            i++;
            continue;
          }
          final start = j + 1;
          final end = start + length > agent.length ? agent.length : start + length;
          final atom = String.fromCharCodes(agent.sublist(start, end));
          if (RegExp(r'^[a-z][a-z0-9-]*$').hasMatch(atom)) names.add(atom);
          i = end;
        }
        return names;
      }

      expect(tokens(ourSub.agentKey!).take(12).toList(), tokens(theirSub.agentKey!).take(12).toList());
      expect(await verifyPgpSelfSignatures(_armored(keyFixtureText('kemlock/pgp-pq-gnupg.public.asc'))), isTrue);
    });

    for (final type in PgpKeyType.values) {
      test('${type.name}: two years on the key and its subkey', () async {
        final before = DateTime.now().toUtc();
        final key = await makeKey(PgpKeyRequest(name: 'Ada Lovelace', email: 'ada@example.org', type: type, expiresInYears: 2));
        final info = key.pgp!;
        final expires = info.primary.expires!;
        expect(expires, yearsAfter(info.primary.created, 2));
        expect(expires.difference(before).inDays, inInclusiveRange(729, 731));
        expect(info.subkeys.single.expires, expires);
      });
    }

    test('a request without an expiry writes the bytes it wrote before, given the same randomness', () async {
      for (final type in _classic) {
        final fixture = _armored(keyFixtureText('kemlock/pgp-${type.name}.unprotected.asc'));
        final packets = _keyPackets(fixture);
        final secrets = [for (final p in packets) unlockSecretKey(p)];
        final bytes = <Uint8List>[
          if (secrets case [Ed25519Secret(:final seed), X25519Secret(:final secret)]) ...[seed, secret],
        ];
        final rsa = [
          for (final s in secrets)
            if (s is RsaSecret) s.material,
        ];
        final again = await generatePgpKey(
          userId: 'Ada Lovelace <ada@example.org>',
          type: type,
          created: packets.first.describe(revoked: false).created,
          random: (n) => bytes.removeAt(0),
          rsa: (bits) => rsa.removeAt(0),
        );
        expect(again, fixture, reason: type.name);
      }
    });
  });

  test('Iterated and Salted S2K hashes the salt and passphrase to the count, and at least once', () {
    // 0x60 is 65536 bytes; 16 bytes of salt and passphrase repeat 4096 times.
    final salt = [1, 2, 3, 4, 5, 6, 7, 8];
    final passphrase = 'abcdefgh'.codeUnits;
    final repeated = [
      for (var i = 0; i < 4096; i++) ...[...salt, ...passphrase],
    ];
    expect(iteratedSaltedS2k(passphrase, salt, 0x60), hash.sha256.convert(repeated).bytes);
    // A count below the length of salt and passphrase hashes them once.
    final long = List.filled(70000, 0x61);
    expect(iteratedSaltedS2k(long, salt, 0x60), hash.sha256.convert([...salt, ...long]).bytes);
  });
  // An OpenPGP card's KDF object gives a plain count and SHA-256 or
  // SHA-512 (openspec: add-openpgp-card). The vectors are GnuPG 2.4.9's:
  // `gpg -c --s2k-mode 3 --s2k-digest-algo SHA256|SHA512 --s2k-count 65536
  // --cipher-algo AES256` with the passphrase 123456, the salt its
  // `--list-packets` printed, and the session key `--show-session-key`
  // printed, which is the S2K's first 32 bytes.
  group('Iterated and Salted S2K as a card hashes PINs', () {
    final pin = '123456'.codeUnits;
    String hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase();
    List<int> unhex(String s) => [for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)];

    test('with SHA-256, GnuPG gives the same', () {
      final salt = unhex('C81181362F90C641');
      expect(hex(iteratedSaltedS2kCount(pin, salt, 65536)), '849DE38C40659DFFF75CE0563A962FFB59B0CE1B77182B91414E512093052422');
      expect(iteratedSaltedS2k(pin, salt, 0x60), iteratedSaltedS2kCount(pin, salt, 65536), reason: 'coded 0x60 is 65536');
    });

    test('with SHA-512, GnuPG gives the same first 32 bytes, and the whole digest is 64', () {
      final salt = unhex('AC0FDB403E1D579F');
      final whole = iteratedSaltedS2kCount(pin, salt, 65536, hashAlgorithm: 10);
      expect(whole, hasLength(64));
      expect(hex(whole.sublist(0, 32)), '0B00AEFBD74F892C1952F7826E3E56E743B2B3C05E230528C220927C18D63A15');
      expect(iteratedSaltedS2k(pin, salt, 0x60, hashAlgorithm: 10, length: 64), whole);
    });

    test('a plain count not a coded one can stand for is taken as it is', () {
      final salt = [1, 2, 3, 4, 5, 6, 7, 8];
      final unit = [...salt, ...pin];
      final data = [for (var i = 0; i < 100000; i++) unit[i % unit.length]];
      expect(iteratedSaltedS2kCount(pin, salt, 100000), hash.sha256.convert(data).bytes);
    });
  });
}
