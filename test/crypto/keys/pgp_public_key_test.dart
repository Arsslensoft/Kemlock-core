@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/public_key.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'pgp_public_fixtures_test.dart' show ListedKey, contactKeyBytes, expectAsListed;

// Other people's public keys, read from the GnuPG keys of test/fixtures/keys/contacts (their README has the
// commands) and the three copies altered by hand beside them.

Uint8List _armored(String path) => readArmor(readPemBlocks(keyFixtureText(path)).single);

List<int> _tags(Uint8List key) => [for (final p in readPackets(key)) p.tag];

/// What GnuPG listed for the one key of the file [name] under `contacts/`.
ListedKey _listed(String name) {
  String? fingerprint;
  final userIds = <String>[];
  final subkeys = <String>[];
  String? pending;
  for (final line in const LineSplitter().convert(keyFixtureText('contacts/$name'))) {
    final f = line.split(':');
    switch (f[0]) {
      case 'pub' || 'sub':
        pending = f[0];
      case 'fpr' when pending == 'pub':
        fingerprint = f[9];
        pending = null;
      case 'fpr' when pending == 'sub':
        subkeys.add(f[9]);
        pending = null;
      case 'uid':
        userIds.add(f[9]);
    }
  }
  return (fingerprint: fingerprint!, userIds: userIds, subkeys: subkeys);
}

void main() {
  group('trimPublicKey', () {
    test('drops the certification of another key and a photo, and keeps the fingerprint', () async {
      final given = contactKeyBytes('rsa3072-certified-photo.public.asc');
      expect(_tags(given), [
        PgpTag.publicKey,
        PgpTag.userId,
        PgpTag.signature,
        PgpTag.signature,
        PgpTag.userAttribute,
        PgpTag.signature,
        PgpTag.publicSubkey,
        PgpTag.signature,
      ]);

      final trimmed = await trimPublicKey(given);

      expect(_tags(trimmed), [PgpTag.publicKey, PgpTag.userId, PgpTag.signature, PgpTag.publicSubkey, PgpTag.signature]);
      expect(readTransferableKey(trimmed).info.primary.fingerprintHex, readTransferableKey(given).info.primary.fingerprintHex);
      expect(trimmed.length, lessThan(given.length));
    });

    test('GnuPG imports the trimmed key and lists the same fingerprint, user IDs and subkeys', () async {
      final trimmed = await trimPublicKey(contactKeyBytes('rsa3072-certified-photo.public.asc'));

      // The bytes GnuPG was given, and what it listed for them
      expect(trimmed, contactKeyBytes('rsa3072-certified-photo.trimmed.public.asc'));
      final info = readTransferableKey(trimmed).info;
      expectAsListed(info, _listed('rsa3072-certified-photo.trimmed.colons.txt'));
      expectAsListed(info, _listed('rsa3072-certified-photo.colons.txt'));
    });

    test('a key GnuPG made with nothing to drop comes out as it went in', () async {
      for (final file in ['grace-1', 'grace-2', 'grace-3', 'alan', 'sign-only']) {
        final given = contactKeyBytes('$file.public.asc');
        expect(await trimPublicKey(given), given, reason: file);
      }
    });

    test('trimming twice changes nothing more', () async {
      final once = await trimPublicKey(contactKeyBytes('rsa3072-certified-photo.public.asc'));
      expect(await trimPublicKey(once), once);
    });

    test('a subkey another key bound is refused as failing its own checks', () async {
      final altered = contactKeyBytes('grace-1.foreign-subkey.public.asc');
      // It reads as the key of Grace with a second subkey: nothing but the signatures says otherwise
      final info = readTransferableKey(altered).info;
      expect(info.primary.fingerprintHex, '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495');
      expect(info.subkeys, hasLength(2));

      await expectLater(trimPublicKey(altered), throwsKeyProblem(KeyProblem.damaged, pgpFailsOwnChecks));
    });

    test('a user ID certification with one byte flipped is refused as failing its own checks', () async {
      await expectLater(
        trimPublicKey(contactKeyBytes('grace-1.flipped-certification.public.asc')),
        throwsKeyProblem(KeyProblem.damaged, pgpFailsOwnChecks),
      );
    });

    test('a subkey whose binding was taken away is refused', () async {
      final packets = readPackets(contactKeyBytes('grace-1.public.asc'));
      final cut = Uint8List.fromList([for (final p in packets.take(packets.length - 1)) ...p.encoded]);

      await expectLater(trimPublicKey(cut), throwsKeyProblem(KeyProblem.damaged));
    });

    test('an ECDSA primary key is refused, naming the algorithm', () async {
      await expectLater(
        trimPublicKey(contactKeyBytes('ecdsa-p256.public.asc')),
        throwsKeyProblem(KeyProblem.unsupportedKeyType, 'ECDSA (nistp256)'),
      );
    });

    test('the version 6 key of RFC 9580 is accepted', () async {
      final given = _armored('rfc9580/v6-public.asc');

      final trimmed = await trimPublicKey(given);

      expect(trimmed, given);
      expect(readTransferableKey(trimmed).info.version, 6);
    });

    test('a secret key is never trimmed into a public one', () async {
      await expectLater(trimPublicKey(_armored('gnupg/ed25519.secret.asc')), throwsKeyProblem(KeyProblem.privateKeyGiven));
    });
  });

  group('readPublicKeys', () {
    test('reads an armored key and a binary one', () async {
      final armored = await readPublicKeys(keyFixtureText('gnupg/ed25519.public.asc'));
      final binary = await readPublicKeys(keyFixture('gnupg/ed25519.public.gpg'));
      final armoredBytes = await readPublicKeys(utf8.encode(keyFixtureText('gnupg/ed25519.public.asc')));

      expect(armored.single.info.primary.fingerprintHex, '1FCDA135EE42400EC2B77CE677249ABE661CF8DB');
      expect(armored.single.info.userIds, ['Fixture Ed25519 <ed25519@example.org>']);
      expect(armored.single.bytes, keyFixture('gnupg/ed25519.public.gpg'));
      expect(binary.single.bytes, armored.single.bytes);
      expect(armoredBytes.single.bytes, armored.single.bytes);
    });

    test('a keyring gives its two keys, binary and armored', () async {
      for (final input in <Object>[keyFixture('contacts/two-keys.public.gpg'), keyFixtureText('contacts/two-keys.public.asc')]) {
        final keys = await readPublicKeys(input);

        expect(
          [for (final k in keys) k.info.userIds.single],
          ['Alan Turing <alan@example.org>', 'Fixture Sign Only <sign-only@example.org>'],
        );
        expect(keys[0].bytes, contactKeyBytes('alan.public.asc'));
        expect(keys[1].bytes, contactKeyBytes('sign-only.public.asc'));
      }
    });

    test('two armored blocks one after the other give two keys', () async {
      final keys = await readPublicKeys('${keyFixtureText('contacts/alan.public.asc')}\n${keyFixtureText('contacts/grace-1.public.asc')}');

      expect([for (final k in keys) k.info.userIds.single], ['Alan Turing <alan@example.org>', 'Grace Hopper <grace@example.org>']);
    });

    test('what it gives is trimmed and checked', () async {
      final keys = await readPublicKeys(keyFixtureText('contacts/rsa3072-certified-photo.public.asc'));
      expect(keys.single.bytes, contactKeyBytes('rsa3072-certified-photo.trimmed.public.asc'));

      await expectLater(
        readPublicKeys(keyFixtureText('contacts/grace-1.foreign-subkey.public.asc')),
        throwsKeyProblem(KeyProblem.damaged, pgpFailsOwnChecks),
      );
      await expectLater(
        readPublicKeys(keyFixtureText('contacts/ecdsa-p256.public.asc')),
        throwsKeyProblem(KeyProblem.unsupportedKeyType, 'ECDSA (nistp256)'),
      );
    });

    test('a private key block and a binary secret key give privateKeyGiven', () async {
      await expectLater(readPublicKeys(keyFixtureText('gnupg/ed25519.secret.asc')), throwsKeyProblem(KeyProblem.privateKeyGiven));
      await expectLater(readPublicKeys(keyFixture('gnupg/ed25519.secret.gpg')), throwsKeyProblem(KeyProblem.privateKeyGiven));
      // A secret key after a public one in the same input
      await expectLater(
        readPublicKeys([...keyFixture('gnupg/ed25519.public.gpg'), ...keyFixture('gnupg/rsa3072.secret.gpg')]),
        throwsKeyProblem(KeyProblem.privateKeyGiven),
      );
    });

    test('an SSH public key line, a PUBLIC KEY PEM and a certificate give unrecognized', () async {
      for (final file in ['openssh/ed25519.pub', 'openssl/p256.spki.pem', 'openssl/p256.cert.pem']) {
        await expectLater(readPublicKeys(keyFixtureText(file)), throwsKeyProblem(KeyProblem.unrecognized), reason: file);
        await expectLater(readPublicKeys(keyFixture(file)), throwsKeyProblem(KeyProblem.unrecognized), reason: file);
      }
      await expectLater(readPublicKeys(keyFixture('openssl/p256.spki.der')), throwsKeyProblem(KeyProblem.unrecognized));
      await expectLater(readPublicKeys('https://example.org/'), throwsKeyProblem(KeyProblem.unrecognized));
      await expectLater(readPublicKeys(''), throwsKeyProblem(KeyProblem.unrecognized));
    });

    test('a block cut short gives damaged', () async {
      await expectLater(readPublicKeys(keyFixtureText('contacts/grace-1.cut.public.asc')), throwsKeyProblem(KeyProblem.damaged));
      // Cut inside the base64, with its end line left in place
      final lines = keyFixtureText('contacts/grace-1.public.asc').trimRight().split('\n');
      final cut = [...lines.take(4), lines.last].join('\n');
      await expectLater(readPublicKeys(cut), throwsKeyProblem(KeyProblem.damaged));
    });

    test('more than 1 MB gives tooLarge, as bytes and as text', () async {
      final big = Uint8List(maxKeyInputLength + 1)..setAll(0, keyFixture('gnupg/ed25519.public.gpg'));

      await expectLater(readPublicKeys(big), throwsKeyProblem(KeyProblem.tooLarge));
      await expectLater(readPublicKeys(latin1.decode(big)), throwsKeyProblem(KeyProblem.tooLarge));
    });

    test('readPrivateKey still says a public key alone is not a private key', () async {
      await expectLater(readPrivateKey(keyFixtureText('contacts/grace-1.public.asc')), throwsKeyProblem(KeyProblem.publicKeyOnly));
      await expectLater(readPrivateKey(keyFixture('contacts/two-keys.public.gpg')), throwsKeyProblem(KeyProblem.publicKeyOnly));
    });
  });

  group('mergePublicKeys', () {
    late Uint8List first;
    late Uint8List second;
    late Uint8List third;

    setUp(() {
      first = contactKeyBytes('grace-1.public.asc');
      second = contactKeyBytes('grace-2.public.asc');
      third = contactKeyBytes('grace-3.public.asc');
    });

    test('an old copy with a new one gives the new expiry and the added subkey', () async {
      final merged = await mergePublicKeys(first, second);

      final info = readTransferableKey(merged).info;
      final newer = readTransferableKey(second).info;
      expect(info.primary.expires, newer.primary.expires);
      expect(info.subkeys.first.expires, newer.subkeys.first.expires);
      expect([for (final k in info.subkeys) k.fingerprintHex], [for (final k in newer.subkeys) k.fingerprintHex]);
      expect(info.primary.revoked, isFalse);
      // Nothing either copy held is gone: the earlier self-signatures are there beside the later ones
      expect(merged.length, greaterThan(second.length));
      expect(await mergePublicKeys(second, first), merged);
    });

    test('a revoked copy with an old one, in either order, is revoked', () async {
      final oneWay = await mergePublicKeys(third, first);
      final other = await mergePublicKeys(first, third);

      expect(readTransferableKey(oneWay).info.primary.revoked, isTrue);
      expect(other, oneWay);
    });

    test('a key merged with itself is byte for byte itself', () async {
      for (final key in [first, second, third, contactKeyBytes('alan.public.asc')]) {
        expect(await mergePublicKeys(key, key), key);
      }
    });

    test('a copy merged with one that holds nothing more is byte for byte itself', () async {
      final all = await mergePublicKeys(await mergePublicKeys(first, second), third);

      for (final older in [first, second, third]) {
        expect(await mergePublicKeys(all, older), all);
        expect(await mergePublicKeys(older, all), all);
      }
    });

    test('two keys of different fingerprints throw an ArgumentError', () async {
      await expectLater(mergePublicKeys(first, contactKeyBytes('alan.public.asc')), throwsArgumentError);
    });

    test('the merged key passes the checks a key is read with', () async {
      final merged = await mergePublicKeys(await mergePublicKeys(first, second), third);

      expect(await trimPublicKey(merged), merged);
      expect((await readPublicKeys(merged)).single.bytes, merged);
      expect(await verifyPgpSelfSignatures(merged), isTrue);
    });

    test('the union made without verifying, for two copies the vault holds, is the same key', () async {
      final merged = await mergePublicKeys(await mergePublicKeys(first, second), third);

      expect(unionPublicKeys(unionPublicKeys(first, second), third), merged);
      expect(unionPublicKeys(third, unionPublicKeys(second, first)), merged);
      expect(unionPublicKeys(first, first), first);
      expect(() => unionPublicKeys(first, contactKeyBytes('alan.public.asc')), throwsArgumentError);
    });

    test('a copy altered on its way is refused, not merged', () async {
      await expectLater(
        mergePublicKeys(first, contactKeyBytes('grace-1.foreign-subkey.public.asc')),
        throwsKeyProblem(KeyProblem.damaged, pgpFailsOwnChecks),
      );
    });
  });

  group('fingerprintGroups', () {
    test('ten groups of four for a version 4 key', () {
      final hex = readTransferableKey(contactKeyBytes('grace-1.public.asc')).info.primary.fingerprintHex;

      final groups = fingerprintGroups(hex);

      expect(groups, ['894F', '6AAC', '8FCE', '0FAF', '7EE2', '1BB6', 'B405', 'E72A', 'FBA2', '3495']);
      expect(groups.join(), hex);
    });

    test('sixteen for a version 6 key, upper case', () {
      final hex = readTransferableKey(_armored('rfc9580/v6-public.asc')).info.primary.fingerprintHex;

      final groups = fingerprintGroups(hex.toLowerCase());

      expect(groups, hasLength(16));
      expect(groups.every((g) => g.length == 4 && g == g.toUpperCase()), isTrue);
      expect(groups.join(), hex);
    });
  });
}
