@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart' show parseKeyPacket;
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// test/fixtures/keys/gnupg/card holds GnuPG card stubs (openspec:
// add-openpgp-card): secret keys whose secret parts are on a card. Its
// README says how each was made and what GnuPG made of it.

void main() {
  group('a card stub made by hand', () {
    final stub = keyFixture('gnupg/card/stub-ed25519.gpg');
    final public = keyFixture('gnupg/ed25519.public.gpg');

    test('is read as a secret key that keeps its secret elsewhere', () {
      final info = readPgpKeyInfo(stub);

      expect(info.isSecret, isTrue);
      expect(info.protected, isTrue);
      expect(info.primary.hasSecret && info.primary.protected, isTrue);
      expect(info.subkeys.single.hasSecret && info.subkeys.single.protected, isTrue);
    });

    test('has the fingerprints, user ID and flags of its public half', () {
      final info = readPgpKeyInfo(stub);
      final expected = readPgpKeyInfo(public);

      expect(info.primary.fingerprintHex, '1FCDA135EE42400EC2B77CE677249ABE661CF8DB');
      expect(info.primary.fingerprintHex, expected.primary.fingerprintHex);
      expect(info.subkeys.single.fingerprintHex, expected.subkeys.single.fingerprintHex);
      expect(info.userIds, expected.userIds);
      expect(info.primary.flags, expected.primary.flags);
      expect(info.subkeys.single.expires, expected.subkeys.single.expires);
    });
  });

  group("Kemlock's card stub", () {
    final public = keyFixture('gnupg/ed25519.public.gpg');
    final info = readPgpKeyInfo(public);
    final aid = Uint8List.fromList([0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0xff, 0xff, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00]);

    test('is the hand-made stub byte for byte when both keys are on the card', () {
      final stub = cardStubKey(public, cardAid: aid, onCard: [info.primary.fingerprint, info.subkeys.single.fingerprint]);

      expect(stub, keyFixture('gnupg/card/stub-ed25519.gpg'));
    });

    test('gives a key not on the card the stub with no secret', () {
      final stub = cardStubKey(public, cardAid: aid, onCard: [info.subkeys.single.fingerprint]);

      expect(stub, keyFixture('gnupg/card/stub-ed25519-subkey.gpg'));
      final primary = parseKeyPacket(readPackets(stub).first);
      expect(primary.packet.body.sublist(primary.publicBody.length), [0xff, 0x00, 0x65, 0x00, 0x47, 0x4e, 0x55, 0x01]);
      expect(readPgpKeyInfo(stub).primary.protected, isTrue);
    });

    test('names the card of each key on it', () {
      final serials = cardStubSerials(keyFixture('gnupg/card/stub-ed25519-subkey.gpg'));

      expect(serials.keys, [info.subkeys.single.fingerprintHex]);
      expect(serials.values.single, aid);
      expect(cardStubSerials(keyFixture('gnupg/card/stub-ed25519.gpg')), hasLength(2));
      expect(cardStubSerials(keyFixture('gnupg/ed25519.secret.gpg')), isEmpty);
      expect(cardStubSerials(keyFixture('gnupg/ed25519-protected.secret.gpg')), isEmpty);
    });

    test('is made from a public key only', () {
      expect(() => cardStubKey(keyFixture('gnupg/ed25519.secret.gpg'), cardAid: aid, onCard: const []), throwsArgumentError);
    });
  });
}
