@TestOn('vm')
library;

// Changing a PGP key (openspec: add-pgp-key-editing): each change on keys
// GnuPG, Sequoia and Kemlock made, with a fixed clock. tool/keys/gnupg_check.sh
// imports the results into GnuPG.

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/edit.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart' as pgp;
import 'package:test/test.dart';

import 'fixtures.dart';

/// A key of test/fixtures/keys as binary packets.
Uint8List _key(String path) => path.endsWith('.asc') ? readArmorBlock(keyFixture(path)) : keyFixture(path);

const _signing = 'gnupg/editing/signing-subkey.secret.asc';
const _rsa = 'gnupg/editing/rsa3072-expiring.secret.asc';
const _protected = 'gnupg/editing/protected.secret.asc';
const _direct = 'other/editing/direct-key.secret.asc';
const _expired = 'gnupg/expiry/expired.secret.asc';
const _passphrase = 'fixture passphrase';

/// A day the fixtures of gnupg/editing were made on, at noon.
final _now = DateTime.utc(2026, 11, 20, 12);

/// Whether every packet of [before] is in [after], in the same order.
bool _keepsInOrder(Uint8List before, Uint8List after) {
  final old = readPackets(before).map((p) => p.encoded).toList();
  var i = 0;
  for (final p in readPackets(after)) {
    if (i < old.length && _sameBytes(p.encoded, old[i])) i++;
  }
  return i == old.length;
}

bool _sameBytes(List<int> a, List<int> b) => a.length == b.length && Iterable<int>.generate(a.length).every((i) => a[i] == b[i]);

/// The new packets of [after], those [before] does not hold, by tag.
List<int> _added(Uint8List before, Uint8List after) {
  final old = readPackets(before).map((p) => p.encoded).toList();
  return [
    for (final p in readPackets(after))
      if (!old.any((o) => _sameBytes(o, p.encoded))) p.tag,
  ];
}

/// The signatures of [after] that [before] does not hold.
List<PgpSignature> _newSignatures(Uint8List before, Uint8List after) {
  final old = readPackets(before).map((p) => p.encoded).toList();
  return [
    for (final p in readPackets(after))
      if (p.tag == PgpTag.signature && !old.any((o) => _sameBytes(o, p.encoded))) parseSignature(p.body),
  ];
}

/// The checks every changed key passes: it reads, its fingerprint is the
/// old one, every old packet is there in order, and its self-signatures
/// verify.
Future<PgpKeyInfo> _expectChanged(Uint8List before, Uint8List after) async {
  final info = readPgpKeyInfo(after);
  expect(info.primary.fingerprintHex, readPgpKeyInfo(before).primary.fingerprintHex);
  expect(_keepsInOrder(before, after), isTrue, reason: 'a change only adds');
  expect(await verifySelfSignatures(after), isTrue);
  expect(after.length, greaterThan(before.length));
  return info;
}

void main() {
  group('what can be changed', () {
    test('keys GnuPG, Sequoia and Kemlock made, protected or not', () {
      for (final path in [_signing, _rsa, _protected, _direct, 'kemlock/pgp-ed25519.unprotected.asc', 'kemlock/pgp-rsa4096.secret.asc']) {
        expect(editRefusal(_key(path)), isNull, reason: path);
      }
      expect(primaryNeedsPassphrase(_key(_protected)), isTrue);
      expect(primaryNeedsPassphrase(_key(_signing)), isFalse);
    });

    test('and what cannot, with the reason', () {
      PgpEditBlock? block(String path) => editRefusal(_key(path))?.block;
      expect(block('gnupg/expiry/revoked.secret.asc'), PgpEditBlock.revoked);
      expect(block('gnupg/editing/protected.stub.secret.asc'), PgpEditBlock.noPrimarySecret);
      // A version 6 key is changed since add-post-quantum-pgp: see its group below
      expect(editRefusal(_key('gnupg/ed25519.public.gpg'))?.block, PgpEditBlock.noPrimarySecret);
      final nist = editRefusal(readArmorBlock(keyFixture('../pgp/gnupg/nistp256.secret.asc')));
      expect((nist?.block, nist?.detail), (PgpEditBlock.algorithm, 'nistp256'));
    });

    // Joined with add-openpgp-card: a card does not sign key changes
    test('a key on an OpenPGP card is refused, and a delegated secret signs no change', () async {
      final stub = _key('gnupg/card/stub-ed25519.gpg');
      Matcher problem(PgpProblem problem) => throwsA(isA<PgpException>().having((e) => e.problem, 'problem', problem));

      expect(editRefusal(stub)?.block, PgpEditBlock.noPrimarySecret);
      expect(() => PgpSigner.of(stub), problem(PgpProblem.noSecretHere));

      var asked = false;
      final card = DelegatedSecret(
        sign: (key, digest) async {
          asked = true;
          return Uint8List(64);
        },
        decipher: (key, input) async => Uint8List(32),
      );
      final primary = parseKeyPacket(readPackets(stub).first);
      await expectLater(PgpSigner(primary, card).sign(Uint8List(64)), problem(PgpProblem.unsupported));
      expect(asked, isFalse, reason: 'the card is never asked');
    });
  });

  group('setExpiry', () {
    test('a date, for the primary key and every subkey', () async {
      final before = _key(_signing);
      final when = DateTime.utc(2032, 6, 1);
      final after = await setExpiry(before, PgpSigner.of(before), expires: when, alsoSubkeys: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, when);
      expect(info.subkeys.map((s) => s.expires), [when, when]);
      // One certification for the user ID and a binding for each subkey
      expect(_added(before, after), [PgpTag.signature, PgpTag.signature, PgpTag.signature]);
      for (final s in _newSignatures(before, after)) {
        expect((s.version, s.hashAlgorithm, s.created), (4, 10, _now.millisecondsSinceEpoch ~/ 1000));
      }
      // The flags and preferences of what it superseded are kept
      expect(info.primary.flags, readPgpKeyInfo(before).primary.flags);
      expect(info.subkeys.map((s) => s.flags), readPgpKeyInfo(before).subkeys.map((s) => s.flags));
    });

    test('the primary key alone leaves each subkey as it was', () async {
      final before = _key(_signing);
      final after = await setExpiry(before, PgpSigner.of(before), expires: DateTime.utc(2032, 6, 1), now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, DateTime.utc(2032, 6, 1));
      expect(info.subkeys.map((s) => s.expires), readPgpKeyInfo(before).subkeys.map((s) => s.expires));
    });

    test('never', () async {
      final before = _key(_rsa);
      final after = await setExpiry(before, PgpSigner.of(before), expires: null, alsoSubkeys: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, isNull);
      expect(info.subkeys.single.expires, isNull);
      for (final s in _newSignatures(before, after)) {
        expect(s.keyExpiry, isNull);
      }
    });

    test('a key that already expired', () async {
      final before = _key(_expired);
      expect(readPgpKeyInfo(before).primary.expires!.isBefore(_now), isTrue);
      final when = DateTime.utc(2027, 11, 20, 12);
      final after = await setExpiry(before, PgpSigner.of(before), expires: when, alsoSubkeys: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, when);
      expect(info.subkeys.single.expires, when);
    });

    test('a key whose expiry is in a direct-key signature', () async {
      final before = _key(_direct);
      final when = DateTime.utc(2031, 3, 1);
      final after = await setExpiry(before, PgpSigner.of(before), expires: when, alsoSubkeys: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, when);
      expect(info.subkeys.map((s) => s.expires), [when, when, when]);
      final added = _newSignatures(before, after);
      // A direct-key signature, the two user IDs, the three subkeys
      expect(added.map((s) => s.type), [0x1f, 0x13, 0x13, 0x18, 0x18, 0x18]);
      // Sequoia's critical bits and its notation are copied
      final direct = readSubpackets(added.first.hashedArea);
      expect([for (final s in direct) (s.type, s.critical)], containsAll([(2, true), (9, true), (27, true), (20, false)]));
    });

    test('one signing subkey: its back-signature goes with the new binding', () async {
      final before = _key(_signing);
      final signing = readPgpKeyInfo(before).subkeys.first;
      expect(signing.canSign, isTrue);
      final when = DateTime.utc(2028, 1, 1);
      final after = await setExpiry(before, PgpSigner.of(before), expires: when, subkey: signing.fingerprint, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, readPgpKeyInfo(before).primary.expires);
      expect(info.subkeys.map((s) => s.expires), [when, readPgpKeyInfo(before).subkeys[1].expires]);
      final binding = _newSignatures(before, after).single;
      expect(binding.type, 0x18);
      final packets = readPackets(after);
      final primary = parseKeyPacket(packets.first);
      final subkey = parseKeyPacket(packets.firstWhere((p) => p.tag == PgpTag.secretSubkey));
      expect(await verifyBackSignature(primary, subkey, binding), isTrue);
    });

    test('a clock behind the latest self-signature', () async {
      final before = _key(_signing);
      final behind = DateTime.utc(2020, 1, 1);
      final when = DateTime.utc(2033, 1, 1);
      final after = await setExpiry(before, PgpSigner.of(before), expires: when, alsoSubkeys: true, now: behind);
      final info = await _expectChanged(before, after);
      expect(info.primary.expires, when);
      final latest = [
        for (final p in readPackets(before))
          if (p.tag == PgpTag.signature) parseSignature(p.body).created!,
      ].reduce((a, b) => a > b ? a : b);
      for (final s in _newSignatures(before, after)) {
        expect(s.created, latest + 1);
      }
    });

    test('a protected key, signed with its passphrase, stays protected', () async {
      final before = _key(_protected);
      final after = await setExpiry(
        before,
        PgpSigner.of(before, passphrase: _passphrase),
        expires: DateTime.utc(2029, 1, 1),
        alsoSubkeys: true,
        now: _now,
      );
      final info = await _expectChanged(before, after);
      expect(info.protected, isTrue);
      expect(info.primary.expires, DateTime.utc(2029, 1, 1));
    });

    test('a date that is not ahead, and a subkey the key does not have, are refused', () async {
      final before = _key(_signing);
      final signer = PgpSigner.of(before);
      expect(() => setExpiry(before, signer, expires: _now, now: _now), throwsArgumentError);
      expect(() => setExpiry(before, signer, expires: _now.subtract(const Duration(days: 1)), now: _now), throwsArgumentError);
      expect(() => setExpiry(before, signer, expires: DateTime.utc(2030), subkey: Uint8List(20), now: _now), throwsArgumentError);
    });
  });

  group('addUserId', () {
    /// The hashed subpackets of [s] but the creation time and the primary user ID flag.
    List<(int, bool, String)> kept(PgpSignature s) => [
      for (final p in readSubpackets(s.hashedArea))
        if (p.type != 2 && p.type != 25) (p.type, p.critical, p.data.join(',')),
    ];

    test('a second user ID, certified with the main one\'s preferences, flags and expiry', () async {
      final before = _key(_rsa);
      final after = await addUserId(before, PgpSigner.of(before), name: ' Ada Lovelace ', email: 'ada@work.example', now: _now);
      final info = await _expectChanged(before, after);
      expect(info.userIds, ['Fixture RSA <rsa@example.org>', 'Ada Lovelace <ada@work.example>']);
      expect(info.mainUserId, 'Fixture RSA <rsa@example.org>');
      expect(_added(before, after), [PgpTag.userId, PgpTag.signature]);
      final cert = _newSignatures(before, after).single;
      final main = parseSignature(readPackets(before).firstWhere((p) => p.tag == PgpTag.signature).body);
      expect(cert.type, 0x13);
      expect(kept(cert), kept(main));
      expect(cert.primaryUserId, isFalse);
      // The key still expires on the same date
      expect(info.primary.expires, readPgpKeyInfo(before).primary.expires);
      expect(info.primary.flags, readPgpKeyInfo(before).primary.flags);
    });

    test('made the main user ID, the reader names it first', () async {
      final before = _key(_signing);
      final after = await addUserId(before, PgpSigner.of(before), name: 'Ada', email: 'ada@work.example', makePrimary: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(_newSignatures(before, after).single.primaryUserId, isTrue);
      expect(info.mainUserIndex, 1);
      expect(info.mainUserId, 'Ada <ada@work.example>');
      expect(info.userIdsMainFirst, ['Ada <ada@work.example>', 'Fixture Signing <signing@example.org>']);
    });

    test('a key whose main user ID is marked keeps it, and the new one goes after the last user ID', () async {
      final before = _key(_direct);
      expect(readPgpKeyInfo(before).mainUserId, 'Fixture Direct');
      final after = await addUserId(before, PgpSigner.of(before), name: 'Fixture Direct', email: 'direct@work.example', now: _now);
      final info = await _expectChanged(before, after);
      expect(info.mainUserId, 'Fixture Direct');
      expect(info.userIds.last, 'Fixture Direct <direct@work.example>');
      // Before the subkeys, in the new header format of the key's packets
      final tags = readPackets(after).map((p) => p.tag).toList();
      expect(tags.indexOf(PgpTag.userId, 3), lessThan(tags.indexOf(PgpTag.secretSubkey)));
      expect(readPackets(after).every((p) => !p.oldFormat), isTrue);
      // Copied from the primary-marked one, which the new one is not
      final cert = _newSignatures(before, after).single;
      expect(cert.primaryUserId, isFalse);
      expect(cert.keyExpiry, isNotNull);
    });

    test('a user ID the key has, and an empty name or email, are refused', () async {
      final before = _key(_signing);
      final signer = PgpSigner.of(before);
      expect(
        () => addUserId(before, signer, name: 'Fixture Signing', email: 'signing@example.org', now: _now),
        throwsA(isA<ArgumentError>().having((e) => e.name, 'name', 'userId')),
      );
      expect(
        () => addUserId(before, signer, name: ' ', email: 'a@example.org', now: _now),
        throwsA(isA<ArgumentError>().having((e) => e.name, 'name', 'name')),
      );
      expect(
        () => addUserId(before, signer, name: 'Ada', email: '', now: _now),
        throwsA(isA<ArgumentError>().having((e) => e.name, 'name', 'email')),
      );
    });
  });

  group('addSubkey', () {
    Future<(Uint8List, PgpKey)> add(String path, PgpKeyType type, PgpSubkeyUse use, {DateTime? expires, String? passphrase}) async {
      final before = _key(path);
      final after = await addSubkey(
        before,
        PgpSigner.of(before, passphrase: passphrase),
        type: type,
        use: use,
        expires: expires,
        passphrase: passphrase,
        now: _now,
      );
      final info = await _expectChanged(before, after);
      expect(info.subkeys, hasLength(readPgpKeyInfo(before).subkeys.length + 1));
      expect(_added(before, after), [PgpTag.secretSubkey, PgpTag.signature]);
      // At the end, after every old packet
      expect(readPackets(after).last.tag, PgpTag.signature);
      return (after, info.subkeys.last);
    }

    Future<void> expectBound(Uint8List key, {required bool signs}) async {
      final packets = readPackets(key);
      final primary = parseKeyPacket(packets.first);
      final sub = parseKeyPacket(packets[packets.length - 2]);
      final binding = parseSignature(packets.last.body);
      expect(await verifyBackSignature(primary, sub, binding), signs);
    }

    test('Curve25519 to encrypt, the default, with an expiry', () async {
      final (after, sub) = await add(_signing, PgpKeyType.ed25519, PgpSubkeyUse.encrypt, expires: DateTime.utc(2030, 1, 1));
      expect((sub.algorithm, sub.canEncrypt, sub.canSign, sub.hasSecret, sub.protected), ('cv25519', true, false, true, false));
      expect(sub.flags, PgpKeyFlag.encryptCommunications | PgpKeyFlag.encryptStorage);
      expect(sub.expires, DateTime.utc(2030, 1, 1));
      expect(sub.created, _now);
      await expectBound(after, signs: false);
    });

    test('Ed25519 to sign, never expiring, with its back-signature', () async {
      final (after, sub) = await add(_rsa, PgpKeyType.ed25519, PgpSubkeyUse.sign);
      expect((sub.algorithm, sub.canSign, sub.canEncrypt, sub.expires), ('ed25519', true, false, null));
      await expectBound(after, signs: true);
    });

    test('RSA 4096 to encrypt and to sign', () async {
      final (encrypting, e) = await add(_direct, PgpKeyType.rsa4096, PgpSubkeyUse.encrypt);
      expect((e.algorithm, e.canEncrypt), ('rsa4096', true));
      await expectBound(encrypting, signs: false);
      final (signing, s) = await add(_signing, PgpKeyType.rsa4096, PgpSubkeyUse.sign);
      expect((s.algorithm, s.canSign), ('rsa4096', true));
      await expectBound(signing, signs: true);
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('a protected key\'s new subkey opens with its passphrase', () async {
      final (after, sub) = await add(_protected, PgpKeyType.ed25519, PgpSubkeyUse.encrypt, passphrase: _passphrase);
      expect(sub.protected, isTrue);
      final packet = parseKeyPacket(readPackets(after)[readPackets(after).length - 2]);
      expect(needsPassphrase(packet), isTrue);
      expect(unlockSecretKey(packet, passphrase: _passphrase), isA<X25519Secret>());
    });

    test('in the background, through the request the sheets make, and cancelled leaving nothing', () async {
      final before = _key(_signing);
      final done = await generateKey(
        PgpChangeRequest(
          before,
          const AddPgpSubkey(type: PgpKeyType.ed25519, use: PgpSubkeyUse.encrypt),
          now: _now,
        ),
      ).result;
      final changed = (done as KeyGenerated).key;
      expect(changed.pgp!.subkeys, hasLength(3));
      expect(changed.public, transferablePublicKey(readPackets(changed.private)));

      final cancelled = generateKey(
        PgpChangeRequest(
          before,
          const AddPgpSubkey(type: PgpKeyType.rsa4096, use: PgpSubkeyUse.sign),
          now: _now,
        ),
      );
      cancelled.cancel();
      expect(await cancelled.result, isA<KeyGenerationCancelled>());
      expect(before, _key(_signing));
    });

    test('a wrong passphrase comes back from the background as it was thrown', () async {
      final generation = generateKey(
        PgpChangeRequest(
          _key(_protected),
          const AddPgpSubkey(type: PgpKeyType.ed25519, use: PgpSubkeyUse.encrypt),
          passphrase: 'wrong',
          now: _now,
        ),
      );
      await expectLater(generation.result, throwsA(isA<PgpException>().having((e) => e.problem, 'problem', PgpProblem.wrongPassphrase)));
    });
  });

  group('revocation', () {
    Matcher problem(PgpEditProblem p) => throwsA(isA<PgpEditException>().having((e) => e.problem, 'problem', p));

    test('each reason, and a note, in a certificate that leaves the key as it is', () async {
      final key = _key(_signing);
      final signer = PgpSigner.of(key);
      for (final reason in PgpRevocationReason.values) {
        final certificate = await revocation(
          key,
          signer,
          reason: reason,
          note: reason == PgpRevocationReason.retired ? ' Moved to a new key ' : '',
          now: _now,
        );
        final packet = readPackets(certificate).single;
        expect(packet.oldFormat, readPackets(key).first.oldFormat);
        final signature = parseSignature(packet.body);
        expect(signature.type, 0x20);
        expect(signature.issuedBy(signer.key.fingerprint), isTrue);
        expect(await verifySignature(signature, signer.key, hashedKey(signer.key)), isTrue);
        final reasonSubpacket = readSubpackets(signature.hashedArea).singleWhere((s) => s.type == 29);
        expect(reasonSubpacket.data.first, reason.code);
        expect(String.fromCharCodes(reasonSubpacket.data.skip(1)), reason == PgpRevocationReason.retired ? 'Moved to a new key' : '');
      }
      expect(readPgpKeyInfo(key).primary.revoked, isFalse);
    });

    test('applied, armored as the sheet hands it out, the key is revoked; applied again, nothing changes', () async {
      final before = _key(_signing);
      final signer = PgpSigner.of(before);
      final text = armorRevocation(
        await revocation(before, signer, reason: PgpRevocationReason.retired, now: _now),
        signer.key.fingerprint.map((b) => b.toRadixString(16).padLeft(2, '0')).join().toUpperCase(),
      );
      expect(
        text,
        startsWith(
          '-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: Revocation certificate for E770227F48E661EAF271EAA7F92D39E6751913DD\n\n',
        ),
      );
      final after = await applyRevocation(before, text.codeUnits);
      final info = await _expectChanged(before, after);
      expect(info.primary.revoked, isTrue);
      expect(editRefusal(after)?.block, PgpEditBlock.revoked);
      // After the primary key's own signatures, before the user ID
      expect(readPackets(after).map((p) => p.tag).take(3), [PgpTag.secretKey, PgpTag.signature, PgpTag.userId]);
      expect(await applyRevocation(after, text.codeUnits), after);
      // The public half carries it
      expect(readPgpKeyInfo(transferablePublicKey(readPackets(after))).primary.revoked, isTrue);
    });

    test('revoked at once, through the request the sheets make', () async {
      final before = _key(_rsa);
      final after = await changePgpKey(before, const RevokePgpKey(reason: PgpRevocationReason.compromised), now: _now);
      expect((await _expectChanged(before, after)).primary.revoked, isTrue);
    });

    test("GnuPG's own certificates, with and without the colon before the armor, and in binary", () async {
      for (final (key, rev) in [
        (_signing, 'gnupg/editing/signing-subkey.rev'),
        ('gnupg/editing/signing-subkey.after.secret.asc', 'gnupg/editing/signing-subkey.rev'),
        (_rsa, 'gnupg/editing/rsa3072-expiring.rev'),
        (_protected, 'gnupg/editing/protected.rev'),
      ]) {
        final before = _key(key);
        final text = keyFixtureText(rev);
        expect(text, contains('\n:-----BEGIN PGP PUBLIC KEY BLOCK-----'));
        final binary = readArmorBlock(Uint8List.fromList(text.replaceFirst(':-----BEGIN', '-----BEGIN').codeUnits));
        for (final given in [text.codeUnits, text.replaceFirst(':-----BEGIN', '-----BEGIN').codeUnits, binary]) {
          final after = await applyRevocation(before, given);
          expect((await _expectChanged(before, after)).primary.revoked, isTrue, reason: rev);
          expect(_added(before, after), [PgpTag.signature]);
        }
      }
    });

    test("Sequoia's certificate, the primary key and the signature", () async {
      final before = _key(_direct);
      final after = await applyRevocation(before, keyFixture('other/editing/direct-key.rev'));
      expect((await _expectChanged(before, after)).primary.revoked, isTrue);
    });

    test('a certificate for another key, a signature that revokes nothing, a flipped byte, and no certificate', () async {
      final key = _key(_rsa);
      await expectLater(applyRevocation(key, keyFixture('gnupg/editing/signing-subkey.rev')), problem(PgpEditProblem.otherKey));
      await expectLater(applyRevocation(key, keyFixture('other/editing/direct-key.rev')), problem(PgpEditProblem.otherKey));
      await expectLater(applyRevocation(key, keyFixture('../pgp/gnupg/message.txt.rsa3072.sig')), problem(PgpEditProblem.notARevocation));
      await expectLater(
        applyRevocation(key, keyFixture('gnupg/editing/rsa3072-expiring.public.asc')),
        problem(PgpEditProblem.notARevocation),
      );
      final rev = readArmorBlock(
        Uint8List.fromList(keyFixtureText('gnupg/editing/rsa3072-expiring.rev').replaceFirst(':-----', '-----').codeUnits),
      );
      final flipped = Uint8List.fromList(rev)..[rev.length - 10] ^= 0x01;
      await expectLater(applyRevocation(key, flipped), problem(PgpEditProblem.damaged));
      await expectLater(applyRevocation(key, 'not a certificate'.codeUnits), problem(PgpEditProblem.notACertificate));
      await expectLater(applyRevocation(key, rev.sublist(0, 20)), problem(PgpEditProblem.damaged));
    });
  });

  // openspec: add-post-quantum-pgp, task 9.1 (design decision 14)
  group('a version 6 key', () {
    const standard = 'kemlock/pgp-pq-standard.unprotected.asc';

    /// Every signature [after] adds is version 6 over SHA-512 with its 32-byte
    /// salt, of the key's own algorithm.
    void expectVersion6(Uint8List before, Uint8List after, int algorithm) {
      final added = _newSignatures(before, after);
      expect(added, isNotEmpty);
      for (final s in added) {
        expect((s.version, s.publicKeyAlgorithm, s.hashAlgorithm, s.salt?.length), (6, algorithm, 10, 32));
      }
    }

    test('a standard key, RFC 9980\'s and RFC 9580\'s samples can be changed', () {
      for (final path in [
        standard,
        'kemlock/pgp-pq-standard.secret.asc',
        'sequoia/pqc/standard.secret.asc',
        'rfc9980/a3-secret.asc',
        'rfc9580/v6-secret.asc',
      ]) {
        expect(editRefusal(_key(path)), isNull, reason: path);
      }
      // RFC 9980's ML-DSA-87 key is of a kind Kemlock does not sign with
      final a4 = editRefusal(_key('rfc9980/a4-secret.asc'));
      expect((a4?.block, a4?.detail), (PgpEditBlock.algorithm, 'mld87'));
    });

    test('a new expiry for the key and its subkey: a direct-key signature, a certification and a binding, each composite', () async {
      final before = _key(standard);
      final after = await setExpiry(before, PgpSigner.of(before), expires: DateTime.utc(2030, 1, 1), alsoSubkeys: true, now: _now);
      final info = await _expectChanged(before, after);
      expect(info.version, 6);
      expect(info.primary.expires, DateTime.utc(2030, 1, 1));
      expect(info.subkeys.single.expires, DateTime.utc(2030, 1, 1));
      expect(_newSignatures(before, after).map((s) => s.type), unorderedEquals([0x1f, 0x13, 0x18]));
      expectVersion6(before, after, 30);
    });

    test('never, on the protected copy, which stays protected', () async {
      final before = _key('kemlock/pgp-pq-standard.secret.asc');
      final after = await setExpiry(before, PgpSigner.of(before, passphrase: _passphrase), expires: null, now: _now);
      final info = await _expectChanged(before, after);
      expect((info.primary.expires, info.protected), (null, true));
      expectVersion6(before, after, 30);
    });

    test('a second user ID', () async {
      final before = _key(standard);
      final after = await addUserId(before, PgpSigner.of(before), name: 'Ada Added', email: 'added@example.org', now: _now);
      final info = await _expectChanged(before, after);
      expect(info.userIds, contains('Ada Added <added@example.org>'));
      expectVersion6(before, after, 30);
    });

    test("RFC 9580's Ed25519 key, which has no user ID, takes a new expiry on its direct-key signature, in version 6 too", () async {
      final before = _key('rfc9580/v6-secret.asc');
      final after = await setExpiry(before, PgpSigner.of(before), expires: DateTime.utc(2030, 1, 1), now: _now);
      expect((await _expectChanged(before, after)).primary.expires, DateTime.utc(2030, 1, 1));
      expect(_newSignatures(before, after).single.type, 0x1f);
      expectVersion6(before, after, 27);
    });

    test('a revocation certificate is the primary key then the signature, and revokes the key', () async {
      final key = _key(standard);
      final signer = PgpSigner.of(key);
      final certificate = await revocation(key, signer, reason: PgpRevocationReason.superseded, now: _now);
      final packets = readPackets(certificate);
      expect(packets.map((p) => p.tag), [PgpTag.publicKey, PgpTag.signature]);
      expect(packets.first.body, signer.key.publicBody);
      final signature = parseSignature(packets.last.body);
      expect((signature.version, signature.type, signature.publicKeyAlgorithm), (6, 0x20, 30));
      expect(await verifySignature(signature, signer.key, hashedKey(signer.key)), isTrue);

      final revoked = await applyRevocation(key, certificate);
      expect(readPgpKeyInfo(revoked).primary.revoked, isTrue);
      expect(await verifySelfSignatures(revoked), isTrue);
      // As the sheet hands it out, armored
      final armored = await revocationCertificate(key, reason: PgpRevocationReason.superseded, now: _now);
      expect(readPgpKeyInfo(await applyRevocation(key, armored.codeUnits)).primary.revoked, isTrue);
    });

    test('revoked at once, through the request the sheets make', () async {
      final key = _key(standard);
      final done = await generateKey(PgpChangeRequest(key, const RevokePgpKey(reason: PgpRevocationReason.compromised), now: _now)).result;
      final changed = (done as KeyGenerated).key;
      expect(changed.pgp!.primary.revoked, isTrue);
      expect(await verifySelfSignatures(changed.private), isTrue);
    });
  });

  // openspec: add-post-quantum-pgp, task 9.2 (design decision 14)
  group('a post-quantum subkey', () {
    Future<(Uint8List, Uint8List, PgpKey)> add(
      String path,
      PgpKeyType type, {
      PgpSubkeyUse use = PgpSubkeyUse.encrypt,
      String? passphrase,
    }) async {
      final before = _key(path);
      final after = await addSubkey(
        before,
        PgpSigner.of(before, passphrase: passphrase),
        type: type,
        use: use,
        passphrase: passphrase,
        now: _now,
      );
      final info = await _expectChanged(before, after);
      expect(_added(before, after), [PgpTag.secretSubkey, PgpTag.signature]);
      return (before, after, info.subkeys.last);
    }

    /// A message Kemlock encrypts to [key] at [now], opened by [key].
    Future<pgp.PgpDecrypted> roundTrip(Uint8List key, {String? passphrase}) async {
      final public = (await readPrivateKey(key)).public!;
      final message = await pgp.encrypt(
        data: pgp.PgpData.bytes(Uint8List.fromList(utf8.encode('to the new subkey'))),
        recipients: [public],
        text: true,
        now: _now,
      );
      return pgp.decrypt(
        data: pgp.PgpData.bytes(message!),
        keys: [pgp.PgpSecretKey(key, passphrase: passphrase)],
        now: _now,
      );
    }

    test('ML-KEM-768+X25519 on a version 4 Ed25519 key: version 4, the fingerprint kept, and a message to the key goes to it', () async {
      final (before, after, sub) = await add('kemlock/pgp-ed25519.unprotected.asc', PgpKeyType.pqStandard);
      expect((sub.version, sub.algorithm, sub.canEncrypt, sub.canSign, sub.created), (4, 'mlk768', true, false, _now));
      expect(readPgpKeyInfo(after).primary.fingerprintHex, readPgpKeyInfo(before).primary.fingerprintHex);
      final opened = await roundTrip(after);
      expect(utf8.decode(opened.bytes!), 'to the new subkey');
      expect(opened.openedWithAlgorithm, 'mlk768');
    });

    test("Kyber-768 with X25519: version 5, its secret in gpg-agent's form, protected with the key's own passphrase", () async {
      final (_, after, sub) = await add('kemlock/pgp-ed25519.secret.asc', PgpKeyType.pqGnupg, passphrase: _passphrase);
      expect((sub.version, sub.algorithm, sub.canEncrypt, sub.protected), (5, 'ky768_cv25519', true, true));
      final packet = parseKeyPacket(readPackets(after)[readPackets(after).length - 2]);
      expect(packet.agentKey, isNotNull);
      expect(unlockSecretKey(packet, passphrase: _passphrase), isA<KyberSecret>());
      final opened = await roundTrip(after, passphrase: _passphrase);
      expect(opened.openedWithAlgorithm, 'ky768_cv25519');
    });

    test("a version 6 key's own: ML-KEM-768+X25519 to encrypt, ML-DSA-65+Ed25519 to sign with its back-signature", () async {
      const standard = 'kemlock/pgp-pq-standard.unprotected.asc';
      final (_, encrypting, e) = await add(standard, PgpKeyType.pqStandard);
      expect((e.version, e.algorithm, e.canEncrypt), (6, 'mlk768', true));
      expect((await roundTrip(encrypting)).encrypted, isTrue);
      final (_, signing, s) = await add(standard, PgpKeyType.pqStandard, use: PgpSubkeyUse.sign);
      expect((s.version, s.algorithm, s.canSign), (6, 'mld65', true));
      final packets = readPackets(signing);
      final binding = parseSignature(packets.last.body);
      expect((binding.version, binding.publicKeyAlgorithm), (6, 30));
      expect(await verifyBackSignature(parseKeyPacket(packets.first), parseKeyPacket(packets[packets.length - 2]), binding), isTrue);
    });

    test('neither signs on a version 4 key, and a version 6 key takes no version 4 or 5 subkey', () async {
      Future<Uint8List> adding(String path, PgpKeyType type, PgpSubkeyUse use) {
        final key = _key(path);
        return addSubkey(key, PgpSigner.of(key), type: type, use: use, now: _now);
      }

      const v4 = 'kemlock/pgp-ed25519.unprotected.asc';
      const v6 = 'kemlock/pgp-pq-standard.unprotected.asc';
      await expectLater(adding(v4, PgpKeyType.pqStandard, PgpSubkeyUse.sign), throwsArgumentError);
      await expectLater(adding(v4, PgpKeyType.pqGnupg, PgpSubkeyUse.sign), throwsArgumentError);
      for (final type in [PgpKeyType.ed25519, PgpKeyType.rsa4096, PgpKeyType.pqGnupg]) {
        await expectLater(adding(v6, type, PgpSubkeyUse.encrypt), throwsArgumentError, reason: type.name);
      }
    });
  });
}
