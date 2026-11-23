@TestOn('vm')
library;

// The entry points the app calls: what a message is, read without a
// secret, and a public key read for one use.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'decrypt_test.dart' show throwsProblem;
import 'fixtures.dart';

PgpMessageInfo _inspect(String fixture) => inspectMessage(PgpData.bytes(pgpFixture(fixture)));

void main() {
  group('inspectMessage', () {
    const edSubkey = '841A40E3B199EA67';
    const rsaSubkey = 'B8A3CCC781F74F29';

    test('messages to keys name their recipients', () {
      for (final (fixture, ids, form) in [
        ('gnupg/to-ed25519.seipd.gpg', [edSubkey], EncryptedForm.seipd1),
        ('gnupg/to-rsa3072.seipd.gpg', [rsaSubkey], EncryptedForm.seipd1),
        ('gnupg/to-two.gpg', [edSubkey, rsaSubkey], EncryptedForm.seipd1),
        ('gnupg/armored.asc', [edSubkey], EncryptedForm.seipd1),
        ('gnupg/signed-encrypted.gpg', [edSubkey], EncryptedForm.seipd1),
        ('gnupg/large.gpg', [edSubkey], EncryptedForm.seipd1),
        ('kemlock/to-two.signed.asc', [edSubkey, rsaSubkey], EncryptedForm.seipd1),
        ('kemlock/report.txt.gpg', [edSubkey, rsaSubkey], EncryptedForm.seipd1),
      ]) {
        final info = _inspect(fixture);
        expect(info.kind, PgpMessageKind.encrypted, reason: fixture);
        expect(info.recipientKeyIds, ids);
        expect((info.hiddenRecipients, info.passphrase, info.form), (0, false, form));
        // The cipher of this form travels with the session key
        expect((info.cipher, info.mode, info.unsupported, info.noIntegrity), (null, null, null, false));
      }
    });

    test('the AEAD forms name their cipher and mode', () {
      final ocb = _inspect('gnupg/to-ed25519.ocb.gpg');
      expect((ocb.form, ocb.cipher, ocb.mode), (EncryptedForm.ocbPacket, 'AES-256', 'OCB'));
      expect(ocb.recipientKeyIds, [edSubkey]);
      final rfc = _inspect('rfc9580/a8-x25519-ocb.asc');
      expect((rfc.form, rfc.cipher, rfc.mode), (EncryptedForm.seipd2, 'AES-128', 'OCB'));
      expect(rfc.recipientKeyIds, ['12C83F1E706F6308']);
      final eax = _inspect('rfc9580/a9-skesk6-eax.asc');
      expect((eax.form, eax.cipher, eax.mode, eax.passphrase), (EncryptedForm.seipd2, 'AES-128', 'EAX', true));
      expect(_inspect('rfc9580/a11-skesk6-gcm.asc').mode, 'GCM');
    });

    test('hidden recipients are counted, not named', () {
      final info = _inspect('gnupg/hidden.gpg');
      expect(info.recipientKeyIds, isEmpty);
      expect(info.hiddenRecipients, 1);
    });

    test('messages with a passphrase say so, and their cipher', () {
      for (final (fixture, cipher) in [
        ('gnupg/sym-default.gpg', 'AES-256'),
        ('gnupg/sym-aes128.gpg', 'AES-128'),
        ('gnupg/sym-s2k0.gpg', 'AES-256'),
        ('kemlock/passphrase.asc', 'AES-256'),
        ('kemlock/passphrase.signed.gpg', 'AES-256'),
      ]) {
        final info = _inspect(fixture);
        expect(
          (info.kind, info.passphrase, info.recipientKeyIds.length, info.cipher),
          (PgpMessageKind.encrypted, true, 0, cipher),
          reason: fixture,
        );
        expect(info.unsupported, isNull);
      }
      final ocb = _inspect('gnupg/sym-ocb.gpg');
      expect((ocb.passphrase, ocb.cipher, ocb.mode), (true, 'AES-256', 'OCB'));
      // For a key and a passphrase both
      final both = _inspect('gnupg/sym-and-key.gpg');
      expect(both.passphrase, isTrue);
      expect(both.recipientKeyIds, [edSubkey]);
    });

    test('what cannot be read is named before any secret is asked for', () {
      expect(_inspect('gnupg/sym-cast5.gpg').unsupported, 'CAST5');
      expect(_inspect('gnupg/no-mdc.gpg').noIntegrity, isTrue);
      // An SKESK with Argon2, then encrypted data
      final argon2 = Uint8List.fromList([0xc3, 22, 4, 7, 4, ...List.filled(16, 1), 1, 4, 21, 0xd2, 3, 1, 2, 3]);
      expect(inspectMessage(PgpData.bytes(argon2)).unsupported, 'Argon2');
      // A chunk size no reader should hold
      final chunk = Uint8List.fromList([0xd2, 40, 2, 7, 2, 17, ...List.filled(36, 0)]);
      expect(inspectMessage(PgpData.bytes(chunk)).unsupported, 'AEAD chunks over 4 MiB');
      // To a key, CAST5 shows only once the session key is open
      expect(_inspect('gnupg/cast5.gpg').unsupported, isNull);
    });

    test('signed messages, clear-signed text and lone signatures', () {
      expect(_inspect('gnupg/inline-signed.gpg').kind, PgpMessageKind.signed);
      expect(_inspect('gnupg/inline-signed.asc').kind, PgpMessageKind.signed);
      expect(_inspect('gnupg/two-signers.gpg').kind, PgpMessageKind.signed);
      expect(_inspect('rfc9580/a7-inline-signed.asc').kind, PgpMessageKind.signed);
      expect(_inspect('gnupg/clearsigned.asc').kind, PgpMessageKind.cleartextSigned);
      expect(_inspect('kemlock/clearsigned.asc').kind, PgpMessageKind.cleartextSigned);
      expect(_inspect('gnupg/message.txt.ed25519.sig').kind, PgpMessageKind.detachedSignature);
      expect(_inspect('gnupg/message.txt.ed25519.asc').kind, PgpMessageKind.detachedSignature);
      expect(_inspect('kemlock/report.txt.rsa3072.sig').kind, PgpMessageKind.detachedSignature);
    });

    test('keys are told from messages', () {
      expect(inspectMessage(PgpData.bytes(Keys.edPublic)).kind, PgpMessageKind.publicKey);
      expect(inspectMessage(PgpData.bytes(Keys.ed)).kind, PgpMessageKind.secretKey);
      expect(_inspect('gnupg/rsa1024.public.asc').kind, PgpMessageKind.publicKey);
      expect(_inspect('gnupg/rsa1024.secret.asc').kind, PgpMessageKind.secretKey);
    });

    test('what is no message', () {
      expect(
        () => inspectMessage(PgpData.bytes(Uint8List.fromList(utf8.encode('see you on Monday')))),
        throwsProblem(PgpProblem.notAMessage),
      );
      expect(() => inspectMessage(PgpData.bytes(Uint8List(0))), throwsProblem(PgpProblem.notAMessage));
      expect(() => inspectMessage(PgpData.bytes(Uint8List.fromList([0xff, 0xfe, 1, 2, 3]))), throwsProblem(PgpProblem.notAMessage));
      final part = pgpFixtureText('gnupg/armored.asc').replaceAll('MESSAGE-----', 'MESSAGE, PART 2/3-----');
      expect(
        () => inspectMessage(PgpData.bytes(Uint8List.fromList(utf8.encode(part)))),
        throwsProblem(PgpProblem.unsupported, detail: 'multi-part armor'),
      );
    });

    test('a file is read by its path', () {
      final info = inspectMessage(PgpData.file(pgpFixturePath('gnupg/large.gpg')));
      expect(info.kind, PgpMessageKind.encrypted);
      expect(info.recipientKeyIds, [edSubkey]);
      expect(inspectMessage(PgpData.file(pgpFixturePath('gnupg/clearsigned.asc'))).kind, PgpMessageKind.cleartextSigned);
      expect(PgpData.file(pgpFixturePath('gnupg/report.txt')).length, 216000);
    });
  });

  group('readPgpPublicKey', () {
    test('armored and binary public keys', () async {
      for (final name in ['ed25519', 'rsa3072', 'ed25519-protected', 'rsa3072-protected']) {
        final binary = File('test/fixtures/keys/gnupg/$name.public.gpg').readAsBytesSync();
        final fromBinary = await readPgpPublicKey(binary);
        final fromArmor = await readPgpPublicKey(File('test/fixtures/keys/gnupg/$name.public.asc').readAsStringSync());
        expect(fromBinary.transferableKey, binary);
        expect(fromArmor.transferableKey, binary);
        expect(fromArmor.fingerprintHex, fromBinary.fingerprintHex);
        expect(fromBinary.info.isSecret, isFalse);
      }
      final ed = await readPgpPublicKey(Keys.edPublic);
      expect((ed.fingerprintHex, ed.userId), (Keys.edFingerprint, 'Fixture Ed25519 <ed25519@example.org>'));
    });

    test('a secret key pasted by mistake is reduced to its public part', () async {
      for (final (secret, public) in [
        (File('test/fixtures/keys/gnupg/ed25519.secret.asc').readAsStringSync(), Keys.edPublic),
        (File('test/fixtures/keys/gnupg/rsa3072-protected.secret.asc').readAsStringSync(), Keys.rsaProtectedPublic),
      ]) {
        final key = await readPgpPublicKey(secret);
        expect(key.transferableKey, public);
        expect(key.info.isSecret, isFalse);
      }
      expect((await readPgpPublicKey(Keys.kemlockRsa)).info.isSecret, isFalse);
    });

    test('a pasted key with a mail around it, and the version 6 sample', () async {
      final armored = File('test/fixtures/keys/gnupg/ed25519.public.asc').readAsStringSync();
      expect((await readPgpPublicKey('My key:\n\n$armored\nthanks\n')).fingerprintHex, Keys.edFingerprint);
      final v6 = await readPgpPublicKey(File('test/fixtures/keys/rfc9580/v6-public.asc').readAsStringSync());
      expect(v6.fingerprintHex, 'CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9');
      expect(v6.userId, '');
    });

    test('a key whose self-signatures fail is refused', () async {
      final broken = Uint8List.fromList(Keys.edPublic);
      broken[broken.length - 3] ^= 1;
      await expectLater(
        readPgpPublicKey(broken),
        throwsA(
          isA<PgpException>()
              .having((e) => e.problem, 'problem', PgpProblem.keyUnusable)
              .having((e) => e.reason, 'reason', PgpKeyTrouble.invalid)
              .having((e) => e.fingerprint, 'fingerprint', Keys.edFingerprint),
        ),
      );
    });

    test('a kind of key Kemlock cannot check is named', () async {
      await expectLater(
        readPgpPublicKey(pgpFixtureText('gnupg/brainpoolP256r1.public.asc')),
        throwsProblem(PgpProblem.unsupported, detail: 'brainpoolP256r1'),
      );
    });

    test('what is no key, and a damaged one', () async {
      await expectLater(readPgpPublicKey('hello'), throwsProblem(PgpProblem.notAMessage));
      await expectLater(readPgpPublicKey(''), throwsProblem(PgpProblem.notAMessage));
      await expectLater(readPgpPublicKey(pgpFixtureText('gnupg/armored.asc')), throwsProblem(PgpProblem.notAMessage));
      await expectLater(readPgpPublicKey(pgpFixture('gnupg/to-ed25519.seipd.gpg')), throwsProblem(PgpProblem.notAMessage));
      await expectLater(readPgpPublicKey(Keys.edPublic.sublist(0, 100)), throwsProblem(PgpProblem.damaged));
      final armored = File('test/fixtures/keys/gnupg/ed25519.public.asc').readAsStringSync();
      await expectLater(readPgpPublicKey(armored.substring(0, armored.length ~/ 2)), throwsProblem(PgpProblem.damaged));
      await expectLater(readPgpPublicKey(Uint8List(2 << 20)), throwsProblem(PgpProblem.tooLarge));
    });
  });

  group('pgpKeyTrouble', () {
    Uint8List expiry(String name) => binaryKey('keys/gnupg/expiry/$name.public.asc');

    test('says why a key may not be written to, or that it may', () async {
      expect(await pgpKeyTrouble(Keys.edPublic, fixtureNow), isNull);
      expect((await pgpKeyTrouble(expiry('expired'), fixtureNow))!.reason, PgpKeyTrouble.expired);
      expect((await pgpKeyTrouble(expiry('revoked'), fixtureNow))!.reason, PgpKeyTrouble.revoked);
      // A version 6 key is written to since add-post-quantum-pgp; one of an algorithm Kemlock does not use is named
      expect(await pgpKeyTrouble(Keys.v6Public, fixtureNow), isNull);
      expect((await pgpKeyTrouble(binaryKey('keys/rfc9980/a4-public.asc'), fixtureNow))!.detail, 'mld87');
      // To sign, a public key has no secret
      expect((await pgpKeyTrouble(Keys.edPublic, fixtureNow, toSign: true))!.problem, PgpProblem.noSecretHere);
      expect(await pgpKeyTrouble(Keys.ed, fixtureNow, toSign: true), isNull);
      expect((await pgpKeyTrouble(Uint8List.fromList([1, 2, 3]), fixtureNow))!.problem, PgpProblem.damaged);
    });
  });

  group('cleanFileName', () {
    test('keeps a base name, and nothing that could leave the directory', () {
      expect(cleanFileName('report.pdf'), 'report.pdf');
      expect(cleanFileName('../../etc/passwd'), 'passwd');
      expect(cleanFileName(r'C:\Users\ada\notes.txt'), 'notes.txt');
      expect(cleanFileName('a\u0000b\nc.txt'), 'abc.txt');
      expect(cleanFileName('what?*.txt'), 'what.txt');
      expect(cleanFileName('  spaced.txt '), 'spaced.txt');
    });

    test('falls back to the input name without its extension', () {
      expect(cleanFileName('', inputName: 'report.pdf.gpg'), 'report.pdf');
      expect(cleanFileName('', inputName: 'message.ASC'), 'message');
      expect(cleanFileName('', inputName: 'archive.pgp'), 'archive');
      expect(cleanFileName('..', inputName: 'x.gpg'), 'x');
      // GnuPG's name for data that came from a pipe
      expect(cleanFileName('_CONSOLE', inputName: 'large.gpg'), 'large');
      expect(cleanFileName(''), 'decrypted');
      expect(cleanFileName('/', inputName: '.gpg'), 'decrypted');
    });
  });
}
