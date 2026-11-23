@TestOn('vm')
library;

// Messages GnuPG made and RFC 9580's samples, decrypted: every form the
// reader takes, and each it refuses by name.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

Matcher throwsProblem(PgpProblem problem, {Object? detail, Object? fingerprint, Object? keyIds}) => throwsA(
  isA<PgpException>()
      .having((e) => e.problem, 'problem', problem)
      .having((e) => e.detail, 'detail', detail ?? anything)
      .having((e) => e.fingerprint, 'fingerprint', fingerprint ?? anything)
      .having((e) => e.keyIds, 'keyIds', keyIds ?? anything),
);

PgpSecretKey _key(Uint8List key, [String? passphrase]) => PgpSecretKey(key, passphrase: passphrase);

Future<PgpDecrypted> _decrypt(
  String fixture, {
  List<PgpSecretKey> keys = const [],
  String? passphrase,
  List<Uint8List> verifiers = const [],
  Uint8List? bytes,
  int maxInMemory = 8 << 20,
}) => decrypt(
  data: PgpData.bytes(bytes ?? pgpFixture(fixture)),
  keys: keys,
  passphrase: passphrase,
  verifiers: verifiers,
  maxInMemory: maxInMemory,
  now: fixtureNow,
);

void main() {
  final report = pgpFixture('gnupg/report.txt');

  group('to a key', () {
    final cases = <(String, Uint8List Function(), String, String, String?)>[
      ('gnupg/default-to-ed25519.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/to-ed25519.seipd.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/to-ed25519.ocb.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', 'OCB'),
      ('gnupg/to-rsa3072.seipd.gpg', () => Keys.rsa, Keys.rsaFingerprint, 'rsa3072', null),
      ('gnupg/to-rsa3072.ocb.gpg', () => Keys.rsa, Keys.rsaFingerprint, 'rsa3072', 'OCB'),
      ('gnupg/to-two.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/to-two.gpg', () => Keys.rsa, Keys.rsaFingerprint, 'rsa3072', null),
      ('gnupg/aes128.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/aes192.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/armored.asc', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/armored-headers.asc', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
      ('gnupg/to-rsa1024.gpg', () => Keys.rsa1024, 'E95EE09FEF5558A822254BE1072C81B8334FE703', 'rsa1024', null),
      ('gnupg/sym-and-key.gpg', () => Keys.ed, Keys.edFingerprint, 'cv25519', null),
    ];
    for (final (fixture, key, fingerprint, algorithm, mode) in cases) {
      test('$fixture opens with $algorithm', () async {
        final result = await _decrypt(fixture, keys: [_key(key())]);
        expect(result.bytes, messageTxt);
        expect(result.fileName, 'message.txt');
        expect(result.isText, isFalse);
        expect(result.encrypted, isTrue);
        expect(result.openedWithFingerprint, fingerprint);
        expect(result.openedWithAlgorithm, algorithm);
        expect(result.openedWithPassphrase, isFalse);
        expect(result.mode, mode);
        expect(result.cipher, switch (fixture) {
          'gnupg/aes128.gpg' => 'AES-128',
          'gnupg/aes192.gpg' => 'AES-192',
          _ => 'AES-256',
        });
        expect(result.signatures, isEmpty);
      });
    }

    test('the keys Kemlock generated open what GnuPG wrote to them', () async {
      for (final (fixture, key, algorithm) in [
        ('gnupg/to-kemlock-ed25519.gpg', Keys.kemlockEd, 'cv25519'),
        ('gnupg/to-kemlock-rsa4096.gpg', Keys.kemlockRsa, 'rsa4096'),
      ]) {
        final result = await _decrypt(fixture, keys: [_key(key)]);
        expect(result.bytes, messageTxt, reason: fixture);
        expect(result.openedWithAlgorithm, algorithm);
        expect(result.form, EncryptedForm.seipd1);
      }
    });

    test('the key is found among several', () async {
      final result = await _decrypt('gnupg/to-rsa3072.seipd.gpg', keys: [_key(Keys.ed), _key(Keys.rsa), _key(Keys.kemlockEd)]);
      expect(result.openedWithFingerprint, Keys.rsaFingerprint);
    });

    test('hidden recipients: each key is tried', () async {
      final result = await _decrypt('gnupg/hidden.gpg', keys: [_key(Keys.rsa), _key(Keys.kemlockEd), _key(Keys.ed)]);
      expect(result.bytes, messageTxt);
      expect(result.openedWithFingerprint, Keys.edFingerprint);
      await expectLater(_decrypt('gnupg/hidden.gpg', keys: [_key(Keys.rsa)]), throwsProblem(PgpProblem.noKeyOpensIt, keyIds: isEmpty));
    });

    test('a message for someone else names the key IDs', () async {
      await expectLater(
        _decrypt('gnupg/to-rsa3072.seipd.gpg', keys: [_key(Keys.ed)]),
        throwsProblem(PgpProblem.noKeyOpensIt, keyIds: ['B8A3CCC781F74F29']),
      );
      await expectLater(
        _decrypt('gnupg/to-two.gpg'),
        throwsProblem(PgpProblem.noKeyOpensIt, keyIds: ['841A40E3B199EA67', 'B8A3CCC781F74F29']),
      );
    });

    test('a protected key needs its passphrase, and says whose', () async {
      for (final (fixture, key, fingerprint) in [
        ('gnupg/to-protected-ed25519.gpg', Keys.edProtected, Keys.edProtectedFingerprint),
        ('gnupg/to-protected-rsa3072.gpg', Keys.rsaProtected, Keys.rsaProtectedFingerprint),
      ]) {
        await expectLater(_decrypt(fixture, keys: [_key(key)]), throwsProblem(PgpProblem.passphraseNeeded, fingerprint: fingerprint));
        await expectLater(
          _decrypt(fixture, keys: [_key(key, 'not it')]),
          throwsProblem(PgpProblem.wrongPassphrase, fingerprint: fingerprint),
        );
        final result = await _decrypt(fixture, keys: [_key(key, fixturePassphrase)]);
        expect(result.bytes, messageTxt);
        expect(result.openedWithFingerprint, fingerprint);
      }
    });

    test('a copy whose primary secret is a stub still decrypts with its subkey', () async {
      expect((await _decrypt('gnupg/to-ed25519.seipd.gpg', keys: [_key(Keys.stub)])).bytes, messageTxt);
    });

    test('a subkey beside a signing subkey', () async {
      final result = await _decrypt('gnupg/to-signing-subkey.gpg', keys: [_key(Keys.signingSubkey)]);
      expect(result.bytes, messageTxt);
      expect(result.openedWithAlgorithm, 'cv25519');
    });
  });

  // openspec: add-post-quantum-pgp, tasks 6.1 and 6.2
  group('to post-quantum keys', () {
    for (final (section, message, form) in [
      ('a1', 'a1-message', EncryptedForm.seipd2),
      ('a2', 'a2-message-seipd1', EncryptedForm.seipd1),
      ('a2', 'a2-message-seipd2', EncryptedForm.seipd2),
      ('a3', 'a3-message', EncryptedForm.seipd2),
    ]) {
      test("RFC 9980's $message decrypts to its text", () async {
        final key = binaryKey('keys/rfc9980/$section-secret.asc');
        final result = await _decrypt('', bytes: binaryKey('keys/rfc9980/$message.asc'), keys: [_key(key)]);
        expect(utf8.decode(result.bytes!), 'Testing\n');
        expect(result.form, form);
        expect(result.cipher, 'AES-256');
        expect(result.openedWithAlgorithm, 'mlk768');
      });
    }

    final plain = File('test/fixtures/keys/gnupg/pqc/message.txt').readAsBytesSync();
    for (final (file, key, form) in [
      ('ky768-cv25519.message.gpg', 'ky768-cv25519', EncryptedForm.ocbPacket),
      ('ky768-cv25519.force-ocb.gpg', 'ky768-cv25519', EncryptedForm.ocbPacket),
      ('ky768-cv25519.seipd1.gpg', 'ky768-cv25519', EncryptedForm.seipd1),
      ('ky768-cv25519-protected.message.gpg', 'ky768-cv25519-protected', EncryptedForm.ocbPacket),
      ('pqc.message.gpg', 'pqc', EncryptedForm.ocbPacket),
      ('pqc-protected.message.gpg', 'pqc-protected', EncryptedForm.ocbPacket),
      ('ky1024-bp384.message.gpg', 'ky1024-bp384', EncryptedForm.ocbPacket),
      ('ky1024-bp384-protected.message.gpg', 'ky1024-bp384-protected', EncryptedForm.ocbPacket),
    ]) {
      test("GnuPG's $file gives its plain file", () async {
        final secret = binaryKey('keys/gnupg/pqc/$key.secret.asc');
        final result = await _decrypt(
          '',
          bytes: File('test/fixtures/keys/gnupg/pqc/$file').readAsBytesSync(),
          keys: [_key(secret, key.endsWith('-protected') ? fixturePassphrase : null)],
        );
        expect(result.bytes, plain);
        expect(result.form, form);
        expect(result.openedWithAlgorithm, startsWith('ky'));
      });
    }

    test('a protected Kyber key asks for its passphrase, and refuses a wrong one', () async {
      final bytes = File('test/fixtures/keys/gnupg/pqc/ky768-cv25519-protected.message.gpg').readAsBytesSync();
      final secret = binaryKey('keys/gnupg/pqc/ky768-cv25519-protected.secret.asc');
      await expectLater(_decrypt('', bytes: bytes, keys: [_key(secret)]), throwsProblem(PgpProblem.passphraseNeeded));
      await expectLater(_decrypt('', bytes: bytes, keys: [_key(secret, 'wrong')]), throwsProblem(PgpProblem.wrongPassphrase));
    });

    test('a file for another key says no key opens it', () async {
      final bytes = File('test/fixtures/keys/gnupg/pqc/ky768-cv25519.message.gpg').readAsBytesSync();
      await expectLater(
        _decrypt('', bytes: bytes, keys: [_key(binaryKey('keys/gnupg/pqc/ky1024-bp384.secret.asc'))]),
        throwsProblem(PgpProblem.noKeyOpensIt),
      );
    });
  });

  group('RFC 9580', () {
    test('A.8: X25519 and OCB, with the sample version 6 key', () async {
      final result = await _decrypt('rfc9580/a8-x25519-ocb.asc', keys: [_key(Keys.v6)]);
      expect(utf8.decode(result.bytes!), 'Hello, world!');
      expect(result.fileName, '');
      expect(result.form, EncryptedForm.seipd2);
      expect((result.cipher, result.mode), ('AES-128', 'OCB'));
      expect(result.openedWithFingerprint, 'CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9');
      expect(result.openedWithAlgorithm, 'cv25519');
    });

    for (final (fixture, mode) in [
      ('rfc9580/a9-skesk6-eax.asc', 'EAX'),
      ('rfc9580/a10-skesk6-ocb.asc', 'OCB'),
      ('rfc9580/a11-skesk6-gcm.asc', 'GCM'),
    ]) {
      test('$fixture: the passphrase "password"', () async {
        final result = await _decrypt(fixture, passphrase: 'password');
        expect(utf8.decode(result.bytes!), 'Hello, world!');
        expect(result.openedWithPassphrase, isTrue);
        expect(result.openedWithFingerprint, isNull);
        expect((result.cipher, result.mode), ('AES-128', mode));
        await expectLater(_decrypt(fixture, passphrase: 'Password'), throwsProblem(PgpProblem.wrongPassphrase));
        await expectLater(_decrypt(fixture), throwsProblem(PgpProblem.passphraseNeeded, fingerprint: isNull));
      });
    }
  });

  group('with a passphrase', () {
    for (final fixture in [
      'sym-default',
      'sym-ocb',
      'sym-s2k0',
      'sym-s2k1',
      'sym-s2k3-SHA1',
      'sym-s2k3-SHA224',
      'sym-s2k3-SHA256',
      'sym-s2k3-SHA384',
      'sym-s2k3-SHA512',
      'sym-aes128',
    ]) {
      test('gnupg/$fixture.gpg', () async {
        final result = await _decrypt('gnupg/$fixture.gpg', passphrase: fixturePassphrase);
        expect(result.bytes, messageTxt);
        expect(result.fileName, 'message.txt');
        expect(result.openedWithPassphrase, isTrue);
        expect(result.cipher, fixture == 'sym-aes128' ? 'AES-128' : 'AES-256');
        expect(result.mode, fixture == 'sym-ocb' ? 'OCB' : null);
        await expectLater(_decrypt('gnupg/$fixture.gpg', passphrase: 'fixture passphrasE'), throwsProblem(PgpProblem.wrongPassphrase));
        await expectLater(_decrypt('gnupg/$fixture.gpg'), throwsProblem(PgpProblem.passphraseNeeded, fingerprint: isNull));
      });
    }

    test('a message for a key and a passphrase: the key first, then the passphrase', () async {
      final withKey = await _decrypt('gnupg/sym-and-key.gpg', keys: [_key(Keys.ed)]);
      expect(withKey.openedWithPassphrase, isFalse);
      await expectLater(
        _decrypt('gnupg/sym-and-key.gpg', keys: [_key(Keys.rsa)]),
        throwsProblem(PgpProblem.passphraseNeeded, fingerprint: isNull),
      );
      final withPassphrase = await _decrypt('gnupg/sym-and-key.gpg', keys: [_key(Keys.rsa)], passphrase: fixturePassphrase);
      expect(withPassphrase.bytes, messageTxt);
      expect(withPassphrase.openedWithPassphrase, isTrue);
      await expectLater(_decrypt('gnupg/sym-and-key.gpg', passphrase: 'no'), throwsProblem(PgpProblem.wrongPassphrase));
    });
  });

  group('compressed, large and in pieces', () {
    for (final fixture in ['zip', 'zlib', 'bzip2', 'uncompressed']) {
      test('gnupg/$fixture.gpg', () async {
        final result = await _decrypt('gnupg/$fixture.gpg', keys: [_key(Keys.ed)]);
        expect(result.bytes, report);
        expect(result.fileName, 'report.txt');
      });
    }

    test('a file signed and encrypted with BZip2 in the OCB packet', () async {
      final result = await _decrypt('gnupg/signed-bzip2.ocb.gpg', keys: [_key(Keys.ed)], verifiers: [Keys.rsaPublic]);
      expect(result.bytes, report);
      expect(result.signatures.single.verdict, SignatureVerdict.good);
      expect(result.signatures.single.signerFingerprint, Keys.rsaFingerprint);
    });

    test('5 MB in partial lengths, to memory and to a file', () async {
      final sample = sampleBytes(5242880);
      final result = await _decrypt('gnupg/large.gpg', keys: [_key(Keys.ed)]);
      expect(result.bytes, sample);
      expect(result.fileName, '');

      final directory = Directory.systemTemp.createTempSync('pgp-decrypt-test');
      addTearDown(() => directory.deleteSync(recursive: true));
      var read = 0;
      final onDisk = await decrypt(
        data: PgpData.file(pgpFixturePath('gnupg/large.gpg')),
        keys: [_key(Keys.ed)],
        outputDirectory: directory.path,
        inputName: 'large.gpg',
        now: fixtureNow,
        onRead: (n) => read = n,
      );
      expect(onDisk.bytes, isNull);
      expect(onDisk.path, '${directory.path}${Platform.pathSeparator}large');
      expect(onDisk.fileName, 'large');
      expect(onDisk.length, sample.length);
      expect(File(onDisk.path!).readAsBytesSync(), sample);
      expect(read, pgpFixture('gnupg/large.gpg').length);
      expect(directory.listSync(), hasLength(1));
    });

    test('a megabyte in sixteen OCB chunks', () async {
      final result = await _decrypt('gnupg/chunks.ocb.gpg', keys: [_key(Keys.ed)]);
      expect(result.bytes, sampleBytes(1048576));
    });

    test('more than fits in memory with nowhere to put it is too large', () async {
      await expectLater(_decrypt('gnupg/zip.gpg', keys: [_key(Keys.ed)], maxInMemory: 1000), throwsProblem(PgpProblem.tooLarge));
    });

    test('a file cut short leaves no partial output', () async {
      final directory = Directory.systemTemp.createTempSync('pgp-decrypt-test');
      addTearDown(() => directory.deleteSync(recursive: true));
      final whole = pgpFixture('gnupg/large.gpg');
      final cut = File('${directory.path}/cut.gpg')..writeAsBytesSync(whole.sublist(0, whole.length - 300000));
      final out = Directory('${directory.path}/out')..createSync();
      await expectLater(
        decrypt(data: PgpData.file(cut.path), keys: [_key(Keys.ed)], outputDirectory: out.path, now: fixtureNow),
        throwsProblem(PgpProblem.damaged),
      );
      expect(out.listSync(), isEmpty);
    });
  });

  group('signatures inside', () {
    test('signed and encrypted: good, with the signer and GnuPG\'s time', () async {
      for (final (fixture, key, verifier, fingerprint) in [
        ('signed-encrypted.gpg', Keys.ed, Keys.edPublic, Keys.edFingerprint),
        ('signed-encrypted-rsa.gpg', Keys.rsa, Keys.rsaPublic, Keys.rsaFingerprint),
      ]) {
        final result = await _decrypt('gnupg/$fixture', keys: [_key(key)], verifiers: [verifier]);
        expect(result.bytes, messageTxt);
        final signature = result.signatures.single;
        expect(signature.verdict, SignatureVerdict.good, reason: fixture);
        expect(signature.signerFingerprint, fingerprint);
        expect(signature.made, gnupgSignatures(fixture).single.made);
        expect((signature.keyExpired, signature.keyRevoked), (false, false));
      }
    });

    test('a secret key verifies as well as its public key', () async {
      final result = await _decrypt('gnupg/signed-encrypted.gpg', keys: [_key(Keys.ed)], verifiers: [Keys.ed]);
      expect(result.signatures.single.verdict, SignatureVerdict.good);
    });

    test('the signer is unknown without its key', () async {
      final result = await _decrypt('gnupg/signed-encrypted.gpg', keys: [_key(Keys.ed)], verifiers: [Keys.rsaPublic]);
      final signature = result.signatures.single;
      expect(signature.verdict, SignatureVerdict.unknownSigner);
      expect(signature.issuer, Keys.edFingerprint);
      expect(signature.signerFingerprint, isNull);
    });

    test('two signers give two results', () async {
      final result = await _decrypt('gnupg/two-signers-encrypted.gpg', keys: [_key(Keys.ed)], verifiers: [Keys.edPublic, Keys.rsaPublic]);
      expect(result.signatures.map((s) => s.verdict), [SignatureVerdict.good, SignatureVerdict.good]);
      expect(result.signatures.map((s) => s.signerFingerprint).toSet(), {Keys.edFingerprint, Keys.rsaFingerprint});

      final oneKnown = await _decrypt('gnupg/two-signers-encrypted.gpg', keys: [_key(Keys.ed)], verifiers: [Keys.rsaPublic]);
      expect(oneKnown.signatures.map((s) => s.verdict).toSet(), {SignatureVerdict.good, SignatureVerdict.unknownSigner});
    });

    test('a signed message that is not encrypted is read too', () async {
      for (final fixture in ['gnupg/inline-signed.gpg', 'gnupg/inline-signed.asc']) {
        final result = await _decrypt(fixture, verifiers: [Keys.edPublic]);
        expect(result.bytes, messageTxt);
        expect(result.encrypted, isFalse);
        expect(result.signatures.single.verdict, SignatureVerdict.good);
      }
      final two = await _decrypt('gnupg/two-signers.gpg', verifiers: [Keys.edPublic, Keys.rsaPublic]);
      expect(two.signatures.map((s) => s.verdict), [SignatureVerdict.good, SignatureVerdict.good]);
    });

    test('A.7: a version 6 one-pass signature', () async {
      final result = await _decrypt('rfc9580/a7-inline-signed.asc', verifiers: [Keys.v6Public]);
      expect(utf8.decode(result.bytes!), 'What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n');
      expect(result.isText, isTrue);
      final signature = result.signatures.single;
      expect(signature.verdict, SignatureVerdict.good);
      expect(signature.made, DateTime.utc(2022, 12, 13, 16, 8, 3));
    });
  });

  group('one changed byte', () {
    for (final (fixture, keys, passphrase, problem) in [
      ('gnupg/to-ed25519.seipd.gpg', true, null, PgpProblem.damaged),
      ('gnupg/to-ed25519.ocb.gpg', true, null, PgpProblem.damaged),
      ('gnupg/to-rsa3072.seipd.gpg', true, null, PgpProblem.damaged),
      ('gnupg/sym-ocb.gpg', false, fixturePassphrase, PgpProblem.damaged),
      // Nothing but the data's own check proves this passphrase, so a
      // failed check is "wrong passphrase, or damaged"
      ('gnupg/sym-default.gpg', false, fixturePassphrase, PgpProblem.wrongPassphrase),
    ]) {
      test('$fixture: damaged at five places, and nothing comes out', () async {
        final whole = pgpFixture(fixture);
        // Inside the encrypted data, which is the last packet
        for (final back in [1, 12, 30, 60, 100]) {
          final changed = Uint8List.fromList(whole)..[whole.length - back] ^= 0x10;
          await expectLater(
            _decrypt(fixture, bytes: changed, keys: keys ? [_key(Keys.ed), _key(Keys.rsa)] : const [], passphrase: passphrase),
            throwsProblem(problem),
            reason: '$back bytes from the end',
          );
        }
      });
    }

    test('in the session key packet, too', () async {
      final whole = pgpFixture('gnupg/to-ed25519.seipd.gpg');
      // The wrapped key of the PKESK
      final changed = Uint8List.fromList(whole)..[60] ^= 1;
      await expectLater(_decrypt('', bytes: changed, keys: [_key(Keys.ed)]), throwsProblem(PgpProblem.damaged));
    });

    test('A.8 in the RFC\'s authenticated form', () async {
      final binary = PgpReader.bytes(pgpFixture('rfc9580/a8-x25519-ocb.asc'));
      expect(binary.atEnd, isFalse);
      final armored = pgpFixtureText('rfc9580/a8-x25519-ocb.asc');
      final lines = armored.split('\n');
      // A character of the last full line of base64
      final at = lines[5].length ~/ 2;
      lines[5] = '${lines[5].substring(0, at)}${lines[5][at] == 'A' ? 'B' : 'A'}${lines[5].substring(at + 1)}';
      await expectLater(
        _decrypt('', bytes: Uint8List.fromList(utf8.encode(lines.join('\n'))), keys: [_key(Keys.v6)]),
        throwsProblem(PgpProblem.damaged),
      );
    });
  });

  group('refused by name', () {
    test('CAST5', () async {
      // The cipher is the message's, not the key's: no key is named for it
      await expectLater(
        _decrypt('gnupg/cast5.gpg', keys: [_key(Keys.ed)]),
        throwsProblem(PgpProblem.unsupported, detail: 'CAST5', fingerprint: isNull),
      );
      await expectLater(
        _decrypt('gnupg/sym-cast5.gpg', passphrase: fixturePassphrase),
        throwsProblem(PgpProblem.unsupported, detail: 'CAST5'),
      );
      // Named before any passphrase is asked for
      await expectLater(_decrypt('gnupg/sym-cast5.gpg'), throwsProblem(PgpProblem.unsupported, detail: 'CAST5'));
    });

    test('the old form with no integrity protection', () async {
      await expectLater(_decrypt('gnupg/no-mdc.gpg', passphrase: fixturePassphrase), throwsProblem(PgpProblem.noIntegrity));
      await expectLater(_decrypt('gnupg/no-mdc.gpg'), throwsProblem(PgpProblem.noIntegrity));
    });

    test('a key on NIST P-256', () async {
      await expectLater(
        _decrypt('gnupg/to-nistp256.gpg', keys: [_key(Keys.nistp256)]),
        throwsProblem(PgpProblem.unsupported, detail: 'nistp256', fingerprint: 'FF0070B8D0A1B78F13F3D72A76A2714FAD13F199'),
      );
    });

    test('what is no message', () async {
      await expectLater(
        _decrypt('', bytes: Uint8List.fromList(utf8.encode('Dear Ada,\nsee you on Monday.\n'))),
        throwsProblem(PgpProblem.notAMessage),
      );
      await expectLater(_decrypt('', bytes: Uint8List(0)), throwsProblem(PgpProblem.notAMessage));
      await expectLater(_decrypt('', bytes: Keys.edPublic), throwsProblem(PgpProblem.notAMessage));
      await expectLater(_decrypt('gnupg/message.txt.ed25519.asc'), throwsProblem(PgpProblem.notAMessage));
      await expectLater(_decrypt('gnupg/message.txt.ed25519.sig'), throwsProblem(PgpProblem.notAMessage));
    });
  });

  group('decompression is bounded', () {
    /// An unencrypted message: literal data of [length] zeros, deflated.
    Uint8List zeros(int length) {
      final literal = Uint8List(6 + 6 + length)
        ..setAll(0, [
          0xc0 | 11,
          0xff,
          ...[(length + 6) >> 24, (length + 6) >> 16, (length + 6) >> 8, length + 6].map((b) => b & 0xff),
        ]);
      literal[6] = 0x62;
      final deflated = ZLibCodec(raw: true).encode(literal);
      return Uint8List.fromList([
        0xc0 | 8,
        0xff,
        ...[deflated.length + 1 >> 24, deflated.length + 1 >> 16, deflated.length + 1 >> 8, deflated.length + 1].map((b) => b & 0xff),
        1,
        ...deflated,
      ]);
    }

    test('an ordinary compressed message opens', () async {
      final result = await _decrypt('', bytes: zeros(3 << 20));
      expect(result.length, 3 << 20);
      expect(result.bytes!.every((b) => b == 0), isTrue);
    });

    test('one that unpacks past 64 MB and a hundred times its size stops there', () async {
      final bomb = zeros(80 << 20);
      expect(bomb.length, lessThan(100000));
      final directory = Directory.systemTemp.createTempSync('pgp-bomb-test');
      addTearDown(() => directory.deleteSync(recursive: true));
      await expectLater(
        decrypt(data: PgpData.bytes(bomb), outputDirectory: directory.path, now: fixtureNow),
        throwsProblem(PgpProblem.tooLarge),
      );
      // The partial output is gone
      expect(directory.listSync(), isEmpty);
    });

    test('a corrupt stream is damaged', () async {
      final message = zeros(100000);
      final corrupt = Uint8List.fromList(message)..fillRange(20, 40, 0xff);
      await expectLater(_decrypt('', bytes: corrupt), throwsProblem(PgpProblem.damaged));
      final cut = Uint8List.fromList([...message.sublist(0, 1), 60, ...message.sublist(6, 66)]);
      await expectLater(_decrypt('', bytes: cut), throwsProblem(PgpProblem.damaged));
    });
  });
}
