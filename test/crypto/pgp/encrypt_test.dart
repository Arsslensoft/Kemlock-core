@TestOn('vm')
library;

// What Kemlock writes: pinned byte for byte with fixed randomness, read
// back by its own reader, and refused for keys that may not be used.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/message.dart' show writeEncryptedMessage;
import 'package:kemlock_core/crypto/keys/openpgp/modes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/session_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'decrypt_test.dart' show throwsProblem;
import 'fixtures.dart';
import 'samples.dart';

Uint8List _utf8(String text) => Uint8List.fromList(utf8.encode(text));

/// The tag, and whether the body came in partial lengths, of each packet.
List<(int, bool)> _packets(Uint8List data) {
  final reader = PacketReader(PgpReader.bytes(data));
  return [for (var p = reader.next(); p != null; p = reader.next()) (p.tag, p.partial)];
}

void main() {
  late List<Sample> samples;
  setUpAll(() async => samples = await kemlockSamples());

  group('with fixed randomness', () {
    test('every sample is the file written once into the fixtures', () async {
      final manifest = pgpFixtureText('kemlock/manifest.txt').trim().split('\n');
      expect(manifest, hasLength(samples.length));
      for (final (i, sample) in samples.indexed) {
        expect(await sample.make(), pgpFixture('kemlock/${sample.file}'), reason: sample.file);
        expect(manifest[i].split(' ').first, sample.file);
      }
    });

    test('Kemlock\'s own reader opens each with each recipient\'s key', () async {
      final verifiers = [Keys.edPublic, Keys.rsaPublic, Keys.kemlockEd, Keys.kemlockRsa];
      for (final sample in samples.where((s) => s.kind == SampleKind.toKeys || s.kind == SampleKind.toPassphrase)) {
        final plain = pgpFixture('gnupg/${sample.plain}');
        final openers = sample.kind == SampleKind.toPassphrase ? <Uint8List Function()?>[null] : sample.recipients;
        for (final recipient in openers) {
          final result = await decrypt(
            data: PgpData.bytes(pgpFixture('kemlock/${sample.file}')),
            keys: [if (recipient != null) PgpSecretKey(recipient())],
            passphrase: recipient == null ? fixturePassphrase : null,
            verifiers: verifiers,
            now: sampleTime,
          );
          expect(result.bytes, plain, reason: sample.file);
          expect((result.form, result.cipher, result.mode), (EncryptedForm.seipd1, 'AES-256', null));
          expect(result.isText, sample.armored);
          expect(result.fileName, sample.armored ? '' : sample.plain);
          expect(result.openedWithPassphrase, recipient == null);
          expect(result.signatures.map((s) => s.verdict), [for (final _ in sample.signers) SignatureVerdict.good]);
          expect(result.signatures.map((s) => s.signerFingerprint), sample.signers);
          for (final signature in result.signatures) {
            expect(signature.made, sampleTime);
          }
        }
        // Nobody else opens it
        if (sample.kind == SampleKind.toKeys) {
          await expectLater(
            decrypt(
              data: PgpData.bytes(pgpFixture('kemlock/${sample.file}')),
              keys: [PgpSecretKey(Keys.edProtected, passphrase: fixturePassphrase)],
            ),
            throwsProblem(PgpProblem.noKeyOpensIt),
          );
        }
      }
    });

    test('the signatures among them verify', () async {
      final verifiers = [Keys.edPublic, Keys.rsaPublic, Keys.kemlockEd, Keys.kemlockRsa];
      for (final sample in samples.where((s) => s.kind == SampleKind.clearSigned || s.kind == SampleKind.detached)) {
        final verified = await verify(
          signed: PgpData.bytes(pgpFixture('kemlock/${sample.file}')),
          data: sample.kind == SampleKind.detached ? PgpData.bytes(pgpFixture('gnupg/${sample.plain}')) : null,
          verifiers: verifiers,
          now: sampleTime,
        );
        expect(verified.signatures.single.verdict, SignatureVerdict.good, reason: sample.file);
        expect(verified.signatures.single.signerFingerprint, sample.signers.single);
      }
    });
  });

  group('the one written form', () {
    test('to people: a PKESK version 3 each, then SEIPD version 1', () {
      final binary = readArmorBlock(pgpFixture('kemlock/to-two.signed.asc'), type: pgpMessageBlock);
      // A typed message has definite lengths throughout
      expect(_packets(binary), [(1, false), (1, false), (18, false)]);
      final reader = PacketReader(PgpReader.bytes(binary));
      final first = parsePkesk(reader.next()!.body.rest(max: 1000));
      final second = parsePkesk(reader.next()!.body.rest(max: 1000));
      expect((first.version, first.algorithm, first.keyIdHex), (3, 18, '841A40E3B199EA67'));
      expect((second.version, second.algorithm, second.keyIdHex), (3, 1, 'B8A3CCC781F74F29'));
      expect(reader.next()!.body.byte(), 1);
    });

    test('a file: binary, in partial lengths', () {
      final file = pgpFixture('kemlock/report.txt.gpg');
      expect(_packets(file), [(1, false), (1, false), (18, true)]);
      // New-format headers; 64 KiB pieces
      expect(file[0], 0xc1);
      final seipd = file.indexOf(0xd2, 96 + 398);
      expect(file[seipd + 1], 0xf0);
    });

    test('with a passphrase: one SKESK version 4 with no key in it', () {
      final binary = readArmorBlock(pgpFixture('kemlock/passphrase.asc'));
      expect(_packets(binary), [(3, false), (18, false)]);
      final skesk = parseSkesk(PacketReader(PgpReader.bytes(binary)).next()!.body.rest(max: 100));
      // AES-256, Iterated and Salted S2K over SHA-256, the count key export uses
      expect((skesk.version, skesk.cipher, skesk.s2k.type, skesk.s2k.hashAlgorithm, skesk.s2k.codedCount), (4, 9, 3, 8, 0xf0));
      expect(skesk.encrypted, isNull);
      expect(skesk.s2k.salt, fixedBytes('passphrase salt', 8));
    });

    test('text is armored with the CRC line GnuPG writes', () {
      final text = pgpFixtureText('kemlock/to-ed25519.asc');
      expect(text, startsWith('-----BEGIN PGP MESSAGE-----\n\n'));
      expect(text, endsWith('-----END PGP MESSAGE-----\n'));
      final lines = text.trimRight().split('\n');
      expect(lines[lines.length - 2], matches(r'^=[A-Za-z0-9+/]{4}$'));
      expect(lines.sublist(2, lines.length - 3).every((l) => l.length == 64), isTrue);
    });

    test('inside: a one-pass signature, literal data with date zero, the signature', () {
      final file = pgpFixture('kemlock/report.txt.gpg');
      final outer = PacketReader(PgpReader.bytes(file))
        ..next()
        ..next();
      final body = outer.next()!.body;
      expect(body.byte(), 1);
      // The session key is the fixed one; the reader checks prefix and MDC
      final inner = PacketReader(PgpReader(Seipd1Reader(fixedBytes('report.txt session key', 32), body)));

      final onePass = inner.next()!;
      expect(onePass.tag, 4);
      final announced = onePass.body.rest(max: 100);
      // Version 3, binary, SHA-512, EdDSA, the signer's key ID, not nested
      expect(announced.sublist(0, 4), [3, 0x00, 10, 22]);
      expect(announced.last, 1);

      final literal = inner.next()!;
      expect((literal.tag, literal.partial), (11, true));
      expect(literal.body.byte(), 0x62);
      expect(utf8.decode(literal.body.bytes(literal.body.byte())), 'report.txt');
      expect(literal.body.bytes(4), [0, 0, 0, 0]);
      expect(literal.body.rest(max: 1 << 20), pgpFixture('gnupg/report.txt'));

      final signature = inner.next()!;
      expect(signature.tag, 2);
      final parsed = parseSignature(signature.body.rest(max: 1000));
      expect((parsed.version, parsed.type, parsed.hashAlgorithm), (4, 0x00, 10));
      expect(parsed.issuerKeyId, announced.sublist(4, 12));
      // Nothing after it but the MDC, which the reader has taken
      expect(inner.next(), isNull);
    });
  });

  group('with real randomness', () {
    final text = _utf8('The same words, twice.\n');

    test('two runs differ, and both open', () async {
      for (final passphrase in [null, 'correct horse']) {
        Future<Uint8List> run() async => (await encrypt(
          data: PgpData.bytes(text),
          recipients: passphrase == null ? [Keys.edPublic, Keys.rsaPublic] : const [],
          passphrase: passphrase,
          text: true,
          now: sampleTime,
        ))!;
        final first = await run();
        final second = await run();
        expect(first, isNot(second));
        for (final message in [first, second]) {
          final result = await decrypt(
            data: PgpData.bytes(message),
            keys: [PgpSecretKey(Keys.rsa)],
            passphrase: passphrase,
            now: sampleTime,
          );
          expect(result.bytes, text);
          expect(result.isText, isTrue);
        }
      }
    });

    test('a file of 3 MB goes through paths, with progress, and comes back', () async {
      final directory = Directory.systemTemp.createTempSync('pgp-encrypt-test');
      addTearDown(() => directory.deleteSync(recursive: true));
      final sample = sampleBytes(3 << 20);
      final input = File('${directory.path}/holiday.jpg')..writeAsBytesSync(sample);
      final output = '${directory.path}/holiday.jpg.gpg';
      final progress = <int>[];
      final returned = await encrypt(
        data: PgpData.file(input.path),
        recipients: [Keys.edPublic],
        signer: PgpSecretKey(Keys.rsa),
        text: false,
        fileName: 'holiday.jpg',
        outputPath: output,
        now: sampleTime,
        onRead: progress.add,
      );
      expect(returned, isNull);
      expect(progress.last, sample.length);
      expect(progress.length, 48);
      expect(input.readAsBytesSync(), sample, reason: 'the file itself is not changed');
      final written = File(output).readAsBytesSync();
      expect(_packets(written), [(1, false), (18, true)]);

      final out = Directory('${directory.path}/out')..createSync();
      final result = await decrypt(
        data: PgpData.file(output),
        keys: [PgpSecretKey(Keys.ed)],
        verifiers: [Keys.rsaPublic],
        outputDirectory: out.path,
        inputName: 'holiday.jpg.gpg',
        now: sampleTime,
      );
      expect(result.path, '${out.path}${Platform.pathSeparator}holiday.jpg');
      expect(File(result.path!).readAsBytesSync(), sample);
      expect(result.signatures.single.verdict, SignatureVerdict.good);
    });
  });

  // openspec: add-post-quantum-pgp, task 6.1
  group('the version 2 form', () {
    final recipient = readPackets(binaryKey('keys/kemlock/pgp-pq-standard.public.asc'))
        .where((p) => p.tag == PgpTag.publicSubkey)
        .map(parseKeyPacket)
        .single;
    final key = binaryKey('keys/kemlock/pgp-pq-standard.unprotected.asc');
    final random = MessageRandom(
      sessionKey: Uint8List.fromList(List.generate(32, (i) => i * 3)),
      prefix: Uint8List(16),
      salt: Uint8List(8),
      perRecipient: [Uint8List.fromList(List.generate(64, (i) => 200 - i))],
      aeadSalt: Uint8List.fromList(List.generate(32, (i) => 7 * i)),
    );
    final data = Uint8List.fromList(List.generate(150000, (i) => (i * 31) & 0xff));

    Future<Uint8List> write({bool definite = true}) async {
      final out = BytesSink();
      await writeEncryptedMessage(
        data: BytesSource(data),
        out: out,
        recipients: [recipient],
        format: 0x62,
        definite: definite,
        random: random,
        time: fixtureNow,
        aead: true,
      );
      return out.takeBytes();
    }

    test('written with fixed randomness, PKESK 6 and SEIPD 2 in chunks, it reads back', () async {
      final message = await write();
      expect(await write(), message);
      expect(_packets(message), [(PgpTag.pkesk, false), (PgpTag.seipd, false)]);
      for (final bytes in [message, await write(definite: false)]) {
        final result = await decrypt(data: PgpData.bytes(bytes), keys: [PgpSecretKey(key)], now: fixtureNow, maxInMemory: 1 << 20);
        expect(result.bytes, data);
        expect((result.form, result.cipher, result.mode), (EncryptedForm.seipd2, 'AES-256', 'OCB'));
        expect(result.openedWithAlgorithm, 'mlk768');
      }
    });

    /// [message] with its SEIPD packet's body changed by [change].
    Uint8List changed(Uint8List message, Uint8List Function(Uint8List body) change) {
      final reader = PacketReader(PgpReader.bytes(message));
      final pkesk = reader.next()!;
      final pkeskBody = pkesk.body.rest(max: message.length);
      final seipd = reader.next()!.body.rest(max: message.length);
      return Uint8List.fromList([...writePacket(PgpTag.pkesk, pkeskBody), ...writePacket(PgpTag.seipd, change(Uint8List.fromList(seipd)))]);
    }

    test('a changed chunk, a dropped last chunk and a changed final tag show nothing', () async {
      final message = await write();
      Future<void> refused(Uint8List bytes) => expectLater(
        decrypt(data: PgpData.bytes(bytes), keys: [PgpSecretKey(key)], now: fixtureNow, maxInMemory: 1 << 20),
        throwsProblem(PgpProblem.damaged),
      );
      // 36 bytes of head, then chunks of 65536 and their 16-byte tags
      await refused(changed(message, (b) => b..[36 + 100] ^= 1));
      const sealedChunk = 65536 + 16;
      final lastChunkAt = 36 + 2 * sealedChunk;
      await refused(changed(message, (b) => Uint8List.fromList([...b.sublist(0, lastChunkAt), ...b.sublist(b.length - 16)])));
      await refused(changed(message, (b) => b..[b.length - 1] ^= 1));
    });
  });

  group('refused', () {
    final text = _utf8('not sent');
    Uint8List expiry(String name) => binaryKey('keys/gnupg/expiry/$name.public.asc');

    Future<Uint8List?> to(List<Uint8List> recipients, {String? outputPath}) =>
        encrypt(data: PgpData.bytes(text), recipients: recipients, text: outputPath == null, outputPath: outputPath, now: fixtureNow);

    test('a recipient whose key may not be used stops the write, saying whose and why', () async {
      for (final (key, reason) in [
        (expiry('expired'), PgpKeyTrouble.expired),
        (expiry('revoked'), PgpKeyTrouble.revoked),
        (expiry('subkey-expired'), PgpKeyTrouble.expired),
        (Keys.rsa1024, PgpKeyTrouble.weak),
      ]) {
        final fingerprint = (await readPgpPublicKey(key)).fingerprintHex;
        await expectLater(
          to([Keys.edPublic, key]),
          throwsA(
            isA<PgpException>()
                .having((e) => e.problem, 'problem', PgpProblem.keyUnusable)
                .having((e) => e.reason, 'reason', reason)
                .having((e) => e.fingerprint, 'fingerprint', fingerprint),
          ),
        );
      }
      final broken = Uint8List.fromList(Keys.edPublic);
      broken[broken.length - 3] ^= 1;
      await expectLater(to([broken]), throwsA(isA<PgpException>().having((e) => e.reason, 'reason', PgpKeyTrouble.invalid)));
      // A version 6 key is written to since add-post-quantum-pgp; one Kemlock cannot write to is named
      await expectLater(to([binaryKey('keys/rfc9980/a4-public.asc')]), throwsProblem(PgpProblem.unsupported, detail: 'mld87'));
      await expectLater(to([Keys.brainpool]), throwsProblem(PgpProblem.unsupported, detail: 'brainpoolP256r1'));
    });

    test('nothing is written when it is refused', () async {
      final directory = Directory.systemTemp.createTempSync('pgp-encrypt-test');
      addTearDown(() => directory.deleteSync(recursive: true));
      final output = '${directory.path}/out.gpg';
      await expectLater(to([Keys.edPublic, expiry('expired')], outputPath: output), throwsProblem(PgpProblem.keyUnusable));
      expect(directory.listSync(), isEmpty);
    });

    test('no recipient and no passphrase', () async {
      await expectLater(to(const []), throwsA(isA<PgpException>().having((e) => e.reason, 'reason', PgpKeyTrouble.noSuchKey)));
      await expectLater(
        encrypt(data: PgpData.bytes(text), passphrase: '', text: true),
        throwsA(isA<PgpException>().having((e) => e.reason, 'reason', PgpKeyTrouble.noSuchKey)),
      );
    });

    test('a signer that may not sign, or is locked', () async {
      Future<Uint8List?> signedBy(PgpSecretKey signer) =>
          encrypt(data: PgpData.bytes(text), recipients: [Keys.edPublic], signer: signer, text: true, now: fixtureNow);
      await expectLater(
        signedBy(PgpSecretKey(binaryKey('keys/gnupg/expiry/expired.secret.asc'))),
        throwsA(isA<PgpException>().having((e) => e.reason, 'reason', PgpKeyTrouble.expired)),
      );
      await expectLater(
        signedBy(PgpSecretKey(Keys.edProtected)),
        throwsProblem(PgpProblem.passphraseNeeded, fingerprint: Keys.edProtectedFingerprint),
      );
      await expectLater(
        signedBy(PgpSecretKey(Keys.edProtected, passphrase: 'no')),
        throwsProblem(PgpProblem.wrongPassphrase, fingerprint: Keys.edProtectedFingerprint),
      );
      final message = await signedBy(PgpSecretKey(Keys.edProtected, passphrase: fixturePassphrase));
      final result = await decrypt(
        data: PgpData.bytes(message!),
        keys: [PgpSecretKey(Keys.ed)],
        verifiers: [Keys.edProtectedPublic],
        now: fixtureNow,
      );
      expect(result.signatures.single.verdict, SignatureVerdict.good);
    });
  });

  // openspec: add-post-quantum-pgp, task 6.4
  group('to post-quantum recipients', () {
    final standard = binaryKey('keys/kemlock/pgp-pq-standard.unprotected.asc');
    final gnupg = binaryKey('keys/kemlock/pgp-pq-gnupg.unprotected.asc');
    final standardPublic = binaryKey('keys/kemlock/pgp-pq-standard.public.asc');
    final gnupgPublic = binaryKey('keys/kemlock/pgp-pq-gnupg.public.asc');
    final data = _utf8('To whom it may concern, post-quantum.\n');

    for (final (name, recipients, keys, form) in [
      ('a standard key', [standardPublic], [standard], EncryptedForm.seipd2),
      ('a GnuPG Kyber key', [gnupgPublic], [gnupg], EncryptedForm.seipd1),
      (
        'standard, Kyber and RSA keys together',
        [standardPublic, gnupgPublic, Keys.rsaPublic],
        [standard, gnupg, Keys.rsa],
        EncryptedForm.seipd1,
      ),
    ]) {
      test('$name: the form of decision 3, AES-256, opened by each key', () async {
        final message = await encrypt(data: PgpData.bytes(data), recipients: recipients, text: true, now: fixtureNow);
        final armored = latin1.decode(message!);
        // A message ending in SEIPD version 2 has no CRC line
        expect(armored.split('\n').any((l) => l.startsWith('=')), form != EncryptedForm.seipd2);
        for (final key in keys) {
          final result = await decrypt(data: PgpData.bytes(message), keys: [PgpSecretKey(key)], now: fixtureNow);
          expect(result.bytes, data);
          expect((result.form, result.cipher), (form, 'AES-256'));
        }
      });
    }

    test('signed by a standard key inside SEIPD version 2, the signature is good', () async {
      final message = await encrypt(
        data: PgpData.bytes(data),
        recipients: [standardPublic],
        signer: PgpSecretKey(standard),
        text: true,
        now: fixtureNow,
      );
      final result = await decrypt(
        data: PgpData.bytes(message!),
        keys: [PgpSecretKey(standard)],
        verifiers: [standardPublic],
        now: fixtureNow,
      );
      expect(result.signatures.single.verdict, SignatureVerdict.good);
      expect(result.form, EncryptedForm.seipd2);
    });
  });
}
