@TestOn('vm')
library;

// Clear-signed text: GnuPG's and RFC 9580's read, and Kemlock's own
// written and read back.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/cleartext.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'decrypt_test.dart' show throwsProblem;
import 'fixtures.dart';

Uint8List _utf8(String text) => Uint8List.fromList(utf8.encode(text));

Future<PgpVerified> _verify(Object signed, List<Uint8List> keys) =>
    verify(signed: PgpData.bytes(signed is String ? _utf8(signed) : signed as Uint8List), verifiers: keys, now: fixtureNow);

void main() {
  // GnuPG signs `message.txt` whole, its last line ending included, and
  // writes one more line ending before the signature, which is not part
  // of the text
  final signedText = utf8.decode(messageTxt);

  group('read', () {
    test('GnuPG\'s clear-signed text is good, and its text comes out', () async {
      for (final (file, key, fingerprint) in [
        ('clearsigned.asc', Keys.edPublic, Keys.edFingerprint),
        ('clearsigned-rsa.asc', Keys.rsaPublic, Keys.rsaFingerprint),
      ]) {
        final verified = await _verify(pgpFixture('gnupg/$file'), [key]);
        final result = verified.signatures.single;
        expect(result.verdict, SignatureVerdict.good, reason: file);
        expect(result.signerFingerprint, fingerprint);
        expect(result.made, gnupgSignatures(file).single.made);
        expect(utf8.decode(verified.content!), signedText);
        expect(verified.isText, isTrue);
      }
    });

    test('with CR LF line endings, and with a mail around it', () async {
      final text = pgpFixtureText('gnupg/clearsigned.asc');
      expect((await _verify(text.replaceAll('\n', '\r\n'), [Keys.edPublic])).signatures.single.verdict, SignatureVerdict.good);
      final mail = 'On Monday Ada wrote:\n\n$text\n-- \nsent from a phone\n';
      final verified = await _verify(mail, [Keys.edPublic]);
      expect(verified.signatures.single.verdict, SignatureVerdict.good);
      expect(utf8.decode(verified.content!), signedText);
    });

    test('the dash-escapes and what is not hashed', () {
      final message = readCleartext(pgpFixture('gnupg/clearsigned.asc'));
      final lines = message.text.split('\n');
      expect(lines[1], '- a line that starts with a dash');
      expect(lines[2], 'From a line that starts with From');
      // Trailing spaces and tabs stay in the text and are left out of the hash
      expect(lines[3], 'trailing spaces   ');
      final hashed = latin1.decode(cleartextSignedBytes(message.textBytes)).split('\r\n');
      expect(hashed[3], 'trailing spaces');
      expect(hashed[4], '\ta tab, then a trailing tab');
      expect(hashed, hasLength(lines.length));
    });

    test('what is hashed, line by line', () {
      String hashed(String text) => latin1.decode(cleartextSignedBytes(Uint8List.fromList(latin1.encode(text))));
      expect(hashed(''), '');
      expect(hashed('one'), 'one');
      expect(hashed('one\n'), 'one\r\n');
      expect(hashed('one \t\ntwo\t \n\n three'), 'one\r\ntwo\r\n\r\n three');
      // CR LF line endings, and a CR that only trails
      expect(hashed('one\r\ntwo \r\n'), 'one\r\ntwo\r\n');
      expect(hashed('one\r\r\n \r \ntwo'), 'one\r\n\r\ntwo');
      // Inside a line they stay
      expect(hashed('a  b\tc\rd'), 'a  b\tc\rd');
      expect(hashed(' \t '), '');
    });

    test('a long run of spaces that ends no line takes no time', () {
      // A megabyte of spaces and then a letter: with a pattern for "spaces
      // up to the end" every space was tried as the start of the run
      final line = Uint8List(1 << 20)..fillRange(0, 1 << 20, 0x20);
      final text = Uint8List.fromList([...line, 0x78, 0x0a, ...line, 0x09, 0x78]);
      final hashed = cleartextSignedBytes(text);
      expect(hashed.length, text.length + 1);
      expect(hashed.sublist((1 << 20) - 1, (1 << 20) + 4), [0x20, 0x78, 0x0d, 0x0a, 0x20]);
    }, timeout: const Timeout(Duration(seconds: 20)));

    test('A.6 of RFC 9580 is good, with the RFC\'s version 6 key', () async {
      final verified = await _verify(pgpFixture('rfc9580/a6-cleartext-signed.asc'), [Keys.v6Public]);
      expect(verified.signatures.single.verdict, SignatureVerdict.good);
      expect(verified.signatures.single.made, DateTime.utc(2022, 12, 13, 16, 8, 3));
      expect(utf8.decode(verified.content!), 'What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n');
      // The canonical text the RFC lists
      expect(
        utf8.decode(cleartextSignedBytes(verified.content!)),
        'What we need from the grocery store:\r\n\r\n- tofu\r\n- vegetables\r\n- noodles\r\n',
      );
    });

    test('a changed word is bad', () async {
      final text = pgpFixtureText('gnupg/clearsigned.asc');
      final changed = await _verify(text.replaceFirst('A message', 'A massage'), [Keys.edPublic]);
      expect(changed.signatures.single.verdict, SignatureVerdict.bad);
      expect(utf8.decode(changed.content!), startsWith('A massage'));
      // Added trailing spaces change nothing; an added line does
      expect(
        (await _verify(text.replaceFirst('fixtures.\n', 'fixtures.  \t\n'), [Keys.edPublic])).signatures.single.verdict,
        SignatureVerdict.good,
      );
      expect(
        (await _verify(text.replaceFirst('fixtures.\n', 'fixtures.\n\n'), [Keys.edPublic])).signatures.single.verdict,
        SignatureVerdict.bad,
      );
    });

    test('the signer unknown', () async {
      final verified = await _verify(pgpFixture('gnupg/clearsigned.asc'), [Keys.rsaPublic]);
      expect((verified.signatures.single.verdict, verified.signatures.single.issuer), (SignatureVerdict.unknownSigner, Keys.edFingerprint));
    });

    test('NotDashEscaped is refused by name', () async {
      final text = pgpFixtureText('gnupg/clearsigned.asc')
          .replaceFirst('Hash: SHA512\n', 'Hash: SHA512\nNotDashEscaped: You need GnuPG to verify this\n');
      await expectLater(_verify(text, [Keys.edPublic]), throwsProblem(PgpProblem.unsupported, detail: 'NotDashEscaped'));
    });

    test('broken framing is damaged', () async {
      final text = pgpFixtureText('gnupg/clearsigned.asc');
      // A text line that starts with a dash and was not escaped
      await expectLater(_verify(text.replaceFirst('- - a line', '-a line'), [Keys.edPublic]), throwsProblem(PgpProblem.damaged));
      await expectLater(_verify(text.replaceFirst('Hash: SHA512', 'Comment: no'), [Keys.edPublic]), throwsProblem(PgpProblem.damaged));
      final cut = text.substring(0, text.indexOf('-----BEGIN PGP SIGNATURE'));
      await expectLater(_verify(cut, [Keys.edPublic]), throwsProblem(PgpProblem.damaged));
    });
  });

  group('written', () {
    final time = DateTime.utc(2026, 11, 20, 9, 30);

    Future<String> clearsign(String text, [Uint8List? key]) async => utf8.decode(
      await sign(data: PgpData.bytes(_utf8(text)), signer: PgpSecretKey(key ?? Keys.ed), form: PgpSignatureForm.cleartext, now: time),
    );

    test('"hello" stays readable between the two armor lines', () async {
      final signed = await clearsign('hello');
      expect(signed, startsWith('-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nhello\n-----BEGIN PGP SIGNATURE-----\n\n'));
      expect(signed, endsWith('-----END PGP SIGNATURE-----\n'));
      final verified = await _verify(signed, [Keys.edPublic]);
      expect(verified.signatures.single.verdict, SignatureVerdict.good);
      expect(verified.signatures.single.made, time);
      expect(utf8.decode(verified.content!), 'hello');
    });

    for (final (name, text) in [
      ('lines starting with a dash and with From', '- a list\n-- \nFrom here on\n-----BEGIN PGP MESSAGE-----\nplain'),
      ('trailing spaces and tabs', 'spaces   \ntabs\t\t\nboth \t \nnone'),
      ('an empty last line', 'one\ntwo\n'),
      ('no final newline', 'one\ntwo'),
      ('several empty lines at the end', 'one\n\n\n'),
      ('text outside ASCII', 'Clé, naïve, 日本.\n«guillemets»'),
      ('an empty text', ''),
      ('CR LF line endings', 'one\r\ntwo\r\n'),
    ]) {
      test('$name: its own reader says good and gives the text back', () async {
        for (final key in [Keys.ed, Keys.rsa]) {
          final signed = await clearsign(text, key);
          final verified = await _verify(signed, [Keys.edPublic, Keys.rsaPublic]);
          expect(verified.signatures.single.verdict, SignatureVerdict.good);
          expect(utf8.decode(verified.content!), text.replaceAll('\r\n', '\n'));
          // No line of the framed text starts with a bare dash
          final body = signed.substring(signed.indexOf('\n\n') + 2, signed.indexOf('-----BEGIN PGP SIGNATURE'));
          for (final line in body.split('\n')) {
            expect(line.startsWith('-') && !line.startsWith('- '), isFalse, reason: line);
          }
        }
      });
    }

    test('one changed letter of what Kemlock signed is bad', () async {
      final signed = await clearsign('pay Ada 10\nthanks');
      expect((await _verify(signed.replaceFirst('10', '90'), [Keys.edPublic])).signatures.single.verdict, SignatureVerdict.bad);
    });

    test('text over 1 MB is not clear-signed', () async {
      await expectLater(clearsign('x' * (maxPgpTextLength + 1)), throwsProblem(PgpProblem.tooLarge));
    });
  });

  // openspec: add-post-quantum-pgp, task 6.3
  group('post-quantum', () {
    test("Sequoia's clear-signed text is good, by its signing subkey", () async {
      final verified = await _verify(File('test/fixtures/keys/sequoia/pqc/message.cleartext.asc').readAsBytesSync(), [
        binaryKey('keys/sequoia/pqc/standard.public.asc'),
      ]);
      expect(verified.signatures.single.verdict, SignatureVerdict.good);
      expect(verified.content, File('test/fixtures/keys/sequoia/pqc/message.txt').readAsBytesSync());
    });

    test('a standard key clear-signs without the Hash header and the CRC line, and it is good', () async {
      final text = await sign(
        data: PgpData.bytes(_utf8('Post-quantum, in the clear.\n')),
        signer: PgpSecretKey(binaryKey('keys/kemlock/pgp-pq-standard.unprotected.asc')),
        form: PgpSignatureForm.cleartext,
        now: fixtureNow,
      );
      final lines = utf8.decode(text).split('\n');
      expect(lines.take(2), ['-----BEGIN PGP SIGNED MESSAGE-----', '']);
      expect(lines.where((l) => l.startsWith('=')), isEmpty);
      final verified = await _verify(text, [binaryKey('keys/kemlock/pgp-pq-standard.public.asc')]);
      expect(verified.signatures.single.verdict, SignatureVerdict.good);
      final changed = utf8.decode(text).replaceFirst('in the clear', 'in the dark');
      expect(
        (await _verify(changed, [binaryKey('keys/kemlock/pgp-pq-standard.public.asc')])).signatures.single.verdict,
        SignatureVerdict.bad,
      );
    });
  });
}
