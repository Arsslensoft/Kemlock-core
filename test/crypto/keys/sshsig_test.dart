@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openssh.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:kemlock_core/crypto/keys/sshsig.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'sshsig_kit.dart';

// Kemlock against OpenSSH: every signature ssh-keygen 10.3 made
// (test/fixtures/keys/openssh/sshsig, NOTES.md) must verify, and signing
// with the same Ed25519 or RSA key must write the same bytes.

Matcher _throwsSshsig(SshsigProblem problem) => throwsA(isA<SshsigFormatException>().having((e) => e.problem, 'problem', problem));

Matcher _verdict(SshsigVerdict verdict, [String? detail]) =>
    isA<SshsigResult>().having((r) => r.verdict, 'verdict', verdict).having((r) => r.detail, 'detail', detail);

Future<KeyMaterial> _material(String key) async => readPkcs8((await readPrivateKey(keyFixture('openssh/$key'))).private);

Uint8List _publicBlob(String pubFile) => base64.decode(keyFixtureText('openssh/$pubFile').trim().split(' ')[1]);

/// The bytes of an `SSH SIGNATURE` block, each part as given.
Uint8List _blob({
  String preamble = 'SSHSIG',
  int version = 1,
  required List<int> publicKey,
  String namespace = 'file',
  List<int> reserved = const [],
  String hashName = 'sha512',
  required String algorithm,
  required List<int> signature,
  List<int> trailing = const [],
}) =>
    (SshWriter()
          ..raw(ascii.encode(preamble))
          ..uint32(version)
          ..string(publicKey)
          ..text(namespace)
          ..string(reserved)
          ..text(hashName)
          ..string(
            (SshWriter()
                  ..text(algorithm)
                  ..string(signature))
                .bytes,
          )
          ..raw(trailing))
        .bytes;

String _armor(Uint8List blob, {int lineLength = 70}) => writePem('SSH SIGNATURE', blob, lineLength: lineLength);

/// A fixture's parts, to build a changed copy from.
({Uint8List publicKey, String algorithm, Uint8List signature}) _parts(SshsigFixture f) {
  final s = readSshsig(f.text);
  return (publicKey: s.publicKeyBlob, algorithm: s.algorithm, signature: s.signature);
}

SshsigFixture _fixture(String key, [String variant = 'file', String message = 'hello.txt']) =>
    sshsigFixtures.singleWhere((f) => f.key == key && f.variant == variant && f.message == message);

void main() {
  group('verifies what ssh-keygen signed', () {
    for (final f in sshsigFixtures.where((f) => f.key != 'ecdsa521')) {
      test('${f.file}: good over its message and namespace, bad with a byte changed', () async {
        final signature = readSshsig(f.text);
        expect(signature.namespace, f.namespace);
        expect(signature.hashName, f.hash);
        expect(signature.publicKeyBlob, _publicBlob('${f.key}.pub'));
        expect(await sshsigVerify(signature, f.namespace, f.messageBytes), _verdict(SshsigVerdict.good));

        final changed = f.messageBytes.isEmpty ? Uint8List(1) : (Uint8List.fromList(f.messageBytes)..[0] ^= 1);
        expect(await sshsigVerify(signature, f.namespace, changed), _verdict(SshsigVerdict.bad));
        expect(await sshsigVerify(signature, f.namespace, [...f.messageBytes, 0x0a]), _verdict(SshsigVerdict.bad));
      });
    }

    test('the fingerprint is the one ssh-keygen -l printed', () {
      final printed = keyFixtureText('openssh/fingerprints.txt');
      for (final key in ['ed25519', 'rsa3072', 'ecdsa256', 'ecdsa384', 'ecdsa521']) {
        final signature = readSshsig(_fixture(key).text);
        expect(printed, contains(' ${signature.fingerprint} '), reason: key);
      }
    });

    test('a signature made for another namespace says which, and is not checked further', () async {
      final git = readSshsig(_fixture('ed25519', 'git').text);
      expect(await sshsigVerify(git, 'file', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.wrongNamespace, 'git'));
      final custom = readSshsig(_fixture('ed25519', 'custom').text);
      expect(await sshsigVerify(custom, 'git', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.wrongNamespace, sshsigCustomNamespace));
      final file = readSshsig(_fixture('rsa3072').text);
      expect(await sshsigVerify(file, 'File', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.wrongNamespace, 'file'));
    });

    test('a signature of one key does not verify under another', () async {
      final ed = _parts(_fixture('ed25519'));
      final other = _publicBlob('ed25519.rounds4.pub');
      final swapped = readSshsigBlob(_blob(publicKey: other, algorithm: ed.algorithm, signature: ed.signature));
      expect(await sshsigVerify(swapped, 'file', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.bad));
    });

    test('the signed data has an empty reserved string, whatever the block carries', () async {
      final ed = _parts(_fixture('ed25519'));
      final reserved = readSshsigBlob(
        _blob(publicKey: ed.publicKey, reserved: [1, 2, 3], algorithm: ed.algorithm, signature: ed.signature),
      );
      expect(await sshsigVerify(reserved, 'file', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.good));
    });
  });

  group('names what it does not check', () {
    test('an ECDSA P-521 key', () async {
      for (final message in sshsigMessages) {
        final f = _fixture('ecdsa521', 'file', message);
        final signature = readSshsig(f.text);
        expect(signature.publicKey, isNull);
        expect(await sshsigVerify(signature, 'file', f.messageBytes), _verdict(SshsigVerdict.unsupported, 'ecdsa-sha2-nistp521'));
      }
    });

    test('a security key', () async {
      const type = 'sk-ssh-ed25519@openssh.com';
      final key =
          (SshWriter()
                ..text(type)
                ..string(Uint8List(32))
                ..text('ssh:'))
              .bytes;
      final signature = readSshsig(_armor(_blob(publicKey: key, algorithm: type, signature: Uint8List(70))));
      expect(signature.keyType, type);
      expect(await sshsigVerify(signature, 'file', const []), _verdict(SshsigVerdict.unsupported, type));
    });

    test('a certificate', () async {
      final signature = readSshsig(
        _armor(_blob(publicKey: _publicBlob('ed25519-cert.pub'), algorithm: 'ssh-ed25519', signature: Uint8List(64))),
      );
      expect(await sshsigVerify(signature, 'file', const []), _verdict(SshsigVerdict.unsupported, 'ssh-ed25519-cert-v01@openssh.com'));
    });

    test('an RSA signature over SHA-1 is weak, not checked', () async {
      final rsa = _parts(_fixture('rsa3072'));
      final signature = readSshsig(_armor(_blob(publicKey: rsa.publicKey, algorithm: 'ssh-rsa', signature: rsa.signature)));
      expect(await sshsigVerify(signature, 'file', sshsigMessage('hello.txt')), _verdict(SshsigVerdict.weak));
    });

    test('a signature by an RSA key under 2048 bits matches, and is weak: such a key can be factored', () async {
      final small = generateRsa(1024);
      expect(small.n.bitLength, lessThan(minRsaSignatureBits));
      final message = utf8.encode('signed by a small key');
      final signature = readSshsig(await sshsigSign(small, 'file', message));
      expect(await sshsigVerify(signature, 'file', message), _verdict(SshsigVerdict.weakKey, 'RSA ${small.n.bitLength}'));
      // One that does not match is bad, whatever the key
      expect(await sshsigVerify(signature, 'file', utf8.encode('another message')), _verdict(SshsigVerdict.bad));
      // A key of 2048 bits is not weak
      final enough = generateRsa(2048);
      expect(await sshsigVerify(readSshsig(await sshsigSign(enough, 'file', message)), 'file', message), _verdict(SshsigVerdict.good));
    });

    test('an algorithm that does not belong to the key, or bytes not laid out as it says, are bad', () async {
      final ed = _parts(_fixture('ed25519'));
      final rsa = _parts(_fixture('rsa3072'));
      final ec = _parts(_fixture('ecdsa256'));
      final message = sshsigMessage('hello.txt');
      for (final blob in [
        _blob(publicKey: rsa.publicKey, algorithm: 'ssh-ed25519', signature: ed.signature),
        _blob(publicKey: rsa.publicKey, algorithm: 'rsa-sha2-256', signature: rsa.signature),
        _blob(publicKey: ed.publicKey, algorithm: 'rsa-sha2-512', signature: rsa.signature),
        _blob(publicKey: ed.publicKey, algorithm: 'ssh-ed25519', signature: ed.signature.sublist(1)),
        _blob(publicKey: ec.publicKey, algorithm: 'ecdsa-sha2-nistp384', signature: ec.signature),
        _blob(publicKey: ec.publicKey, algorithm: 'ecdsa-sha2-nistp256', signature: [...ec.signature, 0]),
        _blob(publicKey: ec.publicKey, algorithm: 'ecdsa-sha2-nistp256', signature: ec.signature.sublist(0, 20)),
      ]) {
        expect(await sshsigVerify(readSshsigBlob(blob), 'file', message), _verdict(SshsigVerdict.bad));
      }
    });
  });

  group('refuses what is not a signature it reads', () {
    final ed = _parts(_fixture('ed25519'));

    test('version 2', () {
      expect(
        () => readSshsig(_armor(_blob(version: 2, publicKey: ed.publicKey, algorithm: ed.algorithm, signature: ed.signature))),
        _throwsSshsig(SshsigProblem.damaged),
      );
    });

    test('a hash named sha1', () {
      expect(
        () => readSshsig(_armor(_blob(hashName: 'sha1', publicKey: ed.publicKey, algorithm: ed.algorithm, signature: ed.signature))),
        _throwsSshsig(SshsigProblem.damaged),
      );
    });

    test('a bad preamble', () {
      expect(
        () => readSshsig(_armor(_blob(preamble: 'SSHSIg', publicKey: ed.publicKey, algorithm: ed.algorithm, signature: ed.signature))),
        _throwsSshsig(SshsigProblem.damaged),
      );
      expect(() => readSshsig(_armor(Uint8List(3))), _throwsSshsig(SshsigProblem.damaged));
    });

    test('bytes after the signature', () {
      expect(
        () => readSshsig(_armor(_blob(publicKey: ed.publicKey, algorithm: ed.algorithm, signature: ed.signature, trailing: [0]))),
        _throwsSshsig(SshsigProblem.damaged),
      );
    });

    test('a block cut short, at every length', () {
      final text = _fixture('ed25519').text;
      // Without its end marker.
      expect(() => readSshsig(text.substring(0, text.indexOf('-----END'))), _throwsSshsig(SshsigProblem.damaged));
      expect(() => readSshsig(text.substring(0, 60)), _throwsSshsig(SshsigProblem.damaged));
      // With its markers and less inside them.
      final blob = readPemBlocks(text).single.decode();
      for (var length = 0; length < blob.length; length++) {
        expect(
          () => readSshsig(_armor(Uint8List.sublistView(blob, 0, length))),
          _throwsSshsig(SshsigProblem.damaged),
          reason: '$length bytes',
        );
      }
      expect(() => readSshsig('-----BEGIN SSH SIGNATURE-----\n!!!!\n-----END SSH SIGNATURE-----\n'), _throwsSshsig(SshsigProblem.damaged));
    });

    test('a key of a known type that is not laid out as one', () {
      final short =
          (SshWriter()
                ..text('ssh-ed25519')
                ..string(Uint8List(31)))
              .bytes;
      expect(
        () => readSshsigBlob(_blob(publicKey: short, algorithm: 'ssh-ed25519', signature: Uint8List(64))),
        _throwsSshsig(SshsigProblem.damaged),
      );
      final mixed =
          (SshWriter()
                ..text('ecdsa-sha2-nistp256')
                ..text('nistp384')
                ..string(Uint8List(97)..[0] = 4))
              .bytes;
      expect(
        () => readSshsigBlob(_blob(publicKey: mixed, algorithm: 'ecdsa-sha2-nistp256', signature: Uint8List(8))),
        _throwsSshsig(SshsigProblem.damaged),
      );
    });

    test('a PGP block and plain text', () {
      expect(
        () => readSshsig('-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQQ=\n=abcd\n-----END PGP SIGNATURE-----\n'),
        _throwsSshsig(SshsigProblem.notASignature),
      );
      expect(() => readSshsig('-----BEGIN PGP SIGNATURE-----\n\niHUEABYKAB0WIQQ'), _throwsSshsig(SshsigProblem.notASignature));
      expect(() => readSshsig('hello'), _throwsSshsig(SshsigProblem.notASignature));
      expect(() => readSshsig(''), _throwsSshsig(SshsigProblem.notASignature));
      expect(() => readSshsig(keyFixtureText('openssh/ed25519.pub')), _throwsSshsig(SshsigProblem.notASignature));
    });
  });

  group('reads the armor whatever its lines', () {
    final f = _fixture('rsa3072');
    final blob = readPemBlocks(f.text).single.decode();

    for (final (name, text) in [
      ('wrapped at 76', _armor(blob, lineLength: 76)),
      ('on one line', _armor(blob, lineLength: 100000)),
      ('with CRLF line endings', f.text.replaceAll('\n', '\r\n')),
      ('with text round it', 'Signature:\n\n${f.text}\nSent from my phone'),
      ('indented, as in a commit', f.text.split('\n').map((l) => ' $l').join('\n')),
    ]) {
      test(name, () async {
        expect(text, isNot(f.text));
        expect(await sshsigVerify(readSshsig(text), 'file', f.messageBytes), _verdict(SshsigVerdict.good));
      });
    }
  });

  group('reads a public key line', () {
    test('of each fixture key, with or without its comment', () {
      for (final key in ['ed25519', 'rsa3072', 'ecdsa256', 'ecdsa384', 'ecdsa521', 'ed25519-cert']) {
        final line = keyFixtureText('openssh/$key.pub');
        expect(readSshPublicLine(line), _publicBlob('$key.pub'), reason: key);
        expect(readSshPublicLine('  ${line.split(' ').take(2).join(' ')}'), _publicBlob('$key.pub'));
      }
      expect(
        sshBlobFingerprint(readSshPublicLine(keyFixtureText('openssh/ed25519.pub'))),
        'SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4',
      );
    });

    test('and refuses what is not one', () {
      final line = keyFixtureText('openssh/ed25519.pub');
      expect(() => readSshPublicLine('hello'), throwsKeyProblem(KeyProblem.unrecognized));
      expect(() => readSshPublicLine(''), throwsKeyProblem(KeyProblem.unrecognized));
      expect(() => readSshPublicLine(keyFixtureText('openssh/ed25519')), throwsKeyProblem(KeyProblem.unrecognized));
      expect(() => readSshPublicLine(line.replaceFirst('ssh-ed25519', 'ssh-rsa')), throwsKeyProblem(KeyProblem.damaged));
      expect(() => readSshPublicLine(line.substring(0, 30)), throwsKeyProblem(KeyProblem.damaged));
    });
  });

  group('signs as ssh-keygen does', () {
    for (final f in sshsigFixtures.where((f) => (f.key == 'ed25519' || f.key == 'rsa3072') && f.hash == 'sha512')) {
      test('${f.file}: the same bytes', () async {
        expect(await sshsigSign(await _material(f.key), f.namespace, f.messageBytes), f.text);
      });
    }

    for (final key in ['ecdsa256', 'ecdsa384']) {
      test('$key: verifies, repeats, and differs between messages', () async {
        final material = await _material(key);
        final signed = <String>{};
        for (final message in sshsigMessages) {
          final text = await sshsigSign(material, 'file', sshsigMessage(message));
          expect(await sshsigSign(material, 'file', sshsigMessage(message)), text, reason: 'the nonce is deterministic');
          final signature = readSshsig(text);
          expect(signature.publicKeyBlob, _publicBlob('$key.pub'));
          expect(signature.hashName, 'sha512');
          expect(await sshsigVerify(signature, 'file', sshsigMessage(message)), _verdict(SshsigVerdict.good));
          expect(await sshsigVerify(signature, 'file', [...sshsigMessage(message), 1]), _verdict(SshsigVerdict.bad));
          signed.add(text);
        }
        expect(signed, hasLength(sshsigMessages.length));
        expect(
          await sshsigSign(material, 'git', sshsigMessage('hello.txt')),
          isNot(await sshsigSign(material, 'file', sshsigMessage('hello.txt'))),
        );
      });
    }

    test('an empty namespace, or one with a space or a line break, throws', () async {
      final material = await _material('ed25519');
      for (final namespace in ['', ' ', 'my files', 'file\n', '\tfile', 'a\rb']) {
        expect(isSshsigNamespace(namespace), isFalse, reason: jsonEncode(namespace));
        await expectLater(sshsigSign(material, namespace, const []), throwsArgumentError);
      }
      for (final namespace in ['file', 'git', sshsigCustomNamespace, 'é']) {
        expect(isSshsigNamespace(namespace), isTrue, reason: namespace);
      }
    });

    test('a key with no SSH form throws', () async {
      final x25519 = await readPkcs8((await readPrivateKey(keyFixture('openssl/x25519.pkcs8.pem'))).private);
      await expectLater(sshsigSign(x25519, 'file', const []), throwsArgumentError);
    });
  });
}
