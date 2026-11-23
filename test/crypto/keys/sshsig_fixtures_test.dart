@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openssh.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'sshsig_kit.dart';

// What ssh-keygen and git wrote, read with the SSH wire reader alone: the
// layout of PROTOCOL.sshsig, before any code of Kemlock's signs or verifies.

void main() {
  test('the messages are what NOTES.md says', () {
    expect(sshsigMessage('empty'), isEmpty);
    expect(sshsigMessage('hello.txt'), utf8.encode('hello'));
    expect(sshsigMessage('bytes.bin'), List.generate(256, (i) => i));
  });

  for (final f in sshsigFixtures) {
    test('${f.file}: preamble, version, public key, namespace and hash', () {
      final block = readPemBlocks(f.text).single;
      expect(block.label, 'SSH SIGNATURE');
      final blob = block.decode();
      expect(ascii.decode(blob.sublist(0, 6)), 'SSHSIG');
      final r = SshReader(Uint8List.sublistView(blob, 6));
      expect(r.uint32(), 1, reason: 'version');
      expect(base64.encode(r.string()), f.publicLine.split(' ')[1], reason: 'the key of ${f.key}.pub');
      expect(r.text(), f.namespace);
      expect(r.string(), isEmpty, reason: 'reserved');
      expect(r.text(), f.hash);
      final signature = SshReader(r.string());
      r.done();
      expect(signature.text(), switch (f.key) {
        'ed25519' => 'ssh-ed25519',
        'rsa3072' => 'rsa-sha2-512',
        'ecdsa256' => 'ecdsa-sha2-nistp256',
        'ecdsa384' => 'ecdsa-sha2-nistp384',
        _ => 'ecdsa-sha2-nistp521',
      });
      signature.string();
      signature.done();
    });

    test('${f.file}: armored in lines of 70 characters, ending in a line ending', () {
      final lines = f.text.split('\n');
      expect(lines.first, '-----BEGIN SSH SIGNATURE-----');
      expect(lines.last, isEmpty);
      expect(lines[lines.length - 2], '-----END SSH SIGNATURE-----');
      final body = lines.sublist(1, lines.length - 2);
      expect(body.take(body.length - 1).map((l) => l.length).toSet(), anyOf(isEmpty, {70}));
      expect(body.last.length, inInclusiveRange(1, 70));
    });
  }

  test('the commit and the tag carry a signature block of the ed25519 key for git', () {
    for (final name in ['git-commit.txt', 'git-tag.txt']) {
      final text = keyFixtureText('openssh/sshsig/$name');
      expect(text.endsWith('\n'), isTrue);
      final blob = readPemBlocks(text).single.decode();
      final r = SshReader(Uint8List.sublistView(blob, 6))..uint32();
      expect(base64.encode(r.string()), keyFixtureText('openssh/ed25519.pub').split(' ')[1]);
      expect(r.text(), 'git');
    }
    expect(keyFixtureText('openssh/sshsig/git-commit.txt'), contains('\ngpgsig -----BEGIN SSH SIGNATURE-----\n '));
  });
}
