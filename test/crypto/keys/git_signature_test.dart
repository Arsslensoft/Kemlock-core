@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/git_signature.dart';
import 'package:kemlock_core/crypto/keys/sshsig.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// git-commit.txt and git-tag.txt are `git cat-file` of a commit and a tag
// that git 2.55 signed with the ed25519 fixture key (`gpg.format ssh`), and
// that `git verify-commit` and `git verify-tag` called good (NOTES.md).

final Uint8List _commit = keyFixture('openssh/sshsig/git-commit.txt');
final Uint8List _tag = keyFixture('openssh/sshsig/git-tag.txt');
const _fingerprint = 'SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4';

const _pgpBlock = [
  '-----BEGIN PGP SIGNATURE-----',
  '',
  'iHUEABYKAB0WIQTFlLtp++hnHVBzFoaPAmIzBSAtNgUCaRnGgAAKCRCPAmIzBSAt',
  'NlZ5AQDp',
  '=abcd',
  '-----END PGP SIGNATURE-----',
];

/// The fixture commit with [header] where its `gpgsig` header is.
Uint8List _commitWith(List<String> header) {
  final lines = utf8.decode(_commit).split('\n');
  final first = lines.indexWhere((l) => l.startsWith('gpgsig '));
  final after = lines.indexWhere((l) => !l.startsWith(' '), first + 1);
  return utf8.encode([...lines.sublist(0, first), ...header, ...lines.sublist(after)].join('\n'));
}

Matcher _verified(SshsigVerdict verdict) => isA<GitVerification>()
    .having((v) => v.kind, 'kind', GitSignatureKind.ssh)
    .having((v) => v.result?.verdict, 'verdict', verdict)
    .having((v) => v.signature?.fingerprint, 'fingerprint', _fingerprint);

void main() {
  group('a commit', () {
    test('splits into the commit without its gpgsig header, and the signature', () {
      final split = splitGitSignature(_commit);
      expect(split.kind, GitSignatureKind.ssh);
      expect(utf8.decode(split.payload), utf8.decode(_commitWith([])));
      expect(
        utf8.decode(split.payload),
        'tree 04df07b08ca746b3167d0f1d1514e2f39a52c16c\n'
        'author Fixture Author <author@example.org> 1794830400 +0000\n'
        'committer Fixture Committer <committer@example.org> 1794830400 +0000\n'
        '\n'
        'Add a greeting\n'
        '\n'
        'The body of the fixture commit.\n',
      );
      final lines = split.signature!.split('\n');
      expect(lines.first, '-----BEGIN SSH SIGNATURE-----');
      expect(lines[lines.length - 2], '-----END SSH SIGNATURE-----');
      expect(lines.any((l) => l.startsWith(' ')), isFalse);
      expect(readSshsig(split.signature!).namespace, 'git');
    });

    test('that git signed is good for git', () async {
      expect(await verifyGitSignature(_commit), _verified(SshsigVerdict.good));
      final split = splitGitSignature(_commit);
      expect((await sshsigVerify(readSshsig(split.signature!), 'git', split.payload)).verdict, SshsigVerdict.good);
      expect((await sshsigVerify(readSshsig(split.signature!), 'file', split.payload)).verdict, SshsigVerdict.wrongNamespace);
    });

    test('pasted without its final line ending verifies through the retry', () async {
      final pasted = Uint8List.sublistView(_commit, 0, _commit.length - 1);
      expect(pasted.last, isNot(0x0a));
      final split = splitGitSignature(pasted);
      expect((await sshsigVerify(readSshsig(split.signature!), 'git', split.payload)).verdict, SshsigVerdict.bad);
      expect(await verifyGitSignature(pasted), _verified(SshsigVerdict.good));
      expect(await verifyGitSignature(utf8.encode('\n  ${utf8.decode(pasted)}')), _verified(SshsigVerdict.good));
    });

    test('with one letter of its message changed is bad, with or without the final line ending', () async {
      final changed = utf8.encode(utf8.decode(_commit).replaceFirst('Add a greeting', 'Add a greetinG'));
      expect(await verifyGitSignature(changed), _verified(SshsigVerdict.bad));
      expect(await verifyGitSignature(Uint8List.sublistView(changed, 0, changed.length - 1)), _verified(SshsigVerdict.bad));
      // Two line endings lost: the retry adds one only.
      expect(
        await verifyGitSignature(utf8.encode(utf8.decode(_commit).trimRight().replaceFirst('commit.', 'commit'))),
        _verified(SshsigVerdict.bad),
      );
      final author = utf8.encode(utf8.decode(_commit).replaceFirst('author@example.org', 'other@example.org'));
      expect(await verifyGitSignature(author), _verified(SshsigVerdict.bad));
    });

    test('with a gpgsig-sha256 header is read the same', () async {
      final text = utf8.decode(_commit).replaceFirst('\ngpgsig ', '\ngpgsig-sha256 ');
      final split = splitGitSignature(utf8.encode(text));
      expect(split.kind, GitSignatureKind.ssh);
      expect(split.payload, splitGitSignature(_commit).payload);
      expect(await verifyGitSignature(utf8.encode(text)), _verified(SshsigVerdict.good));
    });

    test('of a SHA-256 repository with both headers is checked by gpgsig-sha256, and both are removed', () {
      final signature = splitGitSignature(_commit).signature!.trimRight().split('\n');
      final both = utf8
          .decode(
            _commitWith([
              'gpgsig ${_pgpBlock.first}',
              for (final line in _pgpBlock.skip(1)) ' $line',
              'gpgsig-sha256 ${signature.first}',
              for (final line in signature.skip(1)) ' $line',
            ]),
          )
          .replaceFirst('tree 04df07b08ca746b3167d0f1d1514e2f39a52c16c', 'tree ${'ab' * 32}');
      final split = splitGitSignature(utf8.encode(both));
      expect(split.kind, GitSignatureKind.ssh);
      expect(utf8.decode(split.payload), isNot(contains('gpgsig')));
      expect(utf8.decode(split.payload), isNot(contains('BEGIN')));
    });

    test('with no signature is reported as unsigned', () async {
      final unsigned = _commitWith([]);
      final split = splitGitSignature(unsigned);
      expect(split.kind, GitSignatureKind.unsigned);
      expect(split.signature, isNull);
      expect(split.payload, unsigned);
      final verification = await verifyGitSignature(unsigned);
      expect(verification.kind, GitSignatureKind.unsigned);
      expect(verification.result, isNull);
    });

    test('whose message quotes a signature block is still unsigned', () {
      final quoting = utf8.encode('${utf8.decode(_commitWith([]))}\ngpgsig -----BEGIN SSH SIGNATURE-----\n abc\n');
      expect(splitGitSignature(quoting).kind, GitSignatureKind.unsigned);
      expect(splitGitSignature(quoting).payload, quoting);
    });

    test('with a PGP block is reported as signed with PGP', () async {
      final pgp = _commitWith(['gpgsig ${_pgpBlock.first}', for (final line in _pgpBlock.skip(1)) ' $line']);
      final split = splitGitSignature(pgp);
      expect(split.kind, GitSignatureKind.pgp);
      expect(split.signature, '${_pgpBlock.join('\n')}\n');
      expect(split.payload, _commitWith([]));
      expect((await verifyGitSignature(pgp)).kind, GitSignatureKind.pgp);
    });

    test('with an X.509 block is neither', () {
      final x509 = _commitWith(['gpgsig -----BEGIN SIGNED MESSAGE-----', ' MIIB', ' -----END SIGNED MESSAGE-----']);
      expect(splitGitSignature(x509).kind, GitSignatureKind.other);
    });

    test('with a damaged signature block is a read error', () async {
      final damaged = utf8.encode(utf8.decode(_commit).replaceFirst(' U1NIU0lH', ' U1NIU0lI'));
      await expectLater(
        verifyGitSignature(damaged),
        throwsA(isA<SshsigFormatException>().having((e) => e.problem, 'problem', SshsigProblem.damaged)),
      );
    });
  });

  group('a tag', () {
    test('splits before the line that starts the signature', () {
      final split = splitGitSignature(_tag);
      expect(split.kind, GitSignatureKind.ssh);
      expect(
        utf8.decode(split.payload),
        'object 5aeee2dc8bf106c91741bbe9530674262f36fe90\n'
        'type commit\n'
        'tag v1\n'
        'tagger Fixture Committer <committer@example.org> 1794830400 +0000\n'
        '\n'
        'The first fixture tag\n',
      );
      expect(split.signature, startsWith('-----BEGIN SSH SIGNATURE-----\n'));
      expect(split.signature, endsWith('-----END SSH SIGNATURE-----\n'));
    });

    test('that git signed is good for git, with or without its final line ending', () async {
      expect(await verifyGitSignature(_tag), _verified(SshsigVerdict.good));
      expect(await verifyGitSignature(Uint8List.sublistView(_tag, 0, _tag.length - 1)), _verified(SshsigVerdict.good));
    });

    test('with its message changed is bad', () async {
      final changed = utf8.encode(utf8.decode(_tag).replaceFirst('first fixture', 'second fixture'));
      expect(await verifyGitSignature(changed), _verified(SshsigVerdict.bad));
      final retargeted = utf8.encode(utf8.decode(_tag).replaceFirst('object 5a', 'object 5b'));
      expect(await verifyGitSignature(retargeted), _verified(SshsigVerdict.bad));
    });

    test('unsigned, and signed with PGP', () {
      final body = utf8.decode(splitGitSignature(_tag).payload);
      expect(splitGitSignature(utf8.encode(body)).kind, GitSignatureKind.unsigned);
      final pgp = splitGitSignature(utf8.encode('$body${_pgpBlock.join('\n')}\n'));
      expect(pgp.kind, GitSignatureKind.pgp);
      expect(utf8.decode(pgp.payload), body);
    });
  });

  test('text that is not a git object is refused', () {
    for (final text in [
      '',
      'hello',
      'commit 5aeee2dc8bf106c91741bbe9530674262f36fe90\nAuthor: Fixture Author <author@example.org>\n\n    Add a greeting\n',
      'tree 04df07b0\nauthor x\n\nmessage\n',
      'object 5aeee2dc8bf106c91741bbe9530674262f36fe90\n',
      keyFixtureText('openssh/sshsig/ed25519-git-hello.txt.sig'),
    ]) {
      expect(() => splitGitSignature(utf8.encode(text)), throwsA(isA<NotAGitObjectException>()), reason: text);
    }
    expect(() => verifyGitSignature(utf8.encode('hello')), throwsA(isA<NotAGitObjectException>()));
  });

  test('a message that is not UTF-8 keeps its bytes', () {
    final latin = Uint8List.fromList([..._commitWith([]), 0xe9, 0xff, 0x0a]);
    expect(splitGitSignature(latin).payload, latin);
  });
}
