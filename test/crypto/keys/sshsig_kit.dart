import 'dart:typed_data';

import 'fixtures.dart';

// The files of test/fixtures/keys/openssh/sshsig, which
// tool/keys/make_sshsig_fixtures.sh made with ssh-keygen from OpenSSH 10.3
// and git 2.55 (NOTES.md).

const sshsigMessages = ['empty', 'hello.txt', 'bytes.bin'];

/// The custom namespace of the `custom` signatures.
const sshsigCustomNamespace = 'kemlock-test@example.org';

/// One `ssh-keygen -Y sign` signature: `<key>-<variant>-<message>.sig`.
typedef SshsigFixture = ({String key, String variant, String message, String namespace, String hash});

/// Every signature file: each key over each message for `file`, and the
/// Ed25519 key for `git`, the custom namespace and SHA-256.
final List<SshsigFixture> sshsigFixtures = [
  for (final message in sshsigMessages) ...[
    for (final key in ['ed25519', 'rsa3072', 'ecdsa256', 'ecdsa384', 'ecdsa521'])
      (key: key, variant: 'file', message: message, namespace: 'file', hash: 'sha512'),
    (key: 'ed25519', variant: 'git', message: message, namespace: 'git', hash: 'sha512'),
    (key: 'ed25519', variant: 'custom', message: message, namespace: sshsigCustomNamespace, hash: 'sha512'),
    (key: 'ed25519', variant: 'sha256', message: message, namespace: 'file', hash: 'sha256'),
  ],
];

extension SshsigFixtureFiles on SshsigFixture {
  String get file => '$key-$variant-$message.sig';

  /// The armored signature as ssh-keygen wrote it.
  String get text => keyFixtureText('openssh/sshsig/$file');

  Uint8List get messageBytes => sshsigMessage(message);

  /// The key's `.pub` line.
  String get publicLine => keyFixtureText('openssh/$key.pub').trim();
}

Uint8List sshsigMessage(String name) => keyFixture('openssh/sshsig/$name');
