// The one error type every key reader in `crypto/keys` throws, and the size
// cap they all apply before parsing.

/// The most a key reader takes: 1 MB. A private key file is a few KB at most
/// (an RSA 4096 key in PEM is 3.3 KB, an ML-DSA-65 key 5.5 KB); a GnuPG
/// export with photos and many signatures stays far below this.
const maxKeyInputLength = 1024 * 1024;

/// Why a key couldn't be read. The import sheet turns each into a message.
enum KeyProblem {
  /// A public key or a certificate, and no private key: a `.pub` line, an
  /// OpenSSH certificate, a `PUBLIC KEY` or `CERTIFICATE` PEM, an RFC 4716
  /// `SSH2 PUBLIC KEY` block, or an OpenPGP public key.
  publicKeyOnly,

  /// A PuTTY `.ppk` file. `puttygen` converts it to OpenSSH.
  puttyKey,

  /// A PEM key encrypted the legacy OpenSSL way, with `Proc-Type` and
  /// `DEK-Info` headers. `ssh-keygen -p -f <file>` rewrites it in OpenSSH
  /// format, `openssl pkcs8 -topk8` as PKCS#8.
  legacyPemEncryption,

  /// Encrypted with a cipher or key derivation this app doesn't read;
  /// [KeyFormatException.detail] names it (`chacha20-poly1305@openssh.com`,
  /// `scrypt`, `des-ede3-cbc`, ...).
  unsupportedCipher,

  /// A key type this app doesn't keep in this form;
  /// [KeyFormatException.detail] names it (`ecdsa-sha2-nistp521`,
  /// `sk-ssh-ed25519@openssh.com`, `OpenPGP version 5`, ...).
  unsupportedKeyType,

  /// Over [maxKeyInputLength].
  tooLarge,

  /// Looks like a key in a known format, but is cut short, has lengths that
  /// run past the end, or fails its own checks.
  damaged,

  /// Not a key in any format this app knows.
  unrecognized,

  /// The key is protected by a passphrase and none was given.
  passphraseNeeded,

  /// The passphrase given doesn't open the key.
  wrongPassphrase,

  /// A secret key where someone else's public key was asked for: a `PGP
  /// PRIVATE KEY BLOCK` or a binary OpenPGP secret key. Only the reader of
  /// other people's keys gives this; a private key is the person's own, and
  /// is imported as such.
  privateKeyGiven,
}

/// A key couldn't be read or written; [problem] says why. The readers in
/// `crypto/keys` throw this and nothing else, whatever the input.
class KeyFormatException implements Exception {
  const KeyFormatException(this.problem, [this.detail]);

  final KeyProblem problem;

  /// The cipher or key type for [KeyProblem.unsupportedCipher] and
  /// [KeyProblem.unsupportedKeyType]; otherwise a note for logs, not for
  /// people.
  final String? detail;

  @override
  String toString() => 'KeyFormatException: ${problem.name}${detail == null ? '' : ' ($detail)'}';
}

/// Throws [KeyProblem.damaged] unless [condition] holds.
void check(bool condition, [String? detail]) {
  if (!condition) throw KeyFormatException(KeyProblem.damaged, detail);
}

/// Throws [KeyProblem.tooLarge] for more than [maxKeyInputLength] bytes or
/// characters.
void checkSize(int length) {
  if (length > maxKeyInputLength) throw const KeyFormatException(KeyProblem.tooLarge);
}
