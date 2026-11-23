// The one error type the OpenPGP message code throws, as `key_error.dart`
// is for the key readers.

import '../key_error.dart';

/// Why a message could not be read or written. The sheets turn each into a
/// sentence.
enum PgpProblem {
  /// Not an OpenPGP message, signature or key at all.
  notAMessage,

  /// Encrypted to keys that are not among those given;
  /// [PgpException.keyIds] names them.
  noKeyOpensIt,

  /// A passphrase is needed and none was given: the message's own, or that
  /// of the key [PgpException.fingerprint] names.
  passphraseNeeded,

  /// The passphrase given opens neither the key nor the message.
  wrongPassphrase,

  /// Cut short, altered, or failing its own checks.
  damaged,

  /// The old encrypted form that nothing protects against tampering.
  noIntegrity,

  /// A cipher, key algorithm, hash, passphrase method or format this app
  /// does not handle; [PgpException.detail] is its usual name.
  unsupported,

  /// A key that may not be used for this; [PgpException.reason] says why.
  keyUnusable,

  /// The key's secret part is not in this copy (a GnuPG stub).
  noSecretHere,

  /// Over a bound: a pasted text, or what a compressed message unpacks to.
  tooLarge,

  /// The phone ran out of space while writing.
  outOfSpace,

  /// Stopped by the person or by the vault locking.
  cancelled,
}

/// Why a key may not encrypt or sign.
enum PgpKeyTrouble {
  expired,
  revoked,

  /// Its self-signatures do not verify.
  invalid,

  /// RSA under 2048 bits: read, never written to or with.
  weak,

  /// It has no key that may do this (no encryption or signing flag).
  noSuchKey,
}

/// What the OpenPGP message code throws, and nothing else, whatever the
/// input.
class PgpException implements Exception {
  const PgpException(this.problem, {this.detail, this.keyIds = const [], this.reason, this.fingerprint});

  final PgpProblem problem;

  /// The name to show for [PgpProblem.unsupported]; otherwise a note for
  /// tests, never for people.
  final String? detail;

  /// For [PgpProblem.noKeyOpensIt]: the key IDs the message names, in
  /// upper-case hexadecimal. A hidden recipient is not among them.
  final List<String> keyIds;

  /// For [PgpProblem.keyUnusable].
  final PgpKeyTrouble? reason;

  /// The primary key fingerprint, in upper-case hexadecimal, of the key a
  /// [PgpProblem.keyUnusable], [PgpProblem.passphraseNeeded],
  /// [PgpProblem.wrongPassphrase] or [PgpProblem.noSecretHere] is about.
  final String? fingerprint;

  @override
  String toString() =>
      'PgpException: ${problem.name}${detail == null ? '' : ' ($detail)'}${reason == null ? '' : ' ${reason!.name}'}'
      '${keyIds.isEmpty ? '' : ' $keyIds'}';
}

/// Throws [PgpProblem.damaged] unless [condition] holds.
void pgpCheck(bool condition, [String? detail]) {
  if (!condition) throw PgpException(PgpProblem.damaged, detail: detail);
}

/// Runs [body], turning what the key readers throw into a [PgpException]:
/// the message code reads keys too, and must throw one type only.
T asPgpError<T>(T Function() body) {
  try {
    return body();
  } on KeyFormatException catch (e) {
    throw pgpErrorOf(e);
  }
}

/// The [PgpException] that stands for a key reader's error.
PgpException pgpErrorOf(KeyFormatException e) => switch (e.problem) {
  KeyProblem.unsupportedKeyType || KeyProblem.unsupportedCipher => PgpException(PgpProblem.unsupported, detail: e.detail),
  KeyProblem.tooLarge => const PgpException(PgpProblem.tooLarge),
  KeyProblem.passphraseNeeded => const PgpException(PgpProblem.passphraseNeeded),
  KeyProblem.wrongPassphrase => const PgpException(PgpProblem.wrongPassphrase),
  KeyProblem.unrecognized ||
  KeyProblem.publicKeyOnly ||
  KeyProblem.privateKeyGiven ||
  KeyProblem.puttyKey ||
  KeyProblem.legacyPemEncryption => PgpException(PgpProblem.notAMessage, detail: e.detail),
  KeyProblem.damaged => PgpException(PgpProblem.damaged, detail: e.detail),
};
