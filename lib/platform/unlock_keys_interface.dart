// Pure Dart: the errors of the phone's hardware key for biometric unlock, and what a platform gives to it. The method
// channel over it is in `unlock_keys.dart`.
import 'dart:typed_data';

/// Why the phone's hardware key for biometric unlock didn't give or keep a
/// key (openspec: harden-unlock-and-clipboard, biometric-unlock).
sealed class UnlockKeyError implements Exception {
  const UnlockKeyError();

  /// The code the platform channel sends for it.
  String get code;
}

/// The person cancelled the system's prompt.
class UnlockKeyCancelled extends UnlockKeyError {
  const UnlockKeyCancelled();

  @override
  String get code => 'cancelled';

  @override
  String toString() => 'The biometric prompt was cancelled.';
}

/// The key no longer opens: a face or fingerprint was added, the phone's
/// passcode was removed, or the key is gone.
class UnlockKeyInvalidated extends UnlockKeyError {
  const UnlockKeyInvalidated();

  @override
  String get code => 'invalidated';

  @override
  String toString() => 'The phone’s biometrics changed since biometric unlock was turned on.';
}

/// The phone has no biometrics the key can be bound to (on Android, none of
/// Class 3), or a build without the native side.
class UnlockKeyUnavailable extends UnlockKeyError {
  const UnlockKeyUnavailable();

  @override
  String get code => 'unavailable';

  @override
  String toString() => 'This phone has no biometrics Kemlock can use.';
}

/// The system's prompt itself failed: biometrics locked out after too many
/// tries, the prompt timed out, or the sensor's own error, with the
/// system's [message]. Nothing else may open the vault in its place: the
/// old entry's fallback prompt is weaker (on Android it takes Class 2
/// biometrics), and would undo the lockout.
class UnlockKeyPromptFailed extends UnlockKeyError {
  const UnlockKeyPromptFailed([this.message]);

  final String? message;

  @override
  String get code => 'prompt';

  @override
  String toString() => message ?? 'The biometric prompt failed.';
}

/// Anything else, with the system's [message] when it gave one: the
/// Keystore or Keychain failing, after the prompt was passed or before it
/// showed.
class UnlockKeyFailed extends UnlockKeyError {
  const UnlockKeyFailed([this.message]);

  final String? message;

  @override
  String get code => 'failed';

  @override
  String toString() => message ?? 'Biometric unlock failed.';
}

/// The error a platform channel [code] stands for, with its [message].
UnlockKeyError unlockKeyError(String code, [String? message]) => switch (code) {
  'cancelled' => const UnlockKeyCancelled(),
  'invalidated' => const UnlockKeyInvalidated(),
  'unavailable' => const UnlockKeyUnavailable(),
  'prompt' => UnlockKeyPromptFailed(message),
  _ => UnlockKeyFailed(message),
};

/// The phone's side of biometric unlock: a 32-byte key per vault, kept in
/// the iOS Keychain (`ios/Runner/UnlockKeyChannel.swift`) or wrapped by an
/// Android Keystore key (`android/.../unlock/UnlockKeyChannel.kt`), and
/// given out only after the system's biometric prompt, which these calls
/// show. On Android that has to be the prompt that authorises the key, so
/// `local_auth` can't show it.
abstract interface class UnlockKeys {
  /// Whether the phone has biometrics the key can be bound to: Face ID or
  /// Touch ID with a passcode set on iOS, Class 3 biometrics on Android.
  Future<bool> status();

  /// Shows the prompt with [reason], then puts [key] in the hardware for
  /// [vault], replacing any earlier one. Returns what the vault's entry
  /// keeps beside it to open it again: the wrapped key on Android, nothing
  /// on iOS. Throws an [UnlockKeyError].
  Future<String> seal(String vault, Uint8List key, String reason);

  /// Shows the prompt with [reason] and returns [vault]'s key, given the
  /// [wrap] that [seal] returned. Throws an [UnlockKeyError].
  Future<Uint8List> open(String vault, String wrap, String reason);

  /// Deletes [vault]'s key, if there is one.
  Future<void> delete(String vault);

  /// Deletes every vault's key, and no other key of the app.
  Future<void> deleteAll();
}

/// [UnlockKeys] for a build with no hardware keys, as one without the native side has none: no biometrics, no key
/// kept, and every call that needs one throws [UnlockKeyUnavailable]. The default where nothing else is given.
class NoUnlockKeys implements UnlockKeys {
  const NoUnlockKeys();

  @override
  Future<bool> status() async => false;

  @override
  Future<String> seal(String vault, Uint8List key, String reason) => Future.error(const UnlockKeyUnavailable());

  @override
  Future<Uint8List> open(String vault, String wrap, String reason) => Future.error(const UnlockKeyUnavailable());

  @override
  Future<void> delete(String vault) async {}

  @override
  Future<void> deleteAll() async {}
}
