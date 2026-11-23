// Pure Dart: what the vault asks of the phone's biometric prompt. `biometrics.dart` has the `local_auth` one.

/// The system's biometric prompt failed in a way worth telling the person
/// about. [message] is the system's description, when it gave one.
class BiometricError implements Exception {
  const BiometricError([this.message]);

  final String? message;

  @override
  String toString() => message ?? 'Biometric authentication failed.';
}

/// Face ID, Touch ID or the fingerprint sensor: the gate in front of the
/// stored biometric unlock, as `@aparajita/capacitor-biometric-auth` was.
abstract interface class Biometrics {
  /// True when the phone has biometrics set up that the app can use.
  Future<bool> isAvailable();

  /// Shows the system prompt with [reason]. True when the person passed it,
  /// false when they cancelled; throws [BiometricError] when it can't run.
  Future<bool> authenticate(String reason);
}
