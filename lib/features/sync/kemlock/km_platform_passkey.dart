/// A passkey held by the phone's credential provider, through Android 14's
/// Credential Manager (add-kemlock-server-sync, task 7.2, owner decision 4).
///
/// The platform checks the server's name against the app itself: the server
/// must serve `/.well-known/assetlinks.json` naming this app's package with
/// the `delegate_permission/common.get_login_creds` relation. The phone reads
/// that file first ([assetLinksNameApp]) so the way in is offered only where it
/// can work. There are no platform passkeys on iOS: the native side exists
/// only on Android, and the security key and the password stay.
///
/// This builds the WebAuthn request as JSON and reads the answer, so the
/// native side only carries two strings. The PRF extension asks for the
/// output of `prfEvalInput`, which opens the account like a security key's.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import 'km_auth_api.dart' show KmPasskeyOptions;
import 'km_passkey.dart';

/// What the phone can do: whether its credential provider can be asked, and the app's package name.
class KmPlatformPasskeyInfo {
  const KmPlatformPasskeyInfo({required this.supported, this.package});

  static const unsupported = KmPlatformPasskeyInfo(supported: false);

  final bool supported;
  final String? package;
}

/// The phone's credential provider.
abstract interface class KmPlatformPasskeys {
  Future<KmPlatformPasskeyInfo> info();

  /// Asks for a passkey with the WebAuthn request [requestJson] and returns its response as JSON. A closed picker
  /// throws `SecurityKeyCancelled`; anything else a [KmPlatformPasskeyError].
  Future<String> get(String requestJson);
}

/// The credential provider refused or failed: [code] is `noCredential` when the phone has no passkey for the
/// account, `unsupported` or `failed`.
class KmPlatformPasskeyError implements Exception {
  const KmPlatformPasskeyError(this.code, [this.message]);

  final String code;
  final String? message;

  @override
  String toString() => 'KmPlatformPasskeyError($code${message != null ? ': $message' : ''})';
}

/// Whether the statements of an `assetlinks.json` name [package] for the passkey relation.
bool assetLinksNameApp(Object? statements, String package) {
  if (statements is! List<Object?>) return false;
  for (final statement in statements) {
    if (statement is! Map<String, Object?>) continue;
    final relation = statement['relation'];
    final target = statement['target'];
    if (relation is List<Object?> &&
        relation.contains('delegate_permission/common.get_login_creds') &&
        target is Map<String, Object?> &&
        target['namespace'] == 'android_app' &&
        target['package_name'] == package) {
      return true;
    }
  }
  return false;
}

/// The WebAuthn `PublicKeyCredentialRequestOptions` for [options], as JSON, with the PRF asked for [prfInput]. The
/// allow list is empty for the server's discoverable credentials, so the provider offers the phone's passkeys for it.
String platformPasskeyRequest(KmPasskeyOptions options, Uint8List prfInput) => jsonEncode({
  'challenge': b64urlEncode(options.challenge),
  'rpId': options.rpId,
  'timeout': 60000,
  'userVerification': options.userVerification,
  'allowCredentials': [
    for (final id in options.credentialIds) {'type': 'public-key', 'id': b64urlEncode(id)},
  ],
  'extensions': {
    'prf': {
      'eval': {'first': b64urlEncode(prfInput)},
    },
  },
});

/// The assertion in the credential provider's JSON answer. A PRF output that isn't 32 bytes is no output.
KmPasskeyAssertion readPlatformPasskeyResponse(String json) {
  try {
    final decoded = jsonDecode(json);
    if (decoded is! Map<String, Object?>) throw const FormatException('not an object');
    final response = decoded['response'];
    if (response is! Map<String, Object?>) throw const FormatException('no response');
    Uint8List bytes(Object? value, String name) {
      if (value is! String || value.isEmpty) throw FormatException('no $name');
      return b64urlDecode(value);
    }

    Uint8List? prf;
    final extensions = decoded['clientExtensionResults'];
    final results = extensions is Map<String, Object?> && extensions['prf'] is Map<String, Object?>
        ? (extensions['prf']! as Map<String, Object?>)['results']
        : null;
    if (results is Map<String, Object?> && results['first'] is String) {
      final output = b64urlDecode(results['first']! as String);
      if (output.length == 32) prf = output;
    }
    return KmPasskeyAssertion(
      credentialId: bytes(decoded['rawId'] ?? decoded['id'], 'credential id'),
      authenticatorData: bytes(response['authenticatorData'], 'authenticator data'),
      clientData: bytes(response['clientDataJSON'], 'client data'),
      signature: bytes(response['signature'], 'signature'),
      userHandle: response['userHandle'] is String && (response['userHandle']! as String).isNotEmpty
          ? b64urlDecode(response['userHandle']! as String)
          : null,
      prfOutput: prf,
    );
  } on FormatException catch (e) {
    throw KmPlatformPasskeyError('failed', e.message);
  } on MalformedException catch (e) {
    throw KmPlatformPasskeyError('failed', e.message);
  }
}

/// A [KmPasskeyAsserter] over the phone's credential provider.
class KmPlatformAsserter implements KmPasskeyAsserter {
  const KmPlatformAsserter(this.passkeys);

  final KmPlatformPasskeys passkeys;

  @override
  Future<KmPasskeyAssertion> assertion(KmPasskeyOptions options, Uint8List prfInput, Uri server) async =>
      readPlatformPasskeyResponse(await passkeys.get(platformPasskeyRequest(options, prfInput)));
}
