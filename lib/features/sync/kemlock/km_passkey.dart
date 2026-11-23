/// Signing in with a passkey or security key that has WebAuthn's PRF
/// extension, which signs in and also opens the account (add-kemlock-server-sync,
/// design 8, owner decision 4):
///
/// 1. `POST /auth/passkey/options` gives WebAuthn's request options and the
///    server's sealed challenge. The credentials are discoverable: the request
///    names no account, and the allow list is empty, so the authenticator
///    offers its own credential for the server;
/// 2. a [KmPasskeyAsserter] (a security key over NFC or USB through the app's
///    own CTAP stack, or Android 14's Credential Manager) signs the challenge
///    as a browser would, claiming the server's web-vault origin, and asks the
///    PRF for `first = SHA-256("kemlock/v1/prf-salt")` (`prfEvalInput`);
/// 3. `POST /auth/passkey/verify` signs the phone in, with the credential as a
///    browser's `PublicKeyCredential.toJSON()` writes it ([kmPasskeyCredential]),
///    and answers the copy of the root key this credential holds for the
///    account's current key version, when it has one;
/// 4. the PRF output unwraps that copy (`crypto.md` "The passkey PRF wrap"),
///    which opens the account.
///
/// The PRF output never leaves the phone: it goes straight into the unwrap and
/// is wiped, and it is not in the credential the server gets. A passkey with no
/// copy for the current key version, or an authenticator without PRF, signs in
/// but leaves the account to be opened by an approval or the password.
///
/// Pure Dart, no Flutter. The CTAP asserter is `lib/features/sync/kemlock_key_step.dart`.
library;

import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import 'km_auth_api.dart' show KmPasskeyOptions, KmSignInAnswer;
import 'km_signin.dart';

/// What an authenticator answered: the assertion the server verifies, and the PRF output when it gave one.
class KmPasskeyAssertion {
  const KmPasskeyAssertion({
    required this.credentialId,
    required this.authenticatorData,
    required this.clientData,
    required this.signature,
    this.userHandle,
    this.prfOutput,
  });

  final Uint8List credentialId;
  final Uint8List authenticatorData;

  /// The client data JSON as a browser writes it, which the signature covers by its hash.
  final Uint8List clientData;
  final Uint8List signature;

  /// The user handle of a discoverable credential, which the server checks against the one it made.
  final Uint8List? userHandle;

  /// The 32-byte PRF output for `prfEvalInput`, or null when the authenticator has no PRF.
  final Uint8List? prfOutput;
}

/// An authenticator that signs a passkey challenge and asks the PRF.
abstract interface class KmPasskeyAsserter {
  /// Signs [options]' challenge for the server at [server]. Throws what the authenticator throws (cancelled,
  /// no credential, a PIN it locked).
  Future<KmPasskeyAssertion> assertion(KmPasskeyOptions options, Uint8List prfInput, Uri server);
}

/// [assertion] as the browser's `PublicKeyCredential.toJSON()` for `navigator.credentials.get`, which
/// `/auth/passkey/verify` takes. It carries no `clientExtensionResults`: the PRF output is a secret that opens the
/// vault, and the server has no use for it.
Map<String, Object?> kmPasskeyCredential(KmPasskeyAssertion assertion) {
  final id = b64urlEncode(assertion.credentialId);
  final handle = assertion.userHandle;
  return {
    'id': id,
    'rawId': id,
    'type': 'public-key',
    'response': {
      'authenticatorData': b64urlEncode(assertion.authenticatorData),
      'clientDataJSON': b64urlEncode(assertion.clientData),
      'signature': b64urlEncode(assertion.signature),
      'userHandle': handle == null ? null : b64urlEncode(handle),
    },
    'clientExtensionResults': <String, Object?>{},
  };
}

/// Signs [signIn] in with a passkey and, when the authenticator gave a PRF output and the server a copy of the root
/// key for it, opens the account with them. Goes on as [KmSignIn.continueWith] does. [email] is only what the
/// sign-in remembers for later steps: the request names no account.
Future<KmSignInStep> kmPasskeySignIn(KmSignIn signIn, KmPasskeyAsserter asserter, String email, Uint8List prfInput) async {
  final options = await signIn.auth.passkeyOptions(signIn.server);
  final assertion = await asserter.assertion(options, prfInput, signIn.server);
  final prf = assertion.prfOutput;
  try {
    final answer = await signIn.auth.passkeyVerify(signIn.server, options.sealedChallenge, kmPasskeyCredential(assertion), signIn.device);
    final step = await signIn.continueWith(KmSignInAnswer(grant: answer.grant), email: email);
    final wrap = answer.prf;
    if (step is KmSignedIn && prf != null && wrap != null) {
      final account = await signIn.openWithPrf(step.session, prf, assertion.credentialId, wrap);
      if (account != null) {
        return KmSignedIn(session: step.session, account: account, newAccount: step.newAccount, mfaViaSso: step.mfaViaSso);
      }
    }
    return step;
  } finally {
    if (prf != null) {
      wipe(prf);
    }
  }
}
