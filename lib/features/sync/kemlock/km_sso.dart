/// SSO through the system browser, bound by PKCE and the device key
/// (add-kemlock-server-sync, design 9). The server runs the code flow with
/// PKCE against the company's provider; the phone adds a second PKCE between
/// itself and the server:
///
/// 1. The phone makes `verifier`, and sends `challenge = S256(verifier)`, a
///    `state` of its own and a DPoP proof to `POST /auth/sso/start`.
/// 2. It opens the provider address it got back in the system's browser
///    sheet (`ASWebAuthenticationSession` on iOS, a Custom Tab on Android),
///    never a view the app draws.
/// 3. The server's callback ends the browser's trip at
///    `kemlock://sso?code=<one-time>&state=...`.
/// 4. The phone sends the code and `verifier` with a DPoP proof to
///    `POST /auth/sso/finish`. The server checks that both match step 1.
///
/// Another app can claim the `kemlock` scheme. A code taken that way is
/// useless without `verifier` and the device key, and a redirect whose
/// `state` isn't this sign-in's is dropped. A cancel leaves the phone signed
/// out. SSO never hands out a vault key: the account opens by the
/// trusted-device copy, an approval or the master password after it.
///
/// Pure Dart, no Flutter; the browser sheet is [KmBrowserAuth],
/// `platform/browser_auth.dart`'s channel.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/bytes.dart' show constantTimeEquals, randomBytes;
import 'km_signin.dart';

/// The system browser sheet.
abstract interface class KmBrowserAuth {
  /// Opens [url] and waits for the redirect to `kemlock://sso`. Returns the redirect's URL, or null when the
  /// person cancelled. [state] is what the redirect must carry: the platform drops one that carries another
  /// and keeps waiting. Throws a [KmBrowserFailure] when the sheet can't be opened.
  Future<Uri?> authenticate(Uri url, {required String state});

  /// Closes the sheet and ends a pending [authenticate] with null, as a "Cancel" on the sign-in sheet does.
  Future<void> cancel();
}

/// The browser sheet couldn't be opened: no browser, or a build without the native side.
class KmBrowserFailure implements Exception {
  const KmBrowserFailure([this.message]);

  final String? message;

  @override
  String toString() => 'KmBrowserFailure${message != null ? ': $message' : ''}';
}

/// The PKCE challenge of [verifier]: the unpadded base64url SHA-256 of its ASCII.
String ssoChallenge(String verifier) => b64urlEncode(hash.sha256.convert(verifier.codeUnits).bytes);

/// The one-time code a redirect to `kemlock://sso` carries, or the issue it stopped with.
String _readRedirect(Uri redirect, String state) {
  if (redirect.scheme != 'kemlock' || redirect.host != 'sso') {
    throw KmSignInError(KmSignInIssue.ssoFailed, detail: 'a redirect to ${redirect.scheme}://${redirect.host}');
  }
  final got = redirect.queryParameters['state'] ?? '';
  if (!constantTimeEquals(Uint8List.fromList(got.codeUnits), Uint8List.fromList(state.codeUnits))) {
    throw const KmSignInError(KmSignInIssue.ssoFailed, detail: 'the redirect is for another sign-in');
  }
  final error = redirect.queryParameters['error'];
  if (error != null) throw KmSignInError(KmSignInIssue.ssoFailed, detail: error);
  final code = redirect.queryParameters['code'];
  if (code == null || code.isEmpty) throw const KmSignInError(KmSignInIssue.ssoFailed, detail: 'no code');
  return code;
}

/// Signs [signIn] in through SSO and goes on from the server's answer: tokens, or a second step. The account
/// isn't open after it ([KmSignedIn.account] is null). A cancel throws [KmSignInIssue.cancelled]; nothing was kept.
/// [random] is for tests.
///
/// A browser has no `kemlock://` scheme: the extension gives its own [returnTo] (where the browser's identity API ends the trip), which
/// the server allows for a `kemlock-browser` device, and its [KmBrowserAuth] returns that address's query as a `kemlock://sso` one.
Future<KmSignInStep> kmSsoSignIn(
  KmSignIn signIn,
  KmBrowserAuth browser, {
  Uint8List Function(int length) random = randomBytes,
  Uri? returnTo,
}) async {
  final verifier = b64urlEncode(random(32));
  final state = b64urlEncode(random(24));
  final started = await signIn.auth.ssoStart(
    signIn.server,
    ssoChallenge(verifier),
    state,
    redirect: returnTo?.toString(),
    kind: returnTo == null ? null : signIn.device.kind,
  );
  final url = Uri.tryParse(started.url);
  // The provider is another host, but never plain http: the sheet would send the person's credentials in the clear
  if (url == null || url.scheme != 'https' || url.host.isEmpty) {
    throw KmSignInError(KmSignInIssue.unsupported, detail: 'the provider address isn’t https');
  }
  final Uri? redirect;
  try {
    redirect = await browser.authenticate(url, state: state);
  } on KmBrowserFailure catch (e) {
    throw KmSignInError(KmSignInIssue.ssoFailed, detail: e.message);
  }
  if (redirect == null) throw const KmSignInError(KmSignInIssue.cancelled);
  final code = _readRedirect(redirect, state);
  final answer = await signIn.auth.ssoFinish(signIn.server, code, verifier, signIn.device);
  return signIn.continueWith(answer);
}
