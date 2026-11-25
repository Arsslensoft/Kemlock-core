/// What a browser's passkey provider does with a WebAuthn request, with no browser in it: the relying party
/// checked against the origin that asks, a new ES256 passkey and the response a site gets for it, and the
/// assertion that signs a person in.
///
/// It makes the same bytes as the phone's providers (`passkey_bytes.dart`, held by the fixtures in
/// `test/fixtures/passkeys`), so a passkey made here signs in on the phone and the other way round:
///
/// - the credential id is 16 random bytes (Bitwarden keeps one as a GUID, so plain Vaultwarden storage
///   round-trips), the key is P-256 and is kept as PKCS#8 DER in base64, and the user handle as the site gave it;
/// - authenticator data has the flags user present, user verified, backup eligible and backup state (0x5D with
///   attested credential data on creation, 0x1D when signing in), a counter of 0 and Kemlock's AAGUID;
/// - attestation is `none`;
/// - the client data is `{"type", "challenge", "origin", "crossOrigin"}` in that order, with `topOrigin` after them
///   when a frame of another origin asks.
///
/// A request here is `PublicKeyCredentialCreationOptionsJSON` or `PublicKeyCredentialRequestOptionsJSON` (WebAuthn
/// Level 3), the binary values in base64url, which is also how the phone's providers read them.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../core/ids.dart';
import '../../core/public_suffix_list.dart';
import '../../crypto/bytes.dart';
import '../../crypto/p256.dart';
import '../../models/passkey.dart';
import 'passkey_bytes.dart';

/// What a request that Kemlock cannot answer is, in the DOM's own words: the extension answers the page with
/// that exception, or hands the request to the browser.
enum PasskeyFailure {
  /// `SecurityError`: the relying party isn't one this origin may use, or the origin isn't a secure one.
  security,

  /// `NotSupportedError`: no algorithm the site takes is one Kemlock makes.
  notSupported,

  /// `InvalidStateError`: the site excludes a credential Kemlock already holds.
  invalidState,

  /// `EncodingError`: the request isn't one that can be read.
  encoding,

  /// `NotAllowedError`: no passkey Kemlock holds is one the site takes.
  notAllowed,
}

/// A request Kemlock can't answer.
class PasskeyRequestError implements Exception {
  const PasskeyRequestError(this.failure, [this.detail = '']);

  final PasskeyFailure failure;
  final String detail;

  @override
  String toString() => 'PasskeyRequestError(${failure.name}${detail.isEmpty ? '' : ': $detail'})';
}

/// COSE's number for ES256, the only algorithm Kemlock makes.
const passkeyEs256 = coseEs256;

final _ipv4 = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$');
final _domain = RegExp(r'^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$');

/// The host of [origin], lowercase with no trailing dot, when it is an origin a passkey may be used from: https, or
/// http on `localhost` (and the names under it); anything else throws a `security` failure. An address, which WebAuthn
/// has no relying party for, is refused too.
String passkeyHost(String origin) {
  final uri = Uri.tryParse(origin);
  if (uri == null || !uri.hasAuthority || uri.host.isEmpty) throw const PasskeyRequestError(PasskeyFailure.security, 'no origin');
  var host = uri.host.toLowerCase();
  if (host.endsWith('.')) host = host.substring(0, host.length - 1);
  final local = host == 'localhost' || host.endsWith('.localhost');
  if (uri.scheme != 'https' && !(uri.scheme == 'http' && local)) {
    throw const PasskeyRequestError(PasskeyFailure.security, 'not a secure origin');
  }
  if (host.contains(':') || _ipv4.hasMatch(host) || !_domain.hasMatch(host)) {
    throw const PasskeyRequestError(PasskeyFailure.security, 'not a domain');
  }
  return host;
}

/// The relying party id a request from [origin] uses: [rpId] when it names one (it must be the origin's host, or a
/// registrable domain that is a suffix of it by whole labels), and else the origin's host. Throws a `security` failure
/// when it is not one the origin may use. [suffixes] is the Public Suffix List; without it only the origin's own host
/// is accepted.
String checkPasskeyRp({required String origin, String? rpId, PublicSuffixList? suffixes}) {
  final host = passkeyHost(origin);
  var wanted = rpId?.trim().toLowerCase() ?? '';
  if (wanted.isEmpty) return host;
  if (wanted.endsWith('.')) wanted = wanted.substring(0, wanted.length - 1);
  if (!_domain.hasMatch(wanted) || _ipv4.hasMatch(wanted)) {
    throw const PasskeyRequestError(PasskeyFailure.security, 'not a domain');
  }
  if (wanted == host) return host;
  if (!host.endsWith('.$wanted')) throw const PasskeyRequestError(PasskeyFailure.security, 'not a suffix of the origin');
  // A public suffix (`com`, `co.uk`, `github.io`) is no one's relying party; the Public Suffix List gives no registrable
  // domain for one
  if (suffixes == null || suffixes.registrableDomain(wanted) == null) {
    throw const PasskeyRequestError(PasskeyFailure.security, 'a public suffix');
  }
  return wanted;
}

Uint8List _urlBytes(Object? value, String name, {int? max}) {
  if (value is! String || value.isEmpty) throw PasskeyRequestError(PasskeyFailure.encoding, 'no $name');
  final Uint8List bytes;
  try {
    bytes = unb64url(value);
  } on FormatException {
    throw PasskeyRequestError(PasskeyFailure.encoding, '$name is not base64url');
  }
  if (max != null && bytes.length > max) throw PasskeyRequestError(PasskeyFailure.encoding, '$name is over $max bytes');
  return bytes;
}

/// The credential ids of a list of `{"type": "public-key", "id": …}` descriptors; one that doesn't decode is left out.
List<Uint8List> _descriptors(Object? list) {
  final out = <Uint8List>[];
  if (list is! List<Object?>) return out;
  for (final entry in list) {
    if (entry is! Map<String, Object?>) continue;
    if ((entry['type'] ?? 'public-key') != 'public-key') continue;
    try {
      out.add(_urlBytes(entry['id'], 'id'));
    } on PasskeyRequestError {
      continue;
    }
  }
  return out;
}

String? _text(Object? value) => value is String && value.isNotEmpty ? value : null;

/// What a site asks of a new passkey (`PublicKeyCredentialCreationOptionsJSON`), the part Kemlock reads.
class CreationRequest {
  const CreationRequest({
    required this.rpId,
    required this.rpName,
    required this.userHandle,
    required this.userName,
    required this.userDisplayName,
    required this.challenge,
    required this.algorithms,
    required this.excluded,
    required this.credProps,
  });

  factory CreationRequest.parse(Map<String, Object?> json) {
    final rp = json['rp'];
    final user = json['user'];
    if (rp is! Map<String, Object?>) throw const PasskeyRequestError(PasskeyFailure.encoding, 'no rp');
    if (user is! Map<String, Object?>) throw const PasskeyRequestError(PasskeyFailure.encoding, 'no user');
    final params = json['pubKeyCredParams'];
    final algorithms = <int>[
      if (params is List<Object?>)
        for (final entry in params)
          if (entry is Map<String, Object?> && (entry['type'] ?? 'public-key') == 'public-key' && entry['alg'] is int) entry['alg']! as int,
    ];
    if (params is List<Object?> && params.isNotEmpty && algorithms.isEmpty) {
      throw const PasskeyRequestError(PasskeyFailure.encoding, 'no public-key algorithm');
    }
    final extensions = json['extensions'];
    return CreationRequest(
      rpId: _text(rp['id'])?.toLowerCase(),
      rpName: _text(rp['name']),
      userHandle: _urlBytes(user['id'], 'user id', max: 64),
      userName: user['name'] is String ? user['name']! as String : '',
      userDisplayName: _text(user['displayName']),
      challenge: _urlBytes(json['challenge'], 'challenge'),
      algorithms: algorithms,
      excluded: _descriptors(json['excludeCredentials']),
      credProps: extensions is Map<String, Object?> && extensions['credProps'] == true,
    );
  }

  /// The relying party's id; a request may leave it to the origin's host.
  final String? rpId;
  final String? rpName;
  final Uint8List userHandle;
  final String userName;
  final String? userDisplayName;
  final Uint8List challenge;

  /// The COSE algorithms the site accepts, in its order; empty means WebAuthn's defaults, ES256 among them.
  final List<int> algorithms;

  /// Credentials the site already has for the account, which Kemlock must not make again.
  final List<Uint8List> excluded;

  /// The site asks whether the passkey is discoverable.
  final bool credProps;

  bool get acceptsEs256 => algorithms.isEmpty || algorithms.contains(passkeyEs256);
}

/// What a site asks to sign in with (`PublicKeyCredentialRequestOptionsJSON`), the part Kemlock reads.
class AssertionRequest {
  const AssertionRequest({required this.rpId, required this.challenge, required this.allowed});

  factory AssertionRequest.parse(Map<String, Object?> json) => AssertionRequest(
    rpId: _text(json['rpId'])?.toLowerCase(),
    challenge: _urlBytes(json['challenge'], 'challenge'),
    allowed: _descriptors(json['allowCredentials']),
  );

  final String? rpId;
  final Uint8List challenge;

  /// The credentials the site takes; empty means any of the relying party's.
  final List<Uint8List> allowed;
}

/// The passkeys of [all] for exactly [rpId], never a subdomain or a parent of it, that [allowed] takes when it names any,
/// each credential once.
List<Passkey> matchingPasskeys(String rpId, List<Uint8List> allowed, Iterable<Passkey> all) {
  final rp = _comparableRp(rpId);
  final seen = <String>{};
  final out = <Passkey>[];
  for (final passkey in all) {
    final Uint8List id;
    try {
      id = unb64url(passkey.credentialId);
    } on FormatException {
      continue;
    }
    if (_comparableRp(passkey.rpId) != rp) continue;
    if (allowed.isNotEmpty && !allowed.any((candidate) => _same(candidate, id))) continue;
    if (seen.add(b64url(id))) out.add(passkey);
  }
  return out;
}

String _comparableRp(String rpId) {
  final lower = rpId.toLowerCase();
  return lower.endsWith('.') ? lower.substring(0, lower.length - 1) : lower;
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// A P-256 public key as SubjectPublicKeyInfo DER, as `getPublicKey()` hands it to a site.
Uint8List p256Spki(Uint8List point) {
  const prefix = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, //
  ];
  return Uint8List.fromList([...prefix, ...point]);
}

/// The client data of a WebAuthn operation: what the browser would write, in the order the phone's providers write it.
/// A request from a frame of another origin than the page's carries `crossOrigin: true` and the page's [topOrigin].
String passkeyClientData(String type, Uint8List challenge, String origin, {String? topOrigin}) {
  final cross = topOrigin != null && topOrigin != origin;
  return jsonEncode(<String, Object?>{
    'type': type,
    'challenge': b64url(challenge),
    'origin': origin,
    'crossOrigin': cross,
    if (cross) 'topOrigin': topOrigin,
  });
}

/// A new passkey and what the site is answered.
class CreatedPasskey {
  const CreatedPasskey(this.passkey, this.response);

  /// The record for the vault.
  final Passkey passkey;

  /// `RegistrationResponseJSON`, every binary value base64url.
  final Map<String, Object?> response;
}

/// A new ES256 passkey for [request] at [rpId] (already checked against [origin] by [checkPasskeyRp]), with attestation `none`.
/// [held] are the passkeys the vault has, to refuse one the site excludes. [now] is epoch ms. [key], [credentialId] and [id]
/// are fresh unless given, as the tests do.
CreatedPasskey createPasskey({
  required CreationRequest request,
  required String rpId,
  required String origin,
  String? topOrigin,
  required int now,
  Iterable<Passkey> held = const [],
  P256KeyPair? key,
  Uint8List? credentialId,
  String? id,
}) {
  if (!request.acceptsEs256) throw const PasskeyRequestError(PasskeyFailure.notSupported, 'Kemlock makes ES256 passkeys only');
  // Credentials the vault holds for this relying party, as the ids a site writes them
  final known = {for (final passkey in matchingPasskeys(rpId, const [], held)) b64url(unb64url(passkey.credentialId))};
  for (final excluded in request.excluded) {
    if (known.contains(b64url(excluded))) throw const PasskeyRequestError(PasskeyFailure.invalidState, 'already registered');
  }
  final pair = key ?? newP256KeyPair();
  final credential = credentialId ?? randomBytes(16);
  final authData = registrationAuthData(rpId: rpId, credentialId: credential, point: pair.point);
  final credentialText = b64url(credential);
  final clientData = utf8.encode(passkeyClientData('webauthn.create', request.challenge, origin, topOrigin: topOrigin));
  final passkey = Passkey(
    id: id ?? newUuid(),
    credentialId: credentialText,
    rpId: rpId,
    rpName: request.rpName,
    userHandle: b64url(request.userHandle),
    userName: request.userName,
    userDisplayName: request.userDisplayName,
    privateKey: b64(pair.toPkcs8()),
    addedAt: now,
  );
  final response = <String, Object?>{
    'id': credentialText,
    'rawId': credentialText,
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': <String, Object?>{
      'clientDataJSON': b64url(clientData),
      'attestationObject': b64url(attestationObject(authData)),
      'authenticatorData': b64url(authData),
      'transports': const ['internal'],
      'publicKeyAlgorithm': passkeyEs256,
      'publicKey': b64url(p256Spki(pair.point)),
    },
    'clientExtensionResults': request.credProps
        ? <String, Object?>{
            'credProps': {'rk': true},
          }
        : <String, Object?>{},
  };
  return CreatedPasskey(passkey, response);
}

/// A sign-in with [passkey], which holds its key, for [challenge] from [origin]: the authenticator data signed with the client
/// data's hash. `AuthenticationResponseJSON`, every binary value base64url.
Future<Map<String, Object?>> assertPasskey({
  required Passkey passkey,
  required Uint8List challenge,
  required String origin,
  String? topOrigin,
}) async {
  final key = await P256KeyPair.fromPkcs8(unb64(passkey.privateKey));
  final authData = assertionAuthData(passkey.rpId);
  final clientData = Uint8List.fromList(utf8.encode(passkeyClientData('webauthn.get', challenge, origin, topOrigin: topOrigin)));
  final hash = Uint8List.fromList(sha256.convert(clientData).bytes);
  final signature = es256Sign(key, assertionSignedBytes(authData, hash));
  final id = b64url(unb64url(passkey.credentialId));
  return {
    'id': id,
    'rawId': id,
    'type': 'public-key',
    'authenticatorAttachment': 'platform',
    'response': <String, Object?>{
      'clientDataJSON': b64url(clientData),
      'authenticatorData': b64url(authData),
      'signature': b64url(signature),
      'userHandle': b64url(unb64url(passkey.userHandle)),
    },
    'clientExtensionResults': <String, Object?>{},
  };
}
