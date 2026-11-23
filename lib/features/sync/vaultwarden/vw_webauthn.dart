/// The WebAuthn side of signing in to Vaultwarden with a security key
/// (openspec: add-vaultwarden-security-key): the challenge the server
/// gives for provider 7, the origin Kemlock claims, the rule for which
/// name a key may be asked about, the client data a browser would write,
/// and the public-key credential JSON the server takes as the second
/// step's token. Pure Dart: nothing here talks to a key or to the server.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../core/public_suffix_list.dart';
import '../../../crypto/bytes.dart';

/// The server's challenge for a security key: the WebAuthn request options
/// it puts under `"7"` in `TwoFactorProviders2`.
class VwKeyChallenge {
  const VwKeyChallenge({
    required this.challenge,
    required this.rpId,
    required this.allowCredentials,
    required this.timeout,
    required this.receivedAt,
    this.appId,
  });

  /// The challenge exactly as the server wrote it (base64url), which is
  /// how the client data repeats it.
  final String challenge;

  /// The name the server wants the key asked about.
  final String rpId;

  /// The ids of the credentials registered with the account.
  final List<Uint8List> allowCredentials;

  /// How long the server keeps the challenge.
  final Duration timeout;

  /// When the answer carrying it arrived.
  final DateTime receivedAt;

  /// The U2F-era address (`extensions.appid`), when the server sends one.
  /// Kemlock never asks a key under it; it only shapes a message.
  final String? appId;

  /// How long before its end a challenge is no longer used.
  static const margin = Duration(seconds: 10);

  /// The time the server allows when its challenge names none.
  static const defaultTimeout = Duration(minutes: 1);

  /// Reads the options in [json]. Null, "no challenge", when they are
  /// missing or malformed: no `challenge`, no `rpId`, or no credential.
  static VwKeyChallenge? parse(Object? json, {required DateTime receivedAt}) {
    if (json is! Map<String, Object?>) return null;
    final challenge = json['challenge'];
    final rpId = json['rpId'];
    final allowed = json['allowCredentials'];
    if (challenge is! String || challenge.isEmpty || !_base64url.hasMatch(challenge)) return null;
    if (rpId is! String || rpId.trim().isEmpty) return null;
    if (allowed is! List) return null;
    final ids = <Uint8List>[];
    for (final credential in allowed) {
      if (credential is! Map<String, Object?>) continue;
      final type = credential['type'];
      final id = credential['id'];
      if ((type != null && type != 'public-key') || id is! String || id.isEmpty) continue;
      try {
        ids.add(unb64url(id));
      } on FormatException {
        continue;
      }
    }
    if (ids.isEmpty) return null;
    final timeout = json['timeout'];
    final extensions = json['extensions'];
    final appId = extensions is Map<String, Object?> ? extensions['appid'] : null;
    return VwKeyChallenge(
      challenge: challenge,
      rpId: rpId.trim().toLowerCase(),
      allowCredentials: List.unmodifiable(ids),
      timeout: timeout is num && timeout > 0 ? Duration(milliseconds: timeout.toInt()) : defaultTimeout,
      receivedAt: receivedAt,
      appId: appId is String && appId.isNotEmpty ? appId : null,
    );
  }

  /// Whether the server still keeps the challenge at [now], with [margin]
  /// to spare for the key and the request.
  bool isFresh(DateTime now) => now.difference(receivedAt) < timeout - margin;

  @override
  String toString() => 'VwKeyChallenge($rpId, ${allowCredentials.length} credentials)';
}

final _base64url = RegExp(r'^[A-Za-z0-9_-]+=*$');
final _ipv4 = RegExp(r'^\d{1,3}(\.\d{1,3}){3}$');

String _host(Uri server) => server.host.toLowerCase();

/// The origin a browser showing [server]'s web vault would report: the
/// scheme, the host, and the port when it is not https's own. A path in
/// the address is not part of an origin.
String vwKeyOrigin(Uri server) {
  final host = _host(server);
  final named = host.contains(':') ? '[$host]' : host;
  return 'https://$named${server.hasPort && server.port != 443 ? ':${server.port}' : ''}';
}

/// Whether a key may be asked about [rpId] while signing in to [server]:
/// when it is the address's host, or a parent domain of it that is no
/// public suffix by the Public Suffix List ([suffixes]), as a browser
/// rules. A suffix anyone can register a name under, `co.uk` for
/// `vault.example.co.uk` or `herokuapp.com` for an app there, is never
/// one: a key's credential for it would answer for every site under it.
/// Without the list, only the host itself. A host that is an IP address
/// has no parent domain.
bool vwKeyRpIdAllowed(String rpId, Uri server, {PublicSuffixList? suffixes}) {
  final host = _host(server);
  final wanted = rpId.trim().toLowerCase();
  if (wanted.isEmpty || host.isEmpty) return false;
  if (wanted == host) return true;
  if (suffixes == null || _ipv4.hasMatch(host) || host.contains(':')) return false;
  if (!wanted.contains('.') || wanted.startsWith('.') || wanted.endsWith('.') || !host.endsWith('.$wanted')) return false;
  return suffixes.registrableDomain(wanted) != null;
}

/// The client data of an assertion, as the bytes a browser writes: the
/// members in its order, with [challenge] as the server gave it.
Uint8List vwKeyClientData({required String challenge, required String origin}) => Uint8List.fromList(
  utf8.encode('{"type":"webauthn.get","challenge":${jsonEncode(challenge)},"origin":${jsonEncode(origin)},"crossOrigin":false}'),
);

/// The hash a key signs for [clientData].
Uint8List vwKeyClientDataHash(Uint8List clientData) => Uint8List.fromList(sha256.convert(clientData).bytes);

/// The second step's token for a security key: the JSON of a public-key
/// credential, every binary value base64url without padding.
String vwKeyToken({
  required Uint8List credentialId,
  required Uint8List authenticatorData,
  required Uint8List clientData,
  required Uint8List signature,
}) => jsonEncode({
  'id': b64url(credentialId),
  'rawId': b64url(credentialId),
  'type': 'public-key',
  'extensions': {'appid': false},
  'response': {'authenticatorData': b64url(authenticatorData), 'clientDataJson': b64url(clientData), 'signature': b64url(signature)},
});
