// The OPAQUE-3DH client of RFC 9807, in the configuration of `docs/crypto.md`
// "opaque1":
//
//   OPRF ristretto255-SHA512, group ristretto255, KDF HKDF-SHA512,
//   MAC HMAC-SHA512, hash SHA-512, KSF Identity,
//   context "kemlock/v1/opaque", no client or server identity (the public
//   keys stand for them), password input the 32-byte Argon2id master key.
//
// Registration is two calls, [OpaqueClient.createRegistrationRequest] and
// [OpaqueClient.finalizeRegistrationRequest], which give the record the server
// stores and the 64-byte export key. Sign-in is two calls,
// [OpaqueClient.generateKe1] and [OpaqueClient.generateKe3], which give KE3 for
// the server, the 64-byte session key and the export key.
//
// The server's half (CreateRegistrationResponse, GenerateKE2, ServerFinish)
// lives in the server; only the OPRF's BlindEvaluate is here, in oprf.dart, for
// tests.
//
// A wrong password, a changed server key and an unknown account (whose fake
// KE2 the server makes, RFC 9807 section 6.3.2.2) all fail the same way, with
// an [OpaqueException] of kind [OpaqueFailure.authentication], and give out no
// export key. Secrets (the password input, the blind, the keyshare secret, the
// randomized password, the envelope keys, the MAC keys) are kept in
// `Uint8List`s that are zeroed once the call is done, as far as Dart allows:
// the runtime may have copied them, and a state's [dispose] is for a call that
// never finishes.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../account/encoding.dart';
import '../bytes.dart';
import 'hkdf_sha512.dart';
import 'opaque_messages.dart';
import 'oprf.dart';
import 'ristretto255.dart';

/// The context of `crypto.md` "opaque1".
const kemlockOpaqueContext = 'kemlock/v1/opaque';

/// Why a step failed.
enum OpaqueFailure {
  /// The password, the server key or the account is not the one registered:
  /// the envelope or the server MAC did not verify. A wrong password, a
  /// changed server key and an unknown account look the same.
  authentication,

  /// The server sent an element or a key that is not a valid group element,
  /// or the input can't be used.
  protocol,
}

/// A failed OPAQUE step.
class OpaqueException implements Exception {
  const OpaqueException(this.failure, this.message);

  final OpaqueFailure failure;
  final String message;

  @override
  String toString() => 'OpaqueException(${failure.name}): $message';
}

/// Random bytes of the given length, [randomBytes] by default; a test passes
/// the RFC's nonces and seeds, one draw at a time.
typedef OpaqueRandom = Uint8List Function(int length);

/// What a client keeps between registration's two calls.
final class OpaqueRegistrationState {
  OpaqueRegistrationState._(this._password, this._blind);

  Uint8List? _password;
  Uint8List? _blind;

  /// Zeroes the password input and the blind. [OpaqueClient.finalizeRegistrationRequest]
  /// does it itself; call this when it never will be called.
  void dispose() {
    for (final secret in [_password, _blind]) {
      if (secret != null) wipe(secret);
    }
    _password = null;
    _blind = null;
  }
}

/// What a client keeps between sign-in's two calls.
final class OpaqueLoginState {
  OpaqueLoginState._(this._password, this._blind, this._clientSecret, this._ke1);

  Uint8List? _password;
  Uint8List? _blind;
  Uint8List? _clientSecret;
  final Ke1 _ke1;

  /// Zeroes the secrets. [OpaqueClient.generateKe3] does it itself, whether it
  /// succeeds or not; call this when it never will be called.
  void dispose() {
    for (final secret in [_password, _blind, _clientSecret]) {
      if (secret != null) wipe(secret);
    }
    _password = null;
    _blind = null;
    _clientSecret = null;
  }
}

/// The OPAQUE-3DH client.
class OpaqueClient {
  /// A client with the [context] of the transcript (`kemlock/v1/opaque`), and
  /// the optional [clientIdentity] and [serverIdentity], each the public key
  /// when null, which is what `crypto.md` fixes. [random] draws the nonces and
  /// seeds; fresh random bytes by default.
  OpaqueClient({String context = kemlockOpaqueContext, List<int>? clientIdentity, List<int>? serverIdentity, OpaqueRandom? random})
    : _context = utf8.encode(context),
      _clientIdentity = clientIdentity == null ? null : copyBytes(clientIdentity),
      _serverIdentity = serverIdentity == null ? null : copyBytes(serverIdentity),
      _random = random ?? randomBytes {
    if (_context.length > 0xffff) throw ArgumentError.value(context, 'context', 'over 65535 bytes');
  }

  /// A client with the context given as bytes, as RFC 9807's test vectors
  /// give theirs.
  OpaqueClient.withContextBytes(List<int> context, {List<int>? clientIdentity, List<int>? serverIdentity, OpaqueRandom? random})
    : _context = copyBytes(context),
      _clientIdentity = clientIdentity == null ? null : copyBytes(clientIdentity),
      _serverIdentity = serverIdentity == null ? null : copyBytes(serverIdentity),
      _random = random ?? randomBytes;

  final List<int> _context;
  final Uint8List? _clientIdentity;
  final Uint8List? _serverIdentity;
  final OpaqueRandom _random;

  // ---- Registration (RFC 9807 section 5) ----

  /// CreateRegistrationRequest: blinds [password] (the 32-byte master key). The
  /// state goes to [finalizeRegistrationRequest]. [blind] is for known-answer
  /// tests only.
  ({RegistrationRequest request, OpaqueRegistrationState state}) createRegistrationRequest(List<int> password, {List<int>? blind}) {
    final blinded = _blind(password, blind);
    return (request: RegistrationRequest(blinded.blindedElement), state: OpaqueRegistrationState._(copyBytes(password), blinded.blind));
  }

  /// FinalizeRegistrationRequest: the record for the server to store and the
  /// 64-byte export key, from the server's [response]. The caller zeroes the
  /// export key when done. The state is disposed.
  ({RegistrationRecord record, Uint8List exportKey}) finalizeRegistrationRequest(
    OpaqueRegistrationState state,
    RegistrationResponse response,
  ) {
    final password = state._password;
    final blind = state._blind;
    if (password == null || blind == null) throw StateError('the registration state was disposed');
    Uint8List? randomizedPassword;
    try {
      _requireElement(response.serverPublicKey, 'the server public key');
      randomizedPassword = _randomizedPassword(password, blind, response.evaluatedMessage);
      return _store(randomizedPassword, response.serverPublicKey);
    } finally {
      if (randomizedPassword != null) wipe(randomizedPassword);
      state.dispose();
    }
  }

  // ---- Sign-in (RFC 9807 section 6) ----

  /// GenerateKE1: the first message of sign-in, from [password] (the 32-byte
  /// master key). The state goes to [generateKe3]. [blind] is for known-answer
  /// tests only.
  ({Ke1 ke1, OpaqueLoginState state}) generateKe1(List<int> password, {List<int>? blind}) {
    final blinded = _blind(password, blind);
    final clientNonce = _random(OpaqueSizes.nonce);
    final keyshareSeed = _random(OpaqueSizes.seed);
    try {
      final keyshare = _deriveDiffieHellmanKeyPair(keyshareSeed);
      final ke1 = Ke1(blindedMessage: blinded.blindedElement, clientNonce: clientNonce, clientPublicKeyshare: keyshare.publicKey);
      return (ke1: ke1, state: OpaqueLoginState._(copyBytes(password), blinded.blind, keyshare.privateKey, ke1));
    } finally {
      wipe(keyshareSeed);
    }
  }

  /// GenerateKE3: from the server's [ke2], the client's KE3, the 64-byte
  /// session key and the 64-byte export key. The caller zeroes the keys when
  /// done. The state is disposed, whether this succeeds or not.
  ///
  /// Throws an [OpaqueException] of kind [OpaqueFailure.authentication] when
  /// the envelope or the server MAC does not verify, and gives out no export
  /// key then.
  ({Ke3 ke3, Uint8List sessionKey, Uint8List exportKey}) generateKe3(OpaqueLoginState state, Ke2 ke2) {
    final password = state._password;
    final blind = state._blind;
    final clientSecret = state._clientSecret;
    if (password == null || blind == null || clientSecret == null) throw StateError('the sign-in state was disposed');
    final secrets = <Uint8List>[];
    try {
      final credentialResponse = ke2.credentialResponse;
      final authResponse = ke2.authResponse;

      // RecoverCredentials (section 6.3.2.3)
      final randomizedPassword = _randomizedPassword(password, blind, credentialResponse.evaluatedMessage);
      secrets.add(randomizedPassword);
      final maskingKey = hkdfExpandSha512(randomizedPassword, ascii.encode('MaskingKey'), OpaqueSizes.hash);
      secrets.add(maskingKey);
      final pad = hkdfExpandSha512(
        maskingKey,
        concatBytes([credentialResponse.maskingNonce, ascii.encode('CredentialResponsePad')]),
        OpaqueSizes.publicKey + OpaqueEnvelope.length,
      );
      secrets.add(pad);
      final unmasked = Uint8List(pad.length);
      for (var i = 0; i < pad.length; i++) {
        unmasked[i] = pad[i] ^ credentialResponse.maskedResponse[i];
      }
      secrets.add(unmasked);
      final serverPublicKey = Uint8List.sublistView(unmasked, 0, OpaqueSizes.publicKey);
      final envelope = OpaqueEnvelope.parse(Uint8List.sublistView(unmasked, OpaqueSizes.publicKey));

      // Recover (section 4.1.3)
      final keys = _envelopeKeys(randomizedPassword, envelope.nonce);
      secrets
        ..add(keys.authKey)
        ..add(keys.exportKey)
        ..add(keys.clientPrivateKey);
      final cleartext = _cleartextCredentials(serverPublicKey, keys.clientPublicKey);
      final expectedTag = hmacSha512(keys.authKey, concatBytes([envelope.nonce, cleartext]));
      if (!constantTimeEquals(expectedTag, envelope.authTag)) {
        throw const OpaqueException(OpaqueFailure.authentication, 'the envelope did not authenticate');
      }

      // AuthClientFinalize (section 6.4.3)
      final dh1 = _diffieHellman(clientSecret, authResponse.serverPublicKeyshare);
      final dh2 = _diffieHellman(clientSecret, serverPublicKey);
      final dh3 = _diffieHellman(keys.clientPrivateKey, authResponse.serverPublicKeyshare);
      final ikm = concatBytes([dh1, dh2, dh3]);
      secrets
        ..add(dh1)
        ..add(dh2)
        ..add(dh3)
        ..add(ikm);
      final preamble = _preamble(
        clientIdentity: _clientIdentity ?? keys.clientPublicKey,
        ke1: state._ke1,
        serverIdentity: _serverIdentity ?? serverPublicKey,
        credentialResponse: credentialResponse,
        serverNonce: authResponse.serverNonce,
        serverPublicKeyshare: authResponse.serverPublicKeyshare,
      );
      final derived = _deriveKeys(ikm, preamble);
      secrets
        ..add(derived.km2)
        ..add(derived.km3)
        ..add(derived.sessionKey);
      final preambleHash = sha512Digest(preamble);
      final expectedServerMac = hmacSha512(derived.km2, preambleHash);
      if (!constantTimeEquals(authResponse.serverMac, expectedServerMac)) {
        throw const OpaqueException(OpaqueFailure.authentication, 'the server MAC did not verify');
      }
      final clientMac = hmacSha512(derived.km3, sha512Digest(concatBytes([preamble, expectedServerMac])));

      // The caller owns these two now
      secrets
        ..remove(keys.exportKey)
        ..remove(derived.sessionKey);
      return (ke3: Ke3(clientMac), sessionKey: derived.sessionKey, exportKey: keys.exportKey);
    } finally {
      for (final secret in secrets) {
        wipe(secret);
      }
      state.dispose();
    }
  }

  // ---- Pieces ----

  ({Uint8List blind, Uint8List blindedElement}) _blind(List<int> password, List<int>? blind) {
    try {
      return Oprf.blind(password, blind: blind);
    } on OprfException catch (e) {
      throw OpaqueException(OpaqueFailure.protocol, e.message);
    }
  }

  /// Finalize, then Stretch (the Identity KSF) and Extract: the randomized
  /// password `Extract("", concat(oprf_output, stretched_oprf_output))`.
  Uint8List _randomizedPassword(List<int> password, List<int> blind, List<int> evaluatedMessage) {
    final Uint8List oprfOutput;
    try {
      oprfOutput = Oprf.finalize(password, blind, evaluatedMessage);
    } on OprfException catch (e) {
      throw OpaqueException(OpaqueFailure.protocol, e.message);
    }
    final stretched = oprfOutput; // the Identity KSF
    final ikm = concatBytes([oprfOutput, stretched]);
    try {
      return hkdfExtractSha512(const [], ikm);
    } finally {
      wipe(oprfOutput);
      wipe(ikm);
    }
  }

  /// Store (section 4.1.2).
  ({RegistrationRecord record, Uint8List exportKey}) _store(Uint8List randomizedPassword, Uint8List serverPublicKey) {
    final nonce = _random(OpaqueSizes.nonce);
    final maskingKey = hkdfExpandSha512(randomizedPassword, ascii.encode('MaskingKey'), OpaqueSizes.hash);
    final keys = _envelopeKeys(randomizedPassword, nonce);
    try {
      final cleartext = _cleartextCredentials(serverPublicKey, keys.clientPublicKey);
      final authTag = hmacSha512(keys.authKey, concatBytes([nonce, cleartext]));
      final record = RegistrationRecord(
        clientPublicKey: keys.clientPublicKey,
        maskingKey: maskingKey,
        envelope: OpaqueEnvelope(nonce: nonce, authTag: authTag),
      );
      return (record: record, exportKey: keys.exportKey);
    } catch (_) {
      wipe(keys.exportKey);
      rethrow;
    } finally {
      wipe(maskingKey);
      wipe(keys.authKey);
      wipe(keys.clientPrivateKey);
    }
  }

  /// auth_key, export_key and the key pair of an envelope nonce:
  ///
  ///     auth_key   = Expand(randomized_password, nonce || "AuthKey", Nh)
  ///     export_key = Expand(randomized_password, nonce || "ExportKey", Nh)
  ///     seed       = Expand(randomized_password, nonce || "PrivateKey", Nseed)
  ///     (private, public) = DeriveDiffieHellmanKeyPair(seed)
  ({Uint8List authKey, Uint8List exportKey, Uint8List clientPrivateKey, Uint8List clientPublicKey}) _envelopeKeys(
    Uint8List randomizedPassword,
    Uint8List nonce,
  ) {
    final authKey = hkdfExpandSha512(randomizedPassword, concatBytes([nonce, ascii.encode('AuthKey')]), OpaqueSizes.hash);
    final exportKey = hkdfExpandSha512(randomizedPassword, concatBytes([nonce, ascii.encode('ExportKey')]), OpaqueSizes.hash);
    final seed = hkdfExpandSha512(randomizedPassword, concatBytes([nonce, ascii.encode('PrivateKey')]), OpaqueSizes.seed);
    try {
      final pair = _deriveDiffieHellmanKeyPair(seed);
      return (authKey: authKey, exportKey: exportKey, clientPrivateKey: pair.privateKey, clientPublicKey: pair.publicKey);
    } finally {
      wipe(seed);
    }
  }

  /// CleartextCredentials as the auth tag covers them, after the nonce:
  /// `server_public_key || I2OSP(len(server_identity), 2) || server_identity ||
  /// I2OSP(len(client_identity), 2) || client_identity`, the identities being
  /// the public keys when not set.
  Uint8List _cleartextCredentials(Uint8List serverPublicKey, Uint8List clientPublicKey) {
    final serverIdentity = _serverIdentity ?? serverPublicKey;
    final clientIdentity = _clientIdentity ?? clientPublicKey;
    return concatBytes([serverPublicKey, _lp2(serverIdentity), _lp2(clientIdentity)]);
  }

  /// DeriveDiffieHellmanKeyPair(seed): DeriveKeyPair(seed,
  /// "OPAQUE-DeriveDiffieHellmanKeyPair") of RFC 9497 (section 6.4.1.1).
  ({Uint8List privateKey, Uint8List publicKey}) _deriveDiffieHellmanKeyPair(List<int> seed) {
    try {
      return Oprf.deriveKeyPair(seed, ascii.encode('OPAQUE-DeriveDiffieHellmanKeyPair'));
    } on OprfException catch (e) {
      throw OpaqueException(OpaqueFailure.protocol, e.message);
    }
  }

  /// DiffieHellman(k, B): [publicKey] decoded and multiplied by [privateKey],
  /// encoded (section 6.4.1.1). A key that is not a valid element, or is the
  /// identity, is a protocol failure.
  Uint8List _diffieHellman(Uint8List privateKey, List<int> publicKey) {
    final element = RistrettoPoint.decode(publicKey);
    if (element == null || element.isIdentity) throw const OpaqueException(OpaqueFailure.protocol, 'a public key is not a valid element');
    return element.multiply(privateKey).encode();
  }

  void _requireElement(List<int> bytes, String what) {
    final element = RistrettoPoint.decode(bytes);
    if (element == null || element.isIdentity) throw OpaqueException(OpaqueFailure.protocol, '$what is not a valid element');
  }

  /// The preamble (section 6.4.2.1):
  ///
  ///     "OPAQUEv1-" || I2OSP(len(context), 2) || context ||
  ///     I2OSP(len(client_identity), 2) || client_identity || ke1 ||
  ///     I2OSP(len(server_identity), 2) || server_identity ||
  ///     credential_response || server_nonce || server_public_keyshare
  Uint8List _preamble({
    required Uint8List clientIdentity,
    required Ke1 ke1,
    required Uint8List serverIdentity,
    required CredentialResponse credentialResponse,
    required Uint8List serverNonce,
    required Uint8List serverPublicKeyshare,
  }) => concatBytes([
    ascii.encode('OPAQUEv1-'),
    _lp2(_context),
    _lp2(clientIdentity),
    ke1.bytes,
    _lp2(serverIdentity),
    credentialResponse.bytes,
    serverNonce,
    serverPublicKeyshare,
  ]);
}

/// DeriveKeys (section 6.4.2.2):
///
///     prk              = Extract("", ikm)
///     handshake_secret = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
///     session_key      = Derive-Secret(prk, "SessionKey", Hash(preamble))
///     Km2              = Derive-Secret(handshake_secret, "ServerMAC", "")
///     Km3              = Derive-Secret(handshake_secret, "ClientMAC", "")
({Uint8List km2, Uint8List km3, Uint8List sessionKey}) _deriveKeys(Uint8List ikm, Uint8List preamble) {
  final prk = hkdfExtractSha512(const [], ikm);
  final preambleHash = sha512Digest(preamble);
  final handshakeSecret = _deriveSecret(prk, 'HandshakeSecret', preambleHash);
  final sessionKey = _deriveSecret(prk, 'SessionKey', preambleHash);
  final km2 = _deriveSecret(handshakeSecret, 'ServerMAC', const []);
  final km3 = _deriveSecret(handshakeSecret, 'ClientMAC', const []);
  wipe(prk);
  wipe(handshakeSecret);
  return (km2: km2, km3: km3, sessionKey: sessionKey);
}

/// Derive-Secret(secret, label, transcript hash) = Expand-Label(secret, label,
/// hash, Nx), where Expand-Label(secret, label, context, length) is
/// `Expand(secret, CustomLabel, length)` for the TLS 1.3 structure
/// `uint16 length || opaque label<8..255> = "OPAQUE-" + label ||
/// opaque context<0..255>`, the vectors carrying a one-byte length each.
Uint8List _deriveSecret(Uint8List secret, String labelText, List<int> context) {
  final fullLabel = ascii.encode('OPAQUE-$labelText');
  final info = concatBytes([
    [OpaqueSizes.sessionKey >> 8, OpaqueSizes.sessionKey & 0xff],
    [fullLabel.length],
    fullLabel,
    [context.length],
    context,
  ]);
  return hkdfExpandSha512(secret, info, OpaqueSizes.sessionKey);
}

/// `I2OSP(len(x), 2) || x`.
Uint8List _lp2(List<int> x) {
  if (x.length > 0xffff) throw ArgumentError.value(x.length, 'x', 'over 65535 bytes');
  return concatBytes([
    [x.length >> 8, x.length & 0xff],
    x,
  ]);
}
