// The messages of OPAQUE-3DH (RFC 9807 sections 4.1.1, 5.1, 6.1 and 6.3.1) in
// the configuration of `docs/crypto.md` "opaque1": ristretto255, so an OPRF
// element and a public key are 32 bytes (Noe, Npk), SHA-512 and HMAC-SHA-512,
// so a hash, a MAC and the masking key are 64 (Nh, Nm), and a nonce is 32
// (Nn).
//
// Each message reads from bytes strictly: a length other than the exact one is
// a [MalformedException], and nothing is decoded as a group element here, which
// the client does when it uses one.

library;

import 'dart:typed_data';

import '../account/encoding.dart';
import '../bytes.dart';

/// The sizes of the configuration.
abstract final class OpaqueSizes {
  /// Noe: a serialized OPRF element.
  static const element = 32;

  /// Npk: a serialized AKE public key.
  static const publicKey = 32;

  /// Nn: a nonce.
  static const nonce = 32;

  /// Nseed: a seed for a key pair.
  static const seed = 32;

  /// Nh: a hash, and the masking key.
  static const hash = 64;

  /// Nm: a MAC.
  static const mac = 64;

  /// Nx: the session key, the output of Derive-Secret.
  static const sessionKey = 64;

  /// Nok: the OPRF seed the server derives its per-credential key from.
  static const oprfKeySeed = 32;
}

/// Envelope: the nonce and the tag that authenticates it and the cleartext
/// credentials (section 4.1.1).
final class OpaqueEnvelope {
  OpaqueEnvelope({required List<int> nonce, required List<int> authTag})
    : nonce = copyBytes(requireLength(nonce, OpaqueSizes.nonce, 'the envelope nonce')),
      authTag = copyBytes(requireLength(authTag, OpaqueSizes.mac, 'the envelope tag'));

  factory OpaqueEnvelope.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'an envelope'));
    final envelope = OpaqueEnvelope(nonce: reader.read(OpaqueSizes.nonce, 'nonce'), authTag: reader.read(OpaqueSizes.mac, 'tag'));
    reader.finish();
    return envelope;
  }

  /// Nn + Nm = 96.
  static const length = OpaqueSizes.nonce + OpaqueSizes.mac;

  final Uint8List nonce;
  final Uint8List authTag;

  Uint8List get bytes => concatBytes([nonce, authTag]);
}

/// RegistrationRequest: the blinded OPRF element (section 5.1).
final class RegistrationRequest {
  RegistrationRequest(List<int> blindedMessage)
    : blindedMessage = copyBytes(requireLength(blindedMessage, OpaqueSizes.element, 'the blinded message'));

  factory RegistrationRequest.parse(List<int> bytes) => RegistrationRequest(bytes);

  static const length = OpaqueSizes.element;

  final Uint8List blindedMessage;

  Uint8List get bytes => copyBytes(blindedMessage);
}

/// RegistrationResponse: the evaluated OPRF element and the server's public
/// key (section 5.1).
final class RegistrationResponse {
  RegistrationResponse({required List<int> evaluatedMessage, required List<int> serverPublicKey})
    : evaluatedMessage = copyBytes(requireLength(evaluatedMessage, OpaqueSizes.element, 'the evaluated message')),
      serverPublicKey = copyBytes(requireLength(serverPublicKey, OpaqueSizes.publicKey, 'the server public key'));

  factory RegistrationResponse.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'a registration response'));
    final response = RegistrationResponse(
      evaluatedMessage: reader.read(OpaqueSizes.element, 'evaluated message'),
      serverPublicKey: reader.read(OpaqueSizes.publicKey, 'server public key'),
    );
    reader.finish();
    return response;
  }

  static const length = OpaqueSizes.element + OpaqueSizes.publicKey;

  final Uint8List evaluatedMessage;
  final Uint8List serverPublicKey;

  Uint8List get bytes => concatBytes([evaluatedMessage, serverPublicKey]);
}

/// RegistrationRecord: what the server stores for the client (section 5.1).
final class RegistrationRecord {
  RegistrationRecord({required List<int> clientPublicKey, required List<int> maskingKey, required this.envelope})
    : clientPublicKey = copyBytes(requireLength(clientPublicKey, OpaqueSizes.publicKey, 'the client public key')),
      maskingKey = copyBytes(requireLength(maskingKey, OpaqueSizes.hash, 'the masking key'));

  factory RegistrationRecord.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'a registration record'));
    final record = RegistrationRecord(
      clientPublicKey: reader.read(OpaqueSizes.publicKey, 'client public key'),
      maskingKey: reader.read(OpaqueSizes.hash, 'masking key'),
      envelope: OpaqueEnvelope.parse(reader.read(OpaqueEnvelope.length, 'envelope')),
    );
    reader.finish();
    return record;
  }

  /// Npk + Nh + Nn + Nm = 192.
  static const length = OpaqueSizes.publicKey + OpaqueSizes.hash + OpaqueEnvelope.length;

  final Uint8List clientPublicKey;
  final Uint8List maskingKey;
  final OpaqueEnvelope envelope;

  Uint8List get bytes => concatBytes([clientPublicKey, maskingKey, envelope.bytes]);
}

/// KE1: the credential request and the auth request (sections 6.1 and 6.3.1):
/// the blinded OPRF element, the client nonce and the client's ephemeral
/// public key.
final class Ke1 {
  Ke1({required List<int> blindedMessage, required List<int> clientNonce, required List<int> clientPublicKeyshare})
    : blindedMessage = copyBytes(requireLength(blindedMessage, OpaqueSizes.element, 'the blinded message')),
      clientNonce = copyBytes(requireLength(clientNonce, OpaqueSizes.nonce, 'the client nonce')),
      clientPublicKeyshare = copyBytes(requireLength(clientPublicKeyshare, OpaqueSizes.publicKey, 'the client keyshare'));

  factory Ke1.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'KE1'));
    final ke1 = Ke1(
      blindedMessage: reader.read(OpaqueSizes.element, 'blinded message'),
      clientNonce: reader.read(OpaqueSizes.nonce, 'client nonce'),
      clientPublicKeyshare: reader.read(OpaqueSizes.publicKey, 'client keyshare'),
    );
    reader.finish();
    return ke1;
  }

  /// Noe + Nn + Npk = 96.
  static const length = OpaqueSizes.element + OpaqueSizes.nonce + OpaqueSizes.publicKey;

  final Uint8List blindedMessage;
  final Uint8List clientNonce;
  final Uint8List clientPublicKeyshare;

  Uint8List get bytes => concatBytes([blindedMessage, clientNonce, clientPublicKeyshare]);
}

/// CredentialResponse: the evaluated OPRF element, the masking nonce and the
/// masked server public key and envelope (section 6.3.1).
final class CredentialResponse {
  CredentialResponse({required List<int> evaluatedMessage, required List<int> maskingNonce, required List<int> maskedResponse})
    : evaluatedMessage = copyBytes(requireLength(evaluatedMessage, OpaqueSizes.element, 'the evaluated message')),
      maskingNonce = copyBytes(requireLength(maskingNonce, OpaqueSizes.nonce, 'the masking nonce')),
      maskedResponse = copyBytes(requireLength(maskedResponse, maskedResponseLength, 'the masked response'));

  factory CredentialResponse.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'a credential response'));
    final response = CredentialResponse(
      evaluatedMessage: reader.read(OpaqueSizes.element, 'evaluated message'),
      maskingNonce: reader.read(OpaqueSizes.nonce, 'masking nonce'),
      maskedResponse: reader.read(maskedResponseLength, 'masked response'),
    );
    reader.finish();
    return response;
  }

  /// Npk + Nn + Nm = 128.
  static const maskedResponseLength = OpaqueSizes.publicKey + OpaqueEnvelope.length;

  /// Noe + Nn + Npk + Nn + Nm = 192.
  static const length = OpaqueSizes.element + OpaqueSizes.nonce + maskedResponseLength;

  final Uint8List evaluatedMessage;
  final Uint8List maskingNonce;
  final Uint8List maskedResponse;

  Uint8List get bytes => concatBytes([evaluatedMessage, maskingNonce, maskedResponse]);
}

/// AuthResponse: the server nonce, its ephemeral public key and the server MAC
/// (section 6.1).
final class AuthResponse {
  AuthResponse({required List<int> serverNonce, required List<int> serverPublicKeyshare, required List<int> serverMac})
    : serverNonce = copyBytes(requireLength(serverNonce, OpaqueSizes.nonce, 'the server nonce')),
      serverPublicKeyshare = copyBytes(requireLength(serverPublicKeyshare, OpaqueSizes.publicKey, 'the server keyshare')),
      serverMac = copyBytes(requireLength(serverMac, OpaqueSizes.mac, 'the server MAC'));

  factory AuthResponse.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'an auth response'));
    final response = AuthResponse(
      serverNonce: reader.read(OpaqueSizes.nonce, 'server nonce'),
      serverPublicKeyshare: reader.read(OpaqueSizes.publicKey, 'server keyshare'),
      serverMac: reader.read(OpaqueSizes.mac, 'server MAC'),
    );
    reader.finish();
    return response;
  }

  /// Nn + Npk + Nm = 128.
  static const length = OpaqueSizes.nonce + OpaqueSizes.publicKey + OpaqueSizes.mac;

  final Uint8List serverNonce;
  final Uint8List serverPublicKeyshare;
  final Uint8List serverMac;

  Uint8List get bytes => concatBytes([serverNonce, serverPublicKeyshare, serverMac]);
}

/// KE2: the credential response and the auth response (section 6.1).
final class Ke2 {
  const Ke2({required this.credentialResponse, required this.authResponse});

  factory Ke2.parse(List<int> bytes) {
    final reader = ByteReader(requireLength(bytes, length, 'KE2'));
    final ke2 = Ke2(
      credentialResponse: CredentialResponse.parse(reader.read(CredentialResponse.length, 'credential response')),
      authResponse: AuthResponse.parse(reader.read(AuthResponse.length, 'auth response')),
    );
    reader.finish();
    return ke2;
  }

  /// 192 + 128 = 320.
  static const length = CredentialResponse.length + AuthResponse.length;

  final CredentialResponse credentialResponse;
  final AuthResponse authResponse;

  Uint8List get bytes => concatBytes([credentialResponse.bytes, authResponse.bytes]);
}

/// KE3: the client MAC (section 6.1).
final class Ke3 {
  Ke3(List<int> clientMac) : clientMac = copyBytes(requireLength(clientMac, OpaqueSizes.mac, 'the client MAC'));

  factory Ke3.parse(List<int> bytes) => Ke3(bytes);

  static const length = OpaqueSizes.mac;

  final Uint8List clientMac;

  Uint8List get bytes => copyBytes(clientMac);
}
