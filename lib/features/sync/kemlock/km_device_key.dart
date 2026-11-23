/// The key the phone's tokens are bound to. Every request with a token carries
/// a DPoP proof (RFC 9449) signed by it, so a token copied off the phone is
/// useless elsewhere. The Secure Enclave and the Android Keystore do ECDSA
/// P-256 only, so proofs are ES256, and the hardware keeps the private half:
/// `platform/device_keys.dart` talks to them. Where a phone has none (a
/// simulator, some older phones), a software P-256 key sealed in the vault
/// takes their place and the sheet says so (owner decision 6).
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/keys/der.dart';
import '../../../crypto/p256.dart';

/// Where a device key lives, by the names the server's key copy takes as `protection`.
abstract final class DeviceKeyProtection {
  static const secureEnclave = 'secure-enclave';
  static const keystore = 'keystore';
  static const software = 'software';
}

/// A P-256 key that signs DPoP proofs.
abstract interface class DeviceKey {
  /// The public key as a JWK: `{kty: EC, crv: P-256, x, y}`, the coordinates base64url.
  Map<String, String> get publicJwk;

  /// One of [DeviceKeyProtection].
  String get protection;

  /// An ES256 signature of [message], the 64 bytes `r || s` a JWS carries.
  Future<Uint8List> sign(Uint8List message);
}

/// The JWK of a P-256 public [point], uncompressed (0x04, x, y).
Map<String, String> p256Jwk(Uint8List point) {
  if (point.length != 65 || point[0] != 4) throw const MalformedException('a P-256 point is 65 bytes starting with 4');
  return {'kty': 'EC', 'crv': 'P-256', 'x': b64urlEncode(point.sublist(1, 33)), 'y': b64urlEncode(point.sublist(33))};
}

/// The RFC 7638 thumbprint of a P-256 [jwk]: what the server binds a token to.
String jwkThumbprint(Map<String, String> jwk) =>
    b64urlEncode(hash.sha256.convert('{"crv":"P-256","kty":"EC","x":"${jwk['x']}","y":"${jwk['y']}"}'.codeUnits).bytes);

/// A DER ECDSA signature (`SEQUENCE { r, s }`) as the 64 bytes `r || s` of a JWS.
Uint8List derToRawEs256(Uint8List der) {
  final reader = readSequence(der);
  final r = reader.integer();
  final s = reader.integer();
  reader.done();
  return Uint8List.fromList([...bigIntToBytes(r, 32), ...bigIntToBytes(s, 32)]);
}

/// The 64 bytes `r || s` of a JWS as a DER ECDSA signature.
Uint8List rawToDerEs256(List<int> raw) {
  if (raw.length != 64) throw const MalformedException('an ES256 signature is 64 bytes');
  return derSequence([derInteger(bytesToBigInt(raw.sublist(0, 32))), derInteger(bytesToBigInt(raw.sublist(32)))]);
}

/// A P-256 key held in memory, for a phone with no hardware key. It is sealed in the vault with the
/// session ([scalar] is the private half): a token bound to it is only as safe as the vault is.
class SoftwareDeviceKey implements DeviceKey {
  SoftwareDeviceKey(this._pair);

  /// A new key from the platform's secure random source.
  factory SoftwareDeviceKey.generate() => SoftwareDeviceKey(newP256KeyPair());

  /// The key with the private [scalar], 32 bytes.
  factory SoftwareDeviceKey.fromScalar(Uint8List scalar) => SoftwareDeviceKey(P256KeyPair.fromScalar(scalar));

  final P256KeyPair _pair;

  /// The private half, 32 bytes, to seal in the vault.
  Uint8List get scalar => _pair.d;

  @override
  late final Map<String, String> publicJwk = p256Jwk(_pair.point);

  @override
  String get protection => DeviceKeyProtection.software;

  @override
  Future<Uint8List> sign(Uint8List message) async => derToRawEs256(es256Sign(_pair, message));
}
