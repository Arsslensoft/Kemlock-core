/// The bytes a passkey provider hands a site (WebAuthn Level 3, CTAP 2.1),
/// built the same way in Dart, Swift and Kotlin and pinned by the fixtures
/// in test/fixtures/passkeys:
///
/// - registration: authenticator data with the flags user present, user
///   verified, backup eligible, backup state and attested credential data
///   (0x5D), a signature counter of 0, Kemlock's AAGUID, the credential id
///   and the ES256 public key as a COSE key; and the attestation object
///   `{"fmt": "none", "attStmt": {}, "authData": …}` in CTAP2 canonical CBOR;
/// - assertion: authenticator data with user present, user verified,
///   backup eligible and backup state (0x1D) and a counter of 0, and the
///   bytes signed: that authenticator data followed by the client data's
///   SHA-256.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../crypto/p256.dart';

/// Kemlock's AAGUID, which says which provider made a passkey.
const kemlockAaguid = 'f85899be-d2db-4b3b-9b10-9b48e146dc1c';

/// [kemlockAaguid] as its 16 bytes.
final Uint8List kemlockAaguidBytes = Uint8List.fromList([
  for (var i = 0; i < 32; i += 2) int.parse(kemlockAaguid.replaceAll('-', '').substring(i, i + 2), radix: 16),
]);

/// The flags of a registration's authenticator data: UP, UV, BE, BS, AT.
const registrationFlags = 0x01 | 0x04 | 0x08 | 0x10 | 0x40;

/// The flags of an assertion's authenticator data: UP, UV, BE, BS.
const assertionFlags = 0x01 | 0x04 | 0x08 | 0x10;

/// SHA-256 of the relying party's id, as authenticator data begins.
Uint8List rpIdHash(String rpId) => Uint8List.fromList(sha256.convert(utf8.encode(rpId)).bytes);

/// The ES256 public key at [point] as a COSE key:
/// `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`, in canonical order.
Uint8List coseEs256Key(Uint8List point) {
  final key = P256KeyPair(Uint8List(32), point);
  return Cbor.map([
    (Cbor.integer(1), Cbor.integer(2)),
    (Cbor.integer(3), Cbor.integer(-7)),
    (Cbor.integer(-1), Cbor.integer(1)),
    (Cbor.integer(-2), Cbor.bytes(key.x)),
    (Cbor.integer(-3), Cbor.bytes(key.y)),
  ]);
}

/// A registration's authenticator data for a new passkey.
Uint8List registrationAuthData({required String rpId, required Uint8List credentialId, required Uint8List point}) {
  final out = BytesBuilder(copy: false)
    ..add(rpIdHash(rpId))
    ..addByte(registrationFlags)
    ..add(Uint8List(4))
    ..add(kemlockAaguidBytes)
    ..add([credentialId.length >> 8, credentialId.length & 0xff])
    ..add(credentialId)
    ..add(coseEs256Key(point));
  return out.takeBytes();
}

/// The attestation object of a registration, attestation `none`.
Uint8List attestationObject(Uint8List authData) => Cbor.map([
  (Cbor.text('fmt'), Cbor.text('none')),
  (Cbor.text('attStmt'), Cbor.map(const [])),
  (Cbor.text('authData'), Cbor.bytes(authData)),
]);

/// An assertion's authenticator data.
Uint8List assertionAuthData(String rpId) => Uint8List.fromList([...rpIdHash(rpId), assertionFlags, 0, 0, 0, 0]);

/// What an assertion signs: its authenticator data, then the client data's hash.
Uint8List assertionSignedBytes(Uint8List authData, Uint8List clientDataHash) => Uint8List.fromList([...authData, ...clientDataHash]);

/// The little CBOR passkeys need: unsigned and negative integers, byte and
/// text strings, and maps, each encoded in its shortest form. A map's
/// entries are written in the order given, which callers keep canonical.
abstract final class Cbor {
  static Uint8List _head(int major, int value) {
    if (value < 24) return Uint8List.fromList([major << 5 | value]);
    if (value < 0x100) return Uint8List.fromList([major << 5 | 24, value]);
    if (value < 0x10000) return Uint8List.fromList([major << 5 | 25, value >> 8, value & 0xff]);
    return Uint8List.fromList([major << 5 | 26, value >> 24 & 0xff, value >> 16 & 0xff, value >> 8 & 0xff, value & 0xff]);
  }

  static Uint8List integer(int value) => value >= 0 ? _head(0, value) : _head(1, -1 - value);

  static Uint8List bytes(List<int> value) => Uint8List.fromList([..._head(2, value.length), ...value]);

  static Uint8List text(String value) {
    final encoded = utf8.encode(value);
    return Uint8List.fromList([..._head(3, encoded.length), ...encoded]);
  }

  static Uint8List map(List<(Uint8List, Uint8List)> entries) => Uint8List.fromList([
    ..._head(5, entries.length),
    for (final (key, value) in entries) ...[...key, ...value],
  ]);
}
