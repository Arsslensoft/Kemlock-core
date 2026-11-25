// The bytes a passkey provider builds, held to the fixture the phone's providers (Dart, Swift and Kotlin) are held to:
// test/fixtures/passkeys/passkeys.json, written once and never regenerated.
@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/passkeys/passkey_bytes.dart';
import 'package:test/test.dart';

void main() {
  final fixture = jsonDecode(File('test/fixtures/passkeys/passkeys.json').readAsStringSync()) as Map<String, Object?>;
  final credential = fixture['credential']! as Map<String, Object?>;
  final registration = fixture['registration']! as Map<String, Object?>;
  final assertion = fixture['assertion']! as Map<String, Object?>;
  Uint8List bytes(Map<String, Object?> from, String name) => unb64(from[name]! as String);

  final point = bytes(credential, 'point');
  final credentialId = unb64url(credential['credentialId']! as String);
  const rpId = 'webauthn.io';

  test('Kemlock has one AAGUID, which is the fixture’s', () {
    expect(kemlockAaguid, fixture['aaguid']);
    expect(kemlockAaguidBytes, hasLength(16));
    expect(kemlockAaguidBytes.first, 0xf8);
    expect(kemlockAaguidBytes.last, 0x1c);
  });

  group('a registration', () {
    test('has the COSE key of the credential’s public point', () {
      expect(coseEs256Key(point), bytes(registration, 'coseKey'));
    });

    test('has authenticator data with flags 0x5D, a counter of 0, the AAGUID, the credential id and the key', () {
      final authData = registrationAuthData(rpId: rpId, credentialId: credentialId, point: point);
      expect(authData, bytes(registration, 'authData'));
      expect(authData.sublist(0, 32), rpIdHash(rpId));
      expect(authData[32], 0x5D);
      expect(registrationFlags, 0x5D);
      expect(authData.sublist(33, 37), [0, 0, 0, 0]);
      expect(authData.sublist(37, 53), kemlockAaguidBytes);
      expect(authData.sublist(53, 55), [0, credentialId.length]);
      expect(authData.sublist(55, 55 + credentialId.length), credentialId);
    });

    test('has an attestation object of format none, in canonical CBOR', () {
      final authData = registrationAuthData(rpId: rpId, credentialId: credentialId, point: point);
      final object = attestationObject(authData);
      expect(object, bytes(registration, 'attestationObject'));
      // a3, "fmt", "none", "attStmt", a0, "authData", then the authenticator data as a byte string
      expect(object[0], 0xa3);
      expect(utf8.decode(object.sublist(2, 5)), 'fmt');
      expect(utf8.decode(object.sublist(6, 10)), 'none');
    });
  });

  group('an assertion', () {
    final clientData = utf8.encode(assertion['clientDataJSON']! as String);

    test('has authenticator data with flags 0x1D and a counter of 0', () {
      final authData = assertionAuthData(rpId);
      expect(authData, bytes(assertion, 'authData'));
      expect(authData, hasLength(37));
      expect(authData[32], 0x1D);
      expect(assertionFlags, 0x1D);
      expect(authData.sublist(33), [0, 0, 0, 0]);
    });

    test('signs the authenticator data and the client data’s hash, and the signature is the fixture’s', () {
      final authData = assertionAuthData(rpId);
      final hash = Uint8List.fromList(sha256.convert(clientData).bytes);
      expect(hash, bytes(assertion, 'clientDataHash'));
      final signed = assertionSignedBytes(authData, hash);
      expect(signed, bytes(assertion, 'signedBytes'));
      final key = P256KeyPair(bytes(credential, 'd'), point);
      final signature = es256Sign(key, signed);
      expect(signature, bytes(assertion, 'signature'));
      expect(es256Verify(point, signed, signature), isTrue);
      // The fixture's own signature verifies too, and one over other bytes does not
      expect(es256Verify(point, signed, bytes(assertion, 'signature')), isTrue);
      expect(es256Verify(point, Uint8List.fromList([...signed, 0]), signature), isFalse);
    });
  });

  group('the CBOR a passkey needs', () {
    test('writes integers, byte and text strings and maps in their shortest form', () {
      expect(Cbor.integer(0), [0x00]);
      expect(Cbor.integer(23), [0x17]);
      expect(Cbor.integer(24), [0x18, 24]);
      expect(Cbor.integer(-1), [0x20]);
      expect(Cbor.integer(-7), [0x26]);
      expect(Cbor.integer(256), [0x19, 1, 0]);
      expect(Cbor.bytes([1, 2]), [0x42, 1, 2]);
      expect(Cbor.text('a'), [0x61, 0x61]);
      expect(Cbor.map([(Cbor.text('a'), Cbor.integer(1))]), [0xa1, 0x61, 0x61, 0x01]);
    });
  });
}
