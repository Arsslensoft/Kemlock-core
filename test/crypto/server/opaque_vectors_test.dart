@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/opaque/opaque_client.dart';
import 'package:kemlock_core/crypto/opaque/opaque_messages.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's opaque.json (crypto.md "opaque1"): RFC 9807 OPAQUE-3DH with the
// context "kemlock/v1/opaque", no identities, the 32-byte Argon2id master key
// as the password, and the random inputs of both sides. The client draws the
// envelope nonce when it registers and the client nonce and keyshare seed when
// it signs in, in that order, and takes the blinds as arguments; the server's
// draws (masking nonce, server nonce, keyshare seed, dummy masking key) and
// its oprf_seed and key pair are the server's, and only show up here as bytes
// of the response and of KE2. The credential identifier (the lower-cased
// e-mail) and the OPRF seed feed the server's side only, so the client takes
// neither.

/// An [OpaqueRandom] that hands out the given bytes in order, and fails if it
/// is asked for something else.
OpaqueRandom _drawing(List<Uint8List> draws) {
  final queue = List<Uint8List>.of(draws);
  return (length) {
    expect(queue, isNotEmpty, reason: 'unexpected draw of $length bytes');
    final next = queue.removeAt(0);
    expect(next.length, length, reason: 'a draw of $length bytes');
    return Uint8List.fromList(next);
  };
}

final _authentication = isA<OpaqueException>().having((e) => e.failure, 'failure', OpaqueFailure.authentication);

void main() {
  group("the server's opaque vectors", () {
    for (final c in readServerCases('opaque.json', format: 'opaque1')) {
      final name = c['name']! as String;
      final password = fromHex(c['password']! as String);
      final random = c['random_inputs']! as Map<String, Object?>;
      final registration = c['registration']! as Map<String, Object?>;
      final login = c['login']! as Map<String, Object?>;

      Uint8List draw(String field) => fromHex(random[field]! as String);

      // The client of the case: the Kemlock context, with the draws it makes.
      OpaqueClient registering() => OpaqueClient(random: _drawing([draw('envelope_nonce')]));
      OpaqueClient signingIn() => OpaqueClient(random: _drawing([draw('client_nonce'), draw('client_keyshare_seed')]));

      test('$name: the configuration is the Kemlock one', () {
        expect(c['context_text'], kemlockOpaqueContext);
        expect(toHex(utf8.encode(kemlockOpaqueContext)), c['context']);
        // The credential identifier is the e-mail trimmed and lower-cased, as UTF-8.
        final identifier = c['credential_identifier_text']! as String;
        expect(identifier, identifier.trim().toLowerCase());
        expect(toHex(utf8.encode(identifier)), c['credential_identifier']);
        expect(password, hasLength(32));
      });

      test('$name: the messages have the sizes of the ristretto255-SHA512 configuration and round-trip', () {
        expect(toHex(RegistrationRequest.parse(fromHex(registration['request']! as String)).bytes), registration['request']);
        expect(toHex(RegistrationResponse.parse(fromHex(registration['response']! as String)).bytes), registration['response']);
        expect(toHex(RegistrationRecord.parse(fromHex(registration['record']! as String)).bytes), registration['record']);
        expect(toHex(RegistrationRecord.parse(fromHex(registration['upload']! as String)).bytes), registration['upload']);
        expect(toHex(Ke1.parse(fromHex(login['ke1']! as String)).bytes), login['ke1']);
        expect(toHex(Ke2.parse(fromHex(login['ke2']! as String)).bytes), login['ke2']);
        expect(toHex(Ke3.parse(fromHex(login['ke3']! as String)).bytes), login['ke3']);
      });

      test('$name: the random inputs are where the messages carry them', () {
        final ke1 = fromHex(login['ke1']! as String);
        final ke2 = fromHex(login['ke2']! as String);
        final record = fromHex(registration['record']! as String);
        final response = fromHex(registration['response']! as String);
        expect(toHex(ke1.sublist(32, 64)), random['client_nonce']);
        expect(toHex(ke2.sublist(32, 64)), random['masking_nonce']);
        expect(toHex(ke2.sublist(192, 224)), random['server_nonce']);
        expect(toHex(record.sublist(96, 128)), random['envelope_nonce']);
        expect(toHex(response.sublist(32)), c['server_public_key']);
      });

      test('$name: registration gives the request, the record and the export key', () {
        final client = registering();
        final (:request, :state) = client.createRegistrationRequest(password, blind: draw('blind_registration'));
        expect(toHex(request.bytes), registration['request']);
        final (:record, :exportKey) = client.finalizeRegistrationRequest(
          state,
          RegistrationResponse.parse(fromHex(registration['response']! as String)),
        );
        expect(toHex(record.bytes), registration['record']);
        expect(toHex(record.bytes), registration['upload']);
        expect(toHex(exportKey), registration['export_key']);
      });

      test('$name: sign-in gives KE1, KE3, the session key and the export key', () {
        final client = signingIn();
        final (:ke1, :state) = client.generateKe1(password, blind: draw('blind_login'));
        expect(toHex(ke1.bytes), login['ke1']);
        final (:ke3, :sessionKey, :exportKey) = client.generateKe3(state, Ke2.parse(fromHex(login['ke2']! as String)));
        expect(toHex(ke3.bytes), login['ke3']);
        expect(toHex(sessionKey), login['client_session_key']);
        expect(login['client_session_key'], login['server_session_key']);
        expect(toHex(exportKey), login['export_key']);
        // Registration and sign-in give the one export key, which the password wrap needs.
        expect(login['export_key'], registration['export_key']);
      });

      test('$name: a wrong password fails at the MAC check and gives no export key', () {
        final client = signingIn();
        final wrong = Uint8List.fromList(password)..[0] ^= 1;
        final (:ke1, :state) = client.generateKe1(wrong, blind: draw('blind_login'));
        expect(toHex(ke1.bytes), isNot(login['ke1']));
        expect(() => client.generateKe3(state, Ke2.parse(fromHex(login['ke2']! as String))), throwsA(_authentication));
      });

      test('$name: a changed server key, in the masked response, fails with no export key', () {
        final client = signingIn();
        final (:state, ke1: _) = client.generateKe1(password, blind: draw('blind_login'));
        // KE2 = evaluated (32) || masking nonce (32) || masked response (128) || auth response (128);
        // the first 32 bytes of the masked response are the server public key, masked.
        final ke2 = fromHex(login['ke2']! as String)..[64] ^= 1;
        expect(() => client.generateKe3(state, Ke2.parse(ke2)), throwsA(_authentication));
      });

      test('$name: another context does not verify the server MAC', () {
        final client = OpaqueClient(context: 'kemlock/v1/other', random: _drawing([draw('client_nonce'), draw('client_keyshare_seed')]));
        final (:state, ke1: _) = client.generateKe1(password, blind: draw('blind_login'));
        expect(() => client.generateKe3(state, Ke2.parse(fromHex(login['ke2']! as String))), throwsA(_authentication));
      });
    }
  });
}
