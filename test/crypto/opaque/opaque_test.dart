@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/opaque/opaque_client.dart';
import 'package:kemlock_core/crypto/opaque/opaque_messages.dart';
import 'package:kemlock_core/crypto/opaque/ristretto255.dart';
import 'package:test/test.dart';

import '../vectors.dart';

// RFC 9807 appendix C.1.1 and C.1.2, the real test vectors 1 and 2, copied by
// script from the RFC's text into test/fixtures/account/rfc/opaque_rfc9807.json.
// Both use ristretto255-SHA512, HKDF-SHA512, HMAC-SHA512, the Identity KSF and
// the context "OPAQUE-POC" (4f50415155452d504f43); vector 2 also gives a
// client identity and a server identity. The vectors fix the blinds, the
// nonces and the keyshare seed, which the client takes from `random` and from
// the `blind` argument.

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

void main() {
  final doc = jsonDecode(File('test/fixtures/account/rfc/opaque_rfc9807.json').readAsStringSync()) as Map<String, Object?>;
  final vectors = objects(doc['vectors']);

  Uint8List hex(Map<String, Object?> v, String field) => fromHex(v[field]! as String);

  OpaqueClient clientFor(Map<String, Object?> v, {List<Uint8List> draws = const []}) => OpaqueClient.withContextBytes(
    hex(v, 'Context'),
    clientIdentity: v['client_identity'] == null ? null : hex(v, 'client_identity'),
    serverIdentity: v['server_identity'] == null ? null : hex(v, 'server_identity'),
    random: _drawing(draws),
  );

  for (final v in vectors) {
    group('RFC 9807 ${v['section']} (${v['client_identity'] == null ? 'no identities' : 'with identities'})', () {
      test('registration: the request, the record and the export key', () {
        final client = clientFor(v, draws: [hex(v, 'envelope_nonce')]);
        final (:request, :state) = client.createRegistrationRequest(hex(v, 'password'), blind: hex(v, 'blind_registration'));
        expect(toHex(request.bytes), v['registration_request']);
        final (:record, :exportKey) = client.finalizeRegistrationRequest(
          state,
          RegistrationResponse.parse(hex(v, 'registration_response')),
        );
        expect(toHex(record.bytes), v['registration_upload']);
        expect(toHex(record.envelope.bytes), v['envelope']);
        expect(toHex(record.clientPublicKey), v['client_public_key']);
        expect(toHex(exportKey), v['export_key']);
      });

      test('sign-in: KE1, KE3, the session key and the export key', () {
        final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
        final (:ke1, :state) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
        expect(toHex(ke1.bytes), v['KE1']);
        final (:ke3, :sessionKey, :exportKey) = client.generateKe3(state, Ke2.parse(hex(v, 'KE2')));
        expect(toHex(ke3.bytes), v['KE3']);
        expect(toHex(sessionKey), v['session_key']);
        expect(toHex(exportKey), v['export_key']);
      });

      test('a wrong password fails at the MAC check and gives no export key', () {
        final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
        final password = hex(v, 'password');
        password[0] ^= 1;
        final (:ke1, :state) = client.generateKe1(password, blind: hex(v, 'blind_login'));
        expect(ke1.bytes, isNot(hex(v, 'KE1')));
        expect(() => client.generateKe3(state, Ke2.parse(hex(v, 'KE2'))), throwsA(_authentication));
      });

      test('a changed server key, in the masked response, fails with no export key', () {
        final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
        final (:state, ke1: _) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
        // KE2 = evaluated (32) || masking nonce (32) || masked response (128) || auth response (128);
        // the first 32 bytes of the masked response are the server public key, masked.
        final ke2 = hex(v, 'KE2')..[64] ^= 1;
        expect(() => client.generateKe3(state, Ke2.parse(ke2)), throwsA(_authentication));
      });

      test('a changed byte anywhere in KE2 fails', () {
        for (final index in [0, 31, 32, 63, 64, 95, 96, 191, 192, 223, 224, 255, 256, 319]) {
          final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
          final (:state, ke1: _) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
          final ke2 = hex(v, 'KE2')..[index] ^= 1;
          expect(() => client.generateKe3(state, Ke2.parse(ke2)), throwsA(isA<OpaqueException>()), reason: 'byte $index');
        }
      });
    });
  }

  group('the Kemlock configuration', () {
    final v = vectors.first;

    test('uses the context "kemlock/v1/opaque"', () {
      expect(kemlockOpaqueContext, 'kemlock/v1/opaque');
    });

    test('the context is in the transcript: the RFC KE2, made under "OPAQUE-POC", does not verify under it', () {
      final client = OpaqueClient(random: _drawing([hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]));
      final (:state, ke1: _) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
      expect(() => client.generateKe3(state, Ke2.parse(hex(v, 'KE2'))), throwsA(_authentication));
    });

    test('a request is blinded afresh each time, for a 32-byte master key', () {
      final masterKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final client = OpaqueClient();
      final first = client.createRegistrationRequest(masterKey);
      final second = client.createRegistrationRequest(masterKey);
      expect(first.request.bytes, hasLength(32));
      expect(first.request.bytes, isNot(second.request.bytes), reason: 'a fresh blind each time');
      first.state.dispose();
      second.state.dispose();
    });
  });

  group('state', () {
    final v = vectors.first;

    test('a registration state is used once, and can be disposed', () {
      final client = clientFor(v, draws: [hex(v, 'envelope_nonce')]);
      final (:state, request: _) = client.createRegistrationRequest(hex(v, 'password'), blind: hex(v, 'blind_registration'));
      client.finalizeRegistrationRequest(state, RegistrationResponse.parse(hex(v, 'registration_response')));
      expect(
        () => client.finalizeRegistrationRequest(state, RegistrationResponse.parse(hex(v, 'registration_response'))),
        throwsStateError,
      );
    });

    test('a sign-in state is used once, even when it failed, and can be disposed', () {
      final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
      final (:state, ke1: _) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
      final ke2 = hex(v, 'KE2')..[319] ^= 1;
      expect(() => client.generateKe3(state, Ke2.parse(ke2)), throwsA(_authentication));
      expect(() => client.generateKe3(state, Ke2.parse(hex(v, 'KE2'))), throwsStateError);
      OpaqueClient().generateKe1(hex(v, 'password')).state.dispose();
    });

    test('the server public key of a registration response must be a valid element', () {
      final client = clientFor(v, draws: [hex(v, 'envelope_nonce')]);
      final (:state, request: _) = client.createRegistrationRequest(hex(v, 'password'), blind: hex(v, 'blind_registration'));
      final response = hex(v, 'registration_response')..fillRange(32, 64, 0);
      expect(
        () => client.finalizeRegistrationRequest(state, RegistrationResponse.parse(response)),
        throwsA(isA<OpaqueException>().having((e) => e.failure, 'failure', OpaqueFailure.protocol)),
      );
    });

    test('the identity as a keyshare is refused', () {
      final client = clientFor(v, draws: [hex(v, 'client_nonce'), hex(v, 'client_keyshare_seed')]);
      final (:state, ke1: _) = client.generateKe1(hex(v, 'password'), blind: hex(v, 'blind_login'));
      final ke2 = hex(v, 'KE2')..setRange(224, 256, RistrettoPoint.identity.encode());
      expect(() => client.generateKe3(state, Ke2.parse(ke2)), throwsA(isA<OpaqueException>()));
    });
  });

  group('the messages', () {
    final v = vectors.first;

    test('have the sizes of the ristretto255-SHA512 configuration and round-trip', () {
      expect(RegistrationRequest.length, 32);
      expect(RegistrationResponse.length, 64);
      expect(RegistrationRecord.length, 192);
      expect(Ke1.length, 96);
      expect(Ke2.length, 320);
      expect(Ke3.length, 64);
      expect(toHex(RegistrationRequest.parse(hex(v, 'registration_request')).bytes), v['registration_request']);
      expect(toHex(RegistrationResponse.parse(hex(v, 'registration_response')).bytes), v['registration_response']);
      expect(toHex(RegistrationRecord.parse(hex(v, 'registration_upload')).bytes), v['registration_upload']);
      expect(toHex(Ke1.parse(hex(v, 'KE1')).bytes), v['KE1']);
      expect(toHex(Ke2.parse(hex(v, 'KE2')).bytes), v['KE2']);
      expect(toHex(Ke3.parse(hex(v, 'KE3')).bytes), v['KE3']);
    });

    test('refuse every other length', () {
      for (final (parse, length) in <(void Function(List<int>), int)>[
        (RegistrationRequest.parse, 32),
        (RegistrationResponse.parse, 64),
        (RegistrationRecord.parse, 192),
        (Ke1.parse, 96),
        (Ke2.parse, 320),
        (Ke3.parse, 64),
      ]) {
        expect(() => parse(Uint8List(length - 1)), throwsA(isA<MalformedException>()), reason: '$length - 1');
        expect(() => parse(Uint8List(length + 1)), throwsA(isA<MalformedException>()), reason: '$length + 1');
      }
    });
  });
}

final _authentication = isA<OpaqueException>().having((e) => e.failure, 'failure', OpaqueFailure.authentication);
