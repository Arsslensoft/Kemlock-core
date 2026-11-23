@TestOn('vm')
library;

// AES key wrap (RFC 3394), the ECDH of RFC 6637 on Curve25519, and X25519
// with HKDF against RFC 9580 A.8.2.

import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/ecdh.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'stream_test.dart' show throwsPgp;

KeyPacket _subkey(Uint8List key) =>
    parseKeyPacket(readPackets(key).firstWhere((p) => p.tag == PgpTag.secretSubkey || p.tag == PgpTag.publicSubkey));

void main() {
  group('AES key wrap', () {
    // RFC 3394 section 4: KEK 000102..., key data 00112233...
    final vectors = [
      ('000102030405060708090A0B0C0D0E0F', '00112233445566778899AABBCCDDEEFF', '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'),
      (
        '000102030405060708090A0B0C0D0E0F1011121314151617',
        '00112233445566778899AABBCCDDEEFF',
        '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D',
      ),
      (
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        '00112233445566778899AABBCCDDEEFF',
        '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7',
      ),
      (
        '000102030405060708090A0B0C0D0E0F1011121314151617',
        '00112233445566778899AABBCCDDEEFF0001020304050607',
        '031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2',
      ),
      (
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        '00112233445566778899AABBCCDDEEFF0001020304050607',
        'A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1',
      ),
      (
        '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
        '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
        '28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21',
      ),
    ];

    test('the vectors of RFC 3394 section 4', () {
      for (final (kek, data, wrapped) in vectors) {
        expect(hexOf(aesKeyWrap(unhex(kek), unhex(data))).toUpperCase(), wrapped);
        expect(aesKeyUnwrap(unhex(kek), unhex(wrapped)), unhex(data));
      }
    });

    test('a wrong key, a changed byte and a bad length do not unwrap', () {
      final (kek, _, wrapped) = vectors.first;
      expect(() => aesKeyUnwrap(unhex(kek)..[0] ^= 1, unhex(wrapped)), throwsPgp(PgpProblem.damaged, 'session key'));
      expect(() => aesKeyUnwrap(unhex(kek), unhex(wrapped)..[9] ^= 1), throwsPgp(PgpProblem.damaged, 'session key'));
      expect(() => aesKeyUnwrap(unhex(kek), unhex(wrapped).sublist(0, 20)), throwsPgp(PgpProblem.damaged));
      expect(() => aesKeyUnwrap(unhex(kek), unhex(wrapped).sublist(0, 16)), throwsPgp(PgpProblem.damaged));
      expect(() => aesKeyWrap(unhex(kek), Uint8List(12)), throwsArgumentError);
    });
  });

  group('X25519 with HKDF (RFC 9580 A.8.2)', () {
    final ephemeral = unhex('87cf18d5f1b53f817cce5a004cf393cc8958bddc065f25f84af509b17dd36764');
    final ephemeralSecret = unhex('af1e43c0d123efe893a7d4d390f3a761e3fac33dfc7f3edaa830c9011352c779');
    final public = unhex('8693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435');
    final secret = unhex('4d600a4f794d44775c57a26e0feefed558e9afffd6ad0d582d57fb2ba2dcedb8');
    final shared = unhex('67e30e69cdc7bab2a2680d78aca46a2f8b6e2ae44d398bdc6f92c5ad4a492514');
    final wrapped = unhex('dea355437956617901e06957fbca8a6a47a5b5153e8d3ab7');

    test('the keys belong together', () async {
      expect(await x25519Public(ephemeralSecret), ephemeral);
      expect(await x25519Public(secret), public);
      // The sample key's subkey holds them
      final subkey = _subkey(Keys.v6);
      expect(subkey.publicMaterial, public);
      expect((unlockSecretKey(subkey) as X25519Secret).secret, secret);
    });

    test('the shared point, the HKDF output and the session key', () async {
      expect(await x25519Shared(secret, ephemeral), shared);
      expect(await x25519Shared(ephemeralSecret, public), shared);
      expect(hexOf(x25519Kek(ephemeral, public, shared)), 'f66dadcff64592239b254539b64ff607');
      expect(hexOf(await x25519Unwrap(secret, public, ephemeral, wrapped)), 'dd708f6fa1ed65114d68d2343e7c2f1d');
    });

    test('a point of small order is refused', () async {
      await expectLater(x25519Shared(secret, Uint8List(32)), throwsPgp(PgpProblem.damaged));
    });
  });

  group('ECDH on Curve25519 (RFC 6637)', () {
    final gnupg = _subkey(Keys.ed);
    final kemlock = _subkey(Keys.kemlockEd);
    final encoded = Uint8List.fromList([9, ...List.generate(32, (i) => 200 - i), 0xab, 0xcd]);

    test('the KDF parameters of the key are read', () {
      for (final key in [gnupg, kemlock]) {
        final public = EcdhPublic.of(key);
        expect(public.point, hasLength(32));
        // SHA-256 and AES-128, as GnuPG sets for Curve25519
        expect((public.kdfHash, public.kdfCipher), (8, 7));
        expect(public.oid, [0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01]);
      }
    });

    test('what is wrapped for a key, its secret unwraps', () async {
      for (final key in [gnupg, kemlock]) {
        final secret = (unlockSecretKey(key) as X25519Secret).secret;
        final ephemeralSecret = Uint8List.fromList(List.generate(32, (i) => i + 40));
        final (:ephemeral, :wrapped) = await ecdhWrap(key, encoded, ephemeralSecret);
        expect(ephemeral, await x25519Public(ephemeralSecret));
        // 35 bytes padded to 40, wrapped to 48
        expect(wrapped, hasLength(48));
        expect(await ecdhUnwrap(key, secret, ephemeral, wrapped), encoded);
        // The same inputs give the same bytes
        expect((await ecdhWrap(key, encoded, ephemeralSecret)).wrapped, wrapped);
        // Another key's secret does not open it
        final other = (unlockSecretKey(key == gnupg ? kemlock : gnupg) as X25519Secret).secret;
        await expectLater(ecdhUnwrap(key, other, ephemeral, wrapped), throwsPgp(PgpProblem.damaged, 'session key'));
      }
    });

    // RFC 6637 section 8: a sender MAY pad each session key to 40 bytes, 21 bytes for AES-128 and 13 for AES-192
    test('an AES-128 or AES-192 session key padded to 40 bytes unwraps, as this app wraps it', () async {
      final secret = (unlockSecretKey(gnupg) as X25519Secret).secret;
      final ephemeralSecret = Uint8List.fromList(List.generate(32, (i) => i + 7));
      for (final (cipher, length, pad) in [(7, 16, 21), (8, 24, 13), (9, 32, 5)]) {
        final short = Uint8List.fromList([cipher, ...List.generate(length, (i) => i + 1), 0x01, 0x02]);
        final (:ephemeral, :wrapped) = await ecdhWrap(gnupg, short, ephemeralSecret);
        expect(wrapped, hasLength(48), reason: '40 bytes wrapped');
        expect(await ecdhUnwrap(gnupg, secret, ephemeral, wrapped), short, reason: '$pad bytes of padding');
      }
    });

    test('padding whose bytes are not all its count is refused', () async {
      final shared = Uint8List.fromList(List.filled(32, 5));
      final kek = ecdhKek(EcdhPublic.of(gnupg), shared, gnupg.fingerprint);
      Uint8List padded(int pad, {int last = -1}) =>
          Uint8List.fromList([...List.filled(40 - pad, 1), ...List.filled(pad - 1, pad), if (last < 0) pad else last]);
      expect(await ecdhUnwrapShared(gnupg, shared, aesKeyWrap(kek, padded(21))), hasLength(19));
      // One byte of the 21 that is not 21
      final wrong = padded(21)..[25] = 20;
      await expectLater(ecdhUnwrapShared(gnupg, shared, aesKeyWrap(kek, wrong)), throwsPgp(PgpProblem.damaged, 'session key'));
      // A count of 0, or one that leaves nothing
      await expectLater(
        ecdhUnwrapShared(gnupg, shared, aesKeyWrap(kek, padded(21, last: 0))),
        throwsPgp(PgpProblem.damaged, 'session key'),
      );
      await expectLater(
        ecdhUnwrapShared(gnupg, shared, aesKeyWrap(kek, Uint8List.fromList(List.filled(40, 40)))),
        throwsPgp(PgpProblem.damaged, 'session key'),
      );
    });

    test('the key-wrapping key depends on the fingerprint', () {
      final public = EcdhPublic.of(gnupg);
      final shared = Uint8List.fromList(List.filled(32, 5));
      final kek = ecdhKek(public, shared, gnupg.fingerprint);
      expect(kek, hasLength(16));
      expect(ecdhKek(public, shared, kemlock.fingerprint), isNot(kek));
    });

    /// The subkey's packet with its KDF parameters replaced.
    KeyPacket withKdf(int hash, int cipher) {
      final body = Uint8List.fromList(gnupg.publicBody);
      body[body.length - 2] = hash;
      body[body.length - 1] = cipher;
      return parseKeyPacket(readPackets(writePacket(PgpTag.publicSubkey, body)).single);
    }

    test('SHA-384 and SHA-512, AES-192 and AES-256 are taken', () {
      for (final (hash, cipher, length) in [(9, 8, 24), (10, 9, 32)]) {
        final public = EcdhPublic.of(withKdf(hash, cipher));
        expect(ecdhKek(public, Uint8List(32), gnupg.fingerprint), hasLength(length));
      }
    });

    test('an unknown KDF hash or cipher is refused by name', () {
      expect(() => EcdhPublic.of(withKdf(2, 7)), throwsPgp(PgpProblem.unsupported, 'ECDH with SHA-1'));
      expect(() => EcdhPublic.of(withKdf(8, 3)), throwsPgp(PgpProblem.unsupported, 'CAST5'));
    });

    test('another curve is refused by name', () {
      expect(() => EcdhPublic.of(_subkey(Keys.brainpool)), throwsPgp(PgpProblem.unsupported, 'brainpoolP256r1'));
    });
  });
}
