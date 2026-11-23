@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/ecdh.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pgp_error.dart';
import 'package:kemlock_core/crypto/keys/openpgp/pq_kem.dart';
import 'package:kemlock_core/crypto/keys/openpgp/secret_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/session_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

import '../vectors.dart';
import 'fixtures.dart';

// The two post-quantum key agreements: RFC 9980's ML-KEM-768+X25519,
// checked against the values its appendix A prints for each message
// (rfc9980/values.json), and LibrePGP's Kyber, checked against the files
// GnuPG 2.5.24 encrypted (gnupg/pqc, their session keys in
// session-keys.txt).

Uint8List _binary(String path) {
  final bytes = keyFixture(path);
  return bytes[0] & 0x80 != 0 ? bytes : readArmorBlock(bytes);
}

/// The body of the first packet of a message.
Uint8List _firstPacket(Uint8List message) {
  final packet = PacketReader(PgpReader.bytes(message)).next()!;
  return packet.body.rest(max: message.length);
}

/// The secret key packets of a key.
List<KeyPacket> _secretKeys(String path) => [
  for (final p in readPackets(_binary(path)))
    if (p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey) parseKeyPacket(p),
];

void main() {
  final values = jsonDecode(keyFixtureText('rfc9980/values.json')) as Map<String, Object?>;
  Uint8List value(String message, String name) => fromHex((values[message]! as Map<String, Object?>)[name]! as String);

  group("RFC 9980's ML-KEM-768+X25519", () {
    for (final (section, message) in [
      ('a1', 'a1-message'),
      ('a2', 'a2-message-seipd1'),
      ('a2', 'a2-message-seipd2'),
      ('a3', 'a3-message'),
    ]) {
      test('$message: the key shares, the combined key and the session key the RFC prints', () async {
        final subkey = _secretKeys('rfc9980/$section-secret.asc').last;
        final secret = unlockSecretKey(subkey) as MlKemX25519Secret;
        final pkesk = parsePkesk(_firstPacket(_binary('rfc9980/$message.asc')));
        expect(pkesk.algorithm, 35);
        expect(pkesk.version, message.endsWith('seipd1') ? 3 : 6);
        final m = pkesk.material;
        final ephemeral = m.sublist(0, 32);
        final cipherText = m.sublist(32, 32 + MlKem768.cipherTextLength);
        var rest = m.sublist(32 + MlKem768.cipherTextLength);
        expect(rest[0], rest.length - 1, reason: 'the count of what follows');
        rest = rest.sublist(pkesk.version == 3 ? 2 : 1);

        expect(MlKem768.decapsulate(cipherText, secret.mlKemSecretKey), value(message, 'mlkemKeyShare'));
        expect(await x25519Shared(secret.x25519, ephemeral), value(message, 'ecdhKeyShare'));
        final kek = await mlKemX25519Decapsulate(
          public: subkey.publicMaterial,
          x25519Secret: secret.x25519,
          mlKemSecretKey: secret.mlKemSecretKey,
          ephemeral: ephemeral,
          mlKemCipherText: cipherText,
        );
        expect(kek, value(message, 'multiKeyCombine'));
        expect(aesKeyUnwrap(kek, rest), value(message, 'sessionKey'));
      });
    }

    test('an encapsulation with fixed randomness decapsulates to the same key', () async {
      final subkey = _secretKeys('rfc9980/a1-secret.asc').last;
      final secret = unlockSecretKey(subkey) as MlKemX25519Secret;
      final sent = await mlKemX25519Encapsulate(
        subkey.publicMaterial,
        ephemeralSecret: Uint8List.fromList(List.generate(32, (i) => i + 1)),
        mlKemMessage: Uint8List.fromList(List.filled(32, 9)),
      );
      final again = await mlKemX25519Encapsulate(
        subkey.publicMaterial,
        ephemeralSecret: Uint8List.fromList(List.generate(32, (i) => i + 1)),
        mlKemMessage: Uint8List.fromList(List.filled(32, 9)),
      );
      expect(again.kek, sent.kek);
      final kek = await mlKemX25519Decapsulate(
        public: subkey.publicMaterial,
        x25519Secret: secret.x25519,
        mlKemSecretKey: secret.mlKemSecretKey,
        ephemeral: sent.eccCipherText,
        mlKemCipherText: sent.mlKemCipherText,
      );
      expect(kek, sent.kek);
    });

    test('a changed ML-KEM ciphertext, ephemeral key or wrapped key each fail the same way', () async {
      final subkey = _secretKeys('rfc9980/a1-secret.asc').last;
      final secret = unlockSecretKey(subkey) as MlKemX25519Secret;
      final sessionKey = Uint8List.fromList(List.filled(32, 0x5a));
      final sent = await mlKemX25519Encapsulate(subkey.publicMaterial);
      final wrapped = aesKeyWrap(sent.kek, sessionKey);
      Future<Uint8List> open(Uint8List ephemeral, Uint8List cipherText, Uint8List wrapped) async => aesKeyUnwrap(
        await mlKemX25519Decapsulate(
          public: subkey.publicMaterial,
          x25519Secret: secret.x25519,
          mlKemSecretKey: secret.mlKemSecretKey,
          ephemeral: ephemeral,
          mlKemCipherText: cipherText,
        ),
        wrapped,
      );
      expect(await open(sent.eccCipherText, sent.mlKemCipherText, wrapped), sessionKey);
      final failed = throwsA(
        isA<PgpException>().having((e) => e.problem, 'problem', PgpProblem.damaged).having((e) => e.detail, 'detail', 'session key'),
      );
      await expectLater(open(sent.eccCipherText, Uint8List.fromList(sent.mlKemCipherText)..[100] ^= 1, wrapped), failed);
      await expectLater(open(Uint8List.fromList(sent.eccCipherText)..[5] ^= 1, sent.mlKemCipherText, wrapped), failed);
      await expectLater(open(sent.eccCipherText, sent.mlKemCipherText, Uint8List.fromList(wrapped)..[10] ^= 1), failed);
      // A point of small order is no different
      await expectLater(open(Uint8List(32), sent.mlKemCipherText, wrapped), failed);
    });
  });

  group("LibrePGP's Kyber, as GnuPG 2.5 does it", () {
    final sessionKeys = {
      for (final line in const LineSplitter().convert(keyFixtureText('gnupg/pqc/session-keys.txt')))
        line.split(' ')[0]: fromHex(line.split(' ')[1].split(':')[1]),
    };

    /// The fields of a version 3 PKESK of algorithm 8: the ephemeral point,
    /// the ML-KEM ciphertext, the cipher and the wrapped session key.
    ({Uint8List ephemeral, Uint8List cipherText, int cipher, Uint8List wrapped}) fields(Pkesk pkesk, KyberCurve curve) {
      final r = PgpReader.bytes(pkesk.material);
      final point = r.bytes((r.uint16() + 7) >> 3);
      final ephemeral = Uint8List(curve.pointLength)..setAll(curve.pointLength - point.length, point);
      final cipherText = r.bytes(r.uint32());
      final cipher = r.byte();
      final wrapped = r.bytes(r.byte());
      expect(r.atEnd, isTrue);
      return (ephemeral: ephemeral, cipherText: cipherText, cipher: cipher, wrapped: wrapped);
    }

    /// The ECC point of a Kyber subkey, without X25519's 0x40.
    Uint8List eccPoint(KeyPacket key) {
      final r = PgpReader.bytes(key.publicMaterial);
      r.bytes(r.byte());
      final point = r.bytes((r.uint16() + 7) >> 3);
      return point[0] == 0x40 ? Uint8List.sublistView(point, 1) : point;
    }

    for (final (file, key) in [
      ('ky768-cv25519.message.gpg', 'ky768-cv25519'),
      ('ky768-cv25519.force-ocb.gpg', 'ky768-cv25519'),
      ('ky768-cv25519.seipd1.gpg', 'ky768-cv25519'),
      ('ky768-cv25519-protected.message.gpg', 'ky768-cv25519-protected'),
      ('pqc.message.gpg', 'pqc'),
      ('pqc-protected.message.gpg', 'pqc-protected'),
      ('ky1024-bp384.message.gpg', 'ky1024-bp384'),
      ('ky1024-bp384-protected.message.gpg', 'ky1024-bp384-protected'),
    ]) {
      test('$file: the session key GnuPG printed', () async {
        final subkey = _secretKeys('gnupg/pqc/$key.secret.asc').last;
        final curve = KyberCurve.ofKey(subkey.name)!;
        final secret = await unlockSecretKeyAsync(subkey, passphrase: 'fixture passphrase') as KyberSecret;
        final pkesk = parsePkesk(_firstPacket(_binary('gnupg/pqc/$file')));
        expect(pkesk.algorithm, 8);
        expect(pkesk.isFor(subkey), isTrue);
        final f = fields(pkesk, curve);
        final kek = await kyberDecapsulate(
          curve: curve,
          eccPublic: eccPoint(subkey),
          eccSecret: secret.ecc,
          mlKemSecretKey: secret.mlKemSecretKey,
          ephemeral: f.ephemeral,
          mlKemCipherText: f.cipherText,
          cipher: f.cipher,
          fingerprint: subkey.fingerprint,
        );
        expect(aesKeyUnwrap(kek, f.wrapped), sessionKeys[file]);
      });
    }

    for (final key in ['ky768-cv25519', 'pqc', 'ky1024-bp384']) {
      test('$key: an encapsulation decapsulates to the same key, and a changed part fails the same way', () async {
        final subkey = _secretKeys('gnupg/pqc/$key.secret.asc').last;
        final curve = KyberCurve.ofKey(subkey.name)!;
        final secret = unlockSecretKey(subkey) as KyberSecret;
        final r = PgpReader.bytes(subkey.publicMaterial);
        r.bytes(r.byte());
        r.bytes((r.uint16() + 7) >> 3);
        final mlKemPublic = r.bytes(r.uint32());
        final sent = await kyberEncapsulate(
          curve: curve,
          eccPublic: eccPoint(subkey),
          mlKemPublic: mlKemPublic,
          cipher: 9,
          fingerprint: subkey.fingerprint,
          ephemeralSecret: Uint8List.fromList(List.generate(32, (i) => i + 3)),
          mlKemMessage: Uint8List.fromList(List.filled(32, 4)),
        );
        Future<Uint8List> kek(Uint8List ephemeral, Uint8List cipherText) => kyberDecapsulate(
          curve: curve,
          eccPublic: eccPoint(subkey),
          eccSecret: secret.ecc,
          mlKemSecretKey: secret.mlKemSecretKey,
          ephemeral: ephemeral,
          mlKemCipherText: cipherText,
          cipher: 9,
          fingerprint: subkey.fingerprint,
        );
        expect(await kek(sent.eccCipherText, sent.mlKemCipherText), sent.kek);
        final sessionKey = Uint8List.fromList(List.filled(32, 0x33));
        final wrapped = aesKeyWrap(sent.kek, sessionKey);
        Future<Uint8List> open(Uint8List ephemeral, Uint8List cipherText, Uint8List wrapped) async =>
            aesKeyUnwrap(await kek(ephemeral, cipherText), wrapped);
        final failed = throwsA(
          isA<PgpException>().having((e) => e.problem, 'problem', PgpProblem.damaged).having((e) => e.detail, 'detail', 'session key'),
        );
        await expectLater(open(sent.eccCipherText, Uint8List.fromList(sent.mlKemCipherText)..[7] ^= 1, wrapped), failed);
        // An X25519 key changed, or a brainpool point moved off the curve
        await expectLater(
          open(Uint8List.fromList(sent.eccCipherText)..[curve.pointLength - 1] ^= 1, sent.mlKemCipherText, wrapped),
          failed,
        );
        await expectLater(open(sent.eccCipherText, sent.mlKemCipherText, Uint8List.fromList(wrapped)..[3] ^= 1), failed);
        // The key is bound to the subkey and the cipher
        final other = await kyberDecapsulate(
          curve: curve,
          eccPublic: eccPoint(subkey),
          eccSecret: secret.ecc,
          mlKemSecretKey: secret.mlKemSecretKey,
          ephemeral: sent.eccCipherText,
          mlKemCipherText: sent.mlKemCipherText,
          cipher: 7,
          fingerprint: subkey.fingerprint,
        );
        expect(other, isNot(sent.kek));
      });
    }
  });
}
