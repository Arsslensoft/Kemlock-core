@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sealed_box.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

/// HKDF-SHA256 with one output block, straight from RFC 5869 with
/// `package:crypto`: PRK = HMAC(zeros(32), ikm), OKM = HMAC(PRK, info || 0x01).
Uint8List _hkdfOneBlock(List<int> ikm, List<int> info) {
  final prk = hash.Hmac(hash.sha256, Uint8List(32)).convert(ikm).bytes;
  return Uint8List.fromList(hash.Hmac(hash.sha256, prk).convert([...info, 1]).bytes);
}

void main() {
  final privateKey = Uint8List.fromList(List.generate(96, (i) => (i * 11 + 5) & 0xff));
  final secret = Uint8List.fromList(List.generate(32, (i) => 0x40 + i));
  final aad = utf8.encode('recipient account id');
  late Uint8List publicKey;
  late Uint8List box;

  setUpAll(() async {
    publicKey = await Kx1.publicKeyOf(privateKey);
    box = await sealBox(publicKey, secret, context: SealContext.spaceKey, aad: aad);
  });

  test('has the layout crypto.md gives: version, kx1 ciphertext, nonce, ciphertext, tag', () {
    expect(box[0], 1);
    expect(box, hasLength(1 + 1600 + 12 + secret.length + 16));
    expect(sealedBoxMinimumLength, 1 + 1600 + 12 + 16);
  });

  test('is made as crypto.md says, from its parts', () async {
    final message = Uint8List.fromList(List.generate(32, (i) => i + 1));
    final ephemeral = Uint8List.fromList(List.generate(32, (i) => 0xc0 + i));
    final nonce = Uint8List.fromList(List.generate(12, (i) => 0x30 + i));
    final made = await sealBox(
      publicKey,
      secret,
      context: SealContext.deviceApproval,
      aad: aad,
      mlKemMessage: message,
      ephemeralSecret: ephemeral,
      nonce: nonce,
    );

    final encapsulated = await Kx1.encapsulate(publicKey, mlKemMessage: message, ephemeralSecret: ephemeral);
    final context = utf8.encode('device-approval');
    final key = _hkdfOneBlock(encapsulated.sharedSecret, [...utf8.encode('kemlock/v1/seal'), ...lp(context)]);
    final sealed = await aesGcmEncrypt(key, secret, nonce: nonce, aad: [...lp(context), ...lp(aad)]);
    expect(made, [1, ...encapsulated.ciphertext, ...nonce, ...sealed.ct]);
  });

  test('opens with the private key, the context and the aad', () async {
    expect(await openBox(box, privateKey, context: SealContext.spaceKey, aad: aad), secret);
  });

  test('sealing one secret twice gives different boxes', () async {
    final again = await sealBox(publicKey, secret, context: SealContext.spaceKey, aad: aad);
    expect(again, isNot(box));
  });

  test('a box sealed under one context does not open as another', () async {
    await expectLater(openBox(box, privateKey, context: SealContext.deviceApproval, aad: aad), throwsA(isA<CorruptedException>()));
    await expectLater(openBox(box, privateKey, context: SealContext.collectionKey, aad: aad), throwsA(isA<CorruptedException>()));
  });

  test('another aad, or none, does not open it', () async {
    await expectLater(
      openBox(box, privateKey, context: SealContext.spaceKey, aad: utf8.encode('another account')),
      throwsA(isA<CorruptedException>()),
    );
    await expectLater(openBox(box, privateKey, context: SealContext.spaceKey), throwsA(isA<CorruptedException>()));
  });

  test('the wrong private key, or one with a half changed, does not open it', () async {
    final other = Uint8List.fromList(privateKey)..[0] ^= 1;
    final otherX25519 = Uint8List.fromList(privateKey)..[95] ^= 1;
    await expectLater(openBox(box, other, context: SealContext.spaceKey, aad: aad), throwsA(isA<CorruptedException>()));
    await expectLater(openBox(box, otherX25519, context: SealContext.spaceKey, aad: aad), throwsA(isA<CorruptedException>()));
  });

  test('a changed byte anywhere gives corrupted', () async {
    // The nonce, the sealed secret and the tag, byte by byte; the kx1
    // ciphertext at the edges of both halves and at points between, since
    // ML-KEM's implicit rejection and the tag turn each into a failed open.
    final positions = <int>{
      ...List.generate(box.length - (1 + 1600), (i) => 1 + 1600 + i),
      for (var i = 1; i < 1601; i += 97) i,
      1,
      1568,
      1569,
      1600,
    };
    for (final index in positions) {
      final changed = Uint8List.fromList(box)..[index] ^= 0x01;
      await expectLater(
        openBox(changed, privateKey, context: SealContext.spaceKey, aad: aad),
        throwsA(isA<CorruptedException>()),
        reason: 'byte $index',
      );
    }
  });

  test('a box that is too short, or of another version, is malformed', () async {
    await expectLater(openBox(Uint8List(0), privateKey, context: SealContext.spaceKey), throwsA(isA<MalformedException>()));
    await expectLater(
      openBox(Uint8List.sublistView(box, 0, sealedBoxMinimumLength - 1), privateKey, context: SealContext.spaceKey),
      throwsA(isA<MalformedException>()),
    );
    final version2 = Uint8List.fromList(box)..[0] = 2;
    await expectLater(openBox(version2, privateKey, context: SealContext.spaceKey, aad: aad), throwsA(isA<MalformedException>()));
  });

  test('a box cut short or with bytes added is corrupted, never read', () async {
    final cut = Uint8List.sublistView(box, 0, box.length - 1);
    final added = Uint8List.fromList([...box, 0]);
    await expectLater(openBox(cut, privateKey, context: SealContext.spaceKey, aad: aad), throwsA(isA<CorruptedException>()));
    await expectLater(openBox(added, privateKey, context: SealContext.spaceKey, aad: aad), throwsA(isA<CorruptedException>()));
  });

  test('names the five contexts of crypto.md', () {
    expect(
      [
        SealContext.deviceApproval,
        SealContext.spaceKey,
        SealContext.collectionKey,
        SealContext.emergencyAccess,
        SealContext.accountRecovery,
      ],
      ['device-approval', 'space-key', 'collection-key', 'emergency-access', 'account-recovery'],
    );
  });

  group('the device-approval seal of the root key', () {
    // crypto.md: the root key to a new device's one-time key pair, with aad = account id (16) || request id (16).
    final root = Uint8List.fromList(List.generate(64, (i) => (i * 7 + 3) & 0xff));
    final accountId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ab');
    final requestId = uuidBytes('0189f7c3-1b2c-7d3e-9f40-a1b2c3d4e5f6');
    final approvalAad = Uint8List.fromList([...accountId, ...requestId]);
    // The new device's one-time pair, and another device's
    final oneTimePrivate = Uint8List.fromList(List.generate(96, (i) => (i * 13 + 2) & 0xff));
    late Uint8List oneTimePublic;
    late Uint8List sealedRoot;

    setUpAll(() async {
      oneTimePublic = await Kx1.publicKeyOf(oneTimePrivate);
      sealedRoot = await sealBox(oneTimePublic, root, context: SealContext.deviceApproval, aad: approvalAad);
    });

    test('opens with the new device\'s one-time key, for its request and account', () async {
      expect(approvalAad, hasLength(32));
      expect(sealedRoot, hasLength(1 + 1600 + 12 + 64 + 16));
      expect(await openBox(sealedRoot, oneTimePrivate, context: SealContext.deviceApproval, aad: approvalAad), root);
    });

    test('does not open for another request id, even with the right key', () async {
      final other = uuidBytes('0189f7c3-1b2c-7d3e-9f40-a1b2c3d4e5f7');
      await expectLater(
        openBox(sealedRoot, oneTimePrivate, context: SealContext.deviceApproval, aad: [...accountId, ...other]),
        throwsA(isA<CorruptedException>()),
      );
      // The two halves swapped, or the request id alone, are not the aad either
      await expectLater(
        openBox(sealedRoot, oneTimePrivate, context: SealContext.deviceApproval, aad: [...requestId, ...accountId]),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openBox(sealedRoot, oneTimePrivate, context: SealContext.deviceApproval, aad: requestId),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('does not open for another account id', () async {
      final other = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ac');
      await expectLater(
        openBox(sealedRoot, oneTimePrivate, context: SealContext.deviceApproval, aad: [...other, ...requestId]),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('does not open with another device\'s key, or under another context', () async {
      final another = Uint8List.fromList(oneTimePrivate)..[10] ^= 1;
      await expectLater(
        openBox(sealedRoot, another, context: SealContext.deviceApproval, aad: approvalAad),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openBox(sealedRoot, oneTimePrivate, context: SealContext.spaceKey, aad: approvalAad),
        throwsA(isA<CorruptedException>()),
      );
    });
  });
}
