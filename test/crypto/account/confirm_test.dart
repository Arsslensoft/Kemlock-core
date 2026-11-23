@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/confirm.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

Uint8List _seq(int n, int start) => Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));

void main() {
  final space = _seq(16, 0x10);
  final member = _seq(16, 0x20);
  final confirmer = _seq(16, 0x30);
  final fingerprint = _seq(64, 0x40);

  ConfirmStatement statement({int keyVersion = 1}) =>
      ConfirmStatement(space: space, member: member, memberKeyVersion: keyVersion, fingerprint: fingerprint, confirmer: confirmer);

  test('is "kemlock/v1/confirm", the space, the member, the key version, the fingerprint and the confirmer, 134 bytes', () {
    // Worked out from crypto.md: 18 + 16 + 16 + 4 + 64 + 16
    final expected = [...utf8.encode('kemlock/v1/confirm'), ...space, ...member, 0, 0, 0, 7, ...fingerprint, ...confirmer];
    expect(statement(keyVersion: 7).bytes, expected);
    expect(expected, hasLength(134));
    expect(ConfirmStatement.length, 134);
  });

  test('parses its own bytes back, and refuses another label, a short statement and trailing bytes', () {
    final bytes = statement().bytes;
    final parsed = ConfirmStatement.parse(bytes);
    expect(parsed.space, space);
    expect(parsed.member, member);
    expect(parsed.memberKeyVersion, 1);
    expect(parsed.fingerprint, fingerprint);
    expect(parsed.confirmer, confirmer);
    expect(() => ConfirmStatement.parse(Uint8List.fromList(bytes)..[0] ^= 1), throwsA(isA<MalformedException>()));
    expect(() => ConfirmStatement.parse(bytes.sublist(0, 133)), throwsA(isA<MalformedException>()));
    expect(() => ConfirmStatement.parse([...bytes, 0]), throwsA(isA<MalformedException>()));
  });

  test('refuses an id or a fingerprint of the wrong length', () {
    expect(
      () => ConfirmStatement(space: space.sublist(1), member: member, memberKeyVersion: 1, fingerprint: fingerprint, confirmer: confirmer),
      throwsA(isA<MalformedException>()),
    );
    expect(
      () => ConfirmStatement(space: space, member: member, memberKeyVersion: 1, fingerprint: fingerprint.sublist(1), confirmer: confirmer),
      throwsA(isA<MalformedException>()),
    );
  });

  group('with real keys', () {
    late Uint8List confirmerPrivate;
    late Uint8List confirmerPublic;
    late KeyBundle memberBundle;

    setUpAll(() async {
      final sig = await Sig1.generate(_seq(64, 1));
      confirmerPrivate = sig.privateKey;
      confirmerPublic = sig.publicKey;
      final memberKx1 = await Kx1.publicKeyOf(_seq(96, 3));
      final memberSig1 = await Sig1.publicKeyOf(_seq(64, 5));
      memberBundle = KeyBundle(accountId: member, keyVersion: 2, kx1PublicKey: memberKx1, sig1PublicKey: memberSig1);
    });

    test('is built for a bundle from its account, key version and fingerprint, and covers only that bundle', () async {
      final forBundle = ConfirmStatement.forBundle(space: space, bundle: memberBundle, confirmer: confirmer);
      expect(forBundle.member, member);
      expect(forBundle.memberKeyVersion, 2);
      expect(forBundle.fingerprint, memberBundle.fingerprint);
      expect(forBundle.covers(memberBundle), isTrue);

      final newerKeys = KeyBundle(
        accountId: member,
        keyVersion: 3,
        kx1PublicKey: memberBundle.kx1PublicKey,
        sig1PublicKey: memberBundle.sig1PublicKey,
      );
      expect(forBundle.covers(newerKeys), isFalse);
      final other = KeyBundle(
        accountId: confirmer,
        keyVersion: 2,
        kx1PublicKey: memberBundle.kx1PublicKey,
        sig1PublicKey: memberBundle.sig1PublicKey,
      );
      expect(forBundle.covers(other), isFalse);
    });

    test('signs and verifies, and a changed statement or signature does not', () async {
      final signed = statement();
      final signature = await signConfirmation(signed, confirmerPrivate);
      expect(signature, hasLength(Sig1.signatureLength));
      final verified = await verifyConfirmation(signed.bytes, signature, confirmerPublic);
      expect(verified.fingerprint, fingerprint);

      final changedStatement = Uint8List.fromList(signed.bytes)..[40] ^= 1;
      await expectLater(verifyConfirmation(changedStatement, signature, confirmerPublic), throwsA(isA<CorruptedException>()));
      final changedSignature = Uint8List.fromList(signature)..[10] ^= 1;
      await expectLater(verifyConfirmation(signed.bytes, changedSignature, confirmerPublic), throwsA(isA<CorruptedException>()));
    });

    test('a signature made under another context is not a confirmation', () async {
      final signed = statement();
      final underManifest = await Sig1.sign(confirmerPrivate, signed.bytes, context: SignContext.manifest);
      await expectLater(verifyConfirmation(signed.bytes, underManifest, confirmerPublic), throwsA(isA<CorruptedException>()));
    });
  });
}
