@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/prf_wrap.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

import '../vectors.dart';

/// HKDF-SHA256 with one output block, straight from RFC 5869 with
/// `package:crypto`: PRK = HMAC(zeros(32), ikm), OKM = HMAC(PRK, info || 0x01).
Uint8List _hkdfOneBlock(List<int> ikm, List<int> info) {
  final prk = hash.Hmac(hash.sha256, Uint8List(32)).convert(ikm).bytes;
  return Uint8List.fromList(hash.Hmac(hash.sha256, prk).convert([...info, 1]).bytes);
}

void main() {
  final prfOutput = Uint8List.fromList(List.generate(32, (i) => 0x90 + i));
  final root = Uint8List.fromList(List.generate(64, (i) => (i * 3 + 1) & 0xff));
  final accountId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ab');
  final credentialId = Uint8List.fromList(List.generate(20, (i) => 0xe0 + i));

  Future<Uint8List> wrap({Uint8List? prf, List<int>? credential, List<int>? id, int keyVersion = 1}) => wrapRootWithPrf(
    prfOutput: prf ?? prfOutput,
    credentialId: credential ?? credentialId,
    accountId: id ?? accountId,
    keyVersion: keyVersion,
    rootKey: root,
  );

  Future<Uint8List> unwrap(Uint8List wrapped, {Uint8List? prf, List<int>? credential, List<int>? id, int keyVersion = 1}) =>
      unwrapRootWithPrf(
        prfOutput: prf ?? prfOutput,
        credentialId: credential ?? credentialId,
        accountId: id ?? accountId,
        keyVersion: keyVersion,
        wrapped: wrapped,
      );

  group('the PRF input', () {
    test('is SHA-256 of "kemlock/v1/prf-salt"', () {
      // from `printf 'kemlock/v1/prf-salt' | sha256sum`
      expect(toHex(prfEvalInput), '22f3a59b4a8c0212d1d1ecd26e0a4ad3676e5e862543c138bee7668602589417');
      expect(prfEvalInput, hasLength(32));
    });
  });

  group('the passkey PRF wrap of the root key', () {
    test('is AES-256-GCM under HKDF of the PRF output and lp(credential id), with the aad crypto.md gives', () async {
      final nonce = Uint8List.fromList(List.generate(12, (i) => 0x50 + i));
      final wrapped = await wrapRootWithPrf(
        prfOutput: prfOutput,
        credentialId: credentialId,
        accountId: accountId,
        keyVersion: 3,
        rootKey: root,
        nonce: nonce,
      );
      // wrap key = HKDF(PRF output, info = "kemlock/v1/prf-wrap" || lp(credential id)), by hand
      final wrapKey = _hkdfOneBlock(prfOutput, [...utf8.encode('kemlock/v1/prf-wrap'), 0, 0, 0, 20, ...credentialId]);
      // aad = "kemlock/v1/root-wrap/prf" || account id || u32be(key version) || lp(credential id), by hand
      final aad = [...utf8.encode('kemlock/v1/root-wrap/prf'), ...accountId, 0, 0, 0, 3, 0, 0, 0, 20, ...credentialId];
      final expected = await aesGcmEncrypt(wrapKey, root, nonce: nonce, aad: aad);
      expect(wrapped, [...nonce, ...expected.ct]);
      expect(wrapped, hasLength(prfWrappedRootLength));
      expect(prfWrappedRootLength, 92);
    });

    test('opens with the same PRF output, credential id, account id and key version', () async {
      expect(await unwrap(await wrap()), root);
    });

    test('wrapping twice gives different bytes, both of which open', () async {
      final first = await wrap();
      final second = await wrap();
      expect(first, isNot(second));
      expect(await unwrap(second), root);
    });

    test('fails under another credential id, even with the right PRF output', () async {
      final wrapped = await wrap();
      final other = Uint8List.fromList(credentialId)..[19] ^= 1;
      await expectLater(unwrap(wrapped, credential: other), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, credential: [...credentialId, 0]), throwsA(isA<CorruptedException>()));
    });

    test('fails under another PRF output, account id or key version', () async {
      final wrapped = await wrap();
      await expectLater(unwrap(wrapped, prf: Uint8List.fromList(prfOutput)..[0] ^= 1), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, id: uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ac')), throwsA(isA<CorruptedException>()));
      await expectLater(unwrap(wrapped, keyVersion: 2), throwsA(isA<CorruptedException>()));
    });

    test('a changed byte fails', () async {
      final wrapped = await wrap();
      for (final index in [0, 11, 12, 50, 75, 76, 91]) {
        await expectLater(unwrap(Uint8List.fromList(wrapped)..[index] ^= 1), throwsA(isA<CorruptedException>()), reason: 'byte $index');
      }
    });

    test('a wrapped value, PRF output, credential id or account id of the wrong shape is malformed', () async {
      final wrapped = await wrap();
      await expectLater(unwrap(wrapped.sublist(0, 91)), throwsA(isA<MalformedException>()));
      await expectLater(unwrap(Uint8List.fromList([...wrapped, 0])), throwsA(isA<MalformedException>()));
      await expectLater(unwrap(wrapped, prf: Uint8List(31)), throwsA(isA<MalformedException>()));
      await expectLater(unwrap(wrapped, credential: Uint8List(0)), throwsA(isA<MalformedException>()));
      await expectLater(unwrap(wrapped, id: Uint8List(15)), throwsA(isA<MalformedException>()));
      await expectLater(
        wrapRootWithPrf(prfOutput: prfOutput, credentialId: credentialId, accountId: accountId, keyVersion: 1, rootKey: Uint8List(32)),
        throwsA(isA<MalformedException>()),
      );
    });
  });
}
