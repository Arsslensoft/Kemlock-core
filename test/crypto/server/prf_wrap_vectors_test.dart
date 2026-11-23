@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/prf_wrap.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/hkdf.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's prf-wrap.json (crypto.md "The passkey PRF wrap of the root key"): the PRF's `first` input, the wrap
// key from the PRF output and the credential id, the aad, and the wrapped root as nonce || ciphertext || tag. The
// nonce is in the wrapped bytes, so each case is opened and then sealed again with it.
void main() {
  group("the server's prf-wrap vectors", () {
    for (final c in readServerCases('prf-wrap.json')) {
      final name = c['name']! as String;
      final prfOutput = fromHex(c['prf_output']! as String);
      final credentialId = fromHex(c['credential_id']! as String);
      final accountId = fromHex(c['account_id']! as String);
      final keyVersion = c['key_version']! as int;
      final rootKey = fromHex(c['root_key']! as String);
      final wrapped = fromHex(c['wrapped']! as String);

      test('$name: the PRF input is the salt of the case', () {
        expect(toHex(prfEvalInput), c['prf_salt']);
      });

      test('$name: the wrap key and the aad are what crypto.md says', () async {
        final wrapKey = hkdfSha256(prfOutput, salt: const [], info: [...utf8.encode('kemlock/v1/prf-wrap'), ...lp(credentialId)]);
        expect(toHex(wrapKey), c['wrap_key']);

        final aad = concatBytes([label('kemlock/v1/root-wrap/prf'), accountId, u32be(keyVersion), lp(credentialId)]);
        expect(toHex(aad), c['aad']);

        // Opened by hand, with the nonce at the front and the tag at the end.
        final opened = await aesGcmDecrypt(wrapKey, wrapped.sublist(0, 12), wrapped.sublist(12), aad: aad);
        expect(toHex(opened), c['root_key']);
      });

      test('$name: unwraps to the root key', () async {
        final root = await unwrapRootWithPrf(
          prfOutput: prfOutput,
          credentialId: credentialId,
          accountId: accountId,
          keyVersion: keyVersion,
          wrapped: wrapped,
        );
        expect(toHex(root), c['root_key']);
      });

      test('$name: sealing the root again with the same nonce gives the same bytes', () async {
        final again = await wrapRootWithPrf(
          prfOutput: prfOutput,
          credentialId: credentialId,
          accountId: accountId,
          keyVersion: keyVersion,
          rootKey: rootKey,
          nonce: Uint8List.fromList(wrapped.sublist(0, 12)),
        );
        expect(toHex(again), c['wrapped']);
        expect(again, hasLength(prfWrappedRootLength));
      });

      test('$name: another credential id, PRF output, account id or key version does not open it', () async {
        Future<Uint8List> open({int? version, List<int>? account, List<int>? credential, Uint8List? prf}) => unwrapRootWithPrf(
          prfOutput: prf ?? prfOutput,
          credentialId: credential ?? credentialId,
          accountId: account ?? accountId,
          keyVersion: version ?? keyVersion,
          wrapped: wrapped,
        );

        Uint8List flipped(Uint8List bytes) => Uint8List.fromList(bytes)..[0] ^= 1;

        await expectLater(open(credential: flipped(credentialId)), throwsA(isA<CorruptedException>()));
        await expectLater(open(credential: [...credentialId, 0]), throwsA(isA<CorruptedException>()));
        await expectLater(open(prf: flipped(prfOutput)), throwsA(isA<CorruptedException>()));
        await expectLater(open(account: flipped(accountId)), throwsA(isA<CorruptedException>()));
        await expectLater(open(version: keyVersion + 1), throwsA(isA<CorruptedException>()));
      });
    }
  });
}
