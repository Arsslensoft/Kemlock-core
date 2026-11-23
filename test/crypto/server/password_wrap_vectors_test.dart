@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/password_wrap.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/hkdf.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's password-wrap.json (crypto.md "The password wrap of the root
// key"): the wrap key from the master key and the OPAQUE export key, the aad,
// and the wrapped root as nonce || ciphertext || tag. The nonce is in the
// wrapped bytes, so each case is opened and then sealed again with it.
void main() {
  group("the server's password-wrap vectors", () {
    for (final c in readServerCases('password-wrap.json')) {
      final name = c['name']! as String;
      final masterKey = fromHex(c['master_key']! as String);
      final exportKey = fromHex(c['export_key']! as String);
      final accountId = fromHex(c['account_id']! as String);
      final keyVersion = c['key_version']! as int;
      final rootKey = fromHex(c['root_key']! as String);
      final wrapped = fromHex(c['wrapped']! as String);

      test('$name: the wrap key and the aad are what crypto.md says', () async {
        final wrapKey = hkdfSha256([...masterKey, ...exportKey], salt: const [], info: utf8.encode('kemlock/v1/password-wrap'));
        expect(toHex(wrapKey), c['wrap_key']);

        final aad = concatBytes([label('kemlock/v1/root-wrap'), accountId, u32be(keyVersion)]);
        expect(toHex(aad), c['aad']);

        // Opened by hand, with the nonce at the front and the tag at the end.
        final opened = await aesGcmDecrypt(wrapKey, wrapped.sublist(0, 12), wrapped.sublist(12), aad: aad);
        expect(toHex(opened), c['root_key']);
      });

      test('$name: unwraps to the root key', () async {
        final root = await unwrapRootWithPassword(
          masterKey: masterKey,
          exportKey: exportKey,
          accountId: accountId,
          keyVersion: keyVersion,
          wrapped: wrapped,
        );
        expect(toHex(root), c['root_key']);
      });

      test('$name: sealing the root again with the same nonce gives the same bytes', () async {
        final again = await wrapRootWithPassword(
          masterKey: masterKey,
          exportKey: exportKey,
          accountId: accountId,
          keyVersion: keyVersion,
          rootKey: rootKey,
          nonce: Uint8List.fromList(wrapped.sublist(0, 12)),
        );
        expect(toHex(again), c['wrapped']);
        expect(again, hasLength(wrappedRootLength));
      });

      test('$name: another key version, account id, master key or export key does not open it', () async {
        Future<Uint8List> open({int? version, List<int>? account, Uint8List? master, Uint8List? export}) => unwrapRootWithPassword(
          masterKey: master ?? masterKey,
          exportKey: export ?? exportKey,
          accountId: account ?? accountId,
          keyVersion: version ?? keyVersion,
          wrapped: wrapped,
        );

        Uint8List flipped(Uint8List bytes) => Uint8List.fromList(bytes)..[0] ^= 1;

        await expectLater(open(version: keyVersion + 1), throwsA(isA<CorruptedException>()));
        await expectLater(open(account: flipped(accountId)), throwsA(isA<CorruptedException>()));
        await expectLater(open(master: flipped(masterKey)), throwsA(isA<CorruptedException>()));
        await expectLater(open(export: flipped(exportKey)), throwsA(isA<CorruptedException>()));
      });
    }
  });
}
