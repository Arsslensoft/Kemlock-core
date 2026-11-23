@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/send.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's send.json (crypto.md "Sends"): the keys, aads, seals, wrap,
// proof and KMA1 file of a note and of a file, and what must not open them.
// The nonce of each sealed value is in its bytes, so each is opened and then
// sealed again with that nonce and compared.
void main() {
  group("the server's send vectors", () {
    for (final c in readServerCases('send.json')) {
      final name = c['name']! as String;
      final kind = c['kind']! as String;
      final sendId = fromHex(c['send_id']! as String);
      final linkKey = fromHex(c['link_key']! as String);
      final wrapKey = fromHex(c['wrap_key']! as String);
      final keyVersion = c['key_version']! as int;
      final payloadKey = fromHex(c['payload_key']! as String);
      final metaKey = fromHex(c['meta_key']! as String);
      final payload = fromHex(c['payload']! as String);
      final meta = fromHex(c['meta']! as String);
      final sealedKey = fromHex(c['sealed_key']! as String);
      final otherId = Uint8List.fromList(sendId)..[0] ^= 1;
      final otherKind = kind == sendKindText ? sendKindFile : sendKindText;

      test('$name: the keys come from the link key and the item-wrap key', () {
        expect(toHex(sendPayloadKey(linkKey)), c['payload_key']);
        expect(toHex(sendProofSalt(linkKey, sendId)), c['proof_salt']);
        expect(toHex(sendMetaKey(wrapKey, sendId, keyVersion)), c['meta_key']);
      });

      test('$name: the meta key is not from the link key', () {
        expect(toHex(sendMetaKey(linkKey, sendId, keyVersion)), isNot(c['meta_key']));
      });

      test('$name: the aads are what crypto.md says', () {
        expect(toHex(sendAad(SendLabel.payload, sendId, kind)), c['payload_aad']);
        expect(toHex(sendAad(SendLabel.meta, sendId, kind)), c['meta_aad']);
        expect(toHex(sendKeyAad(sendId, keyVersion)), c['key_aad']);
      });

      test('$name: the access id and the link are the send id and the link key in base64url', () {
        expect(sendAccessId(sendId), c['access_id']);
        expect(sendIdFromAccessId(c['access_id']! as String), sendId);
        expect(c['link'], 'https://example.org/#/send/${c['access_id']}/${b64urlEncode(linkKey)}');
      });

      test('$name: the payload opens to its JSON, and sealing it again with its nonce gives its bytes', () async {
        final plain = await openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: sendId, kind: kind, sealed: payload);
        expect(utf8.decode(plain), c['payload_json']);
        final parsed = SendPayload.parse(plain, kind);
        expect(parsed.kind, kind);
        final again = await sealSendPart(
          sealLabel: SendLabel.payload,
          key: payloadKey,
          sendId: sendId,
          kind: kind,
          plaintext: plain,
          nonce: Uint8List.fromList(payload.sublist(0, 12)),
        );
        expect(toHex(again), c['payload']);
        expect(parsed.encode(), plain);
      });

      test('$name: the meta opens to its JSON, and sealing it again with its nonce gives its bytes', () async {
        final plain = await openSendPart(sealLabel: SendLabel.meta, key: metaKey, sendId: sendId, kind: kind, sealed: meta);
        expect(utf8.decode(plain), c['meta_json']);
        expect(SendMeta.parse(plain).encode(), plain);
        final again = await sealSendPart(
          sealLabel: SendLabel.meta,
          key: metaKey,
          sendId: sendId,
          kind: kind,
          plaintext: plain,
          nonce: Uint8List.fromList(meta.sublist(0, 12)),
        );
        expect(toHex(again), c['meta']);
      });

      test('$name: the sealed key is 64 bytes, names its version and unwraps to the link key', () async {
        expect(sealedKey, hasLength(sendSealedKeyLength));
        expect(sealedKeyVersion(sealedKey), keyVersion);
        expect(toHex(await unwrapLinkKey(itemWrapKey: wrapKey, sendId: sendId, sealedKey: sealedKey)), c['link_key']);
        final again = await wrapLinkKey(
          itemWrapKey: wrapKey,
          sendId: sendId,
          keyVersion: keyVersion,
          linkKey: linkKey,
          nonce: Uint8List.fromList(sealedKey.sublist(4, 16)),
        );
        expect(toHex(again), c['sealed_key']);
      });

      test('$name: a changed id, kind, key or key version does not open', () async {
        await expectLater(
          openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: otherId, kind: kind, sealed: payload),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(
          openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: sendId, kind: otherKind, sealed: payload),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(
          openSendPart(sealLabel: SendLabel.payload, key: metaKey, sendId: sendId, kind: kind, sealed: payload),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(
          openSendPart(sealLabel: SendLabel.meta, key: payloadKey, sendId: sendId, kind: kind, sealed: meta),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(
          openSendPart(sealLabel: SendLabel.meta, key: metaKey, sendId: sendId, kind: otherKind, sealed: meta),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(
          openSendPart(
            sealLabel: SendLabel.meta,
            key: sendMetaKey(wrapKey, sendId, keyVersion + 1),
            sendId: sendId,
            kind: kind,
            sealed: meta,
          ),
          throwsA(isA<CorruptedException>()),
        );
        await expectLater(unwrapLinkKey(itemWrapKey: wrapKey, sendId: otherId, sealedKey: sealedKey), throwsA(isA<CorruptedException>()));
        await expectLater(unwrapLinkKey(itemWrapKey: payloadKey, sendId: sendId, sealedKey: sealedKey), throwsA(isA<CorruptedException>()));
        final otherVersion = Uint8List.fromList(sealedKey)..[3] ^= 1;
        await expectLater(unwrapLinkKey(itemWrapKey: wrapKey, sendId: sendId, sealedKey: otherVersion), throwsA(isA<CorruptedException>()));
      });

      if (c.containsKey('proof')) {
        test('$name: the password gives the proof, from a decomposed spelling too', () async {
          final password = c['password']! as String;
          final nfc = c['password_nfc']! as String;
          expect(normalizePassword(password), nfc);
          final proof = await sendProof(password, linkKey, sendId);
          expect(toHex(proof), c['proof']);
          expect(sendProofText(proof), hasLength(43));
          // The same password spelled decomposed: "e" and U+0301 for U+00E9.
          final decomposed = nfc.replaceAll('é', 'é');
          expect(toHex(await sendProof(decomposed, linkKey, sendId)), c['proof']);
        }, timeout: const Timeout(Duration(minutes: 2)));
      }

      if (c.containsKey('file')) {
        test('$name: the KMA1 file opens under the payload key to the plaintext', () async {
          final file = fromHex(c['file']! as String);
          final plain = fromHex(c['file_plain']! as String);
          final parsed = SendPayload.parse(
            await openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: sendId, kind: kind, sealed: payload),
            kind,
          );
          expect(parsed.size, plain.length);
          expect(file, hasLength(kma1Length(plain.length)));
          expect(sendFileLengthMatches(parsed.size!, file.length), isTrue);
          expect(await openSendFile(file, linkKey, parsed.size!), plain);
          expect(kma1DecryptSync(file, payloadKey), plain);
          expect(() => kma1DecryptSync(file, linkKey), throwsA(isA<AttachmentDamagedError>()));
        });
      }
    }
  });
}
