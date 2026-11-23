@TestOn('vm')
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/send.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:test/test.dart';

void main() {
  final id = Uint8List.fromList(List.generate(16, (i) => 0x10 + i));
  final otherId = Uint8List.fromList(List.generate(16, (i) => 0x20 + i));
  final linkKey = Uint8List.fromList(List.generate(32, (i) => i + 1));
  final wrapKey = Uint8List.fromList(List.generate(32, (i) => 0x80 + i));
  final payloadKey = sendPayloadKey(linkKey);
  final payload = const SendPayload.text(name: 'Wi-Fi', text: 'on the fridge').encode();

  Future<Uint8List> seal({List<int>? sendId, String kind = sendKindText, Uint8List? key}) =>
      sealSendPart(sealLabel: SendLabel.payload, key: key ?? payloadKey, sendId: sendId ?? id, kind: kind, plaintext: payload);

  Future<Uint8List> open(Uint8List sealed, {List<int>? sendId, String kind = sendKindText, Uint8List? key}) =>
      openSendPart(sealLabel: SendLabel.payload, key: key ?? payloadKey, sendId: sendId ?? id, kind: kind, sealed: sealed);

  group('the keys', () {
    test('are 32 bytes, and the proof salt 16, each from its own label', () {
      expect(payloadKey, hasLength(32));
      expect(sendProofSalt(linkKey, id), hasLength(16));
      expect(sendMetaKey(wrapKey, id, 1), hasLength(32));
      expect(payloadKey, isNot(sendMetaKey(linkKey, id, 1)));
    });

    test('the proof salt follows the send id, and the meta key the id and the key version', () {
      expect(sendProofSalt(linkKey, id), isNot(sendProofSalt(linkKey, otherId)));
      expect(sendMetaKey(wrapKey, id, 1), isNot(sendMetaKey(wrapKey, otherId, 1)));
      expect(sendMetaKey(wrapKey, id, 1), isNot(sendMetaKey(wrapKey, id, 2)));
    });

    test('refuse a key or an id of the wrong length', () {
      expect(() => sendPayloadKey(Uint8List(31)), throwsA(isA<MalformedException>()));
      expect(() => sendProofSalt(linkKey, Uint8List(15)), throwsA(isA<MalformedException>()));
      expect(() => sendMetaKey(Uint8List(31), id, 1), throwsA(isA<MalformedException>()));
    });

    test('a new send id is a version 4 UUID, and its access id is 22 characters', () {
      final sendId = newSendId();
      expect(sendId, hasLength(16));
      expect(sendId[6] >> 4, 4);
      expect(sendId[8] >> 6, 2);
      final access = sendAccessId(sendId);
      expect(access, hasLength(22));
      expect(sendIdFromAccessId(access), sendId);
      expect(() => sendIdFromAccessId('${access}A'), throwsA(isA<MalformedException>()));
      expect(() => sendIdFromAccessId('short'), throwsA(isA<MalformedException>()));
    });
  });

  group('the aad', () {
    test('is the label, the send id and the length-prefixed kind, as crypto.md says', () {
      expect(sendAad(SendLabel.payload, id, sendKindText), [
        ...utf8.encode('kemlock/v1/send-payload'),
        ...id,
        0,
        0,
        0,
        4,
        ...utf8.encode('text'),
      ]);
      expect(sendAad(SendLabel.meta, id, sendKindFile), [
        ...utf8.encode('kemlock/v1/send-meta'),
        ...id,
        0,
        0,
        0,
        4,
        ...utf8.encode('file'),
      ]);
      expect(sendKeyAad(id, 2), [...utf8.encode('kemlock/v1/send-key'), ...id, 0, 0, 0, 2]);
    });
  });

  group('the seals', () {
    test('a payload opens under its own id, kind and key', () async {
      expect(await open(await seal()), payload);
    });

    test('a payload under another id fails to open', () async {
      final sealed = await seal();
      await expectLater(open(sealed, sendId: otherId), throwsA(isA<CorruptedException>()));
    });

    test('a payload of another kind fails to open', () async {
      final sealed = await seal();
      await expectLater(open(sealed, kind: sendKindFile), throwsA(isA<CorruptedException>()));
    });

    test('a payload opened with another key fails to open', () async {
      final sealed = await seal();
      await expectLater(open(sealed, key: wrapKey), throwsA(isA<CorruptedException>()));
    });

    test('a changed byte fails to open, and a value under 28 bytes is malformed', () async {
      final sealed = await seal();
      sealed[sealed.length - 1] ^= 1;
      await expectLater(open(sealed), throwsA(isA<CorruptedException>()));
      await expectLater(open(Uint8List(27)), throwsA(isA<MalformedException>()));
    });

    test('a meta opened with a key from the link key fails to open', () async {
      final metaKey = sendMetaKey(wrapKey, id, 1);
      final meta = const SendMeta(name: 'Wi-Fi', notes: 'for the guests').encode();
      final sealed = await sealSendPart(sealLabel: SendLabel.meta, key: metaKey, sendId: id, kind: sendKindText, plaintext: meta);
      expect(await openSendPart(sealLabel: SendLabel.meta, key: metaKey, sendId: id, kind: sendKindText, sealed: sealed), meta);
      await expectLater(
        openSendPart(sealLabel: SendLabel.meta, key: sendMetaKey(linkKey, id, 1), sendId: id, kind: sendKindText, sealed: sealed),
        throwsA(isA<CorruptedException>()),
      );
      await expectLater(
        openSendPart(sealLabel: SendLabel.meta, key: payloadKey, sendId: id, kind: sendKindText, sealed: sealed),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('a meta fails to open as a payload, and the other way round', () async {
      final metaKey = sendMetaKey(wrapKey, id, 1);
      final sealed = await sealSendPart(sealLabel: SendLabel.meta, key: metaKey, sendId: id, kind: sendKindText, plaintext: payload);
      await expectLater(
        openSendPart(sealLabel: SendLabel.payload, key: metaKey, sendId: id, kind: sendKindText, sealed: sealed),
        throwsA(isA<CorruptedException>()),
      );
    });

    test('sealing twice gives different bytes', () async {
      expect(await seal(), isNot(await seal()));
    });

    test('a given nonce leads the sealed bytes', () async {
      final nonce = Uint8List.fromList(List.generate(12, (i) => 0x50 + i));
      final sealed = await sealSendPart(
        sealLabel: SendLabel.payload,
        key: payloadKey,
        sendId: id,
        kind: sendKindText,
        plaintext: payload,
        nonce: nonce,
      );
      expect(sealed.sublist(0, 12), nonce);
      expect(sealed, hasLength(12 + payload.length + 16));
    });

    test('a kind other than text or file is refused', () {
      expect(() => sendAad(SendLabel.payload, id, 'note'), throwsArgumentError);
    });
  });

  group('the wrap of the link key', () {
    test('is 64 bytes, starts with the key version and unwraps to the key', () async {
      final sealedKey = await wrapLinkKey(itemWrapKey: wrapKey, sendId: id, keyVersion: 3, linkKey: linkKey);
      expect(sealedKey, hasLength(sendSealedKeyLength));
      expect(sealedKey.sublist(0, 4), [0, 0, 0, 3]);
      expect(sealedKeyVersion(sealedKey), 3);
      expect(await unwrapLinkKey(itemWrapKey: wrapKey, sendId: id, sealedKey: sealedKey), linkKey);
    });

    test('a sealedKey under another key version fails to open', () async {
      final sealedKey = await wrapLinkKey(itemWrapKey: wrapKey, sendId: id, keyVersion: 3, linkKey: linkKey);
      final changed = Uint8List.fromList(sealedKey)..[3] = 4;
      await expectLater(unwrapLinkKey(itemWrapKey: wrapKey, sendId: id, sealedKey: changed), throwsA(isA<CorruptedException>()));
    });

    test('a sealedKey for another send id or under another key fails to open', () async {
      final sealedKey = await wrapLinkKey(itemWrapKey: wrapKey, sendId: id, keyVersion: 1, linkKey: linkKey);
      await expectLater(unwrapLinkKey(itemWrapKey: wrapKey, sendId: otherId, sealedKey: sealedKey), throwsA(isA<CorruptedException>()));
      await expectLater(unwrapLinkKey(itemWrapKey: payloadKey, sendId: id, sealedKey: sealedKey), throwsA(isA<CorruptedException>()));
    });

    test('a sealedKey of another length is malformed', () async {
      expect(() => sealedKeyVersion(Uint8List(63)), throwsA(isA<MalformedException>()));
      await expectLater(unwrapLinkKey(itemWrapKey: wrapKey, sendId: id, sealedKey: Uint8List(65)), throwsA(isA<MalformedException>()));
    });
  });

  group('the payload and the meta', () {
    test('a text payload round-trips, and a file payload too', () {
      final text = SendPayload.parse(payload, sendKindText);
      expect(text.name, 'Wi-Fi');
      expect(text.text, 'on the fridge');
      expect(text.kind, sendKindText);
      final file = SendPayload.parse(const SendPayload.file(name: 'a.pdf', mime: 'application/pdf', size: 3000000).encode(), sendKindFile);
      expect((file.name, file.mime, file.size), ('a.pdf', 'application/pdf', 3000000));
      expect(file.kind, sendKindFile);
    });

    test('write exactly the fields of crypto.md', () {
      expect(utf8.decode(payload), '{"name":"Wi-Fi","text":"on the fridge"}');
      expect(utf8.decode(const SendMeta(name: 'a', notes: '').encode()), '{"name":"a","notes":""}');
      expect(utf8.decode(const SendPayload.file(name: 'a', mime: 'b', size: 1).encode()), '{"name":"a","mime":"b","size":1}');
    });

    test('an extra field is refused', () {
      expect(() => SendPayload.parse(utf8.encode('{"name":"a","text":"b","x":1}'), sendKindText), throwsA(isA<MalformedException>()));
      expect(
        () => SendPayload.parse(utf8.encode('{"name":"a","mime":"b","size":1,"text":"c"}'), sendKindFile),
        throwsA(isA<MalformedException>()),
      );
      expect(() => SendMeta.parse(utf8.encode('{"name":"a","notes":"","extra":true}')), throwsA(isA<MalformedException>()));
    });

    test('a missing field or a wrong type is refused', () {
      expect(() => SendPayload.parse(utf8.encode('{"name":"a"}'), sendKindText), throwsA(isA<MalformedException>()));
      expect(() => SendPayload.parse(utf8.encode('{"name":"a","text":1}'), sendKindText), throwsA(isA<MalformedException>()));
      expect(() => SendMeta.parse(utf8.encode('{"name":"a"}')), throwsA(isA<MalformedException>()));
      expect(() => SendMeta.parse(utf8.encode('[]')), throwsA(isA<MalformedException>()));
      expect(() => SendMeta.parse(utf8.encode('not json')), throwsA(isA<MalformedException>()));
    });

    test('a payload read as the other kind is refused', () {
      expect(() => SendPayload.parse(payload, sendKindFile), throwsA(isA<MalformedException>()));
      expect(() => SendPayload.parse(payload, 'note'), throwsA(isA<MalformedException>()));
    });

    test('a size that is negative, fractional or above 2^53 is refused', () {
      for (final size in ['-1', '1.5', '9007199254740993', '"7"']) {
        expect(
          () => SendPayload.parse(utf8.encode('{"name":"a","mime":"b","size":$size}'), sendKindFile),
          throwsA(isA<MalformedException>()),
          reason: size,
        );
      }
      expect(SendPayload.parse(utf8.encode('{"name":"a","mime":"b","size":0}'), sendKindFile).size, 0);
    });
  });

  group('the password proof', () {
    test('runs Argon2id with m = 19456, t = 2, p = 1 and the 16-byte proof salt', () async {
      Uint8List? gotPassword;
      Uint8List? gotSalt;
      Argon2idSettings? gotSettings;
      final proof = await sendProof(
        'hunter2',
        linkKey,
        id,
        runner: (password, salt, settings) async {
          gotPassword = Uint8List.fromList(password);
          gotSalt = salt;
          gotSettings = settings;
          return Uint8List(32)..fillRange(0, 32, 9);
        },
      );
      expect(gotSettings, const Argon2idSettings(memoryKiB: 19456, iterations: 2, parallelism: 1));
      expect(gotSettings, sendProofSettings);
      expect(gotSalt, hasLength(16));
      expect(gotSalt, sendProofSalt(linkKey, id));
      expect(gotPassword, utf8.encode('hunter2'));
      expect(proof, List.filled(32, 9));
      expect(sendProofText(proof), hasLength(43));
    });

    test('a decomposed and a precomposed e give one proof', () async {
      Future<Uint8List> run(String password) => sendProof(
        password,
        linkKey,
        id,
        runner: (bytes, salt, _) async => Uint8List(32)
          ..setAll(0, bytes)
          ..setAll(bytes.length, salt),
      );
      expect(await run('café'), await run('café'));
      expect(await run('café'), isNot(await run('cafe')));
    });

    test('another send id gives another salt, so another proof', () async {
      Future<Uint8List> run(Uint8List sendId) =>
          sendProof('pw', linkKey, sendId, runner: (bytes, salt, _) async => Uint8List(32)..setAll(0, salt));
      expect(await run(id), isNot(await run(otherId)));
    });
  });

  group('a file Send', () {
    final random = Random(7);
    for (final size in [0, 65536, 3 * 1000 * 1000]) {
      test('a file of $size bytes round-trips under the payload key', () async {
        final plain = Uint8List.fromList(List.generate(size, (_) => random.nextInt(256)));
        final file = await sealSendFile(plain, linkKey);
        expect(file, hasLength(kma1Length(size)));
        expect(sendFileLengthMatches(size, file.length), isTrue);
        expect(await openSendFile(file, linkKey, size), plain);
        // The file is a KMA1 file under the payload key, not the link key.
        expect(kma1DecryptSync(file, payloadKey), plain);
      });
    }

    test('a size one byte off is refused, before anything is decrypted', () async {
      final plain = Uint8List.fromList(List.generate(70000, (i) => i));
      final file = await sealSendFile(plain, linkKey);
      expect(sendFileLengthMatches(70000, file.length), isTrue);
      expect(sendFileLengthMatches(70001, file.length), isFalse);
      expect(sendFileLengthMatches(69999, file.length), isFalse);
      await expectLater(openSendFile(file, linkKey, 70001), throwsA(isA<MalformedException>()));
      await expectLater(openSendFile(file, linkKey, 69999), throwsA(isA<MalformedException>()));
      await expectLater(openSendFile(Uint8List.fromList([...file, 0]), linkKey, 70000), throwsA(isA<MalformedException>()));
    });

    test('a file opened with another link key does not open', () async {
      final file = await sealSendFile(Uint8List(100), linkKey);
      await expectLater(openSendFile(file, wrapKey, 100), throwsA(isA<AttachmentDamagedError>()));
    });
  });
}
