@TestOn('vm')
library;

// Bitwarden's attachment encryption, and the client's attachment calls
// against a mock server: starting an upload, sending the data, getting the
// download address and the data, and deleting; and that nothing is sent to
// or fetched from another host.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_attachments.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://vault.example.com');
const _cipher = '7f3a2c1e-0b9d-4e8f-a7c6-5d4e3f2a1b0c';

http.Response _json(Object? value, [int status = 200]) =>
    http.Response.bytes(utf8.encode(jsonEncode(value)), status, headers: {'content-type': 'application/json'});

NoteAttachment _file(Uint8List key, {int size = 5}) =>
    NoteAttachment(id: 'q8s3Lw0bVt9Yk2Rr4Xc1Zg', name: 'scan.pdf', size: size, key: b64(key), addedAt: 1);

void main() {
  group("Bitwarden's attachment encryption", () {
    test('round-trips, and is the layout Bitwarden reads', () async {
      final key = BwKey.random();
      for (final length in [0, 1, 15, 16, 17, 70000]) {
        final data = randomBytes(length);

        final buffer = await bwEncryptAttachment(data, key);

        expect(buffer.length, encryptedAttachmentLength(length), reason: '$length');
        expect(buffer[0], 2, reason: 'AES-256-CBC with HMAC-SHA256');
        // The same thing an encrypted string holds, laid out as a buffer
        final asString = EncString(type: 2, iv: buffer.sublist(1, 17), mac: buffer.sublist(17, 49), data: buffer.sublist(49));
        expect(await bwDecrypt(asString, key), data);
        expect(await bwDecryptAttachment(buffer, key), data);
      }
    });

    test('a changed byte, a wrong key or something else is refused', () async {
      final key = BwKey.random();
      final buffer = await bwEncryptAttachment(Uint8List.fromList(utf8.encode('passport scan')), key);
      final changed = Uint8List.fromList(buffer)..[buffer.length - 1] ^= 1;

      await expectLater(bwDecryptAttachment(changed, key), throwsA(isA<BwCryptoError>()));
      await expectLater(bwDecryptAttachment(buffer, BwKey.random()), throwsA(isA<BwCryptoError>()));
      await expectLater(bwDecryptAttachment(Uint8List(10), key), throwsA(isA<BwCryptoError>()));
    });

    test("a file's attachment key comes from the file's own key, the same on every phone", () async {
      final fileKey = randomBytes(32);
      final a = attachmentKey(_file(fileKey));
      final b = attachmentKey(_file(Uint8List.fromList(fileKey)));
      expect(a.bytes, hasLength(64));
      expect(sameKey(a, b), isTrue);
      expect(sameKey(a, attachmentKey(_file(randomBytes(32)))), isFalse);
      expect(a.enc, isNot(fileKey));
    });

    test("finds each file's attachment among an item's by its key", () async {
      final itemKey = BwKey.random();
      final first = _file(randomBytes(32));
      final second = NoteAttachment(id: 'other', name: 'b.txt', size: 1, key: b64(randomBytes(32)), addedAt: 1);
      final attachments = [
        VwAttachment(id: 'att-2', fileName: null, key: (await bwEncrypt(attachmentKey(second).bytes, itemKey)).toString(), size: 1),
        VwAttachment(id: 'att-user', fileName: null, key: (await bwEncrypt(BwKey.random().bytes, itemKey)).toString(), size: 1),
        const VwAttachment(id: 'att-old', fileName: null, key: null, size: 1),
        VwAttachment(id: 'att-1', fileName: null, key: (await bwEncrypt(attachmentKey(first).bytes, itemKey)).toString(), size: 1),
      ];

      final found = await matchAttachments(attachments, [first, second], itemKey);

      expect(found.map((id, attachment) => MapEntry(id, attachment.id)), {first.id: 'att-1', 'other': 'att-2'});
    });

    test("a sealed file's attachment still holds the KMA1 file once Bitwarden's layer is off", () async {
      final fileKey = randomBytes(32);
      final plain = Uint8List.fromList(utf8.encode('%PDF-1.7 passport'));
      final kma1 = kma1EncryptSync(plain, fileKey);

      final buffer = await bwEncryptAttachment(kma1, attachmentKey(_file(fileKey, size: plain.length)));
      final inside = await bwDecryptAttachment(buffer, attachmentKey(_file(fileKey, size: plain.length)));

      expect(inside.sublist(0, 4), kma1Magic);
      expect(kma1DecryptSync(inside, fileKey), plain);
    });
  });

  group('the attachment calls', () {
    late List<http.Request> requests;
    VwApi api(Future<http.Response> Function(http.Request request) answer) {
      requests = [];
      return VwApi(
        MockClient((request) {
          requests.add(request);
          return answer(request);
        }),
      );
    }

    test('starting an upload sends the encrypted key, name and size', () async {
      final client = api(
        (_) async => _json({
          'object': 'attachment-fileUpload',
          'attachmentId': 'att-1',
          'url': '/ciphers/$_cipher/attachment/att-1',
          'fileUploadType': 0,
          'cipherResponse': {'id': _cipher},
        }),
      );

      final upload = await client.startAttachmentUpload(_server, 'token', _cipher, key: '2.key', fileName: '2.name', fileSize: 1234);

      final request = requests.single;
      expect((request.method, request.url.path), ('POST', '/api/ciphers/$_cipher/attachment/v2'));
      expect(request.headers['Authorization'], 'Bearer token');
      expect(jsonDecode(request.body), {'key': '2.key', 'fileName': '2.name', 'fileSize': 1234, 'adminRequest': false});
      expect((upload.attachmentId, upload.fileUploadType, upload.url), ('att-1', 0, '/ciphers/$_cipher/attachment/att-1'));
      expect(upload.cipher, {'id': _cipher});
    });

    test('a server that takes no files says so', () async {
      for (final message in ['Attachments are disabled', 'Attachment storage limit reached! Delete some attachments to free up space']) {
        final client = api((_) async => _json({'message': message, 'object': 'error'}, 400));
        await expectLater(
          client.startAttachmentUpload(_server, 'token', _cipher, key: 'k', fileName: 'n', fileSize: 1),
          throwsA(isA<VwFilesRefused>().having((e) => e.reason, 'reason', VwFilesRefusal.none)),
        );
      }
      // Any other refusal is a problem of its own
      final gone = api((_) async => _json({'message': "Cipher doesn't exist", 'object': 'error'}, 400));
      await expectLater(
        gone.startAttachmentUpload(_server, 'token', _cipher, key: 'k', fileName: 'n', fileSize: 1),
        throwsA(isA<VwError>().having((e) => e.problem, 'problem', VwProblem.server)),
      );
    });

    test("the data goes to the server's own API, as a multipart form", () async {
      final client = api((_) async => http.Response('', 200));
      final data = Uint8List.fromList([0, 1, 2, 250, 255]);
      const upload = VwAttachmentUpload(attachmentId: 'att-1', fileUploadType: 0, url: '/ciphers/$_cipher/attachment/att-1');

      await client.uploadAttachment(_server, 'token', _cipher, upload, data, fileName: '2.name|x');

      final request = requests.single;
      expect((request.method, request.url.toString()), ('POST', 'https://vault.example.com/api/ciphers/$_cipher/attachment/att-1'));
      final type = request.headers['Content-Type']!;
      expect(type, startsWith('multipart/form-data; boundary='));
      final boundary = type.substring(type.indexOf('=') + 1);
      final body = request.bodyBytes;
      final head = latin1.decode(body.sublist(0, body.length - data.length - boundary.length - 8));
      expect(head, contains('Content-Disposition: form-data; name="data"; filename="2.name|x"'));
      expect(body.sublist(body.length - data.length - boundary.length - 8, body.length - boundary.length - 8), data);
      expect(latin1.decode(body.sublist(body.length - boundary.length - 8)), '\r\n--$boundary--\r\n');
    });

    test('nothing is sent to another host, or to another kind of upload', () async {
      final client = api((_) async => http.Response('', 200));
      for (final upload in const [
        VwAttachmentUpload(attachmentId: 'a', fileUploadType: 0, url: 'https://files.example.net/upload/a'),
        VwAttachmentUpload(attachmentId: 'a', fileUploadType: 0, url: 'https://vault.example.com:8443/upload/a'),
        VwAttachmentUpload(attachmentId: 'a', fileUploadType: 0, url: 'http://vault.example.com/upload/a'),
        VwAttachmentUpload(attachmentId: 'a', fileUploadType: 1, url: 'https://blob.core.windows.net/a?sig=1'),
      ]) {
        await expectLater(
          client.uploadAttachment(_server, 'token', _cipher, upload, Uint8List(3)),
          throwsA(isA<VwFilesRefused>().having((e) => e.reason, 'reason', VwFilesRefusal.elsewhere)),
          reason: '${upload.url}',
        );
      }
      expect(requests, isEmpty);
    });

    test('the download address, and the data from it', () async {
      final data = randomBytes(300);
      final client = api((request) async {
        if (request.url.path == '/api/ciphers/$_cipher/attachment/att-1') {
          return _json({
            'id': 'att-1',
            'url': 'https://vault.example.com/attachments/$_cipher/att-1?token=jwt',
            'fileName': '2.name',
            'key': '2.key',
            'size': '300',
            'object': 'attachment',
          });
        }
        return http.Response.bytes(data, 200);
      });

      final address = await client.attachmentAddress(_server, 'token', _cipher, 'att-1');
      final fetched = await client.downloadAttachment(_server, address, maxBytes: 300);

      expect(address.toString(), 'https://vault.example.com/attachments/$_cipher/att-1?token=jwt');
      expect(fetched, data);
      expect(requests.last.headers.containsKey('Authorization'), isFalse, reason: 'the address carries its own token');
      await expectLater(client.downloadAttachment(_server, address, maxBytes: 299), throwsA(isA<VwError>()));
    });

    test('an address on another host is never contacted', () async {
      final client = api((request) async {
        if (request.url.host == 'vault.example.com') {
          return _json({'id': 'att-1', 'url': 'https://bucket.s3.example.net/att-1?X-Amz-Signature=1', 'object': 'attachment'});
        }
        return http.Response.bytes([1, 2, 3], 200);
      });

      await expectLater(
        client.attachmentAddress(_server, 'token', _cipher, 'att-1'),
        throwsA(isA<VwFilesRefused>().having((e) => e.reason, 'reason', VwFilesRefusal.elsewhere)),
      );
      await expectLater(
        client.downloadAttachment(_server, Uri.parse('https://bucket.s3.example.net/att-1'), maxBytes: 10),
        throwsA(isA<VwFilesRefused>()),
      );
      expect(requests.map((request) => request.url.host), ['vault.example.com']);
    });

    test('deleting an attachment', () async {
      final client = api((_) async => _json({'object': 'cipherDetails'}));

      await client.deleteAttachment(_server, 'token', _cipher, 'att-1');

      expect((requests.single.method, requests.single.url.path), ('DELETE', '/api/ciphers/$_cipher/attachment/att-1'));
      final failing = api((_) async => _json({'message': "Attachment doesn't exist"}, 404));
      await expectLater(failing.deleteAttachment(_server, 'token', _cipher, 'att-1'), throwsA(isA<VwError>()));
    });

    test('a server under a path keeps its path, and its own host passes', () {
      final under = Uri.parse('https://example.com/vault');
      expect(sameServer(under, 'https://example.com/vault/attachments/a/b?token=1'), isTrue);
      expect(sameServer(under, 'https://EXAMPLE.com/attachments/a'), isTrue);
      expect(sameServer(under, '/ciphers/a/attachment/b'), isTrue);
      expect(sameServer(under, 'https://example.org/vault/attachments/a'), isFalse);
      expect(sameServer(under, 'ftp://example.com/a'), isFalse);
    });
  });
}
