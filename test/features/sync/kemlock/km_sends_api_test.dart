@TestOn('vm')
library;

// The Send routes of the Kemlock API client: the owner's carry a token and a DPoP proof, a link's carry neither,
// no redirect is followed, answers are capped, and the server's problems become SendsErrors.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/send.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sends_api.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://kem.example.com');
const _id = '3f2c9a71-e4b0-4856-8a00-000000000001';

class _Proofs implements KmProofs {
  @override
  Future<String> proof(String method, Uri url, {String? accessToken}) async => 'proof-$method';

  @override
  void observe(Uri url, Map<String, String> headers) {}
}

http.Response _json(Object? body, [int status = 200]) =>
    http.Response(jsonEncode(body), status, headers: {'content-type': 'application/json'});

http.Response _problem(int status, String slug, [Map<String, Object?> extra = const {}, Map<String, String> headers = const {}]) =>
    http.Response(
      jsonEncode({'type': 'urn:kemlock:problem:$slug', 'status': status, ...extra}),
      status,
      headers: {'content-type': 'application/problem+json', ...headers},
    );

Map<String, Object?> _sendDto({String kind = 'text', Map<String, Object?>? file, String? uploadUrl}) => {
  'id': _id,
  'accessId': sendAccessId(uuidBytes(_id)),
  'kind': kind,
  'meta': b64urlEncode(Uint8List(40)),
  'sealedKey': b64urlEncode(Uint8List(sendSealedKeyLength)),
  'payload': b64urlEncode(Uint8List(50)),
  'file': file,
  'hasPassword': false,
  'maxAccess': null,
  'accessCount': 0,
  'hideEmail': false,
  'disabled': false,
  'expiresAt': null,
  'deletionAt': 1900000000,
  'createdAt': 1800000000,
  'revisedAt': 1800000000,
  'uploadUrl': ?uploadUrl,
};

KmSendsApi _api(Future<http.Response> Function(http.Request request) handler, {List<http.Request>? seen, KmProofs? proofs}) => KmSendsApi(
  KmApi(
    MockClient((request) async {
      seen?.add(request);
      return handler(request);
    }),
    proofs: proofs,
  ),
);

Future<Object?> _error(Future<Object?> Function() action) async {
  try {
    await action();
  } on Object catch (e) {
    return e;
  }
  return null;
}

void main() {
  final proof = Uint8List.fromList(List.generate(32, (i) => i));
  final newSend = KmNewSend(
    id: _id,
    kind: sendKindText,
    meta: Uint8List(40),
    sealedKey: Uint8List(sendSealedKeyLength),
    payload: Uint8List(50),
    deletionAt: DateTime.fromMillisecondsSinceEpoch(1900000000 * 1000, isUtc: true),
  );

  group("the owner's routes", () {
    test('make a Send with a token and a proof, and read the answer', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(_sendDto(), 201), seen: seen, proofs: _Proofs());
      final send = await api.create(
        _server,
        'tok',
        KmNewSend(
          id: _id,
          kind: sendKindText,
          meta: Uint8List(40),
          sealedKey: Uint8List(sendSealedKeyLength),
          payload: Uint8List(50),
          maxAccess: 3,
          expiresAt: DateTime.fromMillisecondsSinceEpoch(1850000000 * 1000, isUtc: true),
          deletionAt: DateTime.fromMillisecondsSinceEpoch(1900000000 * 1000, isUtc: true),
          password: proof,
        ),
      );
      expect(send.id, _id);
      expect(send.accessId, sendAccessId(uuidBytes(_id)));
      expect(send.deletionAt.millisecondsSinceEpoch, 1900000000 * 1000);
      expect(seen.single.method, 'POST');
      expect(seen.single.url.toString(), 'https://kem.example.com/kem/v1/sends');
      expect(seen.single.headers['Authorization'], 'DPoP tok');
      expect(seen.single.headers['DPoP'], 'proof-POST');
      final body = jsonDecode(seen.single.body) as Map<String, Object?>;
      expect(body.keys.toSet(), {
        'id',
        'kind',
        'meta',
        'sealedKey',
        'payload',
        'maxAccess',
        'hideEmail',
        'disabled',
        'expiresAt',
        'deletionAt',
        'password',
      });
      expect(body['maxAccess'], 3);
      expect(body['expiresAt'], 1850000000);
      expect(body['password'], sendProofText(proof));
      expect(body['password'] as String, hasLength(43));
    });

    test('a file Send announces its size, and its answer names the upload address', () async {
      final seen = <http.Request>[];
      final api = _api(
        (request) async => _json(
          _sendDto(kind: 'file', file: {'size': 100, 'ready': false}, uploadUrl: 'https://kem.example.com/kem/v1/sends/$_id/file'),
          201,
        ),
        seen: seen,
      );
      final send = await api.create(
        _server,
        'tok',
        KmNewSend(
          id: _id,
          kind: sendKindFile,
          meta: Uint8List(40),
          sealedKey: Uint8List(sendSealedKeyLength),
          payload: Uint8List(50),
          fileSize: 100,
          deletionAt: newSend.deletionAt,
        ),
      );
      expect((jsonDecode(seen.single.body) as Map<String, Object?>)['file'], {'size': 100});
      expect(send.file!.size, 100);
      expect(send.file!.ready, isFalse);
      expect(send.uploadUrl, endsWith('/sends/$_id/file'));
    });

    test('list the Sends from a JSON array', () async {
      final api = _api((request) async => _json([_sendDto(), _sendDto()]));
      expect(await api.list(_server, 'tok'), hasLength(2));
    });

    test('list a Send of the Bitwarden API as a foreign one, beside a Kemlock Send, in the order given', () async {
      // The server lists the Bitwarden API's Sends from the same table, with the UTF-8 of "2.<iv>|<key>|<mac>"
      const bitwardenId = '3f2c9a71-e4b0-4856-8a00-000000000002';
      final bitwardens = {
        ..._sendDto(kind: 'file', file: {'size': 100, 'ready': true}),
        'id': bitwardenId,
        'accessId': sendAccessId(uuidBytes(bitwardenId)),
        'sealedKey': b64urlEncode(utf8.encode('2.${'A' * 22}==|${'B' * 43}=|${'C' * 43}=')),
        'meta': b64urlEncode(utf8.encode('{"name":"2.${'D' * 22}==|${'E' * 22}==|${'F' * 43}=","notes":null}')),
        'payload': '!! not read !!',
        'hasPassword': true,
        'maxAccess': 5,
        'accessCount': 2,
        'disabled': true,
        'expiresAt': 1850000000,
      };
      final api = _api((request) async => _json([_sendDto(), bitwardens, _sendDto()]));
      final sends = await api.list(_server, 'tok');
      expect(sends.map((send) => send.id), [_id, bitwardenId, _id]);
      expect(sends.map((send) => send.runtimeType), [KmSend, KmForeignSend, KmSend]);
      final foreign = sends[1] as KmForeignSend;
      expect(foreign.accessId, sendAccessId(uuidBytes(bitwardenId)));
      expect(foreign.kind, 'file');
      expect(foreign.file!.size, 100);
      expect(foreign.hasPassword, isTrue);
      expect(foreign.maxAccess, 5);
      expect(foreign.accessCount, 2);
      expect(foreign.disabled, isTrue);
      expect(foreign.expiresAt, DateTime.fromMillisecondsSinceEpoch(1850000000 * 1000, isUtc: true));
      expect(foreign.deletionAt, DateTime.fromMillisecondsSinceEpoch(1900000000 * 1000, isUtc: true));
    });

    test('leave out a Send of the Bitwarden API whose plain fields this app does not read, and keep the rest', () async {
      final bitwardens = {..._sendDto(), 'sealedKey': b64urlEncode(Uint8List(10)), 'accessCount': 'two'};
      final listed = await _api((request) async => _json([bitwardens, _sendDto()])).list(_server, 'tok');
      expect(listed, hasLength(1));
      expect(listed.single, isA<KmSend>());
    });

    test('refuse a Send of another answer whose sealedKey is not 64 bytes, or not base64url', () async {
      final short = {..._sendDto(), 'sealedKey': b64urlEncode(Uint8List(63))};
      final created = await _error(() => _api((request) async => _json(short, 201)).create(_server, 'tok', newSend));
      expect(created, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server));
      final unreadable = {..._sendDto(), 'sealedKey': '!!'};
      final listed = await _error(() => _api((request) async => _json([unreadable])).list(_server, 'tok'));
      expect(listed, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server));
    });

    test('change a Send with every option again, and take a password away', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(_sendDto()), seen: seen);
      await api.update(
        _server,
        'tok',
        _id,
        KmSendUpdate(meta: Uint8List(40), deletionAt: newSend.deletionAt, removePassword: true, disabled: true),
      );
      expect(seen.single.method, 'PUT');
      expect(seen.single.url.path, '/kem/v1/sends/$_id');
      final body = jsonDecode(seen.single.body) as Map<String, Object?>;
      expect(body['removePassword'], isTrue);
      expect(body['disabled'], isTrue);
      expect(body['hideEmail'], isFalse);
      expect(body.containsKey('password'), isFalse);
      expect(body.containsKey('payload'), isFalse);
    });

    test('delete a Send, and count a Send that is gone as deleted', () async {
      final api = _api((request) async => request.method == 'DELETE' ? http.Response('', 204) : _problem(500, 'internal'));
      await api.delete(_server, 'tok', _id);
      final gone = _api((request) async => _problem(404, 'not-found'));
      await gone.delete(_server, 'tok', _id);
    });

    test("upload a file's bytes to the Send's file route with their length", () async {
      final seen = <http.Request>[];
      final api = _api(
        (request) async => _json(_sendDto(kind: 'file', file: {'size': 100, 'ready': true})),
        seen: seen,
        proofs: _Proofs(),
      );
      final sent = await api.upload(_server, 'tok', _id, 'https://kem.example.com/kem/v1/sends/$_id/file', Uint8List(100));
      expect(sent.file!.ready, isTrue);
      expect(seen.single.method, 'PUT');
      expect(seen.single.url.path, '/kem/v1/sends/$_id/file');
      expect(seen.single.contentLength, 100);
      expect(seen.single.headers['Authorization'], 'DPoP tok');
    });

    test("read the upload's answer of a Send whose sealed meta is as long as the server takes", () async {
      // The answer is the whole SendDto: 16 KiB of meta is 21 KiB of base64url, over the room a refusal needs
      final answer = {
        ..._sendDto(kind: 'file', file: {'size': 100, 'ready': true}),
        'meta': b64urlEncode(Uint8List(sendMaxMetaLength)),
      };
      final api = _api((request) async => _json(answer));
      final sent = await api.upload(_server, 'tok', _id, 'https://kem.example.com/kem/v1/sends/$_id/file', Uint8List(100));
      expect(sent.file!.ready, isTrue);
      expect(sent.meta, hasLength(sendMaxMetaLength));
    });

    test('refuse an upload address on another host, before any request', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(_sendDto()), seen: seen);
      final error = await _error(() => api.upload(_server, 'tok', _id, 'https://evil.example.org/kem/v1/sends/$_id/file', Uint8List(100)));
      expect(error, isA<KmError>());
      expect(seen, isEmpty);
    });

    test("the server's refusals become SendsErrors", () async {
      Future<SendsError> refused(http.Response response) async {
        final error = await _error(() => _api((request) async => response).create(_server, 'tok', newSend));
        return error! as SendsError;
      }

      final policy = await refused(_problem(403, 'send-policy', {'detail': 'Sends are turned off for this space'}));
      expect(policy.problem, SendsProblem.policy);
      expect(policy.detail, 'Sends are turned off for this space');
      final big = await refused(_problem(413, 'file-too-large', {'maxSize': 1048576}));
      expect(big.problem, SendsProblem.fileTooLarge);
      expect(big.maxSize, 1048576);
      expect((await refused(_problem(409, 'already-exists'))).problem, SendsProblem.taken);
      expect((await refused(_problem(409, 'already-uploaded'))).problem, SendsProblem.alreadyUploaded);
      expect((await refused(_problem(413, 'storage-limit-reached'))).problem, SendsProblem.storage);
      expect((await refused(_problem(415, 'not-kma1'))).problem, SendsProblem.uploadRefused);
      expect((await refused(_problem(404, 'not-found'))).problem, SendsProblem.notFound);
    });

    test('an answer with no meaning here stays a KmError', () async {
      final error = await _error(() => _api((request) async => _problem(500, 'internal')).create(_server, 'tok', newSend));
      expect(error, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server));
    });
  });

  group("a link's routes", () {
    final access = {
      'id': sendAccessId(uuidBytes(_id)),
      'kind': 'text',
      'payload': b64urlEncode(Uint8List(50)),
      'fileSize': null,
      'expiresAt': null,
      'deletionAt': 1900000000,
      'senderEmail': 'ann@example.com',
    };
    final accessId = sendAccessId(uuidBytes(_id));

    test('carry no Authorization and no DPoP, even when a proof maker is there', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(access), seen: seen, proofs: _Proofs());
      final opened = await api.access(_server, accessId);
      expect(opened.senderEmail, 'ann@example.com');
      expect(opened.payload, hasLength(50));
      expect(seen.single.method, 'POST');
      expect(seen.single.headers.containsKey('Authorization'), isFalse);
      expect(seen.single.headers.containsKey('DPoP'), isFalse);
      expect(seen.single.body, isEmpty);
    });

    test("go to the link's own address, under its path", () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(access), seen: seen);
      await api.access(Uri.parse('https://example.com/kemlock'), accessId);
      expect(seen.single.url.toString(), 'https://example.com/kemlock/kem/v1/send-access/$accessId');
    });

    test('carry the password only as its proof, in base64url', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => _json(access), seen: seen);
      await api.access(_server, accessId, password: proof);
      final body = jsonDecode(seen.single.body) as Map<String, Object?>;
      expect(body, {'password': sendProofText(proof)});
      expect(seen.single.headers['Content-Type'], contains('application/json'));
    });

    test('do not follow a redirect', () async {
      final seen = <http.Request>[];
      final api = _api((request) async => http.Response('', 302, headers: {'location': 'https://evil.example.org/'}), seen: seen);
      final error = await _error(() => api.access(_server, accessId));
      expect(error, isA<KmError>().having((e) => e.status, 'status', 302));
      expect(seen, hasLength(1));
      expect(seen.single.followRedirects, isFalse);
    });

    test('refuse an access answer over 512 KiB', () async {
      final api = _api((request) async => http.Response('{"payload":"${'A' * (513 * 1024)}"}', 200));
      final error = await _error(() => api.access(_server, accessId));
      expect(error, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.tooLarge));
    });

    test('tell the password problems apart, and read the wait of a 429', () async {
      Future<SendsError> refused(http.Response response) async =>
          (await _error(() => _api((request) async => response).access(_server, accessId)))! as SendsError;

      expect((await refused(_problem(401, 'send-password-required'))).problem, SendsProblem.passwordRequired);
      expect((await refused(_problem(401, 'send-wrong-password'))).problem, SendsProblem.wrongPassword);
      expect((await refused(_problem(404, 'not-found'))).problem, SendsProblem.notFound);
      final limited = await refused(_problem(429, 'rate-limited', {'retryAfter': 42}));
      expect(limited.problem, SendsProblem.rateLimited);
      expect(limited.retryAfter, 42);
      final header = await refused(http.Response('{}', 429, headers: {'retry-after': '7'}));
      expect(header.retryAfter, 7);
    });

    test("download a file's bytes with no token, and keep exactly the length announced", () async {
      final seen = <http.Request>[];
      final file = Uint8List.fromList(List.generate(100000, (i) => i));
      final api = _api((request) async => http.Response.bytes(file, 200), seen: seen, proofs: _Proofs());
      expect(await api.download(_server, accessId, fileSize: file.length), file);
      expect(seen.single.url.path, '/kem/v1/send-access/$accessId/file');
      expect(seen.single.headers.containsKey('Authorization'), isFalse);
      expect(seen.single.headers.containsKey('DPoP'), isFalse);
    });

    test('stop a download that is longer than announced', () async {
      final api = _api((request) async => http.Response.bytes(Uint8List(200000), 200));
      final longer = await _error(() => api.download(_server, accessId, fileSize: 100000));
      expect(longer, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.tooLarge));
    });

    test('refuse a download that is shorter than announced', () async {
      final api = _api((request) async => http.Response.bytes(Uint8List(99), 200));
      final shorter = await _error(() => api.download(_server, accessId, fileSize: 100));
      expect(shorter, isA<KmError>().having((e) => e.problem, 'problem', KmProblem.server));
    });

    test('a refusal of a tiny file is still its problem', () async {
      final api = _api((request) async => _problem(404, 'not-found', {'detail': 'x' * 500}));
      final error = await _error(() => api.download(_server, accessId, fileSize: 28));
      expect(error, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.notFound));
    });

    test('no error or request names the link key', () async {
      final key = b64urlEncode(Uint8List.fromList(List.generate(32, (i) => 200 - i)));
      final seen = <http.Request>[];
      final api = _api((request) async => _problem(401, 'send-wrong-password'), seen: seen);
      final error = await _error(() => api.access(_server, accessId, password: proof));
      for (final request in seen) {
        expect('${request.url} ${request.headers} ${request.body}', isNot(contains(key)));
      }
      expect('$error', isNot(contains(key)));
    });
  });
}
