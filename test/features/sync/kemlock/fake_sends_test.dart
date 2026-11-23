@TestOn('vm')
library;

// Smoke tests of the fake server's Send routes: that they hold the rules the tests of the client rely on.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'fake_sends.dart';

const _id = '3f2c9a71-e4b0-4a56-8a00-000000000001';

void main() {
  late FakeKemlockServer server;
  late String token;
  final now = DateTime.utc(2030, 1, 1);

  setUp(() {
    server = FakeKemlockServer()..checkTokens = false;
    server.sends.clock = () => now;
    token = server.issueTokens('jkt')['accessToken']! as String;
  });

  Uri at(String route) => Uri.parse('https://kem.example.com/kem/v1$route');

  Map<String, Object?> body({
    String id = _id,
    String kind = 'text',
    int? fileSize,
    int? maxAccess,
    Uint8List? password,
    bool hideEmail = false,
  }) => {
    'id': id,
    'kind': kind,
    'meta': b64urlEncode(Uint8List(40)),
    'sealedKey': b64urlEncode(Uint8List(64)),
    'payload': b64urlEncode(Uint8List(50)),
    if (fileSize != null) 'file': {'size': fileSize},
    'maxAccess': ?maxAccess,
    'hideEmail': hideEmail,
    'deletionAt': now.millisecondsSinceEpoch ~/ 1000 + 7 * 86400,
    if (password != null) 'password': b64urlEncode(password),
  };

  Future<http.Response> owner(String method, String route, [Object? json]) async {
    final request = http.Request(method, at(route))..headers['Authorization'] = 'DPoP $token';
    if (json != null) {
      request.headers['Content-Type'] = 'application/json';
      request.body = jsonEncode(json);
    }
    return http.Response.fromStream(await server.client.send(request));
  }

  Future<http.Response> access(String route, {Uint8List? password}) => server.client.post(
    at('/send-access/$route'),
    headers: {'Content-Type': 'application/json'},
    body: password == null ? null : jsonEncode({'password': b64urlEncode(password)}),
  );

  String accessId([String id = _id]) => b64urlEncode(uuidBytes(id));

  Object? json(http.Response response) => jsonDecode(response.body);

  test('a text Send limited to one open answers once, then is a plain 404', () async {
    expect((await owner('POST', '/sends', body(maxAccess: 1))).statusCode, 201);
    final first = await access(accessId());
    expect(first.statusCode, 200);
    expect(first.headers['cache-control'], 'private, no-store');
    expect((json(first)! as Map)['senderEmail'], 'ann@example.com');
    expect((await access(accessId())).statusCode, 404);
    expect(server.sends.sends[_id]!.accessCount, 1);
  });

  test("the owner's routes need a token and a link's routes need none", () async {
    final bare = await server.client.post(at('/sends'), headers: {'Content-Type': 'application/json'}, body: jsonEncode(body()));
    expect(bare.statusCode, 401);
    await owner('POST', '/sends', body());
    expect((await access(accessId())).statusCode, 200);
  });

  test('lists newest first, reads, and deletes', () async {
    await owner('POST', '/sends', body());
    await owner('POST', '/sends', body(id: '3f2c9a71-e4b0-4a56-8a00-000000000002'));
    final list = json(await owner('GET', '/sends'))! as List;
    expect(list.map((send) => (send as Map)['id']), ['3f2c9a71-e4b0-4a56-8a00-000000000002', _id]);
    expect((await owner('GET', '/sends/$_id')).statusCode, 200);
    expect((await owner('DELETE', '/sends/$_id')).statusCode, 204);
    expect((await owner('DELETE', '/sends/$_id')).statusCode, 404);
    expect((await access(accessId())).statusCode, 404);
  });

  test('refuses an id that is taken, one that is not version 4, and a deletion too far ahead', () async {
    await owner('POST', '/sends', body());
    expect((await owner('POST', '/sends', body())).statusCode, 409);
    expect((await owner('POST', '/sends', body(id: '3f2c9a71-e4b0-1a56-8a00-000000000009'))).statusCode, 400);
    final far = {...body(id: '3f2c9a71-e4b0-4a56-8a00-000000000003'), 'deletionAt': now.millisecondsSinceEpoch ~/ 1000 + 31 * 86400};
    expect((await owner('POST', '/sends', far)).statusCode, 400);
  });

  test("a refused body is the server's invalid-request problem, with its words in detail", () async {
    final refused = await owner('POST', '/sends', {...body(), 'nope': 1});
    expect(refused.statusCode, 400);
    expect(json(refused)! as Map, containsPair('type', 'urn:kemlock:problem:invalid-request'));
    expect((json(refused)! as Map)['detail'], isA<String>());
    final badKind = await owner('POST', '/sends', body(kind: 'link'));
    expect(json(badKind)! as Map, containsPair('type', 'urn:kemlock:problem:invalid-request'));
    expect((await owner('POST', '/sends', body())).statusCode, 201);
    final unknownField = await server.client.post(
      at('/send-access/${accessId()}'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'nope': 1}),
    );
    expect(unknownField.statusCode, 400);
    expect(json(unknownField)! as Map, containsPair('type', 'urn:kemlock:problem:invalid-request'));
  });

  test('a file Send is closed until its bytes land, which need their length and the KMA1 header', () async {
    final file = kma1EncryptSync(Uint8List.fromList(List.generate(70000, (i) => i)), Uint8List(32));
    final made = await owner('POST', '/sends', body(kind: 'file', fileSize: file.length, maxAccess: 1));
    expect(made.statusCode, 201);
    expect((json(made)! as Map)['uploadUrl'], 'https://kem.example.com/kem/v1/sends/$_id/file');
    expect((await access(accessId())).statusCode, 404);
    expect((await owner('PUT', '/sends/$_id/file')).statusCode, 400);
    final request = http.Request('PUT', at('/sends/$_id/file'))
      ..headers['Authorization'] = 'DPoP $token'
      ..bodyBytes = Uint8List.fromList([...file]..[0] = 0x58);
    expect((await http.Response.fromStream(await server.client.send(request))).statusCode, 415);
    final good = http.Request('PUT', at('/sends/$_id/file'))
      ..headers['Authorization'] = 'DPoP $token'
      ..bodyBytes = file;
    expect((await http.Response.fromStream(await server.client.send(good))).statusCode, 200);
    expect((await owner('PUT', '/sends/$_id/file')).statusCode, 409);
    // The answer names the file and spends no open; the download does
    final opened = await access(accessId());
    expect((json(opened)! as Map)['fileSize'], file.length);
    expect(server.sends.sends[_id]!.accessCount, 0);
    final download = await access('${accessId()}/file');
    expect(download.bodyBytes, file);
    expect(server.sends.sends[_id]!.accessCount, 1);
    expect((await access('${accessId()}/file')).statusCode, 404);
  });

  test('a note takes no file: its upload is an invalid request, not a missing Send', () async {
    await owner('POST', '/sends', body());
    final request = http.Request('PUT', at('/sends/$_id/file'))
      ..headers['Authorization'] = 'DPoP $token'
      ..bodyBytes = Uint8List.fromList(utf8.encode('KMA1'));
    final answer = await http.Response.fromStream(await server.client.send(request));
    expect(answer.statusCode, 400);
    expect(json(answer)! as Map, containsPair('type', 'urn:kemlock:problem:invalid-request'));
    // A Send that isn't there is still a 404
    final missing = http.Request('PUT', at('/sends/3f2c9a71-e4b0-4a56-8a00-0000000000ff/file'))..headers['Authorization'] = 'DPoP $token';
    expect((await http.Response.fromStream(await server.client.send(missing))).statusCode, 404);
  });

  test('a password is needed, a wrong one is counted, and the eleventh try in a minute waits', () async {
    final proof = Uint8List.fromList(List.generate(32, (i) => i));
    await owner('POST', '/sends', body(password: proof));
    expect(json(await access(accessId()))! as Map, containsPair('type', 'urn:kemlock:problem:send-password-required'));
    final wrong = Uint8List(32);
    for (var i = 0; i < 10; i++) {
      final answer = await access(accessId(), password: wrong);
      expect(json(answer)! as Map, containsPair('type', 'urn:kemlock:problem:send-wrong-password'));
    }
    final limited = await access(accessId(), password: wrong);
    expect(limited.statusCode, 429);
    expect((json(limited)! as Map)['retryAfter'], isA<int>());
    expect((await access(accessId(), password: proof)).statusCode, 429);
    // A minute later the count is over, and the right proof opens it and clears the count
    server.sends.clock = () => now.add(const Duration(seconds: 61));
    expect((await access(accessId(), password: proof)).statusCode, 200);
  });

  test('the wait after the tenth try is 1 second and doubles, and a try with no proof costs nothing', () async {
    final proof = Uint8List.fromList(List.generate(32, (i) => i));
    await owner('POST', '/sends', body(password: proof));
    final wrong = Uint8List(32);
    for (var i = 0; i < 10; i++) {
      expect((await access(accessId(), password: wrong)).statusCode, 401);
    }
    for (var i = 0; i < 5; i++) {
      expect((await access(accessId())).statusCode, 401);
    }
    final first = await access(accessId(), password: wrong);
    expect(first.statusCode, 429);
    expect(json(first)! as Map, containsPair('type', 'urn:kemlock:problem:rate-limited'));
    expect((json(first)! as Map)['retryAfter'], 1);
    expect(first.headers['retry-after'], '1');
    // A second later the next try is let through to be counted, and passes the limit again: twice the wait
    server.sends.clock = () => now.add(const Duration(seconds: 1));
    final second = await access(accessId(), password: wrong);
    expect(second.statusCode, 429);
    expect((json(second)! as Map)['retryAfter'], 2);
    expect(second.headers['retry-after'], '2');
  });

  test('a try with a proof is counted before the Send is looked up, and a body that is refused comes before both', () async {
    final ghost = accessId('3f2c9a71-e4b0-4a56-8a00-0000000000aa');
    for (var i = 0; i < 10; i++) {
      expect((await access(ghost, password: Uint8List(32))).statusCode, 404);
    }
    expect((await access(ghost, password: Uint8List(32))).statusCode, 429);
    expect((await access(ghost)).statusCode, 404);
    final refused = await server.client.post(
      at('/send-access/${accessId('3f2c9a71-e4b0-4a56-8a00-0000000000bb')}'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'nope': 1}),
    );
    expect(refused.statusCode, 400);
  });

  test("the server's policies refuse making a Send and hiding the email", () async {
    server.sends.policyShowEmail = "A space's policy always shows the sender's email";
    final hidden = await owner('POST', '/sends', body(hideEmail: true));
    expect(hidden.statusCode, 403);
    expect((json(hidden)! as Map)['detail'], contains('policy'));
    expect((await owner('POST', '/sends', body())).statusCode, 201);
    server.sends.policyRemoveSend = 'Sends are removed in a space of yours';
    expect((await owner('POST', '/sends', body(id: '3f2c9a71-e4b0-4a56-8a00-000000000004'))).statusCode, 403);
  });

  test('an edit replaces the options and takes a password away', () async {
    final proof = Uint8List(32)..fillRange(0, 32, 5);
    await owner('POST', '/sends', body(password: proof));
    final edit = {
      'meta': b64urlEncode(Uint8List(44)),
      'hideEmail': true,
      'disabled': true,
      'deletionAt': now.millisecondsSinceEpoch ~/ 1000 + 86400,
      'removePassword': true,
    };
    final changed = json(await owner('PUT', '/sends/$_id', edit))! as Map;
    expect(changed['hasPassword'], isFalse);
    expect(changed['disabled'], isTrue);
    expect((await access(accessId())).statusCode, 404);
    final both = {...edit, 'password': b64urlEncode(proof)};
    expect((await owner('PUT', '/sends/$_id', both)).statusCode, 400);
    final on = {...edit, 'disabled': false};
    await owner('PUT', '/sends/$_id', on);
    expect((await access(accessId())).statusCode, 200);
  });

  test("a policy that removes Sends refuses an edit but not a delete, and a file Send's content can't be changed", () async {
    final file = kma1EncryptSync(Uint8List(10), Uint8List(32));
    await owner('POST', '/sends', body());
    await owner('POST', '/sends', body(id: '3f2c9a71-e4b0-4a56-8a00-000000000002', kind: 'file', fileSize: file.length));
    final edit = {'meta': b64urlEncode(Uint8List(44)), 'deletionAt': now.millisecondsSinceEpoch ~/ 1000 + 86400};
    final content = {...edit, 'payload': b64urlEncode(Uint8List(60))};
    final refused = await owner('PUT', '/sends/3f2c9a71-e4b0-4a56-8a00-000000000002', content);
    expect(refused.statusCode, 400);
    expect(json(refused)! as Map, containsPair('type', 'urn:kemlock:problem:invalid-request'));
    expect((await owner('PUT', '/sends/3f2c9a71-e4b0-4a56-8a00-000000000002', edit)).statusCode, 200);
    final tooLong = {...edit, 'meta': b64urlEncode(Uint8List(16 * 1024 + 1))};
    expect((await owner('PUT', '/sends/$_id', tooLong)).statusCode, 400);
    server.sends.policyRemoveSend = 'Sends are removed in a space of yours';
    final removed = await owner('PUT', '/sends/$_id', edit);
    expect(removed.statusCode, 403);
    expect(json(removed)! as Map, containsPair('type', 'urn:kemlock:problem:send-policy'));
    expect((json(removed)! as Map)['detail'], 'Sends are removed in a space of yours');
    expect((await owner('DELETE', '/sends/$_id')).statusCode, 204);
  });

  test('finds a secret in the log of requests, in any spelling, and none that was never sent', () async {
    final key = Uint8List.fromList(List.generate(32, (i) => 200 - i));
    await owner('POST', '/sends', body());
    expect(server.sends.requestsHold(key), isFalse);
    expect(server.sends.requestsHold(Uint8List(40)), isTrue);
    expect(server.sends.requestsHoldText(b64urlEncode(Uint8List(40))), isTrue);
  });

  test('knows the lengths a KMA1 file can have', () {
    for (final plain in [0, 1, 65535, 65536, 65537, 131072, 3000000]) {
      expect(isKma1Length(kma1Length(plain)), isTrue, reason: '$plain');
    }
    // Under a header and a tag, and a last chunk that holds nothing after a full one
    for (final size in [0, 11, 27, 12 + 16 + 65536 + 16]) {
      expect(isKma1Length(size), isFalse, reason: '$size');
    }
  });
}
