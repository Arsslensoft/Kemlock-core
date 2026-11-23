@TestOn('vm')
library;

// How the client reads a Vaultwarden server's answers, against a mock
// server: never past a limit, and never by following a redirect.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://vault.example.com');

Matcher _problem(VwProblem problem) => throwsA(isA<VwError>().having((e) => e.problem, 'problem', problem));

void main() {
  test('follows no redirect, to another host or the same, and takes one for the server’s error', () async {
    final sent = <http.Request>[];
    final api = VwApi(
      MockClient((request) async {
        sent.add(request);
        return http.Response('', 302, headers: {'location': 'http://elsewhere.example/api/sync'});
      }),
    );

    await expectLater(api.config(_server), _problem(VwProblem.address));
    await expectLater(api.prelogin(_server, 'me@example.com'), _problem(VwProblem.server));
    await expectLater(api.revisionDate(_server, 'token'), _problem(VwProblem.server));
    await expectLater(api.sync(_server, 'token'), _problem(VwProblem.server));
    await expectLater(api.trashCipher(_server, 'token', 'id'), _problem(VwProblem.server));

    expect(sent, hasLength(5));
    expect([for (final request in sent) request.followRedirects], everyElement(isFalse));
  });

  group('the answers', () {
    test('a vault that never ends is dropped at its limit', () async {
      final chunk = Uint8List(1 << 20);
      var sent = 0;
      Stream<List<int>> endless() async* {
        yield utf8.encode('{"object":"sync","ciphers":["');
        while (true) {
          sent += chunk.length;
          yield chunk;
        }
      }

      final api = VwApi(MockClient.streaming((request, _) async => http.StreamedResponse(endless(), 200)));

      await expectLater(api.sync(_server, 'token'), _problem(VwProblem.server));
      expect(sent, lessThanOrEqualTo(VwApi.maxVaultBytes + 2 * chunk.length));
    });

    test('any other answer is held to a few megabytes, by its length or as it comes', () async {
      final long = VwApi(
        MockClient.streaming(
          (request, _) async => http.StreamedResponse(Stream.value(utf8.encode('1')), 200, contentLength: VwApi.maxAnswerBytes + 1),
        ),
      );
      await expectLater(long.revisionDate(_server, 'token'), _problem(VwProblem.server));

      final big = VwApi(MockClient((request) async => http.Response.bytes(Uint8List(VwApi.maxAnswerBytes + 1), 200)));
      await expectLater(big.config(_server), _problem(VwProblem.server));

      final fits = VwApi(MockClient((request) async => http.Response('1763200000000', 200)));
      expect(await fits.revisionDate(_server, 'token'), 1763200000000);
    });
  });
}
