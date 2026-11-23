@TestOn('vm')
library;

// The first-byte timeout failover relies on (add-kemlock-server-sync, design
// 12): a request that gets no answer headers in time fails as a network
// problem that says it timed out, so the phone moves on at once.
import 'dart:async';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://kem.example.com');

void main() {
  test('no first byte in time is a network problem that timed out', () async {
    final api = KmApi(
      MockClient.streaming((request, body) => Completer<http.StreamedResponse>().future),
      firstByte: const Duration(milliseconds: 20),
    );

    await expectLater(
      api.config(_server),
      throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network).having((e) => e.timedOut, 'timedOut', isTrue)),
    );
  });

  test('without a first-byte limit a slow answer is only a network problem at the whole timeout', () async {
    final api = KmApi(
      MockClient.streaming((request, body) => Completer<http.StreamedResponse>().future),
      timeout: const Duration(milliseconds: 20),
    );

    await expectLater(
      api.config(_server),
      throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.network).having((e) => e.timedOut, 'timedOut', isFalse)),
    );
  });

  test('an answer that comes in time is read as usual', () async {
    final api = KmApi(
      MockClient(
        (request) async => http.Response(
          '{"server":"kemlock-server","apiVersions":["v1"],"serverId":"s","domain":"kem.example.com","version":"1","features":[]}',
          200,
          headers: {'content-type': 'application/json'},
        ),
      ),
      firstByte: const Duration(seconds: 10),
    );

    expect((await api.config(_server)).serverId, 's');
  });
}
