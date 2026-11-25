@TestOn('vm')
library;

import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

/// Stands in for Have I Been Pwned's breach API: answers with [breaches], the last of
/// them as the latest, and keeps what it was asked.
class FakeHibp {
  FakeHibp(this.breaches);

  List<Object?> breaches;
  int status = 200;

  /// Sent as the whole list instead of [breaches], when set.
  String? body;
  bool offline = false;
  final requests = <http.Request>[];

  List<String> get asked => [for (final request in requests) request.url.path];

  late final client = MockClient((request) async {
    requests.add(request);
    if (offline) throw http.ClientException('offline', request.url);
    if (status != 200) return http.Response('error', status);
    return switch (request.url.path) {
      '/api/v3/latestbreach' => http.Response.bytes(utf8.encode(jsonEncode(breaches.last)), 200),
      '/api/v3/breaches' => http.Response.bytes(utf8.encode(body ?? jsonEncode(breaches)), 200),
      _ => http.Response('not found', 404),
    };
  });
}
