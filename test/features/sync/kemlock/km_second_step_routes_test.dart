@TestOn('vm')
library;

// The second steps each answer at their own route (`crates/kemlock-api-kem/src/routes/two_step.rs`): an authenticator
// code at `/auth/two-factor` with its method, an emailed code and the account's recovery code at routes of their own with
// the challenge and the code only, and the email code is mailed by `/auth/two-factor/email/send`.
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:test/test.dart';

final _server = Uri.parse('https://km.example');

const _tokens = {
  'accessToken': 'access',
  'refreshToken': 'refresh',
  'expiresIn': 600,
  'refreshExpiresIn': 86400,
  'userId': '11111111-1111-4111-8111-111111111111',
  'deviceId': '22222222-2222-4222-8222-222222222222',
};

void main() {
  late List<http.Request> seen;
  late KmAuthApi auth;

  setUp(() {
    seen = [];
    auth = KmAuthApi(
      KmApi(
        MockClient((request) async {
          seen.add(request);
          if (request.url.path.endsWith('/email/send')) return http.Response('', 204);
          return http.Response(jsonEncode(_tokens), 200, headers: {'content-type': 'application/json'});
        }),
      ),
    );
  });

  Map<String, Object?> body(http.Request request) => jsonDecode(request.body) as Map<String, Object?>;

  test('an authenticator code goes to /auth/two-factor with its method', () async {
    await auth.twoFactor(_server, 'challenge', 'totp', '123456');
    expect(seen.single.url.path, '/kem/v1/auth/two-factor');
    expect(body(seen.single), {'challenge': 'challenge', 'method': 'totp', 'code': '123456'});
  });

  test('an emailed code goes to /auth/two-factor/email with no method', () async {
    final grant = await auth.twoFactor(_server, 'challenge', 'email', '654321');
    expect(grant.deviceId, _tokens['deviceId']);
    expect(seen.single.url.path, '/kem/v1/auth/two-factor/email');
    expect(body(seen.single), {'challenge': 'challenge', 'code': '654321'});
  });

  test('the recovery code goes to /auth/two-factor/recovery', () async {
    await auth.twoFactor(_server, 'challenge', 'recovery', 'ABCD');
    expect(seen.single.url.path, '/kem/v1/auth/two-factor/recovery');
    expect(body(seen.single), {'challenge': 'challenge', 'code': 'ABCD'});
  });

  test('the email code is mailed by its own route', () async {
    await auth.sendEmailCode(_server, 'challenge');
    expect(seen.single.url.path, '/kem/v1/auth/two-factor/email/send');
    expect(body(seen.single), {'challenge': 'challenge'});
  });
}
