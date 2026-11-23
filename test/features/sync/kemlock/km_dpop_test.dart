@TestOn('vm')
library;

// DPoP proofs (RFC 9449): their shape, the ES256 signature, `ath`, the nonce
// retry and the clock offset.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/p256.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';

final _server = Uri.parse('https://kem.example.com');

Map<String, Object?> _part(String proof, int index) =>
    jsonDecode(utf8.decode(b64urlDecode(proof.split('.')[index]))) as Map<String, Object?>;

({KmApi api, FakeKemlockServer server, KmDpop dpop, String token}) _signedIn({SoftwareDeviceKey? key}) {
  final deviceKey = key ?? SoftwareDeviceKey.generate();
  final server = FakeKemlockServer();
  final dpop = KmDpop(deviceKey);
  final api = KmApi(server.client, proofs: dpop);
  final token = server.issueTokens(jwkThumbprint(deviceKey.publicJwk))['accessToken']! as String;
  return (api: api, server: server, dpop: dpop, token: token);
}

void main() {
  group('a proof', () {
    test('has RFC 9449’s shape: typ dpop+jwt, alg ES256, the public key as jwk, and jti, htm, htu and iat', () async {
      final key = SoftwareDeviceKey.generate();
      final dpop = KmDpop(
        key,
        clock: () => DateTime.fromMillisecondsSinceEpoch(1562262616 * 1000, isUtc: true),
        newJti: () => '-BwC3ESc6acc2lTc',
      );

      final proof = await dpop.proof('POST', Uri.parse('https://server.example.com/token'));

      final header = _part(proof, 0);
      final claims = _part(proof, 1);
      expect(header['typ'], 'dpop+jwt');
      expect(header['alg'], 'ES256');
      expect(header['jwk'], {'kty': 'EC', 'crv': 'P-256', 'x': key.publicJwk['x'], 'y': key.publicJwk['y']});
      expect((header['jwk']! as Map).containsKey('d'), isFalse, reason: 'never the private half');
      expect(claims, {'jti': '-BwC3ESc6acc2lTc', 'htm': 'POST', 'htu': 'https://server.example.com/token', 'iat': 1562262616});
    });

    test('is signed with ES256: the signature is 64 bytes and verifies against the jwk, and not against another key', () async {
      final key = SoftwareDeviceKey.generate();
      final proof = await KmDpop(key).proof('GET', Uri.parse('https://kem.example.com/kem/v1/sync'));
      final parts = proof.split('.');
      final signature = b64urlDecode(parts[2]);
      final input = Uint8List.fromList(utf8.encode('${parts[0]}.${parts[1]}'));
      Uint8List point(SoftwareDeviceKey key) =>
          Uint8List.fromList([4, ...b64urlDecode(key.publicJwk['x']!), ...b64urlDecode(key.publicJwk['y']!)]);

      expect(signature, hasLength(64));
      expect(es256Verify(point(key), input, rawToDerEs256(signature)), isTrue);
      expect(es256Verify(point(SoftwareDeviceKey.generate()), input, rawToDerEs256(signature)), isFalse);
    });

    test('names the URL without its query or fragment, and the same for a path with a colon', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate());

      final sync = await dpop.proof('GET', Uri.parse('https://kem.example.com/kem/v1/sync?since=abc&limit=500#x'));
      final batch = await dpop.proof('POST', Uri.parse('https://kem.example.com:8443/kem/v1/items:batch'));

      expect(_part(sync, 1)['htu'], 'https://kem.example.com/kem/v1/sync');
      expect(_part(batch, 1)['htu'], 'https://kem.example.com:8443/kem/v1/items:batch');
    });

    test('binds a token with ath, the base64url SHA-256 of it, as RFC 9449’s example does', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate());

      final proof = await dpop.proof(
        'GET',
        Uri.parse('https://resource.example.org/protectedresource'),
        accessToken: 'Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU',
      );
      final without = await dpop.proof('GET', Uri.parse('https://resource.example.org/protectedresource'));

      expect(_part(proof, 1)['ath'], 'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo');
      expect(_part(without, 1).containsKey('ath'), isFalse);
    });

    test('has a new jti each time', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate());
      final url = Uri.parse('https://kem.example.com/kem/v1/sync');

      final ids = {for (var i = 0; i < 20; i++) _part(await dpop.proof('GET', url), 1)['jti']};

      expect(ids, hasLength(20));
    });

    test('the key’s thumbprint is RFC 7638’s, as RFC 9449’s example key has it', () {
      const jwk = {
        'kty': 'EC',
        'crv': 'P-256',
        'x': 'l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs',
        'y': '9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA',
      };

      expect(jwkThumbprint(jwk), '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I');
    });
  });

  group('the nonce', () {
    test('a 401 that asks for the server’s nonce is retried once with it, and the next request has it from the start', () async {
      final s = _signedIn();

      final page = await s.api.sync(_server, s.token);

      expect(page, isNotNull);
      expect(s.server.requests, hasLength(2), reason: 'refused for the nonce, then accepted');
      expect(s.dpop.nonceFor(_server), isNotNull);

      s.server.requests.clear();
      await s.api.sync(_server, s.token);
      expect(s.server.requests, hasLength(1));
    });

    test('a rotated nonce is picked up the same way, once', () async {
      final s = _signedIn();
      await s.api.sync(_server, s.token);
      s.server.rotateNonce();
      s.server.requests.clear();

      await s.api.sync(_server, s.token);

      expect(s.server.requests, hasLength(2));
    });

    test('a refusal that stays is not retried more than once', () async {
      final s = _signedIn();
      s.server.respond = (request) async => s.server.problem(
        401,
        'use-dpop-nonce',
        extra: {'error': 'use_dpop_nonce'},
        headers: {'www-authenticate': 'DPoP error="use_dpop_nonce"'},
      );

      await expectLater(s.api.sync(_server, s.token), throwsA(isA<KmError>()));

      expect(s.server.requests, hasLength(2));
    });
  });

  group('the server checks what the proof says', () {
    test('a token is useless with another device’s key', () async {
      final s = _signedIn();
      final other = KmApi(s.server.client, proofs: KmDpop(SoftwareDeviceKey.generate()));

      await expectLater(other.sync(_server, s.token), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.auth)));
    });

    test('a proof sent twice is refused the second time', () async {
      final s = _signedIn();
      await s.api.sync(_server, s.token);
      final proof = await s.dpop.proof('GET', Uri.parse('https://kem.example.com/kem/v1/sync'), accessToken: s.token);
      Future<int> send() async => (await s.server.client.get(
        Uri.parse('https://kem.example.com/kem/v1/sync'),
        headers: {'Authorization': 'DPoP ${s.token}', 'DPoP': proof},
      )).statusCode;

      expect(await send(), 200);
      expect(await send(), 401);
    });
  });

  group('the clock', () {
    final url = Uri.parse('https://kem.example.com/kem/v1/sync');
    final phone = DateTime.utc(2026, 11, 21, 12);

    test('is corrected by the server’s Date when the phone is more than a minute off', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate(), clock: () => phone);
      dpop.observe(url, {'date': HttpDateText.of(phone.add(const Duration(hours: 1)))});

      final claims = _part(await dpop.proof('GET', url), 1);

      expect(claims['iat'], phone.add(const Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000);
      expect(dpop.offsetFor(url), 3600);
    });

    test('is left alone within a minute, and the correction goes when the clock is right again', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate(), clock: () => phone);
      dpop.observe(url, {'date': HttpDateText.of(phone.add(const Duration(minutes: 10)))});
      expect(dpop.offsetFor(url), 600);

      dpop.observe(url, {'date': HttpDateText.of(phone.add(const Duration(seconds: 30)))});

      expect(dpop.offsetFor(url), 0);
      expect(_part(await dpop.proof('GET', url), 1)['iat'], phone.millisecondsSinceEpoch ~/ 1000);
    });

    test('is kept per server, and a date that does not read changes nothing', () async {
      final dpop = KmDpop(SoftwareDeviceKey.generate(), clock: () => phone);
      dpop.observe(url, {'date': HttpDateText.of(phone.add(const Duration(hours: 1))), 'dpop-nonce': 'n1'});

      dpop.observe(url, {'date': 'last Tuesday'});

      expect(dpop.offsetFor(url), 3600);
      expect(dpop.offsetFor(Uri.parse('https://other.example.com/x')), 0);
      expect(dpop.nonceFor(Uri.parse('https://other.example.com/x')), isNull);
      expect(dpop.nonceFor(url), 'n1');
    });
  });
}

/// An HTTP date, `Sat, 21 Nov 2026 13:00:00 GMT`, as a server writes it.
class HttpDateText {
  static String of(DateTime utc) {
    const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    String two(int n) => n.toString().padLeft(2, '0');
    return '${days[utc.weekday - 1]}, ${two(utc.day)} ${months[utc.month - 1]} ${utc.year} ${two(utc.hour)}:${two(utc.minute)}:${two(utc.second)} GMT';
  }
}
