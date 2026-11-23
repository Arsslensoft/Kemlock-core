@TestOn('vm')
library;

import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

void main() {
  test('the device list reads each API\'s last use, this phone and trust', () async {
    final server = FakeKemlockAccountServer()
      ..deviceList = [
        {
          'id': 'dev-1',
          'name': 'Kemlock on Pixel 9',
          'kind': 'kemlock-android',
          'createdAt': '2026-11-01T08:00:00Z',
          'lastSeenAt': '2026-11-22T09:00:00Z',
          'lastKemlockUseAt': '2026-11-22T09:00:00Z',
          'lastBitwardenUseAt': '2026-11-10T12:00:00Z',
          'current': true,
          'trusted': true,
        },
        {
          'id': 'dev-2',
          'name': 'Bitwarden extension',
          'kind': 'bitwarden',
          'createdAt': '2026-10-01T08:00:00Z',
          'lastSeenAt': '2026-11-20T09:00:00Z',
          'lastKemlockUseAt': null,
          'lastBitwardenUseAt': '2026-11-20T09:00:00Z',
          'current': false,
          'trusted': false,
        },
      ];
    final key = SoftwareDeviceKey.generate();
    final token = server.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk))['accessToken']! as String;
    final devices = await KmAuthApi(KmApi(server.client, proofs: KmDpop(key))).devices(FakeKemlockServer.url, token);

    expect(devices, hasLength(2));
    final phone = devices.first;
    expect(phone.current, isTrue);
    expect(phone.trusted, isTrue);
    expect(phone.lastKemlock, DateTime.utc(2026, 11, 22, 9));
    expect(phone.lastBitwarden, DateTime.utc(2026, 11, 10, 12), reason: 'one row with both APIs\' dates');
    expect(phone.createdAt, DateTime.utc(2026, 11, 1, 8));
    final extension = devices.last;
    expect(extension.lastKemlock, isNull, reason: '"Kemlock API: never"');
    expect(extension.lastBitwarden, isNotNull);
    expect(extension.current, isFalse);
  });
}
