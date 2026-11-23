@TestOn('vm')
library;

import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_devices.dart';
import 'package:test/test.dart';

final _now = DateTime.utc(2026, 12, 25, 12);

KmDevice _device(String name, {int? bitwardenDaysAgo, int? kemlockDaysAgo, bool current = false}) => KmDevice(
  id: name,
  name: name,
  kind: 'other',
  current: current,
  lastBitwarden: bitwardenDaysAgo == null ? null : _now.subtract(Duration(days: bitwardenDaysAgo)),
  lastKemlock: kemlockDaysAgo == null ? null : _now.subtract(Duration(days: kemlockDaysAgo)),
);

void main() {
  test('a device that used the Bitwarden API yesterday and never the Kemlock API makes the copy needed', () {
    final devices = [_device('Amethystora', bitwardenDaysAgo: 1), _device('Pixel', kemlockDaysAgo: 0)];
    expect(kmBitwardenDevices(devices, _now).map((d) => d.name), ['Amethystora']);
    expect(
      kmCopyStanding(devices: devices, now: _now, movedAt: _now.subtract(const Duration(days: 90)).millisecondsSinceEpoch),
      KmCopyStanding.needed,
    );
  });

  test('moved phones do not count, whatever their last Bitwarden use', () {
    final devices = [_device('Pixel', bitwardenDaysAgo: 2, kemlockDaysAgo: 1), _device('Mine', bitwardenDaysAgo: 0, current: true)];
    expect(kmBitwardenDevices(devices, _now), isEmpty);
  });

  test('a device last seen 31 days ago does not count, and 29 days ago does', () {
    expect(kmUsesBitwarden(_device('Old', bitwardenDaysAgo: 31), _now), isFalse);
    expect(kmUsesBitwarden(_device('Recent', bitwardenDaysAgo: 29), _now), isTrue);
    expect(kmUsesBitwarden(_device('Never'), _now), isFalse);
  });

  test('the removal is offered only after 30 days since the move, with no device counting', () {
    final devices = [_device('Old', bitwardenDaysAgo: 45)];
    int moved(int daysAgo) => _now.subtract(Duration(days: daysAgo)).millisecondsSinceEpoch;
    expect(kmCopyStanding(devices: devices, now: _now, movedAt: moved(10)), KmCopyStanding.waiting);
    expect(kmCopyStanding(devices: devices, now: _now, movedAt: moved(31)), KmCopyStanding.offered);
    expect(kmCopyStanding(devices: devices, now: _now, movedAt: null), KmCopyStanding.waiting);
  });

  test('a device that returns withdraws the offer', () {
    final moved = _now.subtract(const Duration(days: 40)).millisecondsSinceEpoch;
    expect(kmCopyStanding(devices: [_device('Old', bitwardenDaysAgo: 45)], now: _now, movedAt: moved), KmCopyStanding.offered);
    expect(kmCopyStanding(devices: [_device('Old', bitwardenDaysAgo: 0)], now: _now, movedAt: moved), KmCopyStanding.needed);
  });
}
