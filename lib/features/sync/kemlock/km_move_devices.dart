/// Who still needs a plain home's Bitwarden copy (move-off-vaultwarden-sync, design 8, task 6.1): the
/// account's device list says, per device, when it last used the Bitwarden API and the Kemlock API
/// (`GET /kem/v1/devices`, read by `KmAuthApi.devices`), and the app applies the rule itself.
///
/// A device counts when its last Bitwarden API use is within 30 days and it has never used the Kemlock
/// API. A phone that moved has used the Kemlock API, so it never counts, whatever it did on the Bitwarden
/// API; so this phone doesn't count either. The server gives no client name, only a `kind`, so a device is
/// named by its `name`.
///
/// The copy is offered for removal once no device counts and the move finished 30 days ago, never before,
/// so a device that hasn't been seen yet isn't missed. The offer is withdrawn as soon as a device counts
/// again. The copy is never removed without the person's confirmation.
///
/// Pure Dart, no Flutter.
library;

import 'km_auth_api.dart' show KmDevice;

/// How long a device's last Bitwarden API use keeps the copy needed, and how long after the move the
/// removal is first offered.
const kmBitwardenWindow = Duration(days: 30);

/// Whether [device] still uses the Bitwarden API at [now], so the copy is needed for it.
bool kmUsesBitwarden(KmDevice device, DateTime now) {
  if (device.current || device.lastKemlock != null) {
    return false;
  }
  final last = device.lastBitwarden;
  return last != null && now.difference(last) < kmBitwardenWindow;
}

/// The devices of [devices] that still use the Bitwarden API.
List<KmDevice> kmBitwardenDevices(Iterable<KmDevice> devices, DateTime now) => [
  for (final device in devices)
    if (kmUsesBitwarden(device, now)) device,
];

/// Where the copy stands.
enum KmCopyStanding {
  /// A device still uses the Bitwarden API: the copy stays, and Settings names the device.
  needed,

  /// No device uses it, but the move finished less than 30 days ago.
  waiting,

  /// No device used it for 30 days: the removal is offered.
  offered,
}

/// The standing of the copy for [devices] at [now], the move having finished at [movedAt] (epoch ms), or
/// null when that isn't known, which only waits.
KmCopyStanding kmCopyStanding({required Iterable<KmDevice> devices, required DateTime now, required int? movedAt}) {
  if (kmBitwardenDevices(devices, now).isNotEmpty) {
    return KmCopyStanding.needed;
  }
  if (movedAt == null || now.millisecondsSinceEpoch - movedAt < kmBitwardenWindow.inMilliseconds) {
    return KmCopyStanding.waiting;
  }
  return KmCopyStanding.offered;
}
