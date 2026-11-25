/// Which breaches concern the entries of a vault (openspec: breach-alerts). Everything
/// here runs on the phone, from the list it is given.
library;

import '../../models/backup_service.dart';
import '../../models/otp_account.dart';
import '../accounts/service_names.dart';
import 'breach_list.dart';

/// The breaches of one entry's service.
class EntryBreaches {
  const EntryBreaches({this.fresh = const [], this.earlier = const []});

  static const none = EntryBreaches();

  /// Listed after the entry was added and not marked dealt with: these count against
  /// the vault's health. The latest listed comes first.
  final List<Breach> fresh;

  /// Listed before the entry was added, or dealt with. The latest comes first.
  final List<Breach> earlier;

  bool get isEmpty => fresh.isEmpty && earlier.isEmpty;
}

/// A new breach and the entries of the vault it concerns.
class BreachAlert {
  const BreachAlert(this.breach, {this.accounts = const [], this.services = const []});

  final Breach breach;
  final List<OtpAccount> accounts;
  final List<BackupService> services;
}

/// What a scan found.
class BreachFindings {
  const BreachFindings._(this._byEntry, this.alerts, this.serviceCount);

  static const none = BreachFindings._({}, [], 0);

  final Map<String, EntryBreaches> _byEntry;

  /// The new breaches, the latest listed first, each with its entries.
  final List<BreachAlert> alerts;

  /// How many services have a new breach: two breaches of one service count once, as do
  /// two accounts and a backup-code list of it.
  final int serviceCount;

  /// The breaches of the account or backup-code list with this [id].
  EntryBreaches of(String id) => _byEntry[id] ?? EntryBreaches.none;
}

/// Whether [breach] is new for an entry added at [addedAt] that has marked [dismissed]
/// dealt with: it was listed after the entry reached the vault, and isn't among them.
/// An entry without a date, which the app never writes, counts every breach as new.
bool isNewBreach(Breach breach, {required int addedAt, List<String>? dismissed}) =>
    addedAt < breach.listedBy && !(dismissed?.contains(breach.name) ?? false);

/// Finds the breaches of every account and backup-code list in [list].
BreachFindings scanBreaches(List<OtpAccount> accounts, List<BackupService> services, BreachList list) {
  final byEntry = <String, EntryBreaches>{};
  final alerts = <String, ({Breach breach, List<OtpAccount> accounts, List<BackupService> services})>{};

  EntryBreaches sort(String id, String name, int addedAt, List<String>? dismissed) {
    final found = list.of(name);
    if (found.isEmpty) return EntryBreaches.none;
    final fresh = <Breach>[];
    final earlier = <Breach>[];
    // The list gives the earliest first; the sheets show the latest first
    for (final breach in found.reversed) {
      (isNewBreach(breach, addedAt: addedAt, dismissed: dismissed) ? fresh : earlier).add(breach);
    }
    return byEntry[id] = EntryBreaches(fresh: fresh, earlier: earlier);
  }

  for (final account in accounts) {
    for (final breach in sort(account.id, account.issuer, account.addedAt, account.breachesDismissed).fresh) {
      alerts.putIfAbsent(breach.name, () => (breach: breach, accounts: [], services: [])).accounts.add(account);
    }
  }
  for (final service in services) {
    for (final breach in sort(service.id, service.serviceName, service.addedAt, service.breachesDismissed).fresh) {
      alerts.putIfAbsent(breach.name, () => (breach: breach, accounts: [], services: [])).services.add(service);
    }
  }

  final sorted = [for (final alert in alerts.values) BreachAlert(alert.breach, accounts: alert.accounts, services: alert.services)]
    ..sort((a, b) => b.breach.addedDate.compareTo(a.breach.addedDate));
  // adobe.com and adobe.co.uk are one service
  final breached = {for (final alert in sorted) keysFor(alert.breach.domain).last};
  return BreachFindings._(byEntry, sorted, breached.length);
}
