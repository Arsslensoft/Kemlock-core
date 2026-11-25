// Which accounts have backup codes saved: an account counts as covered when
// a backup-code service has the same name, by the rules in ../accounts/service_names.dart.

import 'package:collection/collection.dart';

import '../../models/backup_service.dart';
import '../../models/otp_account.dart';
import '../accounts/service_names.dart';

final _nonSpace = RegExp(r'\S');

/// The service an account belongs to: its issuer, else the label's part before ":".
String serviceOf(OtpAccount account) {
  if (account.issuer.contains(_nonSpace)) return account.issuer;
  final colon = account.label.indexOf(':');
  return colon > 0 ? account.label.substring(0, colon) : account.label;
}

/// The saved backup codes for an account's service, or null.
BackupService? backupFor(OtpAccount account, List<BackupService> services) {
  final name = serviceOf(account);
  if (!name.contains(_nonSpace)) return null;
  return services.firstWhereOrNull((s) => sameService(name, s.serviceName));
}

class Coverage {
  const Coverage({required this.total, required this.covered, required this.missing});

  /// Accounts the check looks at: all but those marked as offering no codes.
  final int total;
  final int covered;

  /// Accounts with no backup codes saved, A–Z.
  final List<OtpAccount> missing;
}

/// How many of [accounts] have their backup codes among [services], and which don't.
Coverage coverage(List<OtpAccount> accounts, List<BackupService> services) {
  final checked = [
    for (final account in accounts)
      if (account.noBackupCodes != true) account,
  ];
  final missing = [
    for (final account in checked)
      if (backupFor(account, services) == null) account,
  ];
  // A–Z ignoring case and accents, like localeCompare's base sensitivity; a stable
  // sort, like JavaScript's, keeps names that compare equal in their order.
  mergeSort(missing, compare: (a, b) => fold(serviceOf(a)).compareTo(fold(serviceOf(b))));
  return Coverage(total: checked.length, covered: checked.length - missing.length, missing: missing);
}
