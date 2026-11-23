// A frozen copy of _payload and the readers it calls in
// lib/vault/vault_export.dart as they were at 7ee88deb, before cards and
// identities (the add-cards-identities-and-websites plan): how a phone that
// stays on the previous version reads an export payload. Tests read a newer
// export with it to check that such a phone still opens the file for its codes
// and logins and passes the two new lists over. Never update it.

import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:kemlock_core/vault/vault_export.dart' show VaultExportPayload;

List<T> _read<T>(Object? list, T Function(Map<String, Object?> json) from) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) from(json),
];

VaultExportPayload payloadBeforeCards(Map<String, Object?> json) => VaultExportPayload(
  accounts: _accounts(json['accounts']),
  backupServices: _services(json['backupServices']),
  keys: _read(json['keys'], VaultKey.fromJson),
  notes: _read(json['notes'], SecureNote.fromJson),
  passkeys: _read(json['passkeys'], Passkey.fromJson),
  keyAccounts: _read(json['keyAccounts'], KeyAccount.fromJson),
  contacts: _read(json['contacts'], Contact.fromJson),
  logins: _read(json['logins'], Login.fromJson),
);

List<OtpAccount> _accounts(Object? list) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) OtpAccount.fromJson(json),
];

List<BackupService> _services(Object? list) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) BackupService.fromJson(json),
];
