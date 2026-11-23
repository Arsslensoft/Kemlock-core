// A frozen copy of lib/features/sync/sync_merge.dart as it was at ec9350d1,
// before the accounts kept on a security key (openspec:
// add-security-key-codes): what a phone that stays on that version runs.
// Tests merge with it to check that such a phone, syncing between current
// ones, keeps the `keyAccounts` list it does not know. Never update it.
// ignore_for_file: unused_element

/// How sync combines this device's entries with the copy on the server,
/// ported from `syncMerge.ts`.
///
/// A vault syncs in scopes: its own entries (scope null) go to its sync file,
/// and each shared space's entries (spaceId = the space) go to that space's
/// file. Within a scope, entries merge by id and the most recently changed copy
/// wins. A deletion is written down as a tombstone so devices that still have
/// the entry drop it instead of bringing it back; an entry changed after it was
/// deleted (Undo, or an edit elsewhere) outlives its tombstone.
///
/// The generic functions take lists of any [VaultEntry].
library;

import 'dart:convert';
import 'dart:math';

import 'package:collection/collection.dart';

import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/models/vault_key.dart';

/// How long a deletion is remembered for devices that haven't synced since: 180 days, in ms.
const tombstoneTtlMs = 180 * 24 * 60 * 60 * 1000;

/// A deletion, kept in the sync file so other devices drop the entry too.
class Tombstone {
  const Tombstone({required this.id, required this.at, this.extra = const {}});

  factory Tombstone.fromJson(Map<String, Object?> json) =>
      Tombstone(id: asString(json['id']), at: asInt(json['at']) ?? 0, extra: extraKeys(json, const {'id', 'at'}));

  /// The id of the account or backup service that was deleted.
  final String id;

  /// Epoch ms of the deletion.
  final int at;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'id': id, 'at': at, ...extra};

  @override
  bool operator ==(Object other) => other is Tombstone && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(id, at);

  @override
  String toString() => 'Tombstone(${toJson()})';
}

/// A vault's entries, or one scope's: accounts, backup services, keys,
/// notes and passkeys. Passkeys are only ever in the vault's own scope.
class Lists {
  const Lists({
    this.accounts = const [],
    this.backupServices = const [],
    this.keys = const [],
    this.notes = const [],
    this.passkeys = const [],
  });

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;
  final List<VaultKey> keys;
  final List<SecureNote> notes;
  final List<Passkey> passkeys;

  /// The ids of every entry, of every kind.
  Iterable<String> get ids => [
    for (final account in accounts) account.id,
    for (final service in backupServices) service.id,
    for (final key in keys) key.id,
    for (final note in notes) note.id,
    for (final passkey in passkeys) passkey.id,
  ];

  /// The two lists every version writes, then the later ones when they hold
  /// anything, so a file of codes alone is the file it always was.
  Map<String, Object?> toJson() => {
    'accounts': [for (final account in accounts) account.toJson()],
    'backupServices': [for (final service in backupServices) service.toJson()],
    if (keys.isNotEmpty) 'keys': [for (final key in keys) key.toJson()],
    if (notes.isNotEmpty) 'notes': [for (final note in notes) note.toJson()],
    if (passkeys.isNotEmpty) 'passkeys': [for (final passkey in passkeys) passkey.toJson()],
  };

  /// Whether [other] holds the same data in the same order.
  @override
  bool operator ==(Object other) => other is Lists && other.runtimeType == runtimeType && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(accounts.length, backupServices.length, keys.length, notes.length, passkeys.length);

  @override
  String toString() => '$runtimeType(${toJson()})';
}

/// One scope's entries and deletions: what a sync file holds once decrypted.
/// It reads and writes the JSON the TypeScript app does, and keeps the keys
/// it doesn't know, so files written by either app open in the other.
class SyncDoc extends Lists {
  const SyncDoc({
    super.accounts,
    super.backupServices,
    super.keys,
    super.notes,
    super.passkeys,
    this.deleted = const [],
    this.extra = const {},
  });

  /// Reads a decrypted sync file. A missing list, or one that isn't a list,
  /// reads as empty, as in `decryptSyncFile`.
  factory SyncDoc.fromJson(Map<String, Object?> json) => SyncDoc(
    accounts: [for (final account in _objects(json['accounts'])) OtpAccount.fromJson(account)],
    backupServices: [for (final service in _objects(json['backupServices'])) BackupService.fromJson(service)],
    keys: [for (final key in _objects(json['keys'])) VaultKey.fromJson(key)],
    notes: [for (final note in _objects(json['notes'])) SecureNote.fromJson(note)],
    passkeys: [for (final passkey in _objects(json['passkeys'])) Passkey.fromJson(passkey)],
    deleted: [for (final tombstone in _objects(json['deleted'])) Tombstone.fromJson(tombstone)],
    extra: extraKeys(json, const {'accounts', 'backupServices', 'keys', 'notes', 'passkeys', 'deleted'}),
  );

  final List<Tombstone> deleted;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  @override
  Map<String, Object?> toJson() => {
    ...super.toJson(),
    'deleted': [for (final tombstone in deleted) tombstone.toJson()],
    ...extra,
  };
}

Iterable<Map<String, Object?>> _objects(Object? value) => value is List ? value.whereType<Map<String, Object?>>() : const [];

/// [json] as JSON text with every object's keys sorted, so two copies of the
/// same data compare equal. Takes JSON values (maps, lists, strings, numbers,
/// booleans and null); pass models through their `toJson`.
String canonical(Object? json) => jsonEncode(_sortKeys(json));

Object? _sortKeys(Object? value) => switch (value) {
  Map<String, Object?>() => {for (final key in value.keys.toList()..sort()) key: _sortKeys(value[key])},
  List<Object?>() => [for (final item in value) _sortKeys(item)],
  _ => value,
};

/// Marks every entry in [next] that is new or differs from its copy in
/// [previous] as changed [now] (epoch ms, the current time by default).
/// Called on every change the user makes, so sync knows what's newer. An
/// entry that didn't change is returned as it was.
List<T> stampChanged<T extends VaultEntry<T>>(List<T> next, List<T> previous, {int? now}) {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final before = {for (final entry in previous) entry.id: _withoutStamp(entry)};
  return [for (final entry in next) before[entry.id] == _withoutStamp(entry) ? entry : entry.stamped(at)];
}

/// The entries of one scope: the vault's own (null) or one shared space's.
List<T> inScope<T extends VaultEntry<T>>(List<T> list, String? scope) => [
  for (final entry in list)
    if (entry.spaceId == scope) entry,
];

/// The entries of one scope. Passkeys belong to the vault's own scope only.
Lists scopeLists(Lists lists, String? scope) => Lists(
  accounts: inScope(lists.accounts, scope),
  backupServices: inScope(lists.backupServices, scope),
  keys: inScope(lists.keys, scope),
  notes: inScope(lists.notes, scope),
  passkeys: scope == null ? lists.passkeys : const [],
);

/// Merges this device's entries in one scope with the server's copy.
///
/// [local] is this device's entries in the scope. [known] is the ids the
/// scope held after this device's last sync; one that's gone from [local] was
/// deleted here. [remote] is the server's copy, or null before the first
/// upload. [now] is epoch ms, the current time by default.
///
/// Returns the document to write back and to take locally, and the ids it
/// holds. The document keeps the keys of [remote] this version doesn't know.
({SyncDoc doc, List<String> known}) mergeScope(Lists local, List<String> known, SyncDoc? remote, {int? now}) {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final remoteTombs = remote?.deleted ?? const <Tombstone>[];
  final tombs = <String, int>{};
  for (final tomb in remoteTombs) {
    tombs[tomb.id] = max(tomb.at, tombs[tomb.id] ?? 0);
  }

  final here = {...local.ids};
  for (final id in known) {
    if (!here.contains(id)) tombs[id] = max(at, tombs[id] ?? 0);
  }

  tombs.removeWhere((_, deletedAt) => deletedAt < at - tombstoneTtlMs);

  final accounts = _dropDuplicateAccounts(
    _mergeEntries(local.accounts, remote?.accounts ?? const <OtpAccount>[], tombs, combine: _keepCounter),
    tombs,
    at,
  );
  final backupServices = _mergeEntries(local.backupServices, remote?.backupServices ?? const <BackupService>[], tombs);
  final keys = _mergeEntries(local.keys, remote?.keys ?? const <VaultKey>[], tombs);
  final notes = _mergeEntries(local.notes, remote?.notes ?? const <SecureNote>[], tombs);
  final passkeys = _mergeEntries(local.passkeys, remote?.passkeys ?? const <Passkey>[], tombs);

  // A deletion the server already had keeps the keys this version doesn't know.
  final had = {for (final tomb in remoteTombs) tomb.id: tomb};
  final deleted = [
    for (final MapEntry(key: id, value: deletedAt) in tombs.entries)
      if (had[id] case final tomb? when tomb.at == deletedAt) tomb else Tombstone(id: id, at: deletedAt),
  ];
  mergeSort(deleted, compare: (a, b) => a.id.compareTo(b.id));

  final doc = SyncDoc(
    accounts: accounts,
    backupServices: backupServices,
    keys: keys,
    notes: notes,
    passkeys: passkeys,
    deleted: deleted,
    extra: remote?.extra ?? const {},
  );
  return (doc: doc, known: doc.ids.toList());
}

/// True when two documents hold the same entries and deletions, whatever
/// their order.
bool sameDoc(SyncDoc a, SyncDoc b) {
  String norm(SyncDoc doc) {
    final deleted = [...doc.deleted];
    mergeSort(deleted, compare: (a, b) => a.id.compareTo(b.id));
    return canonical({
      'accounts': [
        for (final account in _sortById([...doc.accounts])) account.toJson(),
      ],
      'backupServices': [
        for (final service in _sortById([...doc.backupServices])) service.toJson(),
      ],
      'keys': [
        for (final key in _sortById([...doc.keys])) key.toJson(),
      ],
      'notes': [
        for (final note in _sortById([...doc.notes])) note.toJson(),
      ],
      'passkeys': [
        for (final passkey in _sortById([...doc.passkeys])) passkey.toJson(),
      ],
      'deleted': [for (final tomb in deleted) tomb.toJson()],
    });
  }

  return norm(a) == norm(b);
}

/// This device's lists with one scope replaced by its synced document. A
/// space's document never brings passkeys: they belong to the vault alone.
Lists applyScope(Lists all, String? scope, Lists doc) => Lists(
  accounts: _placeScope(all.accounts, scope, doc.accounts),
  backupServices: _placeScope(all.backupServices, scope, doc.backupServices),
  keys: _placeScope(all.keys, scope, doc.keys),
  notes: _placeScope(all.notes, scope, doc.notes),
  passkeys: scope == null ? _placeScope(all.passkeys, scope, doc.passkeys) : all.passkeys,
);

/// True when two sets of lists hold the same data in the same order.
bool sameLists(Lists a, Lists b) => canonical(a.toJson()) == canonical(b.toJson());

/// HOTP codes must never repeat, so the higher counter survives whichever copy wins.
OtpAccount _keepCounter(OtpAccount winner, OtpAccount other) {
  if (winner.type != OtpType.hotp) return winner;
  final counter = max(winner.counter ?? 0, other.counter ?? 0);
  return counter == (winner.counter ?? 0) ? winner : winner.copyWith(counter: counter);
}

List<T> _mergeEntries<T extends VaultEntry<T>>(
  List<T> local,
  List<T> remote,
  Map<String, int> tombs, {
  T Function(T winner, T other)? combine,
}) {
  final pick = combine ?? (T winner, T other) => winner;
  final merged = <String, T>{};
  for (final entry in remote) {
    merged[entry.id] = entry;
  }
  for (final entry in local) {
    final theirs = merged[entry.id];
    if (theirs == null) {
      merged[entry.id] = entry;
    } else if (entry.changedAt >= theirs.changedAt) {
      merged[entry.id] = pick(entry, theirs);
    } else {
      merged[entry.id] = pick(theirs, entry);
    }
  }
  final out = <T>[];
  for (final entry in merged.values) {
    final deletedAt = tombs[entry.id];
    if (deletedAt != null && deletedAt >= entry.changedAt) continue;
    // Changed after it was deleted somewhere: it stays, and so must the other copies
    if (deletedAt != null) tombs.remove(entry.id);
    out.add(entry);
  }
  return _sortById(out);
}

/// The same account added on two devices before they first synced: keep the newer copy.
List<OtpAccount> _dropDuplicateAccounts(List<OtpAccount> accounts, Map<String, int> tombs, int now) {
  final seen = <String, OtpAccount>{};
  final dropped = <String>{};
  for (final account in accounts) {
    final key = '${account.issuer}::${account.secret}';
    final other = seen[key];
    if (other == null) {
      seen[key] = account;
      continue;
    }
    final (kept, gone) = account.changedAt > other.changedAt ? (account, other) : (other, account);
    seen[key] = kept;
    dropped.add(gone.id);
    tombs[gone.id] = now;
  }
  return [
    for (final account in accounts)
      if (!dropped.contains(account.id)) account,
  ];
}

List<T> _placeScope<T extends VaultEntry<T>>(List<T> all, String? scope, List<T> incoming) {
  final fresh = {for (final entry in incoming) entry.id: entry.inSpace(scope)};
  final out = <T>[];
  for (final entry in all) {
    final synced = fresh[entry.id];
    if (entry.spaceId == scope) {
      // In this scope: the synced copy replaces it, or it was deleted
      if (synced != null) {
        out.add(synced);
        fresh.remove(entry.id);
      }
    } else if (synced != null && synced.changedAt > entry.changedAt) {
      // Moved into this scope on another device after it changed here
      out.add(synced);
      fresh.remove(entry.id);
    } else {
      out.add(entry);
      fresh.remove(entry.id);
    }
  }
  return [...out, ...fresh.values];
}

/// Sorts [list] in place by id, keeping the order of equal ids, and returns it.
List<T> _sortById<T extends VaultEntry<T>>(List<T> list) {
  mergeSort(list, compare: (a, b) => a.id.compareTo(b.id));
  return list;
}

String _withoutStamp<T extends VaultEntry<T>>(T entry) => canonical(entry.toJson()..remove('updatedAt'));
