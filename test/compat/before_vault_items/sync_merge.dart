// A frozen copy of lib/features/sync/sync_merge.dart as it was at 6c72b99,
// before keys, notes and passkeys: what a phone that stays on that version
// runs. Tests merge with it to check that such a phone, syncing between
// current ones, loses none of the new items. Never update it.
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
/// The generic functions take lists of [OtpAccount] or of [BackupService].
library;

import 'dart:convert';
import 'dart:math';

import 'package:collection/collection.dart';

import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/otp_account.dart';

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

/// A vault's accounts and backup services, or one scope's.
class Lists {
  const Lists({this.accounts = const [], this.backupServices = const []});

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;

  Map<String, Object?> toJson() => {
    'accounts': [for (final account in accounts) account.toJson()],
    'backupServices': [for (final service in backupServices) service.toJson()],
  };

  /// Whether [other] holds the same data in the same order.
  @override
  bool operator ==(Object other) => other is Lists && other.runtimeType == runtimeType && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(accounts.length, backupServices.length);

  @override
  String toString() => '$runtimeType(${toJson()})';
}

/// One scope's entries and deletions: what a sync file holds once decrypted.
/// It reads and writes the JSON the TypeScript app does, and keeps the keys
/// it doesn't know, so files written by either app open in the other.
class SyncDoc extends Lists {
  const SyncDoc({super.accounts, super.backupServices, this.deleted = const [], this.extra = const {}});

  /// Reads a decrypted sync file. A missing list, or one that isn't a list,
  /// reads as empty, as in `decryptSyncFile`.
  factory SyncDoc.fromJson(Map<String, Object?> json) => SyncDoc(
    accounts: [for (final account in _objects(json['accounts'])) OtpAccount.fromJson(account)],
    backupServices: [for (final service in _objects(json['backupServices'])) BackupService.fromJson(service)],
    deleted: [for (final tombstone in _objects(json['deleted'])) Tombstone.fromJson(tombstone)],
    extra: extraKeys(json, const {'accounts', 'backupServices', 'deleted'}),
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

/// When sync last saw the account change.
extension AccountChange on OtpAccount {
  /// [OtpAccount.updatedAt], or [OtpAccount.addedAt] if it never changed.
  int get changedAt => updatedAt ?? addedAt;
}

/// When sync last saw the backup service change.
extension ServiceChange on BackupService {
  /// [BackupService.updatedAt], or [BackupService.addedAt] if it never changed.
  int get changedAt => updatedAt ?? addedAt;
}

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
List<T> stampChanged<T extends Object>(List<T> next, List<T> previous, {int? now}) {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final before = {for (final entry in previous) _id(entry): _withoutStamp(entry)};
  return [for (final entry in next) before[_id(entry)] == _withoutStamp(entry) ? entry : _stamped(entry, at)];
}

/// The entries of one scope: the vault's own (null) or one shared space's.
List<T> inScope<T extends Object>(List<T> list, String? scope) => [
  for (final entry in list)
    if (_spaceId(entry) == scope) entry,
];

/// The accounts and backup services of one scope.
Lists scopeLists(Lists lists, String? scope) =>
    Lists(accounts: inScope(lists.accounts, scope), backupServices: inScope(lists.backupServices, scope));

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

  final here = {for (final account in local.accounts) account.id, for (final service in local.backupServices) service.id};
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

  // A deletion the server already had keeps the keys this version doesn't know.
  final had = {for (final tomb in remoteTombs) tomb.id: tomb};
  final deleted = [
    for (final MapEntry(key: id, value: deletedAt) in tombs.entries)
      if (had[id] case final tomb? when tomb.at == deletedAt) tomb else Tombstone(id: id, at: deletedAt),
  ];
  mergeSort(deleted, compare: (a, b) => a.id.compareTo(b.id));

  return (
    doc: SyncDoc(accounts: accounts, backupServices: backupServices, deleted: deleted, extra: remote?.extra ?? const {}),
    known: [for (final account in accounts) account.id, for (final service in backupServices) service.id],
  );
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
      'deleted': [for (final tomb in deleted) tomb.toJson()],
    });
  }

  return norm(a) == norm(b);
}

/// This device's lists with one scope replaced by its synced document.
Lists applyScope(Lists all, String? scope, Lists doc) => Lists(
  accounts: _placeScope(all.accounts, scope, doc.accounts),
  backupServices: _placeScope(all.backupServices, scope, doc.backupServices),
);

/// True when two sets of lists hold the same data in the same order.
bool sameLists(Lists a, Lists b) => canonical(a.toJson()) == canonical(b.toJson());

/// HOTP codes must never repeat, so the higher counter survives whichever copy wins.
OtpAccount _keepCounter(OtpAccount winner, OtpAccount other) {
  if (winner.type != OtpType.hotp) return winner;
  final counter = max(winner.counter ?? 0, other.counter ?? 0);
  return counter == (winner.counter ?? 0) ? winner : winner.copyWith(counter: counter);
}

List<T> _mergeEntries<T extends Object>(List<T> local, List<T> remote, Map<String, int> tombs, {T Function(T winner, T other)? combine}) {
  final pick = combine ?? (T winner, T other) => winner;
  final merged = <String, T>{};
  for (final entry in remote) {
    merged[_id(entry)] = entry;
  }
  for (final entry in local) {
    final theirs = merged[_id(entry)];
    if (theirs == null) {
      merged[_id(entry)] = entry;
    } else if (_changedAt(entry) >= _changedAt(theirs)) {
      merged[_id(entry)] = pick(entry, theirs);
    } else {
      merged[_id(entry)] = pick(theirs, entry);
    }
  }
  final out = <T>[];
  for (final entry in merged.values) {
    final deletedAt = tombs[_id(entry)];
    if (deletedAt != null && deletedAt >= _changedAt(entry)) continue;
    // Changed after it was deleted somewhere: it stays, and so must the other copies
    if (deletedAt != null) tombs.remove(_id(entry));
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

List<T> _placeScope<T extends Object>(List<T> all, String? scope, List<T> incoming) {
  final fresh = {for (final entry in incoming) _id(entry): _inSpace(entry, scope)};
  final out = <T>[];
  for (final entry in all) {
    final synced = fresh[_id(entry)];
    if (_spaceId(entry) == scope) {
      // In this scope: the synced copy replaces it, or it was deleted
      if (synced != null) {
        out.add(synced);
        fresh.remove(_id(entry));
      }
    } else if (synced != null && _changedAt(synced) > _changedAt(entry)) {
      // Moved into this scope on another device after it changed here
      out.add(synced);
      fresh.remove(_id(entry));
    } else {
      out.add(entry);
      fresh.remove(_id(entry));
    }
  }
  return [...out, ...fresh.values];
}

/// Sorts [list] in place by id, keeping the order of equal ids, and returns it.
List<T> _sortById<T extends Object>(List<T> list) {
  mergeSort(list, compare: (a, b) => _id(a).compareTo(_id(b)));
  return list;
}

String _withoutStamp(Object entry) => canonical(_json(entry)..remove('updatedAt'));

String _id(Object entry) => switch (entry) {
  OtpAccount() => entry.id,
  BackupService() => entry.id,
  _ => _notAnEntry(entry),
};

int _changedAt(Object entry) => switch (entry) {
  OtpAccount() => entry.changedAt,
  BackupService() => entry.changedAt,
  _ => _notAnEntry(entry),
};

String? _spaceId(Object entry) => switch (entry) {
  OtpAccount() => entry.spaceId,
  BackupService() => entry.spaceId,
  _ => _notAnEntry(entry),
};

Map<String, Object?> _json(Object entry) => switch (entry) {
  OtpAccount() => entry.toJson(),
  BackupService() => entry.toJson(),
  _ => _notAnEntry(entry),
};

T _stamped<T extends Object>(T entry, int at) => switch (entry) {
  OtpAccount() => entry.copyWith(updatedAt: at) as T,
  BackupService() => entry.copyWith(updatedAt: at) as T,
  _ => _notAnEntry(entry),
};

/// A copy of [entry] in [scope]. As in the TypeScript, an empty scope counts as none.
T _inSpace<T extends Object>(T entry, String? scope) {
  final Object space = scope != null && scope.isNotEmpty ? scope : unset;
  return switch (entry) {
    OtpAccount() => entry.copyWith(spaceId: space) as T,
    BackupService() => entry.copyWith(spaceId: space) as T,
    _ => _notAnEntry(entry),
  };
}

Never _notAnEntry(Object entry) => throw ArgumentError.value(entry, 'entry', 'Not an account or a backup service');
