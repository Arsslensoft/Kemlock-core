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
import 'dart:typed_data';

import 'package:collection/collection.dart';

import '../../crypto/account/encoding.dart' show MalformedException;
import '../../crypto/bytes.dart';
import '../../crypto/keys/keys.dart' as crypto;
import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/json.dart';
import '../../models/key_account.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_entry.dart';
import '../../models/vault_file.dart';
import '../../models/vault_key.dart';
import '../keys/key_bridge.dart' show grownPgpKey, keyIdentity;
import '../spaces/space_head_store.dart' show SpaceAnchors;

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
/// notes and passkeys, the accounts kept on a security key, contacts, and
/// logins, cards, identities and files. Passkeys, on-key accounts and contacts are only ever in the
/// vault's own scope; logins, cards, identities and files follow accounts into spaces.
class Lists {
  const Lists({
    this.accounts = const [],
    this.backupServices = const [],
    this.keys = const [],
    this.notes = const [],
    this.passkeys = const [],
    this.keyAccounts = const [],
    this.contacts = const [],
    this.logins = const [],
    this.cards = const [],
    this.identities = const [],
    this.files = const [],
  });

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;
  final List<VaultKey> keys;
  final List<SecureNote> notes;
  final List<Passkey> passkeys;

  /// What the vault remembers of the accounts on a security key: names,
  /// never secrets (openspec: add-security-key-codes).
  final List<KeyAccount> keyAccounts;

  /// Other people's public keys, only ever in the vault's own scope.
  final List<Contact> contacts;

  /// The vault's logins (openspec: add-passwords).
  final List<Login> logins;

  /// The vault's cards.
  final List<PaymentCard> cards;

  /// The vault's identities.
  final List<Identity> identities;

  /// The vault's File items, each holding one attached file (the `files` list, left out of a file while empty).
  final List<VaultFile> files;

  /// The ids of every entry, of every kind.
  Iterable<String> get ids => [
    for (final account in accounts) account.id,
    for (final service in backupServices) service.id,
    for (final key in keys) key.id,
    for (final note in notes) note.id,
    for (final passkey in passkeys) passkey.id,
    for (final account in keyAccounts) account.id,
    for (final contact in contacts) contact.id,
    for (final login in logins) login.id,
    for (final card in cards) card.id,
    for (final identity in identities) identity.id,
    for (final file in files) file.id,
  ];

  /// The two lists every version writes, then the later ones when they hold
  /// anything, so a file of codes alone is the file it always was.
  Map<String, Object?> toJson() => {
    'accounts': [for (final account in accounts) account.toJson()],
    'backupServices': [for (final service in backupServices) service.toJson()],
    if (keys.isNotEmpty) 'keys': [for (final key in keys) key.toJson()],
    if (notes.isNotEmpty) 'notes': [for (final note in notes) note.toJson()],
    if (passkeys.isNotEmpty) 'passkeys': [for (final passkey in passkeys) passkey.toJson()],
    if (keyAccounts.isNotEmpty) 'keyAccounts': [for (final account in keyAccounts) account.toJson()],
    if (contacts.isNotEmpty) 'contacts': [for (final contact in contacts) contact.toJson()],
    if (logins.isNotEmpty) 'logins': [for (final login in logins) login.toJson()],
    if (cards.isNotEmpty) 'cards': [for (final card in cards) card.toJson()],
    if (identities.isNotEmpty) 'identities': [for (final identity in identities) identity.toJson()],
    if (files.isNotEmpty) 'files': [for (final file in files) file.toJson()],
  };

  /// Whether [other] holds the same data in the same order.
  @override
  bool operator ==(Object other) => other is Lists && other.runtimeType == runtimeType && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(
    accounts.length,
    backupServices.length,
    keys.length,
    notes.length,
    passkeys.length,
    keyAccounts.length,
    contacts.length,
    logins.length,
    cards.length,
    identities.length,
    files.length,
  );

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
    super.keyAccounts,
    super.contacts,
    super.logins,
    super.cards,
    super.identities,
    super.files,
    this.deleted = const [],
    this.seq,
    this.extra = const {},
  });

  /// Reads a decrypted sync file. A missing list, or one that isn't a list,
  /// reads as empty, as in `decryptSyncFile`. A `seq` that isn't a count
  /// ([syncSeq]) reads as none, and is not written back.
  factory SyncDoc.fromJson(Map<String, Object?> json) => SyncDoc(
    accounts: [for (final account in _objects(json['accounts'])) OtpAccount.fromJson(account)],
    backupServices: [for (final service in _objects(json['backupServices'])) BackupService.fromJson(service)],
    keys: [for (final key in _objects(json['keys'])) VaultKey.fromJson(key)],
    notes: [for (final note in _objects(json['notes'])) SecureNote.fromJson(note)],
    passkeys: [for (final passkey in _objects(json['passkeys'])) Passkey.fromJson(passkey)],
    keyAccounts: [for (final account in _objects(json['keyAccounts'])) KeyAccount.fromJson(account)],
    contacts: [for (final contact in _objects(json['contacts'])) Contact.fromJson(contact)],
    logins: [for (final login in _objects(json['logins'])) Login.fromJson(login)],
    cards: [for (final card in _objects(json['cards'])) PaymentCard.fromJson(card)],
    identities: [for (final identity in _objects(json['identities'])) Identity.fromJson(identity)],
    files: [for (final file in _objects(json['files'])) VaultFile.fromJson(file)],
    deleted: [for (final tombstone in _objects(json['deleted'])) Tombstone.fromJson(tombstone)],
    seq: syncSeq(json['seq']),
    extra: extraKeys(json, const {
      'accounts',
      'backupServices',
      'keys',
      'notes',
      'passkeys',
      'keyAccounts',
      'contacts',
      'logins',
      'cards',
      'identities',
      'files',
      'deleted',
      'seq',
    }),
  );

  final List<Tombstone> deleted;

  /// How many times the file was written, counted by the versions that
  /// count: each write of one counts one more than the file it replaced,
  /// or than the last count this device saw if that is more. Null in a
  /// file no such version wrote, which is written without it as before:
  /// the TypeScript app's files, and older versions', which keep the count
  /// of the file they replaced as they keep any key they don't know.
  ///
  /// A file that counts less than one a device saw in the scope is older
  /// than that one: a server handing it back would bring back entries
  /// deleted since, without their deletions (see `syncScope`).
  final int? seq;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  @override
  Map<String, Object?> toJson() => {
    ...super.toJson(),
    'deleted': [for (final tombstone in deleted) tombstone.toJson()],
    'seq': ?seq,
    ...extra,
  };
}

/// The highest count a sync file's `seq` may have: JavaScript's largest
/// safe integer, more than any number of writes, so that one more never
/// overflows. A file that counts more, as a member of a space could write,
/// reads as one that doesn't count.
const maxSyncSeq = 9007199254740991;

/// [value] as a sync file's count: a whole number from 0 to [maxSyncSeq];
/// null for anything else.
int? syncSeq(Object? value) => value is int && value >= 0 && value <= maxSyncSeq ? value : null;

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

/// The entries of one scope. Passkeys, on-key accounts and contacts belong
/// to the vault's own scope only; logins go with their space, as accounts do.
Lists scopeLists(Lists lists, String? scope) => Lists(
  accounts: inScope(lists.accounts, scope),
  backupServices: inScope(lists.backupServices, scope),
  keys: inScope(lists.keys, scope),
  notes: inScope(lists.notes, scope),
  passkeys: scope == null ? lists.passkeys : const [],
  keyAccounts: scope == null ? lists.keyAccounts : const [],
  contacts: scope == null ? lists.contacts : const [],
  logins: inScope(lists.logins, scope),
  cards: inScope(lists.cards, scope),
  identities: inScope(lists.identities, scope),
  files: inScope(lists.files, scope),
);

/// [local] with each PGP key that [remote] holds another copy of combined
/// with it first (openspec: add-pgp-key-editing, design decision 6), so
/// that [mergeScope] keeps what both phones added: call it on what goes
/// into [mergeScope]. The two copies of one key, changed on two phones
/// before they synced, would otherwise come down to the later one whole,
/// and the change made on the other phone, perhaps a new subkey's only
/// secret, would be lost.
///
/// For each key both sides hold under one id with other halves, of which
/// the one [mergeScope] would keep is the winner: when both are PGP keys
/// of one primary key, the winner gets the halves of [mergePgpKeys] of the
/// two, the winner preferred, and an `updatedAt` one millisecond after its
/// own, so it wins the merge. Two phones that combine the same pair on
/// their own then make the same entry, stamp and all, and a phone with an
/// older Kemlock, which keeps the later copy whole, takes it. A winner
/// whose halves do not read gives way to the other copy the same way.
/// Keys of other kinds, and of two primary keys, merge as before. Every
/// other list of [local] comes back as it was: a contact's two copies are
/// joined in [mergeScope] by [crypto.unionPublicKeys], never here, so no
/// key is combined two ways in one run.
Future<Lists> combineKeyCopies(Lists local, SyncDoc? remote) async {
  final theirs = {for (final key in remote?.keys ?? const <VaultKey>[]) key.id: key};
  final keys = <VaultKey>[];
  var changed = false;
  for (final key in local.keys) {
    final other = theirs[key.id];
    if (other == null || other.privateKey == key.privateKey || key.kind != KeyKind.pgp || other.kind != KeyKind.pgp) {
      keys.add(key);
      continue;
    }
    final (winner, loser) = key.changedAt >= other.changedAt ? (key, other) : (other, key);
    final combined = await _combineKey(winner, loser);
    // The winner as it is: this side's, or the other's, which the merge takes anyway
    final kept = identical(combined, winner) ? key : combined;
    changed |= !identical(kept, key);
    keys.add(kept);
  }
  if (!changed) return local;
  return Lists(
    accounts: local.accounts,
    backupServices: local.backupServices,
    keys: keys,
    notes: local.notes,
    passkeys: local.passkeys,
    keyAccounts: local.keyAccounts,
    contacts: local.contacts,
    logins: local.logins,
    cards: local.cards,
    identities: local.identities,
    files: local.files,
  );
}

/// The copy of a PGP key sync keeps, given the [winner] [mergeScope] would
/// keep and the [other] copy; [winner] itself when combining adds nothing.
Future<VaultKey> _combineKey(VaultKey winner, VaultKey other) async {
  Uint8List? read(VaultKey key) {
    try {
      final bytes = unb64(key.privateKey);
      crypto.readPgpKeyInfo(bytes);
      return bytes;
    } on crypto.KeyFormatException {
      return null;
    } on FormatException {
      return null;
    }
  }

  final mine = read(winner);
  final theirs = read(other);
  if (mine == null) return theirs == null ? winner : other.stamped(winner.changedAt + 1);
  if (theirs == null || keyIdentity(winner) != keyIdentity(other)) return winner;
  try {
    final merged = await crypto.mergePgpKeys(mine, theirs, preferA: true);
    if (const ListEquality<int>().equals(merged, mine)) return winner;
    final public = (await crypto.readPrivateKey(merged)).public!;
    return grownPgpKey(winner, merged, public)?.stamped(winner.changedAt + 1) ?? winner;
  } on crypto.KeyFormatException {
    return winner;
  } on ArgumentError {
    return winner;
  }
}

/// Merges this device's entries in one scope with the server's copy.
///
/// [local] is this device's entries in the scope. [known] is the ids the
/// scope held after this device's last sync; one that's gone from [local] was
/// deleted here. [remote] is the server's copy, or null before the first
/// upload. [now] is epoch ms, the current time by default.
///
/// Returns the document to write back and to take locally, and the ids it
/// holds. The document keeps the keys of [remote] this version doesn't know.
///
/// [anchors] is this device's anchors of the account's server spaces in their
/// stored form (`SpaceAnchors.toJson`), for the vault's own scope only. The
/// document's `extra` then holds the union of them and [remote]'s
/// ([syncAnchorsKey]); every other key of `extra` is [remote]'s as before, and
/// without [anchors] so is this one.
({SyncDoc doc, List<String> known}) mergeScope(Lists local, List<String> known, SyncDoc? remote, {int? now, Object? anchors}) {
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
  final keyAccounts = _mergeEntries(local.keyAccounts, remote?.keyAccounts ?? const <KeyAccount>[], tombs);
  final contacts = _dropDuplicateContacts(
    _mergeEntries(local.contacts, remote?.contacts ?? const <Contact>[], tombs, combine: _withBothKeys),
    tombs,
    at,
  );
  final logins = _mergeEntries(local.logins, remote?.logins ?? const <Login>[], tombs, combine: _keepLosingPassword);
  final cards = _mergeEntries(local.cards, remote?.cards ?? const <PaymentCard>[], tombs);
  final identities = _mergeEntries(local.identities, remote?.identities ?? const <Identity>[], tombs);
  final files = _mergeEntries(local.files, remote?.files ?? const <VaultFile>[], tombs);

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
    keyAccounts: keyAccounts,
    contacts: contacts,
    logins: logins,
    cards: cards,
    identities: identities,
    files: files,
    deleted: deleted,
    extra: _withAnchors(remote?.extra ?? const {}, anchors),
  );
  return (doc: doc, known: doc.ids.toList());
}

/// The key of a sync file's `extra` that carries the anchors of the account's server spaces between its devices
/// (`SpaceAnchors`, space_head_store.dart). Older builds pass it through as they pass any key they don't know.
const syncAnchorsKey = 'spaceAnchors';

/// [extra], the remote file's, with [syncAnchorsKey] the union of [local] anchors and the remote's. Without [local]
/// it is [extra] as it was. A copy that can't be read (a later format, or damage) leaves [extra] as it was: the merge
/// writes nothing over what it couldn't read.
Map<String, Object?> _withAnchors(Map<String, Object?> extra, Object? local) {
  if (local == null) {
    return extra;
  }
  try {
    return {...extra, syncAnchorsKey: SpaceAnchors.mergeValues(local, extra[syncAnchorsKey])};
  } on MalformedException {
    return extra;
  }
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
      'keyAccounts': [
        for (final account in _sortById([...doc.keyAccounts])) account.toJson(),
      ],
      'contacts': [
        for (final contact in _sortById([...doc.contacts])) contact.toJson(),
      ],
      'logins': [
        for (final login in _sortById([...doc.logins])) login.toJson(),
      ],
      'cards': [
        for (final card in _sortById([...doc.cards])) card.toJson(),
      ],
      'identities': [
        for (final identity in _sortById([...doc.identities])) identity.toJson(),
      ],
      if (doc.files.isNotEmpty) 'files': [for (final file in _sortById([...doc.files])) file.toJson()],
      'deleted': [for (final tomb in deleted) tomb.toJson()],
    });
  }

  return norm(a) == norm(b);
}

/// This device's lists with one scope replaced by its synced document. A
/// space's document never brings passkeys, on-key accounts or contacts:
/// they belong to the vault alone.
///
/// An entry this device holds in another scope moves into [scope] only when
/// [doc]'s copy is that same entry, moved: changed later, and equal to it
/// but for its space and its stamp. Anything else under its id stays out,
/// and the entry stays where it is: everyone in a shared space writes its
/// document, and an id is no secret to someone who once shared the entry.
/// [heldElsewhere] names the ids kept out.
Lists applyScope(Lists all, String? scope, Lists doc) => Lists(
  accounts: _placeScope(all.accounts, scope, doc.accounts),
  backupServices: _placeScope(all.backupServices, scope, doc.backupServices),
  keys: _placeScope(all.keys, scope, doc.keys),
  notes: _placeScope(all.notes, scope, doc.notes),
  passkeys: scope == null ? _placeScope(all.passkeys, scope, doc.passkeys) : all.passkeys,
  keyAccounts: scope == null ? _placeScope(all.keyAccounts, scope, doc.keyAccounts) : all.keyAccounts,
  contacts: scope == null ? _placeScope(all.contacts, scope, doc.contacts) : all.contacts,
  logins: _placeScope(all.logins, scope, doc.logins),
  cards: _placeScope(all.cards, scope, doc.cards),
  identities: _placeScope(all.identities, scope, doc.identities),
  files: _placeScope(all.files, scope, doc.files),
);

/// The ids of [doc]'s entries that [applyScope] keeps out of [scope] though
/// they changed later than this device's entry of the same id in another
/// scope: they are not that entry moved, but something else under its id.
///
/// The caller leaves them out of what the scope held after the sync, so the
/// next run doesn't take them for entries deleted here and write their
/// deletion into the scope's document: this device never held them there.
Set<String> heldElsewhere(Lists all, String? scope, Lists doc) => {
  ..._keptOut(all.accounts, scope, doc.accounts),
  ..._keptOut(all.backupServices, scope, doc.backupServices),
  ..._keptOut(all.keys, scope, doc.keys),
  ..._keptOut(all.notes, scope, doc.notes),
  // Logins follow accounts into spaces, so every scope places them
  ..._keptOut(all.logins, scope, doc.logins),
  // So do cards, identities and files
  ..._keptOut(all.cards, scope, doc.cards),
  ..._keptOut(all.identities, scope, doc.identities),
  ..._keptOut(all.files, scope, doc.files),
  if (scope == null) ...[
    ..._keptOut(all.passkeys, scope, doc.passkeys),
    ..._keptOut(all.keyAccounts, scope, doc.keyAccounts),
    ..._keptOut(all.contacts, scope, doc.contacts),
  ],
};

/// True when two sets of lists hold the same data in the same order.
bool sameLists(Lists a, Lists b) => canonical(a.toJson()) == canonical(b.toJson());

/// A sync never loses a password (openspec: add-passwords, the logins spec):
/// when two phones changed one login, the losing copy's password goes among
/// the winner's previous passwords, replaced when the loser last changed,
/// unless it is the winner's or already among them; the five most recent
/// are kept. The winner keeps its own change time, so the next merge of the
/// two picks it again and adds nothing.
Login _keepLosingPassword(Login winner, Login other) {
  final lost = other.password;
  return lost == null ? winner : winner.keepingPrevious(lost, other.changedAt);
}

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

/// The fingerprint of the key [contact] holds, upper-case hexadecimal; null
/// when it can't be read.
String? _fingerprintOf(Contact contact) {
  if (!contact.hasKey) return null;
  try {
    return crypto.readPgpKeyInfo(unb64(contact.publicKey)).primary.fingerprintHex;
  } on crypto.KeyFormatException {
    return null;
  } on FormatException {
    return null;
  }
}

/// [winner] holding everything its key and [other]'s hold, when the two are
/// copies of the same key; [winner] as it is otherwise. A revocation or a
/// later expiry one phone learned of is never lost to an edit on another.
Contact _withBothKeys(Contact winner, Contact other) {
  if (winner.publicKey == other.publicKey || !winner.hasKey || !other.hasKey) return winner;
  try {
    final union = b64(crypto.unionPublicKeys(unb64(winner.publicKey), unb64(other.publicKey)));
    return union == winner.publicKey ? winner : winner.copyWith(publicKey: union);
  } on crypto.KeyFormatException {
    return winner;
  } on FormatException {
    return winner;
  } on ArgumentError {
    // Two different keys under one id: the later change wins whole
    return winner;
  }
}

/// The same key added on two devices before they synced: one contact is
/// kept, the checked one, else the one changed last, with the keys of both,
/// and the other is deleted.
List<Contact> _dropDuplicateContacts(List<Contact> contacts, Map<String, int> tombs, int now) {
  final prints = {for (final contact in contacts) contact.id: _fingerprintOf(contact)};
  bool checked(Contact contact) => contact.checkedFingerprint != null && contact.checkedFingerprint!.toUpperCase() == prints[contact.id];
  final seen = <String, Contact>{};
  final dropped = <String>{};
  for (final contact in contacts) {
    final print = prints[contact.id];
    if (print == null) continue;
    final other = seen[print];
    if (other == null) {
      seen[print] = contact;
      continue;
    }
    final contactWins = checked(contact) != checked(other) ? checked(contact) : contact.changedAt > other.changedAt;
    final (kept, gone) = contactWins ? (contact, other) : (other, contact);
    seen[print] = _withBothKeys(kept, gone);
    dropped.add(gone.id);
    tombs[gone.id] = now;
  }
  final merged = {for (final contact in seen.values) contact.id: contact};
  return [
    for (final contact in contacts)
      if (!dropped.contains(contact.id)) merged[contact.id] ?? contact,
  ];
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
    } else if (synced != null && synced.changedAt > entry.changedAt && _sameButPlace(synced, entry)) {
      // Moved into this scope on another device after it changed here
      out.add(synced);
      fresh.remove(entry.id);
    } else {
      // Held in another scope, and what came under its id is older or isn't it: it stays where it is
      out.add(entry);
      fresh.remove(entry.id);
    }
  }
  return [...out, ...fresh.values];
}

/// The ids of [incoming] that [_placeScope] keeps out of [scope] though they
/// changed later than the entry of [all] that holds the id in another scope.
Iterable<String> _keptOut<T extends VaultEntry<T>>(List<T> all, String? scope, List<T> incoming) {
  final elsewhere = {
    for (final entry in all)
      if (entry.spaceId != scope) entry.id: entry,
  };
  return [
    for (final synced in incoming)
      if (elsewhere[synced.id] case final entry? when synced.changedAt > entry.changedAt && !_sameButPlace(synced, entry)) synced.id,
  ];
}

/// Whether [a] and [b] are one entry but for the space it is in and when it
/// last changed, which is all that moving an entry changes.
bool _sameButPlace<T extends VaultEntry<T>>(T a, T b) => _withoutPlace(a) == _withoutPlace(b);

String _withoutPlace<T extends VaultEntry<T>>(T entry) => canonical(
  entry.toJson()
    ..remove('updatedAt')
    ..remove('spaceId'),
);

/// Sorts [list] in place by id, keeping the order of equal ids, and returns it.
List<T> _sortById<T extends VaultEntry<T>>(List<T> list) {
  mergeSort(list, compare: (a, b) => a.id.compareTo(b.id));
  return list;
}

String _withoutStamp<T extends VaultEntry<T>>(T entry) => canonical(entry.toJson()..remove('updatedAt'));
