/// Links between a vault's entries (`crypto.md`, "Item bodies", `links`): which entries an entry is linked to, linking
/// and unlinking two entries, and mending a link that only one end names.
///
/// A link is **two-way**: A links B when both bodies name each other (`links: [{ "id": "<item uuid>" }]`). The id is the
/// lower-case hyphenated UUID of the linked *item*, which is its entry's id when that is a UUID, else the UUID
/// `legacy_ids.dart` makes of it for its owner (`kmItemId`): the account for an entry of the vault's own, the space for
/// an entry of a space. An entry whose id isn't a UUID and whose owner isn't known (no Kemlock Server account, [account]
/// null) has no item id yet: [linkIdOf] gives its own id, which is not a UUID, and [linkEntries] leaves such a pair alone
/// rather than write a link that could never be found again.
///
/// Two older ways to say the same are read as links on both items, and unlinking clears them:
///
/// - an MFA code (`OtpAccount`) that the importer made from a login's TOTP names the login in `linkedLoginId`, by item id;
/// - a login names the code it holds in `accountId`, by entry id (the app's own link).
///
/// Neither is ever copied into `links`. A link that names no entry the vault holds is kept and shown as not available.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert' show jsonEncode;

import '../crypto/account/encoding.dart' show MalformedException, Owner;
import '../crypto/account/legacy_ids.dart' show spaceUuid;
import '../features/sync/kemlock/km_kinds.dart' show kmItemId;
import '../features/sync/sync_merge.dart' show Lists;
import '../models/backup_service.dart';
import '../models/contact.dart';
import '../models/custom_field.dart';
import '../models/identity.dart';
import '../models/item_link.dart';
import '../models/json.dart' show jsonEquals, unset;
import '../models/key_account.dart';
import '../models/login.dart';
import '../models/otp_account.dart';
import '../models/passkey.dart';
import '../models/payment_card.dart';
import '../models/secure_note.dart';
import '../models/vault_entry.dart';
import '../models/vault_file.dart';
import '../models/vault_key.dart';

final _uuid = RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$');

/// An item another entry is linked to, as [linkedItemsOf] finds it.
class LinkedItem {
  const LinkedItem({required this.id, this.entry, this.oneWay = false, this.viaLinkedLogin = false});

  /// The linked item's id: lower-case hyphenated UUID, the one `links` holds.
  final String id;

  /// The entry that is linked; null when the vault holds none with that id ("item not available"). The link is kept.
  final VaultEntry<Object?>? entry;

  /// Only one end names the other (a write that failed halfway): [mendedLinks] writes the other end.
  final bool oneWay;

  /// The two are linked by a login and its code's own link, `linkedLoginId` or `accountId`, whether or not `links` says it too.
  /// Unlinking clears it.
  final bool viaLinkedLogin;
}

/// Every entry of [lists], of every kind, files included.
List<VaultEntry<Object?>> entriesOf(Lists lists) => [
  ...lists.accounts,
  ...lists.backupServices,
  ...lists.keys,
  ...lists.notes,
  ...lists.passkeys,
  ...lists.keyAccounts,
  ...lists.contacts,
  ...lists.logins,
  ...lists.cards,
  ...lists.identities,
  ...lists.files,
];

/// The owner an entry's item id is made for: its space when it is in one, else [account] (the Kemlock Server account's
/// user owner), which is null when there is none.
Owner? _ownerOf(VaultEntry<Object?> entry, Owner? account) {
  final space = entry.spaceId;
  if (space != null && space.isNotEmpty) {
    try {
      return Owner.space(spaceUuid(space));
    } on MalformedException {
      return null;
    }
  }
  return account;
}

/// The id [entry] is linked by: its item id, `kmItemId(entry.id, owner)`, which is the entry's id for a UUID. The owner is
/// the entry's space, else [account]. Without an owner an entry whose id isn't a UUID can't be given one, and its own id
/// comes back, which is not a UUID.
String linkIdOf(VaultEntry<Object?> entry, {Owner? account}) {
  final id = entry.id;
  final owner = _ownerOf(entry, account);
  if (owner == null) {
    return id;
  }
  try {
    return kmItemId(id, owner);
  } on MalformedException {
    return id;
  }
}

/// Whether [id] is an item id a link can name.
bool isLinkId(String id) => _uuid.hasMatch(id);

/// The ids that name [entry] in a link or in `linkedLoginId`, lower case: its item id and its own id.
Set<String> _namesOf(VaultEntry<Object?> entry, Owner? account) => {
  linkIdOf(entry, account: account).toLowerCase(),
  entry.id.toLowerCase(),
};

/// Every entry by the ids that name it.
class _Index {
  _Index(this.all, this.account) {
    for (final entry in all) {
      for (final name in _namesOf(entry, account)) {
        byName.putIfAbsent(name, () => entry);
      }
    }
  }

  final List<VaultEntry<Object?>> all;
  final Owner? account;
  final byName = <String, VaultEntry<Object?>>{};

  VaultEntry<Object?>? operator [](String id) => byName[id.toLowerCase()];

  Set<String> names(VaultEntry<Object?> entry) => _namesOf(entry, account);
}

/// Whether the code and the login [a] and [b] are tied by the code's `linkedLoginId` or the login's `accountId`.
bool _legacyLinked(VaultEntry<Object?> a, VaultEntry<Object?> b, _Index index) {
  bool tied(VaultEntry<Object?> code, VaultEntry<Object?> login) =>
      code is OtpAccount &&
      login is Login &&
      ((code.linkedLoginId != null && index.names(login).contains(code.linkedLoginId!.toLowerCase())) || login.accountId == code.id);
  return tied(a, b) || tied(b, a);
}

/// Whether [from] names [to] in its `links`.
bool _names(VaultEntry<Object?> from, VaultEntry<Object?> to, _Index index) => from.links.ids.any(index.names(to).contains);

/// The items [entry] is linked to, by the three ways a link is written, in the order of their ids:
///
/// 1. the readable entries of its own `links`;
/// 2. its `linkedLoginId`, when it is a code, or its `accountId`, when it is a login: the entry they name;
/// 3. every entry of [lists] that names this one (in its `links`, in its `linkedLoginId` naming this login, or by an
///    `accountId` naming this code), since a link shows on both ends.
///
/// A link naming no entry [lists] holds is returned with a null entry. [account] is the Kemlock Server account's user
/// owner, which a legacy entry id needs to be given its item id; entries in a space use the space.
List<LinkedItem> linkedItemsOf(Lists lists, VaultEntry<Object?> entry, {Owner? account}) {
  final index = _Index(entriesOf(lists), account);
  final mine = index.names(entry);
  final found = <String, _Found>{};

  _Found at(String id, VaultEntry<Object?>? target) {
    final key = target == null ? id.toLowerCase() : linkIdOf(target, account: account).toLowerCase();
    return found.putIfAbsent(key, () => _Found(key, target));
  }

  for (final link in entry.links.readable) {
    if (mine.contains(link.key)) {
      continue;
    }
    at(link.key, index[link.key]).forward = true;
  }
  switch (entry) {
    case OtpAccount(:final linkedLoginId?) when !mine.contains(linkedLoginId.toLowerCase()):
      at(linkedLoginId, index[linkedLoginId]).legacy = true;
    case Login(:final accountId?):
      final code = index[accountId];
      if (code is OtpAccount && code.id == accountId) {
        at(accountId, code).legacy = true;
      }
    default:
  }
  for (final other in index.all) {
    if (identical(other, entry) || (other.id == entry.id && other.spaceId == entry.spaceId)) {
      continue;
    }
    if (other.links.ids.any(mine.contains)) {
      at(other.id, other).reverse = true;
    }
    if (_legacyLinked(entry, other, index)) {
      at(other.id, other).legacy = true;
    }
  }
  return [
    for (final id in found.keys.toList()..sort())
      LinkedItem(
        id: id,
        entry: found[id]!.entry,
        oneWay: !found[id]!.legacy && found[id]!.entry != null && found[id]!.forward != found[id]!.reverse,
        viaLinkedLogin: found[id]!.legacy,
      ),
  ];
}

class _Found {
  _Found(this.id, this.entry);

  final String id;
  final VaultEntry<Object?>? entry;
  bool forward = false;
  bool reverse = false;
  bool legacy = false;
}

/// A copy of [entry] linked to [links], by its kind's own `withLinks`, never to itself: [ownIds] are the ids that name it.
VaultEntry<Object?> _withLinks(VaultEntry<Object?> entry, List<ItemLink> links, Iterable<String> ownIds) => switch (entry) {
  final OtpAccount entry => entry.withLinks(links, ownIds: ownIds),
  final BackupService entry => entry.withLinks(links, ownIds: ownIds),
  final VaultKey entry => entry.withLinks(links, ownIds: ownIds),
  final SecureNote entry => entry.withLinks(links, ownIds: ownIds),
  final Passkey entry => entry.withLinks(links, ownIds: ownIds),
  final KeyAccount entry => entry.withLinks(links, ownIds: ownIds),
  final Contact entry => entry.withLinks(links, ownIds: ownIds),
  final Login entry => entry.withLinks(links, ownIds: ownIds),
  final PaymentCard entry => entry.withLinks(links, ownIds: ownIds),
  final Identity entry => entry.withLinks(links, ownIds: ownIds),
  final VaultFile entry => entry.withLinks(links, ownIds: ownIds),
  _ => throw ArgumentError.value(entry, 'entry', 'not an entry of a kind this version knows'),
};

/// [entry] marked as changed [at].
VaultEntry<Object?> _stamped(VaultEntry<Object?> entry, int at) => switch (entry) {
  final OtpAccount entry => entry.stamped(at),
  final BackupService entry => entry.stamped(at),
  final VaultKey entry => entry.stamped(at),
  final SecureNote entry => entry.stamped(at),
  final Passkey entry => entry.stamped(at),
  final KeyAccount entry => entry.stamped(at),
  final Contact entry => entry.stamped(at),
  final Login entry => entry.stamped(at),
  final PaymentCard entry => entry.stamped(at),
  final Identity entry => entry.stamped(at),
  final VaultFile entry => entry.stamped(at),
  _ => throw ArgumentError.value(entry, 'entry', 'not an entry of a kind this version knows'),
};

/// [entry] naming [id] in its links, or as it is when it does already. [own] are the ids that name [entry] itself: it never names one.
VaultEntry<Object?> _naming(VaultEntry<Object?> entry, String id, int now, Iterable<String> own) =>
    entry.links.names(id) ? entry : _stamped(_withLinks(entry, [...entry.links, ItemLink(id.toLowerCase())], own), now);

/// [entry] with every name of the other entry out of its links, and its own `linkedLoginId` or `accountId` cleared when
/// that is what ties it to [other].
VaultEntry<Object?> _dropping(VaultEntry<Object?> entry, VaultEntry<Object?> other, _Index index, int now) {
  final others = index.names(other);
  var next = entry;
  if (entry.links.readable.any((link) => others.contains(link.key))) {
    next = _withLinks(entry, [
      for (final link in entry.links)
        if (!link.isReadable || !others.contains(link.key)) link,
    ], index.names(entry));
  }
  switch (next) {
    case final OtpAccount code when code.linkedLoginId != null && others.contains(code.linkedLoginId!.toLowerCase()):
      next = code.copyWith(linkedLoginId: unset);
    case final Login login when login.accountId != null && login.accountId == other.id && other is OtpAccount:
      next = login.copyWith(accountId: unset);
    default:
  }
  return identical(next, entry) ? entry : _stamped(next, now);
}

/// [a] and [b] linked to each other: each names the other's item id, stamped [now]. Nothing changes for an end that
/// names the other already, nor for two that a code's `linkedLoginId` or a login's `accountId` tie already, nor for an
/// entry with itself, nor for one that has no item id yet (see the library's comment). [account] is the Kemlock Server
/// account's user owner.
///
/// Both entries go to be saved together, all or none: a link that is written to one end alone is what [mendedLinks] repairs.
({VaultEntry<Object?> a, VaultEntry<Object?> b}) linkEntries(
  VaultEntry<Object?> a,
  VaultEntry<Object?> b, {
  required int now,
  Owner? account,
}) {
  final idA = linkIdOf(a, account: account);
  final idB = linkIdOf(b, account: account);
  final index = _Index([a, b], account);
  if (!isLinkId(idA) || !isLinkId(idB) || idA == idB || _legacyLinked(a, b, index)) {
    return (a: a, b: b);
  }
  return (a: _naming(a, idB, now, index.names(a)), b: _naming(b, idA, now, index.names(b)));
}

/// [a] and [b] no longer linked: each loses the other from its links, and a code's `linkedLoginId` or a login's `accountId`
/// that ties them is cleared, from whichever side it is asked. An end that wasn't linked is returned as it is, and the
/// others are stamped [now].
({VaultEntry<Object?> a, VaultEntry<Object?> b}) unlinkEntries(
  VaultEntry<Object?> a,
  VaultEntry<Object?> b, {
  required int now,
  Owner? account,
}) {
  final index = _Index([a, b], account);
  return (a: _dropping(a, b, index, now), b: _dropping(b, a, index, now));
}

/// The entries of [lists] to save so that every link that only one end names has both: the other end, which the vault
/// holds, now names it too, stamped [now]. A link naming no entry the vault holds is left as it is, and so is a pair that a
/// code's `linkedLoginId` or a login's `accountId` ties. Empty when nothing needs mending.
List<VaultEntry<Object?>> mendedLinks(Lists lists, {required int now, Owner? account}) {
  final index = _Index(entriesOf(lists), account);
  final changed = <VaultEntry<Object?>, VaultEntry<Object?>>{};
  VaultEntry<Object?> current(VaultEntry<Object?> entry) => changed[entry] ?? entry;
  for (final from in index.all) {
    for (final link in from.links.readable) {
      final to = index[link.key];
      if (to == null || identical(to, from) || index.names(from).contains(link.key) || _legacyLinked(from, to, index)) {
        continue;
      }
      final idFrom = linkIdOf(from, account: account);
      if (!isLinkId(idFrom) || _names(current(to), from, index)) {
        continue;
      }
      changed[to] = _naming(current(to), idFrom, now, index.names(to));
    }
  }
  return changed.values.toList();
}

/// The entries of [lists] to save so that the links to an entry that moved to another owner still find it. A move gives an entry
/// whose id isn't a UUID a new item id (`legacy_ids.dart` makes it for the owner it goes to), and every `links` entry and every
/// `linkedLoginId` that named the old one ([oldLinkId], what [linkIdOf] gave before the move) must now name [newLinkId] (what it
/// gives after). An entry with a UUID id keeps its item id whatever its owner, and has nothing to rename.
///
/// An entry that links to [oldLinkId] has it replaced, once, by [newLinkId] (a link made beside it keeps the rest it carries), and a
/// code whose `linkedLoginId` is [oldLinkId] has it replaced; the entries are stamped [now] and the others are not returned. Ids are
/// compared in lower case. Pass every entry of the vault in [lists], the moved entry included or not: an entry whose own id is
/// either id is left alone.
///
/// The app calls it when it moves an entry between the vault and a space, or between two spaces, with the entry's [linkIdOf] before and
/// after, and saves what it returns with the moved entry. The core moves no entry between owners itself.
List<VaultEntry<Object?>> relinkedAfterMove(Lists lists, {required String oldLinkId, required String newLinkId, required int now}) {
  final old = oldLinkId.toLowerCase();
  final next = newLinkId.toLowerCase();
  if (old == next) {
    return const [];
  }
  final out = <VaultEntry<Object?>>[];
  for (final entry in entriesOf(lists)) {
    if (entry.id.toLowerCase() == old || entry.id.toLowerCase() == next) {
      continue;
    }
    var renamed = entry;
    final held = entry.links.where((link) => link.isReadable && link.key == old).firstOrNull;
    if (held != null) {
      final links = [
        for (final link in entry.links)
          if (!link.isReadable || link.key != old) link,
        if (!entry.links.names(next)) ItemLink(next, extra: held.extra),
      ];
      renamed = _withLinks(renamed, links, [entry.id]);
    }
    if (renamed is OtpAccount && renamed.linkedLoginId?.toLowerCase() == old) {
      renamed = renamed.copyWith(linkedLoginId: next);
    }
    if (!identical(renamed, entry)) {
      out.add(_stamped(renamed, now));
    }
  }
  return out;
}

// ─── Merging duplicates, and deleting ──────────────────────────────────────────────────────────────

/// The members of an entry's body that a merge may rewrite on an entry that isn't merged.
const _relinkMembers = ['links', 'linkedLoginId', 'accountId'];

/// What a merge or a delete wrote on one entry besides the ones it merged, for Undo: the entry's [id] and, for each member it changed
/// (`links`, `linkedLoginId`, `accountId`), what the body held before ([before]) and what the merge wrote ([after]). A member the
/// body didn't hold is `null`. Undo ([undoRelink]) puts [before] back only where the entry still holds [after].
///
/// It is plain JSON (see [toJson]) so a merge record can keep it.
class RelinkUndo {
  const RelinkUndo({required this.id, required this.before, required this.after});

  /// A step read from [json] (what [toJson] wrote); null for anything else.
  static RelinkUndo? tryFromJson(Object? json) {
    if (json is! Map) {
      return null;
    }
    final id = json['id'];
    final before = json['before'];
    final after = json['after'];
    if (id is! String || before is! Map || after is! Map) {
      return null;
    }
    Map<String, Object?> members(Map<Object?, Object?> from) => {
      for (final key in _relinkMembers)
        if (from.containsKey(key)) key: from[key],
    };
    return RelinkUndo(id: id, before: members(before), after: members(after));
  }

  /// A step read from [json]; an [ArgumentError] when it isn't one.
  factory RelinkUndo.fromJson(Object? json) => tryFromJson(json) ?? (throw ArgumentError.value(json, 'json', 'not a relink step'));

  /// The id of the entry the merge rewrote.
  final String id;

  /// The members it changed, as the body held them; `null` for one it didn't hold.
  final Map<String, Object?> before;

  /// The same members as the merge wrote them; `null` for one it removed.
  final Map<String, Object?> after;

  Map<String, Object?> toJson() => {'id': id, 'before': before, 'after': after};

  @override
  bool operator ==(Object other) => other is RelinkUndo && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'RelinkUndo($id, ${before.keys.join(', ')})';
}

/// What [relinkForMerge] made: the item that stays, the other entries to save, and what Undo needs.
class MergeRelink {
  const MergeRelink({required this.kept, required this.others, required this.undo});

  /// The item that stays: as it was given when nothing changed, else with the links and custom fields of the items that go joined to
  /// its own, stamped.
  final VaultEntry<Object?> kept;

  /// The entries of the vault, other than the merged ones, that the merge rewrites, stamped.
  final List<VaultEntry<Object?>> others;

  /// What each of [others] held before and holds now, for [undoRelink]. [kept] is not in it: Undo puts the kept item back whole.
  final List<RelinkUndo> undo;
}

/// What a merge does to the entries that point at the entries it removes (the web vault's `relink.ts`). Links are two-way, so when
/// the [removed] items are folded into [kept]:
///
/// - every other entry of [lists] whose `links` named a removed item now names [kept], and so does one that [kept] is now linked to
///   and that didn't name it (both ends are written); an MFA code whose `linkedLoginId` named a removed login now names [kept], and a
///   login whose `accountId` named a removed code now names [kept]'s id;
/// - [kept] links to every item the removed ones linked to, and to every entry outside the merge that names one of the merged items,
///   never to itself or to one of the removed; nothing is written to [kept]'s links when [keptWritable] is false (a space the person
///   can only read), and then the entries that named a removed item still come to name [kept], from their end alone;
/// - [kept] carries over each custom field it lacks from the removed items, in order: a field of an admin's definition once (the
///   kept item's own wins), any other by its name, kind and value, so two values of one field both stay.
///
/// [kept] is the item as the merge made it (`MergeChoices.merged`); the removed ones are as the vault holds them. [now] (epoch ms)
/// stamps what changes; [account] is the Kemlock Server account's user owner, which an entry with a legacy id needs to be given
/// its item id. Nothing changes for an entry the merge doesn't touch, and it is not returned.
MergeRelink relinkForMerge(
  Lists lists, {
  required VaultEntry<Object?> kept,
  required List<VaultEntry<Object?>> removed,
  required int now,
  Owner? account,
  bool keptWritable = true,
}) {
  final merged = {kept.id, for (final entry in removed) entry.id};
  final keptNames = _namesOf(kept, account);
  final removedNames = {for (final entry in removed) ..._namesOf(entry, account)};
  final members = {...keptNames, ...removedNames};
  final keptLink = linkIdOf(kept, account: account).toLowerCase();
  final others = [
    for (final entry in entriesOf(lists))
      if (!merged.contains(entry.id)) entry,
  ];

  var keptOut = kept;
  var keptLinks = kept.links;
  if (keptWritable) {
    final outside = [
      for (final other in others)
        if (other.links.ids.any(members.contains) && isLinkId(linkIdOf(other, account: account)))
          ItemLink(linkIdOf(other, account: account).toLowerCase()),
    ];
    final readable = <ItemLink>[];
    final unread = <ItemLink>[];
    for (final link in [...kept.links, for (final entry in removed) ...entry.links, ...outside]) {
      if (link.isReadable) {
        readable.add(link);
      } else if (!unread.contains(link)) {
        unread.add(link);
      }
    }
    keptLinks = normaliseLinks([...readable, ...unread], ownIds: members);
    if (!jsonEquals([for (final link in keptLinks) link.toJson()], [for (final link in kept.links) link.toJson()])) {
      keptOut = _withLinks(keptOut, keptLinks, members);
    }
    final held = _fieldsOf(kept);
    final fields = _unionOfFields(held, [for (final entry in removed) ..._fieldsOf(entry)]);
    if (fields.length != held.length) {
      keptOut = _withFields(keptOut, fields);
    }
    if (!identical(keptOut, kept)) {
      keptOut = _stamped(keptOut, now);
    }
  }

  final listed = {for (final link in keptLinks.readable) link.key};
  final rewritten = <VaultEntry<Object?>>[];
  final undo = <RelinkUndo>[];
  for (final other in others) {
    var next = other;
    final held = other.links.ids;
    final names = _namesOf(other, account);
    final namesKept = held.any(keptNames.contains);
    // It named an item that goes, or [kept] now links to it and it doesn't link back
    if (held.any(removedNames.contains) || (keptWritable && names.any(listed.contains) && !namesKept)) {
      next = _withLinks(next, [
        for (final link in other.links)
          if (!link.isReadable || !removedNames.contains(link.key)) link,
        if (!namesKept && isLinkId(keptLink)) ItemLink(keptLink),
      ], names);
    }
    final code = next;
    if (code is OtpAccount && kept is Login && removedNames.contains(code.linkedLoginId?.toLowerCase())) {
      next = code.copyWith(linkedLoginId: keptLink);
    }
    final login = next;
    if (login is Login && kept is OtpAccount && removed.any((entry) => entry is OtpAccount && entry.id == login.accountId)) {
      next = login.copyWith(accountId: kept.id);
    }
    if (identical(next, other)) {
      continue;
    }
    final step = _undoOf(other, next);
    if (step == null) {
      continue;
    }
    rewritten.add(_stamped(next, now));
    undo.add(step);
  }
  return MergeRelink(kept: keptOut, others: rewritten, undo: undo);
}

/// The entries of [lists] to save to put back what a merge wrote, from the [undo] steps it returned: each member goes back to what the
/// entry held before the merge, but only where the entry still holds what the merge wrote. An entry edited or linked elsewhere since
/// keeps what it holds there, and an entry the vault no longer holds is skipped. Stamped [now].
List<VaultEntry<Object?>> undoRelink(Lists lists, List<RelinkUndo> undo, {required int now}) {
  final held = {for (final entry in entriesOf(lists)) entry.id: entry};
  final out = <VaultEntry<Object?>>[];
  for (final step in undo) {
    final entry = held[step.id];
    if (entry == null) {
      continue;
    }
    final json = entry.toJson();
    final put = <String, Object?>{
      for (final key in step.after.keys)
        if (jsonEquals(json[key], step.after[key])) key: step.before[key],
    };
    if (put.isNotEmpty) {
      out.add(_stamped(_withMembers(entry, put), now));
    }
  }
  return out;
}

/// The entries of [lists] to save when [removed] is deleted: every other entry that names it, in its `links`, as the login a code's
/// `linkedLoginId` is, or as the code a login's `accountId` is, without that link, so none is left naming an item that is gone. Stamped
/// [now]; the entries that don't name it are not returned. [account] is the Kemlock Server account's user owner.
List<VaultEntry<Object?>> droppedLinksTo(Lists lists, VaultEntry<Object?> removed, {required int now, Owner? account}) {
  final everyone = entriesOf(lists);
  final index = _Index(everyone, account);
  return [
    for (final entry in everyone)
      if (entry.id != removed.id)
        if (_dropping(entry, removed, index, now) case final next when !identical(next, entry)) next,
  ];
}

/// What [before] held of the members a merge rewrites and [after] holds now; null when they are the same.
RelinkUndo? _undoOf(VaultEntry<Object?> before, VaultEntry<Object?> after) {
  final was = before.toJson();
  final now = after.toJson();
  final changed = [
    for (final key in _relinkMembers)
      if (!jsonEquals(was[key], now[key])) key,
  ];
  if (changed.isEmpty) {
    return null;
  }
  return RelinkUndo(id: before.id, before: {for (final key in changed) key: was[key]}, after: {for (final key in changed) key: now[key]});
}

/// [entry] with [members] of its body set to the values given (removed for a `null`), the rest of the body as it was.
VaultEntry<Object?> _withMembers(VaultEntry<Object?> entry, Map<String, Object?> members) {
  final json = {...entry.toJson()};
  for (final MapEntry(:key, :value) in members.entries) {
    if (value == null) {
      json.remove(key);
    } else {
      json[key] = value;
    }
  }
  return switch (entry) {
    OtpAccount() => OtpAccount.fromJson(json),
    BackupService() => BackupService.fromJson(json),
    VaultKey() => VaultKey.fromJson(json),
    SecureNote() => SecureNote.fromJson(json),
    Passkey() => Passkey.fromJson(json),
    KeyAccount() => KeyAccount.fromJson(json),
    Contact() => Contact.fromJson(json),
    Login() => Login.fromJson(json),
    PaymentCard() => PaymentCard.fromJson(json),
    Identity() => Identity.fromJson(json),
    VaultFile() => VaultFile.fromJson(json),
    _ => throw ArgumentError.value(entry, 'entry', 'not an entry of a kind this version knows'),
  };
}

/// The custom fields [entry] holds; none for a kind that has none (a passkey, a File item).
List<CustomField> _fieldsOf(VaultEntry<Object?> entry) => switch (entry) {
  final OtpAccount entry => entry.fields,
  final BackupService entry => entry.fields,
  final VaultKey entry => entry.fields,
  final SecureNote entry => entry.fields,
  final KeyAccount entry => entry.fields,
  final Contact entry => entry.fields,
  final Login entry => entry.fields,
  final PaymentCard entry => entry.fields,
  final Identity entry => entry.fields,
  _ => const [],
};

/// [entry] with [fields] as its custom fields; as it is for a kind that has none.
VaultEntry<Object?> _withFields(VaultEntry<Object?> entry, List<CustomField> fields) => switch (entry) {
  final OtpAccount entry => entry.copyWith(fields: fields),
  final BackupService entry => entry.copyWith(fields: fields),
  final VaultKey entry => entry.copyWith(fields: fields),
  final SecureNote entry => entry.copyWith(fields: fields),
  final KeyAccount entry => entry.copyWith(fields: fields),
  final Contact entry => entry.copyWith(fields: fields),
  final Login entry => entry.copyWith(fields: fields),
  final PaymentCard entry => entry.copyWith(fields: fields),
  final Identity entry => entry.copyWith(fields: fields),
  _ => entry,
};

/// What tells one custom field from another in a merge: its admin definition, else its name, kind and value; a field this version
/// can't edit, by what it holds.
String _fieldKey(CustomField field) {
  final admin = field.adminField;
  if (admin != null) {
    return 'admin:$admin';
  }
  if (!field.isEditable) {
    return 'raw:${jsonEncode(field.toJson())}';
  }
  return 'field:${field.name.trim()}\u0000${field.kind}\u0000${field.value}';
}

/// [held] and then each field of [more] that [held] and the ones before it lack, in order.
List<CustomField> _unionOfFields(List<CustomField> held, List<CustomField> more) {
  final seen = {for (final field in held) _fieldKey(field)};
  return [
    ...held,
    for (final field in more)
      if (!field.isBlank && seen.add(_fieldKey(field))) field,
  ];
}
