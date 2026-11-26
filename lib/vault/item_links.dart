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

import '../crypto/account/encoding.dart' show MalformedException, Owner;
import '../crypto/account/legacy_ids.dart' show spaceUuid;
import '../features/sync/kemlock/km_kinds.dart' show kmItemId;
import '../features/sync/sync_merge.dart' show Lists;
import '../models/backup_service.dart';
import '../models/contact.dart';
import '../models/identity.dart';
import '../models/item_link.dart';
import '../models/json.dart' show unset;
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
