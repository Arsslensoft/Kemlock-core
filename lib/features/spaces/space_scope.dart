// How a server space is one more scope on the phone (docs/plans/add-server-spaces.md,
// tasks 3.3 and 3.4): the ids it and its items go by, and where each item's collection
// is kept.
//
// - **Ids.** A space on the server is a UUID. A moved WebDAV space keeps its WebDAV id on
//   the phone, and takes the UUID crypto.md "Legacy ids" gives that id on the server, so
//   every member's app computes the same one. An entry whose id isn't a UUID takes the
//   legacy-id UUID under the space's owner (`0x02 || space uuid`); its JSON keeps its own
//   id, and the merge pairs copies by it.
// - **The collection.** An item's collection id is metadata of the server item, sent beside
//   `owner`, and never a key of the entry's JSON. The phone keeps it in the scope state
//   (`ScopeState.extra`), per entry id. So `_withoutPlace` in sync_merge.dart, which strips
//   only `updatedAt` and `spaceId`, keeps working: a move into a server space is never refused
//   as "held elsewhere" because of it, and a bridged WebDAV file never gains a `collectionId`.
//
// Pure Dart, no Flutter.

library;

import '../../crypto/account/encoding.dart';
import '../../crypto/account/legacy_ids.dart';
import '../sync/sync_crypto.dart' show isSpaceId;
import '../sync/sync_merge.dart' show Lists;

/// The scope state's key for the collection of each of a server space's entries.
const spaceCollectionsKey = 'collections';

/// Whether a server may list a space under [id]: a UUID, and not one of the names the vault's own entries sync under
/// (`personal` and `vaultwarden`), as the app refuses such an invite (3f8017e7). Anything else is ignored: nothing
/// syncs into or out of it.
bool isServerSpaceId(String id) => isUuidText(id) && isSpaceId(id);

/// The UUID a server gives the space the app calls [appSpaceId]: the id itself when it is a UUID, else the legacy-id
/// UUID. Every member's app computes the same one.
String serverSpaceUuid(String appSpaceId) => spaceUuid(appSpaceId);

/// The UUID of the entry [entryId] among the items of the space with the UUID [spaceUuid]: the id itself when it is a
/// UUID, else the legacy-id UUID under the space's owner.
String serverItemUuid(String entryId, String spaceUuid) => itemUuid(entryId, Owner.space(spaceUuid));

/// The collection of each entry in [extra], the scope state of a server space, by the entry's own id. A value that
/// isn't a map of ids to ids reads as none.
Map<String, String> spaceCollectionsOf(Map<String, Object?> extra) {
  final stored = extra[spaceCollectionsKey];
  if (stored is! Map<String, Object?>) {
    return {};
  }
  return {
    for (final MapEntry(:key, :value) in stored.entries)
      if (value is String && isUuidText(value)) key: value,
  };
}

/// [extra] holding [collections] as the collection of each entry, and every other key as it was.
Map<String, Object?> withSpaceCollections(Map<String, Object?> extra, Map<String, String> collections) => {
  ...extra,
  spaceCollectionsKey: {for (final MapEntry(:key, :value) in collections.entries) key: value},
};

/// The UUID the server gives the space the app calls [appSpaceId], or null when the id can't be mapped (it isn't a UUID and
/// isn't 1 to 64 characters of `[A-Za-z0-9_-]`).
String? serverSpaceUuidOrNull(String appSpaceId) {
  try {
    return spaceUuid(appSpaceId);
  } on MalformedException {
    return null;
  }
}

/// [lists] with every entry that belongs to a space put in the space [space]: what a moved WebDAV space's entries go as to
/// the server, whose members that began on Kemlock Server know it by its UUID. The phone knows the space by its WebDAV id,
/// so its entries carry that as their `spaceId`; without this, a member who began on the server and one who moved from WebDAV
/// would each rewrite the other's copy of an entry, a new revision each time. Passkeys, on-key accounts and contacts never
/// leave the vault's own scope, and are returned as they are.
Lists rescopedTo(Lists lists, String space) => Lists(
  accounts: [for (final entry in lists.accounts) entry.inSpace(space)],
  backupServices: [for (final entry in lists.backupServices) entry.inSpace(space)],
  keys: [for (final entry in lists.keys) entry.inSpace(space)],
  notes: [for (final entry in lists.notes) entry.inSpace(space)],
  passkeys: lists.passkeys,
  keyAccounts: lists.keyAccounts,
  contacts: lists.contacts,
  logins: [for (final entry in lists.logins) entry.inSpace(space)],
  cards: [for (final entry in lists.cards) entry.inSpace(space)],
  identities: [for (final entry in lists.identities) entry.inSpace(space)],
);
