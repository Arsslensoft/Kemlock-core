// Making the tags of a vault's items, and keeping them current (the
// add-duplicate-cleaner plan, design 1 and task 3.2): each item's tags are
// made again only when its change time moved, those of a deleted item go with
// it, and an owner's tags go whole when its key or its version changes or
// when the owner is gone, which is what leaving a space is.
//
// Pure Dart, no Flutter package: the dedup keys are held only while tags are
// made, then wiped.
import 'dart:typed_data';

import '../../crypto/account/dedup.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/legacy_ids.dart';
import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_file.dart';
import '../../models/vault_key.dart';
import 'dedup_cache.dart';
import 'duplicate_normalise.dart';
import 'duplicate_tags.dart';

/// An item to tag, with what the cache needs to know of it: its id, its change time and the space
/// it is in. Ids are unique across the vault's kinds in practice (UUIDs), as the cache keys by id.
final class DedupItem {
  const DedupItem(this.item, {required this.id, required this.changedAt, this.spaceId});

  final Object item;
  final String id;

  /// Epoch ms of the item's last change, which says whether its tags are still the ones made.
  final int changedAt;

  /// The space the item is in; null or empty for the vault's own.
  final String? spaceId;

  /// The owner's slot in the cache: [vaultSlot], or the space's.
  String get slot => spaceId == null || spaceId!.isEmpty ? vaultSlot : spaceSlot(spaceId!);
}

/// Every item of the lists given, ready to tag.
List<DedupItem> dedupItems({
  List<OtpAccount> accounts = const [],
  List<BackupService> services = const [],
  List<SecureNote> notes = const [],
  List<Passkey> passkeys = const [],
  List<VaultKey> keys = const [],
  List<Login> logins = const [],
  List<PaymentCard> cards = const [],
  List<Identity> identities = const [],
  List<Contact> contacts = const [],
  List<VaultFile> files = const [],
}) => [
  for (final item in accounts) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in services) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in notes) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in passkeys) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in keys) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in logins) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in cards) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in identities) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in contacts) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
  for (final item in files) DedupItem(item, id: item.id, changedAt: item.changedAt, spaceId: item.spaceId),
];

/// One owner of items and the key its tags are made under: the vault's own items, or a space's.
final class DedupOwner {
  DedupOwner({required this.slot, required this.owner, required this.key, this.version = 1});

  /// [vaultSlot] or `space:<id>`, the owner's place in the cache.
  final String slot;

  /// The 17 bytes in the dedup key: `0x01` and the root's UUID for the vault, `0x02` and the legacy-id
  /// UUID of the space's id for a space, so a space later moved to the server keeps the same bytes.
  final Owner owner;

  /// The owner's 32-byte key: the dedup root, or the space's own key.
  final Uint8List key;

  /// The key's version, which goes up when the key is replaced.
  final int version;
}

/// The owners of [cache]'s vault: its own, whose key is the root, and each space in [spaceKeys] (the
/// space's app id and its 32-byte key). A space whose id can't be a UUID, or whose key isn't 32 bytes,
/// is left out, and its items are not tagged.
List<DedupOwner> dedupOwners(DedupCache cache, Iterable<({String id, Uint8List key})> spaceKeys) {
  final owners = [DedupOwner(slot: vaultSlot, owner: Owner(OwnerType.user, uuidBytes(cache.rootId)), key: cache.root)];
  for (final space in spaceKeys) {
    if (space.key.length != dedupKeyLength) {
      continue;
    }
    try {
      owners.add(DedupOwner(slot: spaceSlot(space.id), owner: Owner.space(spaceUuid(space.id)), key: space.key));
    } on MalformedException {
      // An id the legacy-id rule doesn't map
    }
  }
  return owners;
}

/// [cache] with every item of [items] tagged under its owner's key in [owners], and whether that
/// changed anything.
///
/// An item whose change time is the one its tags were made for keeps them. An owner whose key
/// check or version differs from the cache's starts again, and an owner the cache holds that
/// [owners] doesn't is dropped with its tags, as are the tags of an item no longer in [items]. An
/// item whose owner isn't in [owners], such as a space with no key, has no tags. Each dedup key is
/// wiped as soon as its owner is done.
({DedupCache cache, bool changed}) refreshTags(
  DedupCache cache,
  List<DedupItem> items,
  List<DedupOwner> owners, {
  SiteResolver sites = const SiteResolver(),
  KeyIdentityOf? keyIdentityOf,
}) {
  var changed = cache.owners.keys.any((slot) => !owners.any((owner) => owner.slot == slot));
  final next = <String, DedupOwnerTags>{};
  for (final owner in owners) {
    final key = dedupKey(owner.key, owner.owner, owner.version);
    try {
      final check = b64urlEncode(dedupTag(key, 'check', const []));
      final held = cache.owners[owner.slot];
      // What was made under this very key and version, which is nothing for a changed one
      final kept = held != null && held.version == owner.version && held.check == check ? held.items : null;
      final before = kept ?? const <String, DedupItemTags>{};
      final tagged = <String, DedupItemTags>{};
      for (final entry in items) {
        if (entry.slot != owner.slot) {
          continue;
        }
        final known = before[entry.id];
        if (known != null && known.at == entry.changedAt) {
          tagged[entry.id] = known;
        } else {
          tagged[entry.id] = DedupItemTags(entry.changedAt, itemTags(entry.item, key, sites: sites, keyIdentityOf: keyIdentityOf));
          changed = true;
        }
      }
      if (kept == null || tagged.length != before.length) {
        changed = true;
      }
      next[owner.slot] = DedupOwnerTags(version: owner.version, check: check, items: tagged);
    } finally {
      wipe(key);
    }
  }
  return (cache: DedupCache(root: cache.root, rootId: cache.rootId, listHash: cache.listHash, owners: next), changed: changed);
}
