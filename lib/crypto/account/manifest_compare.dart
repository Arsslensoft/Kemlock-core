// How a device compares what the server answers with the signed manifest, and
// the record of deleted ids it reads (docs/plans/add-account-crypto.md,
// design 6, "How a sync is compared"). Everything here is a pure function of
// its inputs: no I/O, no clock but the one passed in. The sync plan keeps the
// records in the sealed vault store.
//
// One item at a time is sorted into one of six results:
//
//   expected     the item matches the latest manifest.
//   rolledBack   the item has a lower revision than its manifest entry. (A
//                lower counter rolls back the whole answer: see [checkManifest].)
//   missing      the item is listed and not deleted, but absent with no
//                tombstone. Nothing is deleted on the device.
//   unlisted     the item is absent from the latest signed manifest, or newer
//                than its entry. It is held, not applied, until a manifest from
//                a permitted signer lists it. "Not listed means accepted" is
//                not a rule: a removed space member, or a server replaying items
//                whose tombstones expired, must not be able to add items.
//   resurrected  an id the device saw deleted reappears at or below its
//                tombstone's revision, or after the tombstone left the manifest.
//                It is refused and shown.
//   sibling      the same revision with another hash is a federation sibling,
//                handed to the merge.

library;

import 'dart:typed_data';

import 'encoding.dart';
import 'manifest.dart';

/// The result for one item.
enum ItemVerdict { expected, rolledBack, missing, unlisted, resurrected, sibling }

/// What the device does with an item of each verdict: only [expected] and
/// [sibling] items are applied or merged; the rest are held, kept, refused or
/// shown.
extension ItemVerdictUse on ItemVerdict {
  /// Whether the item may be applied (or handed to the merge, for a sibling).
  bool get isApplied => this == ItemVerdict.expected || this == ItemVerdict.sibling;

  /// Whether the person is shown the item as a warning.
  bool get isFlagged =>
      this == ItemVerdict.unlisted || this == ItemVerdict.resurrected || this == ItemVerdict.rolledBack || this == ItemVerdict.missing;
}

/// An item as the server answered with it: the id, the revision and the
/// SHA-256 of its ciphertext (32 zero bytes for a tombstone).
final class ServerItemState {
  ServerItemState({required List<int> itemId, required this.revision, required List<int> ciphertextHash, required this.deleted})
    : itemId = copyBytes(requireLength(itemId, 16, 'an item id')),
      ciphertextHash = copyBytes(requireLength(ciphertextHash, 32, 'a ciphertext hash'));

  /// The state of a live item, from its sealed ciphertext.
  factory ServerItemState.live({required List<int> itemId, required int revision, required List<int> ciphertext}) {
    final entry = ManifestEntry.forItem(itemId: itemId, revision: revision, ciphertext: ciphertext);
    return ServerItemState(itemId: itemId, revision: revision, ciphertextHash: entry.ciphertextHash, deleted: false);
  }

  /// The state of a tombstone.
  factory ServerItemState.tombstone({required List<int> itemId, required int revision}) =>
      ServerItemState(itemId: itemId, revision: revision, ciphertextHash: Uint8List(32), deleted: true);

  final Uint8List itemId;
  final int revision;
  final Uint8List ciphertextHash;
  final bool deleted;
}

/// One finding: an item id and its verdict.
final class ItemFinding {
  const ItemFinding(this.itemId, this.verdict, {this.revision, this.manifestRevision});

  final Uint8List itemId;
  final ItemVerdict verdict;

  /// The revision the server served, or null for a missing item.
  final int? revision;

  /// The revision the manifest lists, when it lists the item.
  final int? manifestRevision;

  @override
  String toString() => 'ItemFinding(${_hex(itemId)}, ${verdict.name})';
}

/// One id a device saw deleted.
final class DeletedItem {
  const DeletedItem({required this.revision, required this.seenAt});

  /// The revision of the tombstone.
  final int revision;

  /// When the device saw it, in milliseconds since the epoch, so the record
  /// can be pruned after the 180 days tombstones are kept.
  final int seenAt;
}

/// How long a device keeps an id it saw deleted: as long as the server keeps
/// tombstones, 180 days.
const deletedItemRetention = Duration(days: 180);

/// Every item id one owner's device has seen deleted, with that revision.
final class DeletedItems {
  DeletedItems([Map<String, DeletedItem> items = const {}]) : _items = Map.of(items);

  /// Reads the form [toJson] writes.
  factory DeletedItems.fromJson(Object? json) {
    final fields = strictObject(json, required: {'items'});
    final items = fields['items'];
    if (items is! Map<String, Object?>) throw const MalformedException('items is an object');
    return DeletedItems({for (final entry in items.entries) _checkId(entry.key): _deletedItem(entry.value)});
  }

  final Map<String, DeletedItem> _items;

  int get length => _items.length;

  /// The revision of the tombstone seen for [itemId], or null.
  int? revisionOf(List<int> itemId) => _items[_hex(itemId)]?.revision;

  /// A copy that also holds [itemId] deleted at [revision], seen at [now]. A
  /// higher revision replaces a lower one; the first sighting's time stays.
  DeletedItems recording(List<int> itemId, int revision, DateTime now) {
    final key = _hex(itemId);
    final existing = _items[key];
    if (existing != null && existing.revision >= revision) return this;
    return DeletedItems({..._items, key: DeletedItem(revision: revision, seenAt: existing?.seenAt ?? now.millisecondsSinceEpoch)});
  }

  /// A copy that also holds every tombstone in [manifest] and every tombstone
  /// the server answered with, seen at [now].
  DeletedItems recordingAll({Manifest? manifest, Iterable<ServerItemState> answer = const [], required DateTime now}) {
    var out = this;
    for (final entry in manifest?.entries ?? const <ManifestEntry>[]) {
      if (entry.deleted) out = out.recording(entry.itemId, entry.revision, now);
    }
    for (final item in answer) {
      if (item.deleted) out = out.recording(item.itemId, item.revision, now);
    }
    return out;
  }

  /// A copy without the ids seen more than [deletedItemRetention] before [now].
  DeletedItems pruned(DateTime now) {
    final cutoff = now.subtract(deletedItemRetention).millisecondsSinceEpoch;
    return DeletedItems({
      for (final entry in _items.entries)
        if (entry.value.seenAt >= cutoff) entry.key: entry.value,
    });
  }

  Map<String, Object?> toJson() => {
    'items': {
      for (final entry in _items.entries) entry.key: {'revision': entry.value.revision, 'seenAt': entry.value.seenAt},
    },
  };
}

/// What a device keeps per owner: the highest counter it verified, with the
/// manifest itself, whose digest and entries it holds.
final class ManifestRecord {
  const ManifestRecord(this.manifest);

  final Manifest manifest;

  int get counter => manifest.counter;
}

/// What [checkManifest] decides about a manifest that arrived.
enum ManifestVerdict {
  /// A higher counter than the device holds, or the first manifest: accept it.
  newer,

  /// The same counter and the same bytes: nothing changed.
  same,

  /// A lower counter: the whole answer is rolled back, and the device keeps
  /// the manifest it had.
  rolledBack,

  /// Two valid manifests carry one counter but differ: merge them with
  /// [mergeSameCounter]; the higher revision of each item wins, and the next
  /// write signs above both.
  fork,
}

/// Compares a manifest whose signature was already verified with the one the
/// device holds ([record], null the first time). They must have one owner.
ManifestVerdict checkManifest(ManifestRecord? record, Manifest candidate) {
  if (record == null) return ManifestVerdict.newer;
  if (record.manifest.owner != candidate.owner) throw const MalformedException('a manifest of another owner');
  if (candidate.counter > record.counter) return ManifestVerdict.newer;
  if (candidate.counter < record.counter) return ManifestVerdict.rolledBack;
  return _sameBytes(record.manifest.bytes, candidate.bytes) ? ManifestVerdict.same : ManifestVerdict.fork;
}

/// The two manifests of one owner and one counter as one: for each item the
/// entry of the higher revision. Where both hold the same revision with
/// another hash, [a]'s entry stays, and the item is a sibling in the
/// comparison. The result is for comparing only; it carries no signature.
Manifest mergeSameCounter(Manifest a, Manifest b) {
  if (a.owner != b.owner || a.counter != b.counter) throw const MalformedException('only manifests of one owner and counter merge');
  final byId = <String, ManifestEntry>{for (final entry in a.entries) _hex(entry.itemId): entry};
  for (final entry in b.entries) {
    final existing = byId[_hex(entry.itemId)];
    if (existing == null || entry.revision > existing.revision) byId[_hex(entry.itemId)] = entry;
  }
  return Manifest(owner: a.owner, counter: a.counter, entries: byId.values.toList());
}

/// Sorts every item of [answer], and every item [manifest] lists that the
/// answer lacks, into a verdict. [manifest] is the latest signed manifest the
/// device accepted; [deleted] is its record of ids it saw deleted. Findings
/// come in item id order.
///
/// [deleted] should hold what the device saw before this answer, not the
/// answer's own tombstones: record those with [DeletedItems.recordingAll]
/// after.
List<ItemFinding> compareItems({required Manifest manifest, required DeletedItems deleted, required Iterable<ServerItemState> answer}) {
  final findings = <ItemFinding>[];
  final answered = <String>{};
  for (final item in answer) {
    final key = _hex(item.itemId);
    if (!answered.add(key)) throw const MalformedException('the server answered twice for one item');
    findings.add(_classify(item, manifest.entryFor(item.itemId), deleted.revisionOf(item.itemId)));
  }
  for (final entry in manifest.entries) {
    if (!entry.deleted && !answered.contains(_hex(entry.itemId))) {
      findings.add(ItemFinding(entry.itemId, ItemVerdict.missing, manifestRevision: entry.revision));
    }
  }
  findings.sort((a, b) => _hex(a.itemId).compareTo(_hex(b.itemId)));
  return findings;
}

ItemFinding _classify(ServerItemState item, ManifestEntry? entry, int? seenDeletedAt) {
  ItemFinding finding(ItemVerdict verdict) => ItemFinding(item.itemId, verdict, revision: item.revision, manifestRevision: entry?.revision);

  if (!item.deleted && seenDeletedAt != null) {
    // An id the device saw deleted is back: at or below the tombstone's
    // revision, or with the tombstone gone from the manifest, or with the
    // manifest still listing it deleted. A later live entry the manifest does
    // list (an undelete the writer signed) is the one way through.
    final listedLaterAndLive = entry != null && !entry.deleted && entry.revision > seenDeletedAt;
    if (item.revision <= seenDeletedAt || !listedLaterAndLive) return finding(ItemVerdict.resurrected);
  }
  if (entry == null) return finding(ItemVerdict.unlisted);
  if (item.revision < entry.revision) return finding(ItemVerdict.rolledBack);
  if (item.revision > entry.revision) return finding(ItemVerdict.unlisted);
  final same = item.deleted == entry.deleted && _sameBytes(item.ciphertextHash, entry.ciphertextHash);
  return finding(same ? ItemVerdict.expected : ItemVerdict.sibling);
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

DeletedItem _deletedItem(Object? value) {
  if (value is! Map<String, Object?> || value.length != 2) throw const MalformedException('a deleted item has a revision and a seenAt');
  final revision = value['revision'];
  final seenAt = value['seenAt'];
  if (revision is! int || seenAt is! int) throw const MalformedException('a deleted item has a revision and a seenAt');
  return DeletedItem(revision: revision, seenAt: seenAt);
}

String _checkId(String key) {
  if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(key)) throw MalformedException('not an item id: $key');
  return key;
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}
