// What the vault keeps for duplicate matching (the add-duplicate-cleaner
// plan, design 4), as the two sealed values it is written to:
//
// - `backmycodes_dedup`, [DedupCache]: the dedup root, each owner's key
//   version and every item's tags, with the hash of the Public Suffix List
//   the sites were read with. All of it is a cache: remade whenever it is
//   missing, unreadable or made with another list.
// - `backmycodes_dedup_answers`, [DedupAnswers]: the dismissals and the merge
//   records, which can't be remade.
//
// Neither is in an export, a QR transfer, a sync file or a Vaultwarden item:
// they are sealed values of the vault and nothing else reads them. A
// replacement of the vault's key pair seals them again with the rest, and
// deleting the vault deletes them.
library;

import 'dart:typed_data';

import '../../core/ids.dart';
import '../../crypto/account/dedup.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart';
import '../../models/json.dart';
import 'duplicate_rules.dart';
import 'duplicate_tags.dart';

/// The storage key of the cache, under the vault's own suffix.
const keyDedup = 'backmycodes_dedup';

/// The storage key of the answers.
const keyDedupAnswers = 'backmycodes_dedup_answers';

/// The version of both values.
const dedupFormat = 1;

/// The slot of the vault's own items among the owners.
const vaultSlot = 'vault';

/// The slot of the items of the space with the app's id [spaceId].
String spaceSlot(String spaceId) => 'space:$spaceId';

/// One item's tags and the change time ([at], epoch ms) they were made for.
final class DedupItemTags {
  const DedupItemTags(this.at, this.tags);

  /// Reads `{"at": ms, "tags": ["cred:<base64url>", ...]}`; null for anything else.
  static DedupItemTags? fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      return null;
    }
    final at = json['at'];
    final tags = json['tags'];
    if (at is! int || tags is! List<Object?>) {
      return null;
    }
    final read = <DuplicateTag>[];
    for (final text in tags) {
      final tag = text is String ? _readTag(text) : null;
      if (tag == null) {
        return null;
      }
      read.add(tag);
    }
    return DedupItemTags(at, read);
  }

  final int at;
  final List<DuplicateTag> tags;

  Map<String, Object?> toJson() => {
    'at': at,
    'tags': [for (final tag in tags) '${tag.kind.name}:${b64urlEncode(tag.bytes)}'],
  };

  static DuplicateTag? _readTag(String text) {
    final colon = text.indexOf(':');
    if (colon < 0) {
      return null;
    }
    final kinds = TagKind.values.where((kind) => kind.name == text.substring(0, colon));
    if (kinds.isEmpty) {
      return null;
    }
    try {
      return DuplicateTag(kinds.first, b64urlDecode(text.substring(colon + 1)));
    } on MalformedException {
      return null;
    } on ArgumentError {
      return null;
    }
  }
}

/// One owner's tags: the key version they were made under, a check of the dedup key that made them
/// (so a changed key, which the cache doesn't hold, is noticed) and the tags by item id.
final class DedupOwnerTags {
  const DedupOwnerTags({required this.version, required this.check, this.items = const {}});

  /// Reads an owner's entry; null for anything else.
  static DedupOwnerTags? fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      return null;
    }
    final version = json['version'];
    final check = json['check'];
    final items = json['items'];
    if (version is! int || check is! String || items is! Map<String, Object?>) {
      return null;
    }
    final read = <String, DedupItemTags>{};
    for (final MapEntry(:key, :value) in items.entries) {
      final tags = DedupItemTags.fromJson(value);
      if (tags == null) {
        return null;
      }
      read[key] = tags;
    }
    return DedupOwnerTags(version: version, check: check, items: read);
  }

  final int version;

  /// `b64url` of the tag of `["check"]` under the dedup key, which no item makes.
  final String check;
  final Map<String, DedupItemTags> items;

  DedupOwnerTags withItems(Map<String, DedupItemTags> next) => DedupOwnerTags(version: version, check: check, items: next);

  Map<String, Object?> toJson() => {
    'version': version,
    'check': check,
    'items': {for (final MapEntry(:key, :value) in items.entries) key: value.toJson()},
  };
}

/// The cache, `backmycodes_dedup`: `{"v": 1, "root", "rootId", "list", "owners": {slot: {...}}}`.
///
/// The root is 32 random bytes and [rootId] is a random UUID that stands in for the account id
/// until there is one: the vault's owner bytes are `0x01` and that UUID (design 1).
final class DedupCache {
  DedupCache({required this.root, required this.rootId, required this.listHash, this.owners = const {}});

  /// A cache with a new root and nothing tagged, made at the first match.
  factory DedupCache.fresh(String listHash) => DedupCache(root: randomBytes(dedupKeyLength), rootId: newUuid(), listHash: listHash);

  /// Reads the stored value; null when it isn't a cache this version reads, which is then made again.
  static DedupCache? fromJson(Object? json) {
    if (json is! Map<String, Object?> || json['v'] != dedupFormat) {
      return null;
    }
    final root = json['root'];
    final rootId = json['rootId'];
    final list = json['list'];
    final owners = json['owners'];
    if (root is! String || rootId is! String || list is! String || owners is! Map<String, Object?> || !isUuidText(rootId)) {
      return null;
    }
    final Uint8List rootBytes;
    try {
      rootBytes = requireLength(b64urlDecode(root), dedupKeyLength, 'the dedup root');
    } on MalformedException {
      return null;
    }
    final read = <String, DedupOwnerTags>{};
    for (final MapEntry(:key, :value) in owners.entries) {
      final owner = DedupOwnerTags.fromJson(value);
      if (owner == null) {
        return null;
      }
      read[key] = owner;
    }
    return DedupCache(root: rootBytes, rootId: rootId, listHash: list, owners: read);
  }

  /// The random 32-byte dedup root, the key of the vault's own items. Never leaves the sealed value.
  final Uint8List root;
  final String rootId;

  /// The hash of the Public Suffix List the sites were read with.
  final String listHash;
  final Map<String, DedupOwnerTags> owners;

  Map<String, Object?> toJson() => {
    'v': dedupFormat,
    'root': b64urlEncode(root),
    'rootId': rootId,
    'list': listHash,
    'owners': {for (final MapEntry(:key, :value) in owners.entries) key: value.toJson()},
  };

  @override
  String toString() => 'DedupCache(${owners.keys.join(', ')})';
}

/// What the person answered, `backmycodes_dedup_answers`: `{"v": 1, "dismissed": [], "merges": []}`.
/// The groups they dismissed and the records of the merges they made, which tasks 5 and 6 give their
/// shape. Keys this version doesn't know are kept as they were. It can't be made again, so it is
/// kept apart from the cache.
final class DedupAnswers {
  const DedupAnswers({this.dismissed = const [], this.merges = const [], this.extra = const {}});

  /// Reads the stored value; an empty one when it isn't an object.
  factory DedupAnswers.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      return const DedupAnswers();
    }
    final dismissed = json['dismissed'];
    final merges = json['merges'];
    return DedupAnswers(
      dismissed: dismissed is List<Object?> ? [...dismissed] : const [],
      merges: merges is List<Object?> ? [...merges] : const [],
      extra: extraKeys(json, const {'v', 'dismissed', 'merges'}),
    );
  }

  final List<Object?> dismissed;
  final List<Object?> merges;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isEmpty => dismissed.isEmpty && merges.isEmpty && extra.isEmpty;

  Map<String, Object?> toJson() => {'v': dedupFormat, 'dismissed': dismissed, 'merges': merges, ...extra};
}
