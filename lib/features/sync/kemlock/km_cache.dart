/// The sealed cache of a Kemlock Server sync, `backmycodes_kemlock_cache`: the
/// items as this phone last opened them, so a run asks the server only for what
/// changed since its cursor instead of downloading the whole vault every five
/// minutes. It holds, per item id, the revision, the kind, the hash of the
/// ciphertext and the decrypted entry JSON; the cursor; the highest manifest
/// this phone verified; the ids it saw deleted; and the entries recent runs
/// took off this phone, for the removal guard.
///
/// The cursor is stored only at the end of a run, with the merge: a run that
/// dies midway repeats from the old cursor.
///
/// Pure Dart, no Flutter.
library;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/manifest_compare.dart';
import '../../../models/json.dart';
import '../removal_guard.dart' show LostRun;

/// One item as this phone holds it.
class KmCachedItem {
  const KmCachedItem({
    required this.revision,
    required this.kind,
    required this.keyVersion,
    required this.hash,
    this.entry,
    this.entryId,
    this.deletedAt,
    this.heldSince,
    this.opaque = false,
    this.extra = const {},
  });

  factory KmCachedItem.fromJson(Map<String, Object?> json) => KmCachedItem(
    revision: asInt(json['revision']) ?? 0,
    kind: asString(json['kind']),
    keyVersion: asInt(json['keyVersion']) ?? 1,
    hash: asString(json['hash']),
    entry: json['entry'] is Map<String, Object?> ? json['entry']! as Map<String, Object?> : null,
    entryId: asOptionalString(json['entryId']),
    deletedAt: asInt(json['deletedAt']),
    heldSince: asInt(json['heldSince']),
    opaque: json['opaque'] == true,
    extra: extraKeys(json, const {'revision', 'kind', 'keyVersion', 'hash', 'entry', 'entryId', 'deletedAt', 'heldSince', 'opaque'}),
  );

  /// The server's revision of the item.
  final int revision;
  final String kind;
  final int keyVersion;

  /// The base64url SHA-256 of the item's ciphertext, as the manifest lists it; empty for a tombstone,
  /// which the manifest lists with 32 zero bytes.
  final String hash;

  /// The entry's decrypted JSON, null for a tombstone and for an item this version doesn't read.
  final Map<String, Object?>? entry;

  /// The app's id of the entry: of a live item its JSON's `id`, kept on its tombstone so the deletion
  /// reads as the entry's own.
  final String? entryId;

  /// Epoch ms this phone first saw the tombstone: the server dates no deletion. Null for a live item.
  final int? deletedAt;

  /// Epoch ms this phone first saw the item and no signed manifest listed it: it is held, not applied,
  /// until one does.
  final int? heldSince;

  /// An item of a kind or format this version doesn't read, or one that doesn't open: it passes through
  /// untouched, never deleted and never written.
  final bool opaque;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get deleted => hash.isEmpty;

  /// Whether the entry takes part in the merge: live, readable and listed.
  bool get applied => !deleted && !opaque && heldSince == null && entry != null;

  KmCachedItem held(int since) => KmCachedItem(
    revision: revision,
    kind: kind,
    keyVersion: keyVersion,
    hash: hash,
    entry: entry,
    entryId: entryId,
    deletedAt: deletedAt,
    heldSince: heldSince ?? since,
    opaque: opaque,
    extra: extra,
  );

  KmCachedItem listed() => heldSince == null
      ? this
      : KmCachedItem(
          revision: revision,
          kind: kind,
          keyVersion: keyVersion,
          hash: hash,
          entry: entry,
          entryId: entryId,
          deletedAt: deletedAt,
          opaque: opaque,
          extra: extra,
        );

  /// The same item with [json] as its entry: what merging its siblings into it made, until the run writes it.
  KmCachedItem withEntry(Map<String, Object?> json) => KmCachedItem(
    revision: revision,
    kind: kind,
    keyVersion: keyVersion,
    hash: hash,
    entry: json,
    entryId: entryId,
    deletedAt: deletedAt,
    heldSince: heldSince,
    opaque: opaque,
    extra: extra,
  );

  Map<String, Object?> toJson() => {
    'revision': revision,
    'kind': kind,
    'keyVersion': keyVersion,
    'hash': hash,
    'entry': ?entry,
    'entryId': ?entryId,
    'deletedAt': ?deletedAt,
    'heldSince': ?heldSince,
    if (opaque) 'opaque': true,
    ...extra,
  };
}

/// What a Kemlock Server sync keeps between runs.
class KmCache {
  KmCache({
    this.cursor,
    Map<String, KmCachedItem>? items,
    this.manifest,
    this.manifestSignature,
    DeletedItems? deleted,
    List<LostRun>? lost,
    this.knew,
    this.extra = const {},
  }) : items = items ?? {},
       deleted = deleted ?? DeletedItems(),
       lost = lost ?? [];

  /// Reads the stored form. A cache that can't be read is an empty one: the next run downloads everything,
  /// which is slow, not unsafe, since the manifest and the server decide what is real.
  factory KmCache.fromJson(Object? json) {
    if (json is! Map<String, Object?>) return KmCache();
    try {
      final items = json['items'];
      final manifest = json['manifest'];
      return KmCache(
        cursor: asOptionalString(json['cursor']),
        items: {
          if (items is Map<String, Object?>)
            for (final MapEntry(:key, :value) in items.entries)
              if (value is Map<String, Object?>) key: KmCachedItem.fromJson(value),
        },
        manifest: manifest is Map<String, Object?> ? b64urlDecode(asString(manifest['bytes'])) : null,
        manifestSignature: manifest is Map<String, Object?> ? b64urlDecode(asString(manifest['signature'])) : null,
        deleted: json['deleted'] == null ? null : DeletedItems.fromJson(json['deleted']),
        lost: _lost(json['lost']),
        knew: json['knew'] is List ? asStrings(json['knew']) : null,
        extra: extraKeys(json, const {'cursor', 'items', 'manifest', 'deleted', 'lost', 'knew'}),
      );
    } on MalformedException {
      return KmCache();
    }
  }

  /// The opaque cursor of the last page read, sent back unread as `since`; null before the first run.
  String? cursor;

  /// By item id, a UUID.
  final Map<String, KmCachedItem> items;

  /// The highest signed manifest this phone verified, its exact bytes, and the signature over them.
  List<int>? manifest;
  List<int>? manifestSignature;

  /// Every id this phone saw deleted, with that revision, for 180 days: an id that comes back is refused.
  DeletedItems deleted;

  /// The runs that took entries off this phone, for the removal guard.
  List<LostRun> lost;

  /// The kinds of item the version that last stored the cache knew. An item of a kind it didn't know was kept opaque and is read
  /// again once a version that knows the kind runs (see [unreadKnown]). Null for a cache a version that kept no such list stored.
  List<String>? knew;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// A copy a run can change without touching what is stored.
  KmCache copy() => KmCache(
    cursor: cursor,
    items: Map.of(items),
    manifest: manifest,
    manifestSignature: manifestSignature,
    deleted: DeletedItems.fromJson(deleted.toJson()),
    lost: [...lost],
    knew: knew,
    extra: extra,
  );

  /// The ids of the live items this version reads ([knows]) that the cache holds as opaque because the version that stored it
  /// didn't know their kind: the server won't send them again, so a run reads the whole vault once to open them.
  Set<String> unreadKnown(bool Function(String kind) knows) => {
    for (final MapEntry(:key, :value) in items.entries)
      if (!value.deleted && value.opaque && value.entry == null && knows(value.kind) && !(knew ?? const <String>[]).contains(value.kind)) key,
  };

  Map<String, Object?> toJson() => {
    'cursor': ?cursor,
    'items': {for (final MapEntry(:key, :value) in items.entries) key: value.toJson()},
    if (manifest != null && manifestSignature != null)
      'manifest': {'bytes': b64urlEncode(manifest!), 'signature': b64urlEncode(manifestSignature!)},
    'deleted': deleted.toJson(),
    if (lost.isNotEmpty)
      'lost': [
        for (final run in lost) [run.at, run.count],
      ],
    'knew': ?knew,
    ...extra,
  };
}

List<LostRun> _lost(Object? value) => [
  for (final pair in (value as List<Object?>? ?? const []).whereType<List<Object?>>())
    if (pair case [final int at, final int count]) (at: at, count: count),
];
