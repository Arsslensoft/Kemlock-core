/// What the move's steps share of the Kemlock API: reading the whole vault from an empty cursor into the
/// cache's form, sealing and sending a batch, and the errors a move stops with
/// (move-off-vaultwarden-sync, designs 3 and 4).
///
/// The server has no route for one item (`GET /items/{id}` is not served), so a step that must know what
/// is stored reads the vault through `GET /kem/v1/sync` and opens each item with the account crypto, as a
/// Kemlock sync does. A batch is all or none: a 409 `stale-revision` stores nothing, and the step reads
/// again and decides each item afresh.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/kem1.dart';
import 'km_api.dart';
import 'km_cache.dart';
import 'km_crypto.dart';
import 'km_dedup.dart';
import 'km_kinds.dart';

/// Why a move stopped. The names are the ends of the message ids a sheet says them with.
enum KmMoveIssue {
  /// An item on the server under an id this move writes can't be read here: it isn't a `kem1` item of
  /// this account, or it doesn't open.
  unreadable,

  /// A file a note names is neither on the phone nor on the Kemlock API, or the server refused it.
  fileMissing,

  /// The vault read back differs from what was sent: an item missing or different, a manifest that
  /// doesn't list it, or a file that doesn't match. The next attempt sends what differs.
  checkFailed,

  /// The record belongs to a newer build of Kemlock.
  newer,
}

/// A move that stopped before changing anything in the old store.
class KmMoveError implements Exception {
  const KmMoveError(this.issue, {this.detail, this.ids = const []});

  final KmMoveIssue issue;

  /// Which note, file or item, for logs and for the screen that names the note.
  final String? detail;

  /// For [KmMoveIssue.checkFailed]: the entry ids that differ or are missing.
  final List<String> ids;

  @override
  String toString() => 'KmMoveError(${issue.name}${detail != null ? ': $detail' : ''}${ids.isNotEmpty ? ', ${ids.length} entries' : ''})';
}

/// A write of a batch: [json] is the entry, [expected] the revision it replaces or null for a new item.
class KmMoveWrite {
  const KmMoveWrite({
    required this.itemId,
    required this.entryId,
    required this.kind,
    required this.revision,
    required this.json,
    this.expected,
  });

  final String itemId;
  final String entryId;
  final String kind;
  final int revision;
  final int? expected;
  final Map<String, Object?> json;
}

/// The Kemlock API as the move's steps use it.
class KmMoveServer {
  KmMoveServer({required this.connection, required this.server, required this.crypto, this.tags});

  final KmConnection connection;
  final Uri server;
  final KmItemCrypto crypto;

  /// The `cred` tags of the move's batches, when the person turned server matching on for the vault (`km_dedup.dart`):
  /// the move's writes go through the same provider a sync's do, so a login moved in carries its tags. Null sends none.
  final KmCredTags? tags;

  KmApi get api => connection.api;

  /// Every item of the account, read from an empty cursor: opened into [KmCachedItem]s, an item this
  /// version can't read marked opaque, with the cursor of the last page. A cursor the server stops
  /// trusting midway starts the read again once.
  Future<KmCache> read() async {
    for (var again = false; ; again = true) {
      final items = <String, KmCachedItem>{};
      String? since;
      String? cursor;
      try {
        while (true) {
          final page = await connection.call((token) => api.sync(server, token, since: since));
          if (page == null) break;
          for (final wire in page.items) {
            items[wire.id] = await _open(wire);
          }
          cursor = page.cursor;
          if (!page.more) break;
          since = page.cursor;
        }
      } on KmError catch (e) {
        if (e.problem == KmProblem.fullSync && !again) continue;
        rethrow;
      }
      return KmCache(cursor: cursor, items: items);
    }
  }

  Future<KmCachedItem> _open(KmWireItem wire) async {
    if (wire.deleted) {
      return KmCachedItem(revision: wire.revision, kind: wire.kind, keyVersion: wire.keyVersion, hash: '', deletedAt: wire.deletedAt);
    }
    final sum = b64urlEncode(hash.sha256.convert(wire.ciphertext!).bytes);
    KmCachedItem opaque() => KmCachedItem(revision: wire.revision, kind: wire.kind, keyVersion: wire.keyVersion, hash: sum, opaque: true);
    if (wire.owner != crypto.owner.toWire() || !wire.isKem1 || !kmKnowsKind(wire.kind)) return opaque();
    try {
      final json = jsonDecode(utf8.decode(await crypto.openItem(wire.toKem1())));
      if (!kmReadable(wire.kind, json, wire.id, crypto.owner)) return opaque();
      final entry = json as Map<String, Object?>;
      return KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: sum,
        entry: entry,
        entryId: entry['id'] as String,
      );
    } catch (e) {
      if (e is CorruptedException || e is MalformedException || e is FormatException) return opaque();
      rethrow;
    }
  }

  /// Seals [writes] and sends them as one batch of at most [KmApi.batchSize], all or none. A stale write
  /// throws a `stale` [KmError]; nothing was stored. Returns the items as stored.
  Future<List<KmWireItem>> send(List<KmMoveWrite> writes) async {
    final sealed = [for (final write in writes) await _seal(write)];
    final tagged = kmWriteTags(tags, [for (final write in writes) (itemId: write.itemId, kind: write.kind, json: write.json)]);
    return (await connection.call((token) => api.batchTagged(server, token, sealed, tags: tagged))).items;
  }

  Future<KmWrite> _seal(KmMoveWrite write) async {
    final owner = crypto.owner;
    final sealed = await crypto.sealItem(
      itemId: write.itemId,
      revision: write.revision,
      kind: write.kind,
      plaintext: Uint8List.fromList(utf8.encode(jsonEncode(write.json))),
    );
    return (
      expected: write.expected,
      item: Kem1Item(
        id: write.itemId,
        owner: owner,
        kind: write.kind,
        revision: write.revision,
        keyVersion: crypto.keyVersion,
        ciphertext: sealed.ciphertext,
        itemKey: sealed.itemKey,
      ),
    );
  }
}
