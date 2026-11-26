/// One run of Kemlock Server sync for the vault's own entries: a scope of its
/// own, `kemlockScope` (add-kemlock-server-sync, design 2). A run:
///
/// 1. loads the sealed cache: the items as this phone last opened them, the
///    cursor, the highest manifest seen and the removal counts;
/// 2. reads `GET /kem/v1/sync?since=<cursor>` page by page and opens each item
///    into a copy of the cache. A tombstone removes the cached item. The server
///    dates no deletion, so it is dated by this phone's last sync before it saw
///    it, never after now: an edit made here since then outlives it, as an edit
///    after a deletion does. An item of a kind this version doesn't know, or
///    that doesn't open, stays in the cache untouched. Then the account's signed
///    manifest is checked against the whole answer: a rolled-back, missing or
///    resurrected item, or a manifest that fails, stops the run as older data
///    before anything is stored, and an item no manifest lists is held out of
///    the merge until one does. The versions a federated vault holds beside an
///    item's head (`siblings` on the page) are merged into the head here, with
///    the same field merge, and the item is written once more whatever the
///    merge changed;
/// 3. builds the remote `SyncDoc` from the cache and runs
///    `mergeScope(await combineKeyCopies(local, remote), known, remote)`, as
///    `syncScope` does for WebDAV;
/// 4. diffs the merged document against the remote into puts and deletes, and
///    runs the removal guard (`removal_guard.dart`, shared with Vaultwarden);
/// 5. seals each put and sends `POST /kem/v1/items:batch` in chunks of up to
///    500, each write guarded by the revision it replaces, or create-if-absent
///    for a new id. Ids are made on the phone, so a resent batch never
///    duplicates. Puts go before deletes, so a run cut short never leaves less
///    than it found. An item whose siblings were merged is then resolved
///    (`POST /kem/v1/items/{id}/siblings/resolve`), which drops them;
/// 6. on a 409, starts again from the stored cursor: the delta then holds
///    what the other device wrote, and what this run already stored is the
///    same item. Three attempts, as `syncScope` makes;
/// 7. when the run wrote anything, signs one manifest of the merged state and
///    sends it after the last batch;
/// 8. stores the cache, with the new cursor, last.
///
/// The cursor is stored only in step 8. A run that dies midway repeats from the
/// old cursor.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:math' show max, min;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/kem1.dart';
import '../../../crypto/account/manifest.dart';
import '../../../crypto/account/manifest_compare.dart';
import '../../spaces/space_head_store.dart' show SpaceAnchors;
import '../removal_guard.dart';
import '../sync.dart';
import '../sync_merge.dart';
import 'km_api.dart';
import 'km_backend.dart';
import 'km_cache.dart';
import 'km_crypto.dart';
import 'km_dedup.dart';
import 'km_files.dart';
import 'km_kinds.dart';
import 'km_models.dart';

/// Why a Kemlock Server sync stopped before changing anything. The names are the ends of the
/// `sync.problem.*` message ids where a sheet says them.
enum KmSyncIssue {
  /// The server handed back an older copy of the vault than this phone already saw: a rolled-back,
  /// missing or resurrected item, a manifest that fails, or an item no signed manifest lists for over
  /// a day. Nothing was stored.
  older,

  /// The run would remove many entries; the user decides.
  removals,
}

/// A sync that stopped before changing anything, and why.
class KmSyncError implements Exception {
  const KmSyncError(this.issue, {this.count = 0, this.detail});

  final KmSyncIssue issue;

  /// For [KmSyncIssue.removals]: how many entries would go.
  final int count;

  /// Which item or rule, for logs.
  final String? detail;

  @override
  String toString() => 'KmSyncError(${issue.name}${count > 0 ? ', $count' : ''}${detail != null ? ': $detail' : ''})';
}

/// How many attempts a run gets when items keep changing under it.
const _attempts = 3;

/// How long an item no signed manifest lists may be held before it is a problem: another device signs
/// a manifest at the end of the run that wrote it, so a held item is normally listed by the next sync.
const _heldLimit = Duration(hours: 24);

/// A write a run sends: [json] null makes a tombstone.
class _Write {
  _Write({required this.id, required this.kind, required this.revision, this.expected, this.json});

  final String id;
  final String kind;
  final int revision;
  final int? expected;
  final Map<String, Object?>? json;
}

/// The anchors of the account's server spaces as the vault holds them, for a run to carry to the server and back
/// (`space_head_store.dart`): the item [KmKind.spaceAnchors] holds the same value the vault's sync carries on
/// WebDAV.
class KmAnchors {
  const KmAnchors({required this.load, required this.save});

  /// The anchors in their stored form, or null when the vault holds none. Throws when they can't be read: the run
  /// then leaves the item alone, and never writes over what it couldn't read.
  final Future<Map<String, Object?>?> Function() load;

  /// Keeps [anchors], the merge of the vault's and the server's.
  final Future<void> Function(Map<String, Object?> anchors) save;
}

/// Syncs a vault's own entries with one server.
class KmScopeSync {
  KmScopeSync({
    required this.connection,
    required this.server,
    required this.crypto,
    required this.loadCache,
    required this.saveCache,
    this.files,
    this.anchors,
    this.dedup,
    this.clock = DateTime.now,
  });

  final KmConnection connection;
  final Uri server;
  final KmItemCrypto crypto;

  /// Server matching for the vault, when the person turned it on: a run then reads the server's switch and key version,
  /// sends each login's `cred` tags beside its write, gives the tags of the logins the server holds none for, and
  /// reports the server's groups. Null leaves the run as it was: no tag leaves the phone.
  final KmDedup? dedup;

  /// The vault's matching for the run that is going, open while it goes (null when it is off or there is none).
  KmMatching? _matching;

  /// Reads the sealed cache; an empty one when there is none.
  final Future<KmCache> Function() loadCache;

  /// Stores the cache, sealed.
  final Future<void> Function(KmCache cache) saveCache;

  /// The vault's attached files, synced beside their notes' items; without them, notes sync without their files.
  final KmFiles? files;

  /// The anchors of the account's server spaces, carried in an item of their own; without it, none are carried.
  final KmAnchors? anchors;
  final DateTime Function() clock;

  KmApi get _api => connection.api;

  /// Runs once, again when items changed under it. [local] is this phone's entries in the scope and
  /// [state] what the last run kept. Throws a [KmSyncError] when it stops before changing anything and a
  /// [KmError] when the server can't be reached or refuses.
  Future<KmSyncResult> sync(KemlockTarget target, Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    for (var attempt = 1; ; attempt++) {
      try {
        return await _run(local, state, now: now, choice: choice);
      } on KmError catch (e) {
        // Another device wrote an item meanwhile: read it and merge again
        if (e.problem == KmProblem.stale && attempt < _attempts) continue;
        rethrow;
      }
    }
  }

  Future<KmSyncResult> _run(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final dedup = this.dedup;
    _matching = dedup == null ? null : await KmMatching.open(connection, server, dedup, crypto.owner.toWire());
    try {
      return await _runWith(local, state, now: now, choice: choice);
    } finally {
      _matching?.dispose();
      _matching = null;
    }
  }

  Future<KmSyncResult> _runWith(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final stored = await loadCache();
    final work = stored.copy();
    // A deletion first seen now happened after the last sync that didn't see it
    final seenAt = min(now, state.lastSyncAt ?? now);
    final siblings = await _pull(work, seenAt);
    await _checkManifest(work, stored, now);
    final joined = await _mergeSiblings(work, siblings, now, seenAt);

    final owner = crypto.owner;
    final localEntries = kmEntriesOf(local);
    final idByUuid = {
      for (final entry in localEntries)
        if (kmEntryId(entry).isNotEmpty) kmItemId(kmEntryId(entry), owner): kmEntryId(entry),
    };
    final keepAll = choice == RemovalChoice.keep;
    final remote = kmDocOf(
      [
        for (final item in work.items.values)
          if (item.applied) (kind: item.kind, json: item.entry!),
      ],
      deleted: keepAll
          ? const []
          : [
              for (final MapEntry(:key, :value) in work.items.entries)
                if (value.deleted && value.heldSince == null)
                  Tombstone(id: value.entryId ?? idByUuid[key] ?? key, at: min(value.deletedAt ?? now, now)),
              ...joined.tombstones,
            ],
    );
    final merged = mergeScope(await combineKeyCopies(local, remote), keepAll ? const [] : state.known, remote, now: now);

    final plan = _plan(work, local, merged.doc, forced: joined.ids);
    final guard = checkRemovals(
      removals: plan.removals,
      removedHere: plan.removedHere,
      scope: plan.scope,
      recent: lostLately({
        lostKey: [
          for (final run in work.lost) [run.at, run.count],
        ],
      }, now),
      now: now,
      choice: choice,
    );
    if (guard.stop) throw KmSyncError(KmSyncIssue.removals, count: plan.removals);
    work.lost = guard.lostNow;

    var doc = merged.doc;
    var wrote = await _send(work, plan.writes, now);
    await _resolve(joined.ids, plan.writes);
    final files = this.files;
    if (files != null) {
      // A file goes up once its note's or File item's item is on the server, and the item is written again naming it
      final stamped = await files.upload(
        doc,
        now: now,
        itemIdOf: (id) => kmItemId(id, owner),
        onServer: (itemId) => work.items[itemId]?.applied ?? false,
      );
      if (stamped != null) {
        doc = stamped;
        wrote = await _send(work, _plan(work, local, doc).writes, now) || wrote;
      }
      await files.deleteRemoved(_fileIds(stored), _fileIds(work));
    }
    wrote = await _syncAnchors(work, now) || wrote;
    // A deletion is kept as long as the server keeps tombstones
    work.items.removeWhere((_, item) => item.deleted && (item.deletedAt ?? now) < now - tombstoneTtlMs);
    if (wrote) await _signManifest(work);

    final at = DateTime.fromMillisecondsSinceEpoch(now);
    work.deleted = work.deleted
        .recordingAll(
          answer: [
            for (final MapEntry(:key, :value) in work.items.entries)
              if (value.deleted) ServerItemState.tombstone(itemId: uuidBytes(key), revision: value.revision),
          ],
          now: at,
        )
        .pruned(at);
    await _tagStored(work, now);
    await saveCache(work);
    // Outside what the run must get right: a file that can't be fetched now is tried again at the next run
    await files?.download(doc, itemIdOf: (id) => kmItemId(id, owner));

    return (
      doc: doc,
      known: merged.known,
      state: state.extra,
      skipped: work.items.values.where((item) => item.kind != KmKind.spaceAnchors && (item.opaque || item.heldSince != null)).length,
    );
  }

  /// Carries the anchors: the union of this vault's and the server's item (`SpaceAnchors.mergedWith`), written to the
  /// item when it differs from the server's and kept in the vault when it differs from what it held. The item is
  /// owned by the user and its id is the same on every device of the account. A copy that can't be read, an item
  /// no manifest lists yet or one of another format is left alone: the run writes nothing over what it can't read.
  /// Returns whether it wrote.
  Future<bool> _syncAnchors(KmCache work, int now) async {
    final hook = anchors;
    if (hook == null) {
      return false;
    }
    final Map<String, Object?>? ours;
    try {
      ours = await hook.load();
    } catch (_) {
      return false;
    }
    final id = kmItemId(kmSpaceAnchorsEntryId, crypto.owner);
    final cached = work.items[id];
    final Map<String, Object?>? theirs;
    if (cached == null || cached.deleted) {
      theirs = null;
    } else if (cached.kind == KmKind.spaceAnchors && cached.entry != null && cached.heldSince == null) {
      theirs = cached.entry;
    } else {
      return false;
    }
    if (ours == null && theirs == null) {
      return false;
    }
    final Map<String, Object?> merged;
    try {
      merged = SpaceAnchors.mergeValues(ours, theirs);
    } on MalformedException {
      return false;
    }
    var wrote = false;
    if (theirs == null || canonical(merged) != canonical(theirs)) {
      final write = _Write(
        id: id,
        kind: KmKind.spaceAnchors,
        revision: (cached?.revision ?? 0) + 1,
        expected: cached?.revision,
        json: merged,
      );
      wrote = await _send(work, [write], now);
    }
    if (ours == null || canonical(merged) != canonical(ours)) {
      try {
        await hook.save(merged);
      } catch (_) {
        // The next run merges again and keeps it
      }
    }
    return wrote;
  }

  // ─── Step 2: the delta ─────────────────────────────────────────────────

  /// Reads every page since the cursor into [work]; returns the sets of siblings the last page listed.
  Future<List<KmSiblingSet>> _pull(KmCache work, int seenAt) async {
    var since = work.cursor;
    var full = false;
    var siblings = const <KmSiblingSet>[];
    while (true) {
      final KmSyncPage? page;
      try {
        page = await connection.call((token) => _api.sync(server, token, since: since));
      } on KmError catch (e) {
        // A cursor the server no longer trusts: read everything again, once
        if (e.problem == KmProblem.fullSync && since != null && !full) {
          since = null;
          work.cursor = null;
          full = true;
          continue;
        }
        rethrow;
      }
      // Nothing changed
      if (page == null) {
        return siblings;
      }
      for (final item in page.items) {
        await _apply(work, item, seenAt);
      }
      work.cursor = page.cursor;
      siblings = page.siblings;
      if (!page.more) {
        return siblings;
      }
      since = page.cursor;
    }
  }

  Future<void> _apply(KmCache work, KmWireItem wire, int seenAt) async {
    final existing = work.items[wire.id];
    final sum = wire.deleted ? '' : b64urlEncode(hash.sha256.convert(wire.ciphertext!).bytes);
    if (existing != null) {
      // An older revision than this phone holds: the server rolled the item back
      if (wire.revision < existing.revision) {
        throw KmSyncError(KmSyncIssue.older, detail: 'item ${wire.id} at ${wire.revision}, held at ${existing.revision}');
      }
      // The same item again, as this run's own writes come back in the next delta
      if (wire.revision == existing.revision && sum == existing.hash) return;
    }
    if (wire.deleted) {
      work.items[wire.id] = KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: '',
        entryId: existing?.entryId,
        // The server's own date when it gives one; else the last sync before this phone saw the deletion
        deletedAt: wire.deletedAt ?? existing?.deletedAt ?? seenAt,
      );
      return;
    }
    work.items[wire.id] = await _open(wire, sum, existing);
  }

  /// The item as the cache holds it: its entry opened, or marked opaque when this version doesn't read it
  /// (another owner, another format, a kind it doesn't know, an item that doesn't open or whose entry's
  /// id isn't the item's).
  Future<KmCachedItem> _open(KmWireItem wire, String sum, KmCachedItem? existing) async {
    KmCachedItem opaque() => KmCachedItem(
      revision: wire.revision,
      kind: wire.kind,
      keyVersion: wire.keyVersion,
      hash: sum,
      opaque: true,
      heldSince: existing?.heldSince,
    );
    // The anchors item is no entry: its plaintext is kept in the cache, and the item stays opaque to the merge
    final isAnchors = wire.kind == KmKind.spaceAnchors && wire.id == kmItemId(kmSpaceAnchorsEntryId, crypto.owner);
    if (wire.owner != crypto.owner.toWire() || !wire.isKem1 || (!kmKnowsKind(wire.kind) && !isAnchors)) return opaque();
    try {
      final json = jsonDecode(utf8.decode(await crypto.openItem(wire.toKem1())));
      if (isAnchors) {
        if (json is! Map<String, Object?>) {
          return opaque();
        }
        // A value this version can't read (a later format) stays as it is
        SpaceAnchors.fromJson(json);
        return KmCachedItem(
          revision: wire.revision,
          kind: wire.kind,
          keyVersion: wire.keyVersion,
          hash: sum,
          entry: json,
          opaque: true,
          heldSince: existing?.heldSince,
        );
      }
      if (!kmReadable(wire.kind, json, wire.id, crypto.owner)) return opaque();
      final entry = json as Map<String, Object?>;
      return KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: sum,
        entry: entry,
        entryId: entry['id'] as String,
        heldSince: existing?.heldSince,
      );
    } catch (e) {
      if (e is CorruptedException || e is MalformedException || e is FormatException) return opaque();
      rethrow;
    }
  }

  // ─── Siblings ──────────────────────────────────────────────────────────

  /// Merges each item's siblings into its head, on this phone, with the field merge every sync uses: a head that
  /// is live and readable here is merged with each live sibling it can open (the head wins a tie), and a deleted
  /// sibling takes part as a deletion at the time the server dated it, which an edit made after it outlives. The
  /// merge is put in the cache's copy of the head, so the run's merge sees it as the server's copy, and the item
  /// is written as the next revision whatever the merge changed, as the server wants before it drops the siblings.
  ///
  /// A set is left for a version of this app that can read it when its head isn't a live, listed entry here, or a
  /// version is another kind, another entry, or doesn't open.
  Future<({Set<String> ids, List<Tombstone> tombstones})> _mergeSiblings(KmCache work, List<KmSiblingSet> sets, int now, int seenAt) async {
    final ids = <String>{};
    final tombstones = <Tombstone>[];
    for (final set in sets) {
      final head = work.items[set.itemId];
      if (head == null || !head.applied) {
        continue;
      }
      var ours = (kind: head.kind, json: head.entry!);
      final gone = <Tombstone>[];
      var readable = true;
      for (final version in set.versions) {
        if (version.kind != head.kind) {
          readable = false;
          break;
        }
        if (version.deleted) {
          gone.add(Tombstone(id: head.entryId!, at: min(version.deletedAt ?? seenAt, now)));
          continue;
        }
        final opened = await _open(version, b64urlEncode(hash.sha256.convert(version.ciphertext!).bytes), null);
        if (!opened.applied || opened.entryId != head.entryId) {
          readable = false;
          break;
        }
        ours = (kind: head.kind, json: await _joined(ours, (kind: head.kind, json: opened.entry!), now));
      }
      if (!readable) {
        continue;
      }
      work.items[set.itemId] = head.withEntry(ours.json);
      ids.add(set.itemId);
      tombstones.addAll(gone);
    }
    return (ids: ids, tombstones: tombstones);
  }

  /// [ours] and [theirs], two versions of one entry, as one: `mergeScope`'s, with the key copies combined first.
  Future<Map<String, Object?>> _joined(KmEntry ours, KmEntry theirs, int now) async {
    final remote = kmDocOf([theirs]);
    final merged = mergeScope(await combineKeyCopies(kmDocOf([ours]), remote), const [], remote, now: now);
    final entries = kmEntriesOf(merged.doc);
    return entries.length == 1 ? entries.single.json : ours.json;
  }

  /// Tells the server that each item of [ids] that this run wrote now replaces its siblings. One it can't resolve
  /// yet (its head was already sent to another server) keeps them, and the next run merges them again into a
  /// newer version.
  Future<void> _resolve(Set<String> ids, List<_Write> writes) async {
    final written = {for (final write in writes) write.id};
    for (final id in ids) {
      if (!written.contains(id)) {
        continue;
      }
      await connection.call((token) => _api.resolveSiblings(server, token, id));
    }
  }

  // ─── Step 3: the manifest ──────────────────────────────────────────────

  /// Sorts the whole answer (the cache after the delta) against the account's latest signed manifest and
  /// the ids this phone saw deleted. A rolled-back, missing or resurrected item, a manifest whose
  /// signature or counter fails, and an item left unlisted for over a day stop the run as older data.
  /// An item no manifest lists is held, and one a manifest lists again is let in.
  Future<void> _checkManifest(KmCache work, KmCache stored, int now) async {
    final fetched = await connection.call((token) => _api.manifest(server, token, crypto.owner.toWire()));
    final record = _record(stored);
    Manifest? candidate;
    if (fetched != null) {
      try {
        candidate = await crypto.verifyManifest(fetched.manifest, fetched.signature);
      } on CorruptedException {
        throw const KmSyncError(KmSyncIssue.older, detail: 'the manifest does not verify');
      } on MalformedException {
        throw const KmSyncError(KmSyncIssue.older, detail: 'the manifest is malformed');
      }
    } else if (record != null) {
      throw const KmSyncError(KmSyncIssue.older, detail: 'the server no longer has the manifest it had');
    }
    var current = candidate ?? record?.manifest ?? Manifest(owner: crypto.owner, counter: 0, entries: const []);
    if (candidate != null) {
      switch (checkManifest(record, candidate)) {
        case ManifestVerdict.rolledBack:
          throw const KmSyncError(KmSyncIssue.older, detail: 'the manifest counts less than one this phone verified');
        case ManifestVerdict.newer:
          work.manifest = fetched!.manifest;
          work.manifestSignature = fetched.signature;
        case ManifestVerdict.same:
          break;
        case ManifestVerdict.fork:
          // Two devices signed one counter: the higher revision of each item, and the next write signs above both
          current = mergeSameCounter(record!.manifest, candidate);
      }
    }
    final answer = [
      for (final MapEntry(:key, :value) in work.items.entries)
        ServerItemState(
          itemId: uuidBytes(key),
          revision: value.revision,
          ciphertextHash: value.deleted ? Uint8List(32) : b64urlDecode(value.hash),
          deleted: value.deleted,
        ),
    ];
    for (final finding in compareItems(manifest: current, deleted: stored.deleted, answer: answer)) {
      final id = uuidText(finding.itemId);
      switch (finding.verdict) {
        case ItemVerdict.rolledBack || ItemVerdict.missing || ItemVerdict.resurrected:
          throw KmSyncError(KmSyncIssue.older, detail: '${finding.verdict.name} item $id');
        case ItemVerdict.unlisted:
          work.items[id] = work.items[id]!.held(now);
        case ItemVerdict.expected || ItemVerdict.sibling:
          work.items[id] = work.items[id]!.listed();
      }
    }
    // Only a key holder could seal it, but a device signed out, or a server replaying old envelopes, must not add items
    for (final MapEntry(:key, :value) in work.items.entries) {
      final since = value.heldSince;
      if (since != null && now - since > _heldLimit.inMilliseconds) {
        throw KmSyncError(KmSyncIssue.older, detail: 'item $key unlisted since $since');
      }
    }
  }

  ManifestRecord? _record(KmCache cache) {
    final bytes = cache.manifest;
    if (bytes == null) return null;
    try {
      return ManifestRecord(Manifest.parse(bytes));
    } on MalformedException {
      return null;
    }
  }

  /// Signs one manifest of the merged state, above every counter this phone saw, and sends it after the
  /// last batch. Held items are not listed: this phone doesn't vouch for what no manifest listed.
  Future<void> _signManifest(KmCache work) async {
    final record = _record(work);
    final manifest = Manifest(
      owner: crypto.owner,
      counter: (record?.counter ?? 0) + 1,
      entries: [
        for (final MapEntry(:key, :value) in work.items.entries)
          if (value.heldSince == null)
            ManifestEntry(
              itemId: uuidBytes(key),
              revision: value.revision,
              ciphertextHash: value.deleted ? Uint8List(32) : b64urlDecode(value.hash),
              deleted: value.deleted,
            ),
      ],
    );
    final signed = await crypto.signManifest(manifest);
    await connection.call((token) => _api.putManifest(server, token, crypto.owner.toWire(), signed.bytes, signed.signature));
    work.manifest = signed.bytes;
    work.manifestSignature = signed.signature;
  }

  // ─── Step 4: the diff ──────────────────────────────────────────────────

  ({List<_Write> writes, int removals, int removedHere, int scope}) _plan(
    KmCache work,
    Lists local,
    SyncDoc merged, {
    Set<String> forced = const {},
  }) {
    final owner = crypto.owner;
    final puts = <_Write>[];
    final deletes = <_Write>[];
    final liveIds = <String>{};
    for (final entry in kmEntriesOf(merged)) {
      final id = kmEntryId(entry);
      if (id.isEmpty) continue;
      liveIds.add(id);
      final uuid = kmItemId(id, owner);
      final cached = work.items[uuid];
      // What this version can't read or hasn't a signed listing for is left as it is
      if (cached != null && (cached.opaque || cached.heldSince != null)) continue;
      // An item whose siblings were merged is written even when the merge changed nothing: the server drops its
      // siblings only for a head written after it listed them
      if (cached != null && cached.applied && !forced.contains(uuid) && canonical(cached.entry) == canonical(entry.json)) continue;
      puts.add(
        _Write(
          id: uuid,
          kind: cached?.kind ?? entry.kind,
          revision: (cached?.revision ?? 0) + 1,
          expected: cached?.revision,
          json: entry.json,
        ),
      );
    }
    for (final tomb in merged.deleted) {
      if (tomb.id.isEmpty || liveIds.contains(tomb.id)) continue;
      final uuid = kmItemId(tomb.id, owner);
      final cached = work.items[uuid];
      if (cached == null || !cached.applied) continue;
      deletes.add(_Write(id: uuid, kind: cached.kind, revision: cached.revision + 1, expected: cached.revision));
    }
    final localIds = {...local.ids};
    final remoteIds = {
      for (final item in work.items.values)
        if (item.applied) item.entryId!,
    };
    final mergedIds = {...merged.ids};
    return (
      writes: [...puts, ...deletes],
      removals: {...localIds, ...remoteIds}.difference(mergedIds).length,
      removedHere: localIds.difference(mergedIds).length,
      scope: max(localIds.length, remoteIds.length),
    );
  }

  /// The server's file ids each applied note or File item of [cache] names, by its item id.
  Map<String, Set<String>> _fileIds(KmCache cache) => {
    for (final MapEntry(:key, :value) in cache.items.entries)
      if ((value.kind == KmKind.note || value.kind == KmKind.file) && value.applied)
        key: {
          if (value.entry!['attachments'] case final List<Object?> files)
            for (final file in files.whereType<Map<String, Object?>>())
              if (file[kmFileKey] case final String id when id.isNotEmpty) id,
          if (value.entry!['file'] case final Map<String, Object?> file)
            if (file[kmFileKey] case final String id when id.isNotEmpty) id,
        },
  };

  // ─── Server matching ───────────────────────────────────────────────────

  /// With matching on: gives the tags of the logins the server holds none for, then reads the server's groups. Best
  /// effort, since a run that wrote its items is done whatever the tags did: a server that doesn't answer, or
  /// answers badly, leaves them for the next run. A session the server ended is the run's problem, as anywhere.
  Future<void> _tagStored(KmCache work, int now) async {
    final matching = _matching;
    final dedup = this.dedup;
    if (matching == null || dedup == null) {
      return;
    }
    try {
      await kmBackfill(
        connection: connection,
        server: server,
        matching: matching,
        work: work,
        limit: dedup.perRun,
        onSettings: dedup.onSettings,
      );
      await kmReportHints(
        connection: connection,
        server: server,
        owner: crypto.owner.toWire(),
        matching: matching,
        work: work,
        dedup: dedup,
        now: now,
      );
    } on KmError catch (e) {
      if (e.problem == KmProblem.sessionEnded) {
        rethrow;
      }
    }
  }

  // ─── Step 5: the batches ───────────────────────────────────────────────

  /// Seals and sends [writes] in batches, and puts what the server stored in [work]. Returns whether any
  /// went.
  Future<bool> _send(KmCache work, List<_Write> writes, int now) async {
    if (writes.isEmpty) return false;
    final byId = {for (final write in writes) write.id: write};
    final matching = _matching;
    for (var start = 0; start < writes.length; start += KmApi.batchSize) {
      final chunk = writes.sublist(start, min(start + KmApi.batchSize, writes.length));
      final sealed = [for (final write in chunk) await _seal(write)];
      // Only a login's `cred` tags go beside its write, and none while matching is off; a write with none clears the
      // item's tags on the server
      final tags = kmWriteTags(matching?.tags, [for (final write in chunk) (itemId: write.id, kind: write.kind, json: write.json)]);
      final answer = await connection.call((token) => _api.batchTagged(server, token, sealed, tags: tags));
      for (final item in answer.items) {
        final write = byId[item.id];
        if (write == null) continue;
        final cached = work.items[item.id];
        work.items[item.id] = item.deleted
            ? KmCachedItem(
                revision: item.revision,
                kind: item.kind,
                keyVersion: item.keyVersion,
                hash: '',
                entryId: cached?.entryId,
                deletedAt: now,
              )
            : write.kind == KmKind.spaceAnchors
            ? KmCachedItem(
                revision: item.revision,
                kind: item.kind,
                keyVersion: item.keyVersion,
                hash: b64urlEncode(hash.sha256.convert(item.ciphertext!).bytes),
                entry: write.json,
                opaque: true,
              )
            : KmCachedItem(
                revision: item.revision,
                kind: item.kind,
                keyVersion: item.keyVersion,
                hash: b64urlEncode(hash.sha256.convert(item.ciphertext!).bytes),
                entry: write.json,
                entryId: write.json!['id'] as String,
              );
        // The server holds this revision's tags, or there are none to hold
        if (matching != null &&
            !item.deleted &&
            item.kind == KmKind.login &&
            (answer.tagged.contains(item.id) || !tags.containsKey(item.id))) {
          work.items[item.id] = work.items[item.id]!.withTags(matching.version);
        }
      }
    }
    return true;
  }

  Future<KmWrite> _seal(_Write write) async {
    final owner = crypto.owner;
    final json = write.json;
    if (json == null) {
      return (
        expected: write.expected,
        item: Kem1Item.tombstone(id: write.id, owner: owner, kind: write.kind, revision: write.revision, keyVersion: crypto.keyVersion),
      );
    }
    final sealed = await crypto.sealItem(
      itemId: write.id,
      revision: write.revision,
      kind: write.kind,
      plaintext: Uint8List.fromList(utf8.encode(jsonEncode(json))),
    );
    return (
      expected: write.expected,
      item: Kem1Item(
        id: write.id,
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
