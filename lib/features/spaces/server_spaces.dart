// A space on Kemlock Server as one more scope of the sync engine (docs/plans/add-server-spaces.md,
// design 8 and task 4.1). A run for one space:
//
// 1. fetches the space's chain and verifies it against the head this device accepted
//    (`space_verify.dart`); a chain that forks, goes back or carries an unauthorised signature stops
//    the run and the space shows as "Can't be checked". The members, roles and grants it derives, never
//    the server's member list, say who the keys go to;
// 2. opens the keys the server sealed to this account for the space and each collection it is granted
//    (`space_keys.dart`); a copy that doesn't open leaves only that collection unreadable;
// 3. reads `GET /kem/v1/sync` as the vault's own run does, keeping the items of this space: every item's
//    envelope, readable or not, with its collection. An item whose collection key it holds is opened into
//    the cache; the others are kept untouched and still checked by the manifest;
// 4. checks the space's signed manifest against every envelope (`space_manifest.dart`): a rolled-back,
//    missing or resurrected item, or a manifest that fails, stops the run as older data before anything is
//    stored; an item no permitted signer lists is held and flagged;
// 5. merges with `mergeScope`, as `syncScope` and the vault's run do, and diffs the result into puts and
//    deletes, each in the collection of its entry (kept in the scope state, never in the entry's JSON,
//    `space_scope.dart`), sealed under that collection's key at its current version and sent in
//    `items:batch` writes of up to 500, each guarded by the revision it replaces;
// 6. when the run wrote and this account may write the space's items, signs one manifest of every item of
//    the space and sends it after the last batch. A 423, which the server answers while the space waits for
//    new keys, is no failure: keys are being replaced, and the next run signs after the rotation;
// 7. stores the cache with the new cursor, last.
//
// `replaceKeys` is the other run, after a removal has marked keys (design 4, task 6.1): it makes the new keys and
// publishes them with a `keys` record (`space_replace.dart`), then re-wraps every accepted, listed item of the
// replaced collections under a fresh item key and the new collection key, in batches with `If-Match`, signs the
// manifest after the last batch and reads the space back. What is still under an old key version is the progress, so a
// run that stopped is run again.
//
// `heldItems`, `keepHeld` and `deleteHeld` are the held items' (task 5.1's list). The server keeps the live items a
// key replacement didn't accept, serves them to every confirmed member with their old key version, and releases one only
// by a new write of its id under the collection's current key version (keep) or by a tombstone (delete), which only a member with edit may make. Keep writes
// again the copy this phone accepted before, never the held revision, which is under a key this phone doesn't open.
//
// An entry may move between scopes only when it is unchanged but for its space and time: that is
// `applyScope`'s, unchanged, and the scheduler's `heldElsewhere` keeps an item written under the id of this
// device's own login from replacing it.
//
// The chain routes are the server's, pinned in the space chain section of docs/crypto.md and used through
// `space_chain_client.dart`: `GET /kem/v1/spaces/{id}/chain` (with `?from=`), `GET .../chain/{seq}/seals` and the append `POST`,
// which answers `409` when the head moved (the run reads the chain again and rebuilds its record). So are
// `GET /kem/v1/spaces`, `GET /kem/v1/spaces/{id}` with the caller's sealed keys, `GET /kem/v1/sync` and
// `POST /kem/v1/items:batch` with a `collectionId` on each item of a space.
//
// server: to confirm
// The space manifest route is still the server's pending one.
//
// Pure Dart, no Flutter.

library;

import 'dart:convert';
import 'dart:math' show max, min;
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../crypto/account/bundle.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/kem1.dart';
import '../../crypto/account/manifest.dart';
import '../../crypto/account/manifest_compare.dart';
import '../../crypto/bytes.dart' show constantTimeEquals;
import '../sync/kemlock/km_account.dart';
import '../sync/kemlock/km_api.dart';
import '../sync/kemlock/km_cache.dart';
import '../sync/kemlock/km_files.dart';
import '../sync/kemlock/km_kinds.dart';
import '../sync/kemlock/km_move_plan.dart' show kmEntryHash;
import '../sync/removal_guard.dart';
import '../sync/sync.dart';
import '../sync/sync_merge.dart';
import 'space_actions.dart';
import 'space_bridge.dart';
import 'space_chain.dart';
import 'space_chain_client.dart';
import 'space_keys.dart';
import 'space_manifest.dart';
import 'space_move.dart';
import 'space_replace.dart';
import 'space_scope.dart';
import 'space_seals.dart';
import 'space_state.dart';
import 'space_verify.dart';

/// Why a space's sync stopped before changing anything.
enum SpaceSyncIssue {
  /// The chain can't be checked: it forks, goes back, is malformed or carries an unauthorised or bad signature. The
  /// last valid state stays and nothing new is sealed.
  cantBeChecked,

  /// The server handed back an older copy of the space than this phone saw: a rolled-back, missing or resurrected
  /// item, or a manifest that fails.
  older,

  /// The space waits for its keys to be replaced; writes pause. Not a failure: try after the rotation.
  keysPending,

  /// The run would remove many entries; the person decides.
  removals,
}

/// A space's sync that stopped before changing anything, and why.
class SpaceSyncError implements Exception {
  const SpaceSyncError(this.issue, {this.chain, this.manifest, this.count = 0, this.detail});

  final SpaceSyncIssue issue;

  /// For [SpaceSyncIssue.cantBeChecked]: what was wrong with the chain.
  final ChainProblem? chain;

  /// For [SpaceSyncIssue.older]: a manifest problem, when it was one.
  final SpaceManifestProblem? manifest;

  /// For [SpaceSyncIssue.removals]: how many entries would go.
  final int count;
  final String? detail;

  @override
  String toString() => 'SpaceSyncError(${issue.name}${detail != null ? ': $detail' : ''})';
}

/// An item the server holds back from a space: [canKeep] when this phone has a copy of it that it accepted before, which
/// a keep writes again under the collection's current key. [name] is that copy's name, when it has one.
typedef HeldSpaceItem = ({String id, String kind, int revision, int keyVersion, String? collection, String? name, bool canKeep});

/// Why a held item can't be kept or deleted now.
enum HeldItemProblem {
  /// The server doesn't hold it, or this phone doesn't know it.
  notHeld,

  /// The chain doesn't give this account edit on its collection.
  notAllowed,

  /// The collection's key, or the space key, waits for its replacement: nothing is written under a replaced version.
  keysPending,

  /// This phone has no accepted copy to write again, so the item can only be deleted.
  cantKeep,
}

/// A keep or a delete of a held item that wasn't made.
class HeldItemError implements Exception {
  const HeldItemError(this.problem, [this.detail]);

  final HeldItemProblem problem;
  final String? detail;

  @override
  String toString() => 'HeldItemError(${problem.name}${detail != null ? ': $detail' : ''})';
}

/// What a space's run returns, as the other backends' runs do, and the verified state.
typedef SpaceSyncResult = ({
  SyncDoc doc,
  List<String> known,
  Map<String, Object?> state,
  int skipped,

  /// The verified chain's state, for the screens.
  SpaceState chain,
  bool confirmed,
});

/// The owner of the space [id], which must be an id a server may list a space under: a UUID, and neither of the
/// names the vault's own entries sync under, which nothing may sync into or out of.
Owner _spaceOwner(String id) {
  if (!isServerSpaceId(id)) {
    throw ArgumentError.value(id, 'space', 'not an id a server may list a space under');
  }
  return Owner.space(id);
}

/// Why a live item revision isn't accepted, or null when it is (the spec's "Items"): its collection is deleted or
/// unknown to the chain; its `keyVersion` isn't the collection's current one, older or newer; or the collection's key,
/// or the space key, is marked and the revision is newer than the one already accepted ([acceptedRevision], null when
/// none is), until the `keys` record that replaces the marked key. So a removed member's write under a key they kept is
/// never accepted, and the member who replaces the key re-wraps only what was accepted.
String? itemRefusal({
  required SpaceState chain,
  required String? collection,
  required int keyVersion,
  required int revision,
  int? acceptedRevision,
}) {
  final info = collection == null ? null : chain.collections[collection];
  if (info == null) {
    return 'the collection is deleted or unknown';
  }
  if (keyVersion != info.keyVersion) {
    return 'key version $keyVersion, where the collection is at ${info.keyVersion}';
  }
  if ((chain.spaceKeyMarked || info.marked) && (acceptedRevision == null || revision > acceptedRevision)) {
    return 'the key is marked, so nothing newer is accepted';
  }
  return null;
}

/// How many attempts a run gets when items keep changing under it.
const _attempts = 3;

/// How long an item no signed manifest lists may be held before it is a problem.
const _heldLimit = Duration(hours: 24);

/// The key of a cached item's collection, among the keys a [KmCachedItem] holds apart.
const _collectionKey = 'collection';

/// The key of a cached item's mark that the server holds it (`KmWireItem.held`), beside its collection.
const _heldKey = 'serverHeld';

/// The key of a cached item's newest revision this phone refused (a removed member's write under a key they kept, or one
/// made once the key was marked), beside its collection. The item's own revision stays the accepted one, so a key
/// replacement can tell that the server holds a newer one, which it must name held and not write over.
const _refusedKey = 'refusedRevision';

class _Write {
  _Write({required this.id, required this.kind, required this.collection, required this.revision, this.expected, this.json});

  final String id;
  final String kind;
  final String collection;
  final int revision;
  final int? expected;
  final Map<String, Object?>? json;
}

/// Told the chain a read of a space verified, for the account, and the collection of each entry when a sync run knows
/// them (`HiddenPasswordsNotifier.report`).
typedef ChainReport = void Function(String space, String account, SpaceState chain, {Map<String, String>? collections});

/// Syncs one space of the account on one server.
class KmSpaceSync {
  KmSpaceSync({
    required this.connection,
    required this.server,
    required this.account,
    required this.space,
    required this.loadCache,
    required this.saveCache,
    required this.loadAnchor,
    required this.loadCompared,
    required this.saveAnchor,
    this.files,
    this.chainCrypto = const RealChainCrypto(),
    this.manifestCrypto = const RealSpaceManifestCrypto(),
    this.signRecord = signChainEntry,
    this.clock = DateTime.now,
    this.onChain,
    this.onComparedChain,
    this.joining = false,
    this.carriesClosure = false,
    this.homeDown,
    this.homeUrl,
  }) : owner = _spaceOwner(space);

  final KmConnection connection;
  final Uri server;

  /// The account's keys, for the sealed copies and the manifest. The caller wipes them.
  final KmAccount account;

  /// The space's UUID on the server.
  final String space;

  /// The owner every item and the manifest of the space is bound to.
  final Owner owner;
  final Future<KmCache> Function() loadCache;
  final Future<void> Function(KmCache cache) saveCache;

  /// The anchor of the chain this device accepted for the space (the epoch and the link of every record), and where it
  /// keeps the next. [saveAnchor] is told when a fence replaced records the device had accepted, and `compared` when the
  /// anchor is stored by first contact, after the fingerprint was compared.
  ///
  /// Reading a chain never makes an anchor: the run moves one that is stored, and only [rememberAnchor] (first contact)
  /// stores the first, so an anchor with no [loadCompared] is not trusted. [loadCompared] says whether a fingerprint was
  /// compared for the space, on this device or on another device of the account, which the anchors carry.
  final Future<ChainAnchor?> Function(String space) loadAnchor;
  final Future<bool> Function(String space) loadCompared;
  final Future<void> Function(String space, ChainAnchor anchor, {bool afterFence, bool compared}) saveAnchor;

  /// The phone's attached files, synced beside the space's notes and File items as the vault's own are (`KmFiles`, over this
  /// engine's connection and server): uploaded once the item is in the space, named in it, fetched on the other phones. Without
  /// it the space's notes sync without their files, and an item's files are neither sent nor fetched.
  final KmFiles? files;
  final ChainCrypto chainCrypto;
  final SpaceManifestCrypto manifestCrypto;

  /// Signs a record of the chain with the account's `sig1` private key; a test gives a cheap signature.
  final Future<SignedChainEntry> Function(SpaceChainEntry entry, Uint8List sig1PrivateKey) signRecord;
  final DateTime Function() clock;

  /// Told each chain this space verified, so the screens that hide what a grant hides follow a changed grant.
  final ChainReport? onChain;

  /// Told each chain this space verified **and this device compared**: the only chains whose policies, notices and
  /// recovery are applied or shown as checked. A space whose fingerprint wasn't compared reports to [onChain] alone.
  final ChainReport? onComparedChain;

  /// Whether this engine runs for a phone that holds the space's WebDAV copy and has not joined the server space: it reads the
  /// chain only against an anchor this device already stores, from a real comparison of a fingerprint (the accept screen, or the
  /// anchors the account's other devices carry), and never makes one. The space's UUID is computable by anyone who can list
  /// the folder, so a chain seen for the first time here is no reason to open a key or upload an entry.
  final bool joining;

  /// Whether this engine runs for a moved WebDAV space whose copy is still synced (bridged or joining), so that what the chain it
  /// verified says of that copy ([chainClosure]) is carried by whatever a run throws, as a [ClosedRunError]. A space that has
  /// no WebDAV copy has none to close: a chain that restricts or removes someone is no business of its run, which throws what
  /// failed as it is.
  final bool carriesClosure;

  /// The name of the home server while the phone is on a replica and the home isn't known to be back, or null. Every chain record and
  /// every sealed key goes to the home alone (design decision 5): while this names a server nothing of the kind is sent, and nothing
  /// is queued, as a removal sent later under a stale epoch would be refused anyway. Items still sync through the replica.
  final String? Function()? homeDown;

  /// The home server's address, asked each time a record or a sealed key is about to be sent. What decides is the server this
  /// engine's connection is to, which was fixed when the action began (`KmHost.withAccount`): the failover may have gone back to the
  /// home since, and a record sent over a connection to a replica goes to the replica whatever the failover says now. Without it only
  /// [homeDown] is asked.
  final Uri Function()? homeUrl;

  KmApi get _api => connection.api;

  late final SpaceChainClient _chainRoutes = SpaceChainClient(connection: connection, server: server, space: space);

  /// Refuses to send a chain record or a sealed key unless this engine's connection is to the home: a [SpaceActionError] of
  /// [SpaceActionProblem.homeAway], naming the home (never the replica in use), before anything is built on it or sent. It refuses
  /// while [homeDown] says the home is away, and, whatever the failover says now, when the connection's own server isn't the home.
  void requireHome() {
    final away = homeDown?.call();
    if (away != null) {
      throw SpaceActionError(SpaceActionProblem.homeAway, away);
    }
    final home = homeUrl?.call();
    if (home != null && home != connection.server) {
      throw SpaceActionError(SpaceActionProblem.homeAway, home.host);
    }
  }

  /// Appends [request] to the chain, at the home: the server this connection is to, which [requireHome] has found to be the home.
  /// The record carries the epoch of the chain this device last verified (`SpaceChainEntry.epoch`).
  Future<ChainAppended> _appendAtHome(Map<String, Object?> request) async {
    requireHome();
    return _chainRoutes.append(request);
  }

  /// What a member does on this space: invite, confirm, change roles and grants, remove, leave and share keys, each a
  /// record made from the verified chain, signed with this account's key and appended at the home (`space_actions.dart`).
  SpaceActions actions() => SpaceActions(
    account: account.accountId,
    readChain: _verifiedChain,
    openKeyring: (state) => _openKeyring(state, account.accountId),
    append: (request) async {
      await _appendAtHome(request);
    },
    sign: (entry) => signRecord(entry, account.sig1PrivateKey),
    now: () => clock().millisecondsSinceEpoch ~/ 1000,
  );

  /// The space's chain read and verified against this device's anchor, which is the state every screen shows. A [SpaceSyncError]
  /// of `cantBeChecked` when it doesn't verify.
  Future<SpaceState> chainState() => _verifiedChain();

  /// Runs once, again when items changed under it. [local] is this phone's entries in the scope and [state] what the
  /// last run kept. Throws a [SpaceSyncError] when it stops before changing anything and a [KmError] when the server
  /// can't be reached or refuses. A run for a moved space ([carriesClosure]) whose verified chain already closed the WebDAV copy
  /// carries that closure in what it throws, a [ClosedRunError], so a failure after the chain was read can't hide it.
  Future<SpaceSyncResult> sync(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    for (var attempt = 1; ; attempt++) {
      _closure = null;
      try {
        return await _run(local, state, now: now, choice: choice);
      } catch (e) {
        if (e is KmError) {
          if (e.problem == KmProblem.stale && attempt < _attempts) {
            continue;
          }
          if (e.status == 423) {
            throw _withClosure(const SpaceSyncError(SpaceSyncIssue.keysPending));
          }
        }
        throw _withClosure(e);
      }
    }
  }

  /// Why the chain this run verified closes the WebDAV copy, set as soon as it verified, or null.
  SpaceCopyClosed? _closure;

  /// [failure], with the closure the run's chain showed when it showed one.
  Object _withClosure(Object failure) {
    final reason = _closure;
    return reason == null ? failure : ClosedRunError(reason, failure);
  }

  Future<SpaceSyncResult> _run(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    // What an earlier run reported of the WebDAV copy is not carried: each run says it afresh
    final base = takeBridgeSignal(state.extra).state;
    final (chain, compared) = await _readChain();
    // Carried by whatever this run throws from here on: a failure after the chain was read must not hide that it closes the copy
    _closure = carriesClosure ? chainClosure(chain) : null;
    final me = chain.member(account.accountId);
    // A space no fingerprint was compared for holds nothing here, as an invitation doesn't: a server could have made it up,
    // and it opens no key and merges no item until the person has compared (first contact). Whether this account is in it is
    // the server's word until then, so it is no "left": the run says so apart, and the caller leaves the space as it is
    if (!compared) {
      return (
        doc: const SyncDoc(),
        known: const <String>[],
        state: withBridgeSignal(base, BridgeSignal.uncompared),
        skipped: 0,
        chain: chain,
        confirmed: false,
      );
    }
    if (me == null || !me.isConfirmed) {
      // Invited and not yet confirmed, or removed: nothing of the space is held here, and no phone may carry what this run
      // returned into a WebDAV file
      return (
        doc: const SyncDoc(),
        known: const <String>[],
        state: withBridgeSignal(base, BridgeSignal.gone),
        skipped: 0,
        chain: chain,
        confirmed: false,
      );
    }

    final keyring = await _openKeyring(chain, me.id);
    try {
      final crypto = SpaceItemCrypto(space: space, keyring: keyring);
      final stored = await loadCache();
      final work = stored.copy();
      final seenAt = min(now, state.lastSyncAt ?? now);
      await _pull(work, crypto, chain, seenAt);
      await _checkManifest(work, stored, chain, now);
      // What the space says of its WebDAV copy: closed by the chain or by the Owner, or the move marker
      final bridge = bridgeSignalOf(chain, work.items, owner);
      if (joining && bridge == null) {
        // A phone that agreed to join found the move unfinished (no marker): nothing of it is merged, and nothing is uploaded
        return (
          doc: const SyncDoc(),
          known: const <String>[],
          state: withBridgeSignal(base, BridgeSignal.pending),
          skipped: 0,
          chain: chain,
          confirmed: true,
        );
      }

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
              ],
      );
      final merged = mergeScope(await combineKeyCopies(local, remote), keepAll ? const [] : state.known, remote, now: now);
      // An item new in this space names no file of the item it was made from: a server file belongs to one item
      final mergedDoc = kmWithoutForeignFiles(
        merged.doc,
        isNew: (id) {
          final cached = work.items[kmItemId(id, owner)];
          return cached == null || cached.deleted;
        },
      );

      final collections = spaceCollectionsOf(state.extra);
      final plan = _plan(work, local, mergedDoc, chain, keyring, me.id, collections);
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
      if (guard.stop) {
        throw SpaceSyncError(SpaceSyncIssue.removals, count: plan.removals);
      }
      work.lost = guard.lostNow;

      var doc = mergedDoc;
      var wrote = await _send(work, plan.writes, crypto, keyring, now);
      final files = this.files;
      if (files != null) {
        files.refused
          ..clear()
          ..addAll(kmRefusedFilesOf(state.extra));
        // A file goes up once its item is in the space, and the item is written again naming it
        final stamped = await files.upload(
          doc,
          now: now,
          itemIdOf: (id) => kmItemId(id, owner),
          onServer: (itemId) => work.items[itemId]?.applied ?? false,
        );
        if (stamped != null) {
          final before = kmFileIdsOf(doc, itemIdOf: (id) => kmItemId(id, owner));
          doc = stamped;
          try {
            final again = _plan(work, local, doc, chain, keyring, me.id, {...collections, ...plan.collections});
            wrote = await _send(work, again.writes, crypto, keyring, now) || wrote;
          } catch (_) {
            // The items don't name the files just uploaded (another device wrote one: the run is made again): remove them
            await files.discard(kmNewFileIds(before, kmFileIdsOf(stamped, itemIdOf: (id) => kmItemId(id, owner))));
            rethrow;
          }
        }
        await files.deleteRemoved(kmCachedFileIds(stored), kmCachedFileIds(work));
      }
      work.items.removeWhere((_, item) => item.deleted && (item.deletedAt ?? now) < now - tombstoneTtlMs);
      if (wrote && mayWriteItems(chain, me.id)) {
        await _signManifest(work);
      }

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
      work.knew = kmKnownKinds();
      await saveCache(work);
      // Outside what the run must get right: a file that can't be fetched now is tried again at the next run
      await files?.download(doc, itemIdOf: (id) => kmItemId(id, owner));

      // The collection of each entry, with the chain this run verified, tells which logins hide their password
      onChain?.call(space, account.accountId, chain, collections: {...collections, ...plan.collections});
      final next = withBridgeSignal(withSpaceCollections(base, {...collections, ...plan.collections}), bridge?.signal, bridge?.reason);
      return (
        doc: doc,
        known: merged.known,
        state: files == null ? next : kmWithRefusedFiles(next, files.refused),
        skipped: _skipped(work),
        chain: chain,
        confirmed: true,
      );
    } finally {
      keyring.dispose();
    }
  }

  /// How many items of [work] this version leaves alone (held, or of a kind or shape it can't read), not counting the space's two
  /// bridge markers, which are no entries.
  int _skipped(KmCache work) {
    final markers = bridgeMarkerIds(owner);
    return work.items.entries.where((item) => !markers.contains(item.key) && (item.value.opaque || item.value.heldSince != null)).length;
  }

  // ─── Replacing keys ────────────────────────────────────────────────────

  /// Replaces the space's marked keys and re-wraps the items of the replaced collections, or, when nothing is marked,
  /// carries on with the items still under an old key version of a replacement that stopped.
  ///
  /// 1. Verifies the chain and opens the keys at its current versions, the old ones while a key is marked, and reads
  ///    the space as a run does, so the cache holds what this phone accepted and the manifest lists.
  /// 2. If a key is marked, makes the new keys, seals them to the members entitled to them, signs the `keys` record,
  ///    runs it against the state and the authority rules, and sends it with the boxes, the names ([readNames] gives
  ///    the text of every name, which are sealed again under a new space key) and the live items this phone didn't
  ///    accept, named held. The server then takes item writes under the new versions, and no other.
  /// 3. Re-wraps each accepted item of a collection whose key version moved, from the plaintext the cache holds, under
  ///    a fresh item key and the collection's new key, in batches of [batchSize] guarded by the revision replaced, the
  ///    cache saved after each. A batch that loses a race (a 409) reads the space again, which takes the other writer's
  ///    revision, and re-plans: an item already under the new key needs nothing, and one still under an old key is held.
  ///    An item step 2 named held, as one whose newer revision this phone refused, counts as covered: it isn't written.
  /// 4. Signs the manifest once, after the last batch, if this account may write the space's items.
  /// 5. Reads the space back from the start and compares every re-wrapped item's revision, key version and hash, and
  ///    the manifest.
  ///
  /// [onBatch] is told after each batch with the count done and the count to do; one that throws stops the run, which
  /// is how a test stops it. Throws a [KeyReplacementError] when the run can't go on, a [SpaceSyncError] when the chain
  /// can't be checked, and a [KmError] when the server can't be reached or refuses.
  Future<({Set<KeyRef> rotated, int rewritten, int held, int batches})> replaceKeys({
    required int now,
    required Future<Map<NameTarget, String>> Function(SpaceState state, SpaceKeyring keyring) readNames,
    KeyMaker makeKey = randomKeyMaker,
    int batchSize = KmApi.batchSize,
    void Function(int done, int total)? onBatch,
  }) async {
    requireHome();
    var chain = await _verifiedChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      throw const KeyReplacementError(KeyReplacementProblem.nothingToReplace, 'not a confirmed member');
    }
    final old = await _openKeyring(chain, me.id);
    SpaceKeyring? fresh;
    try {
      final stored = await loadCache();
      final work = stored.copy();
      await _pull(work, SpaceItemCrypto(space: space, keyring: old), chain, now);
      await _checkManifest(work, stored, chain, now);

      var rotated = <KeyRef>{};
      var keyring = old;
      // The items the `keys` record this phone appended named held: the server keeps them, so they count as covered
      var named = <String>{};
      if (chain.keysNeedReplacing) {
        // A 409 means another record took the place while this one was made: read the chain again and rebuild
        KeysReplacement? plan;
        Set<KeyRef> marked = const {};
        for (var attempt = 1; ; attempt++) {
          final names = chain.spaceKeyMarked ? await readNames(chain, old) : const <NameTarget, String>{};
          marked = chain.markedKeys;
          final built = await buildKeysRecord(state: chain, signer: me.id, rotate: marked, at: now ~/ 1000, makeKey: makeKey, names: names);
          final signed = await signRecord(built.entry, account.sig1PrivateKey);
          try {
            final after = chain.apply(built.entry);
            final problem = chainAuthorityProblem(chain, after, built.entry);
            if (problem != null) {
              throw KeyReplacementError(KeyReplacementProblem.notAllowed, problem);
            }
          } on ChainRefusal catch (e) {
            throw KeyReplacementError(KeyReplacementProblem.notAllowed, e.detail);
          }
          final replaced = {
            for (final key in marked)
              if (!key.isSpace) key.collection!,
          };
          final held = [
            for (final MapEntry(:key, :value) in work.items.entries)
              if (!value.deleted && (!value.applied || _refused(value)) && replaced.contains(value.extra[_collectionKey])) key,
          ];
          try {
            await _appendAtHome(built.request(signed, held: held));
            plan = built;
            named = held.toSet();
            break;
          } on ChainAppendError catch (e) {
            if (e.failure == ChainAppendFailure.refused) {
              throw KeyReplacementError(KeyReplacementProblem.notAllowed, e.reason);
            }
            if (attempt >= _attempts) {
              throw const KeyReplacementError(KeyReplacementProblem.busy, 'the chain kept moving');
            }
            chain = await _verifiedChain();
            if (!chain.keysNeedReplacing) {
              break;
            }
          }
        }
        if (plan != null) {
          final made = plan;
          rotated = marked;
          // The new chain gives the new versions, and its anchor; the keys this phone made go in the keyring as they are
          chain = await _verifiedChain();
          keyring = SpaceKeyring.fromKeys(
            space: space,
            member: me.id,
            spaceKeyVersion: chain.spaceKeyVersion,
            spaceKey: made.newKeys[const KeyRef.space()] ?? old.spaceKey,
            collectionKeys: {
              for (final collection in chain.collections.values)
                if (made.newKeys[KeyRef.collection(collection.id)] != null)
                  collection.id: {collection.keyVersion: made.newKeys[KeyRef.collection(collection.id)]!}
                else if (old.currentVersion(collection.id) == collection.keyVersion)
                  collection.id: {collection.keyVersion: old.collectionKey(collection.id, collection.keyVersion)!},
            },
          );
          fresh = keyring;
        } else {
          // Someone else replaced the keys first: the ones the chain now gives are theirs, and the server seals them to us
          keyring = await _openKeyring(chain, me.id);
          fresh = keyring;
        }
      }
      // Nothing marked is a replacement that stopped, or none: the keys opened through the chain are the new ones

      final crypto = SpaceItemCrypto(space: space, keyring: keyring);
      var rewritten = 0;
      var batches = 0;
      var wrote = false;
      for (var attempt = 1; ; attempt++) {
        final stale = [
          for (final MapEntry(:key, :value) in work.items.entries)
            if (value.applied &&
                !named.contains(key) &&
                _staleUnder(chain, value) &&
                keyring.currentVersion(value.extra[_collectionKey] as String) == chain.collections[value.extra[_collectionKey]]!.keyVersion)
              key,
        ]..sort();
        if (stale.isEmpty) {
          break;
        }
        if (attempt > _attempts + 2) {
          throw const KeyReplacementError(KeyReplacementProblem.busy, 'items kept changing');
        }
        final total = (stale.length / batchSize).ceil();
        var lostRace = false;
        for (var start = 0; start < stale.length && !lostRace; start += batchSize) {
          final chunk = stale.sublist(start, min(start + batchSize, stale.length));
          final writes = [
            for (final id in chunk)
              _Write(
                id: id,
                kind: work.items[id]!.kind,
                collection: work.items[id]!.extra[_collectionKey]! as String,
                revision: work.items[id]!.revision + 1,
                expected: work.items[id]!.revision,
                json: work.items[id]!.entry,
              ),
          ];
          try {
            await _send(work, writes, crypto, keyring, now);
          } on KmError catch (e) {
            if (e.problem != KmProblem.stale) {
              rethrow;
            }
            // Another writer got there first: read the space again, take what it wrote, and plan again
            await _pull(work, crypto, chain, now);
            lostRace = true;
            continue;
          }
          wrote = true;
          rewritten += chunk.length;
          batches++;
          await saveCache(work);
          onBatch?.call(start ~/ batchSize + 1, total);
        }
        if (!lostRace) {
          break;
        }
      }
      if (wrote && mayWriteItems(chain, me.id)) {
        await _signManifest(work);
      }
      await _readBack(work, crypto, chain);
      await saveCache(work);
      return (
        rotated: rotated,
        rewritten: rewritten,
        held: work.items.entries
            .where((e) => !e.value.deleted && (e.value.opaque || e.value.heldSince != null || named.contains(e.key)))
            .length,
        batches: batches,
      );
    } finally {
      old.dispose();
      fresh?.dispose();
    }
  }

  /// Whether the server holds a revision of [item] that this phone refused and that is newer than the accepted one.
  bool _refused(KmCachedItem item) {
    final refused = item.extra[_refusedKey];
    return refused is int && refused > item.revision;
  }

  /// Whether [item] is under a key version older than its collection's current one.
  bool _staleUnder(SpaceState chain, KmCachedItem item) {
    final collection = item.extra[_collectionKey];
    final info = collection is String ? chain.collections[collection] : null;
    return info != null && item.keyVersion < info.keyVersion;
  }

  /// Reads the space again from the start and compares every accepted item of a replaced collection with what this phone
  /// wrote: its revision, key version and hash, and the manifest. Nothing is stored.
  Future<void> _readBack(KmCache work, SpaceItemCrypto crypto, SpaceState chain) async {
    final check = work.copy()..cursor = null;
    await _pull(check, crypto, chain, 0);
    final problems = <String>[];
    for (final MapEntry(:key, :value) in work.items.entries) {
      final info = value.extra[_collectionKey] is String ? chain.collections[value.extra[_collectionKey]] : null;
      if (!value.applied || info == null || value.keyVersion != info.keyVersion) {
        continue;
      }
      final seen = check.items[key];
      if (seen == null || seen.revision != value.revision || seen.keyVersion != value.keyVersion || seen.hash != value.hash) {
        problems.add(key);
      }
    }
    final manifest = await _fetchManifest();
    if (work.manifest != null && manifest != null && !_same(manifest.manifest, work.manifest!)) {
      problems.add('manifest');
    }
    if (problems.isNotEmpty) {
      throw KeyReplacementError(KeyReplacementProblem.readBack, problems.join(', '));
    }
  }

  // ─── Moving a WebDAV space ─────────────────────────────────────────────

  /// What a phone that holds this space's WebDAV copy may be told of the server space before it merges anything: the chain,
  /// read against the anchor the device stores (`joining`, so none is made), and the confirmed Owners; null when this account
  /// isn't a confirmed member, or when the move is not whole (no marker, and nothing closed the copy). Nothing is written, and
  /// the cache is kept as it was.
  Future<({SpaceState chain, List<String> owners})?> joinOffer({required int now}) async {
    final chain = await _verifiedChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      return null;
    }
    // The move must be whole: its marker is on the server, or the Owner or the chain closed the copy. Read from a copy of the cache,
    // which is kept as it was
    final keyring = await _openKeyring(chain, me.id);
    try {
      final stored = await loadCache();
      final work = stored.copy();
      await _pull(work, SpaceItemCrypto(space: space, keyring: keyring), chain, now);
      await _checkManifest(work, stored, chain, now);
      if (bridgeSignalOf(chain, work.items, owner) == null) {
        return null;
      }
    } finally {
      keyring.dispose();
    }
    final owners = [
      for (final member in chain.confirmedMembers)
        if (member.role == SpaceRole.owner) member.id,
    ]..sort();
    return (chain: chain, owners: owners);
  }

  /// Reads the space again from the start and compares it with [sent], the hash (`kmEntryHash`) of each entry by its own id:
  /// the ids that didn't come back live, readable and listed by the signed manifest, or that came back as other contents.
  /// Nothing is stored. The check of the move (task 8.1): an empty answer means the server holds exactly what was sent. Throws
  /// a [SpaceMoveError] when this account isn't a confirmed member and a [SpaceSyncError] when the manifest doesn't verify.
  Future<List<String>> compareMoved(Map<String, String> sent, {required int now}) async {
    final chain = await _verifiedChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      throw const SpaceMoveError(SpaceMoveProblem.notMember);
    }
    final keyring = await _openKeyring(chain, me.id);
    try {
      final crypto = SpaceItemCrypto(space: space, keyring: keyring);
      final check = KmCache();
      await _pull(check, crypto, chain, now);
      await _checkManifest(check, KmCache(), chain, now);
      bool matches(KmCachedItem? item, String sum) => item != null && item.applied && kmEntryHash(item.entry!) == sum;
      return [
        for (final MapEntry(key: entryId, value: sum) in sent.entries)
          if (!matches(check.items[kmItemId(entryId, owner)], sum)) entryId,
      ]..sort();
    } finally {
      keyring.dispose();
    }
  }

  /// Writes the marker of the WebDAV copy of this space: that the move is complete ([closed] false, `KmKind.bridgeOpen`), or that
  /// the Owner closed the copy (`KmKind.bridgeClosed`). One item in the space's first collection, written once, whose existence
  /// is all anyone reads. Only the Owner may. Nothing is written when the marker is there already, or, for a close, when keys
  /// await replacement, which closes the copy on its own. Throws a [SpaceMoveError] when this account may not, or when no fingerprint
  /// was compared for the space: the space key is not opened, and nothing is uploaded, for a chain no one checked.
  Future<void> markBridge({required bool closed, required int now}) async {
    final (chain, compared) = await _readChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      throw const SpaceMoveError(SpaceMoveProblem.notMember);
    }
    if (me.role != SpaceRole.owner) {
      throw const SpaceMoveError(SpaceMoveProblem.notOwner);
    }
    if (!compared) {
      throw const SpaceMoveError(SpaceMoveProblem.exists, detail: 'no fingerprint was compared for this space on this account');
    }
    if (closed && chainClosure(chain) != null) {
      return;
    }
    final keyring = await _openKeyring(chain, me.id);
    try {
      final crypto = SpaceItemCrypto(space: space, keyring: keyring);
      final stored = await loadCache();
      final work = stored.copy();
      await _pull(work, crypto, chain, now);
      await _checkManifest(work, stored, chain, now);
      final entryId = closed ? kmBridgeClosedId : kmBridgeOpenId;
      final id = kmItemId(entryId, owner);
      final existing = work.items[id];
      if (existing != null && !existing.deleted) {
        return;
      }
      final collection = chain.collections.keys.firstOrNull;
      if (collection == null ||
          !(chain.accessOf(me.id, collection)?.edit ?? false) ||
          keyring.currentVersion(collection) == null ||
          chain.spaceKeyMarked ||
          chain.markedCollections.contains(collection)) {
        throw const SpaceMoveError(SpaceMoveProblem.keysPending);
      }
      final write = _Write(
        id: id,
        kind: closed ? KmKind.bridgeClosed : KmKind.bridgeOpen,
        collection: collection,
        revision: (existing?.revision ?? 0) + 1,
        expected: existing?.revision,
        json: {'id': entryId, 'v': 1, 'at': now, 'by': me.id},
      );
      await _send(work, [write], crypto, keyring, now);
      // A marker is no entry: kept like any item of a kind this version doesn't merge, so no run counts it as one
      final written = work.items[id]!;
      work.items[id] = KmCachedItem(
        revision: written.revision,
        kind: written.kind,
        keyVersion: written.keyVersion,
        hash: written.hash,
        opaque: true,
        extra: written.extra,
      );
      if (mayWriteItems(chain, me.id)) {
        await _signManifest(work);
      }
      await saveCache(work);
    } finally {
      keyring.dispose();
    }
  }

  // ─── Held items ────────────────────────────────────────────────────────

  /// The items the server holds back from the space, which it serves to every confirmed member. A held item is released
  /// only by a new write of its id under its collection's current key version (keep), or by a tombstone (delete), which
  /// only a member with edit on the collection may make.
  /// Reads the space from the start and stores nothing. Empty for an account that isn't a confirmed member.
  Future<List<HeldSpaceItem>> heldItems({required int now}) async {
    final chain = await _verifiedChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      return const [];
    }
    final keyring = await _openKeyring(chain, me.id);
    try {
      final work = (await loadCache()).copy()..cursor = null;
      await _pull(work, SpaceItemCrypto(space: space, keyring: keyring), chain, now);
      final found = <HeldSpaceItem>[
        for (final MapEntry(:key, :value) in work.items.entries)
          if (value.extra[_heldKey] == true && !value.deleted)
            (
              id: key,
              kind: value.kind,
              revision: value.revision,
              keyVersion: value.keyVersion,
              collection: value.extra[_collectionKey] is String ? value.extra[_collectionKey]! as String : null,
              name: _nameOf(value.entry),
              canKeep: value.entry != null && kmReadable(value.kind, value.entry, key, owner),
            ),
      ];
      found.sort((a, b) => a.id.compareTo(b.id));
      return found;
    } finally {
      keyring.dispose();
    }
  }

  /// A title for the held list: the name a login, note or card carries, when its last accepted copy is known.
  String? _nameOf(Map<String, Object?>? entry) {
    final name = entry?['name'];
    return name is String && name.isNotEmpty ? name : null;
  }

  /// Keeps the held item [id]: writes its last accepted copy again under its collection's current key version, with a
  /// fresh item key, which releases it. The copy must be one this phone accepted and that is of this space's owner
  /// (`kmReadable`); the content of the held revision itself, under the old key, is never taken. Throws a
  /// [HeldItemError] when the item can't be kept, and a [KmError] when the server refuses.
  Future<void> keepHeld(String id, {required int now}) => _release(id, keep: true, now: now);

  /// Deletes the held item [id] with a tombstone, which releases it.
  Future<void> deleteHeld(String id, {required int now}) => _release(id, keep: false, now: now);

  Future<void> _release(String id, {required bool keep, required int now}) async {
    final chain = await _verifiedChain();
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      throw const HeldItemError(HeldItemProblem.notAllowed, 'not a confirmed member');
    }
    final keyring = await _openKeyring(chain, me.id);
    try {
      final crypto = SpaceItemCrypto(space: space, keyring: keyring);
      final stored = await loadCache();
      final work = stored.copy()..cursor = null;
      await _pull(work, crypto, chain, now);
      await _checkManifest(work, stored, chain, now);
      final held = work.items[id];
      final collection = held?.extra[_collectionKey];
      if (held == null || held.extra[_heldKey] != true || collection is! String) {
        throw const HeldItemError(HeldItemProblem.notHeld);
      }
      if (!(chain.accessOf(me.id, collection)?.edit ?? false)) {
        throw const HeldItemError(HeldItemProblem.notAllowed, 'edit on the collection');
      }
      final current = chain.collections[collection]?.keyVersion;
      if (chain.spaceKeyMarked ||
          chain.markedCollections.contains(collection) ||
          current == null ||
          keyring.currentVersion(collection) != current) {
        throw const HeldItemError(HeldItemProblem.keysPending);
      }
      final entry = held.entry;
      if (keep && (entry == null || !kmReadable(held.kind, entry, id, owner))) {
        throw const HeldItemError(HeldItemProblem.cantKeep);
      }
      final write = _Write(
        id: id,
        kind: held.kind,
        collection: collection,
        revision: held.revision + 1,
        expected: held.revision,
        json: keep ? entry : null,
      );
      await _send(work, [write], crypto, keyring, now);
      if (mayWriteItems(chain, me.id)) {
        await _signManifest(work);
      }
    } finally {
      keyring.dispose();
    }
  }

  // ─── The chain and the keys ────────────────────────────────────────────

  /// Fetches the space's chain and verifies it against the stored head. The state it derives is what keys are
  /// sealed from. A head this device holds moves on once the whole chain verified; a space with none stays with none, since
  /// only first contact stores the first one ([rememberAnchor]).
  Future<SpaceState> _verifiedChain() async => (await _readChain()).$1;

  /// [_verifiedChain] and whether a fingerprint was compared for the space.
  Future<(SpaceState, bool)> _readChain() async {
    final held = await loadAnchor(space);
    // A phone that is joining a space found by its WebDAV id makes no anchor: it needs the one a real comparison stored, so a
    // stored anchor with no compared record is no more than a chain seen once
    if (joining && (held == null || !await loadCompared(space))) {
      throw const SpaceSyncError(SpaceSyncIssue.cantBeChecked, detail: 'no fingerprint was compared for this space on this account');
    }
    final result = await _checkedChain(held);
    final anchor = result.anchor;
    if (held != null && anchor != null) {
      await saveAnchor(space, anchor, afterFence: result.droppedFrom != null);
    }
    final compared = held != null && await loadCompared(space);
    onChain?.call(space, account.accountId, result.state);
    if (compared) {
      onComparedChain?.call(space, account.accountId, result.state);
    }
    return (result.state, compared);
  }

  /// Whether a fingerprint was compared for the space: first contact is done, here or on another device of the account.
  Future<bool> isCompared() async => await loadAnchor(space) != null && await loadCompared(space);

  /// The chain read and verified against [anchor], this device's, with nothing stored.
  Future<ChainResult> _checkedChain(ChainAnchor? anchor) async {
    final List<SignedChainEntry> entries;
    try {
      entries = await _chainRoutes.read();
    } on ChainRefusal catch (e) {
      throw SpaceSyncError(SpaceSyncIssue.cantBeChecked, chain: e.problem, detail: e.detail);
    }
    final result = await verifyChain(space: space, entries: entries, anchor: anchor, crypto: chainCrypto);
    if (!result.ok) {
      throw SpaceSyncError(SpaceSyncIssue.cantBeChecked, chain: result.problem, detail: result.detail);
    }
    return result;
  }

  /// The chain of a space this device has no anchor for, read and verified for the first-contact screen: the state, the
  /// records that verified and the anchor they make, **none of it stored**. A person who taps "Not now", or whose digits
  /// differ, stores nothing; [rememberAnchor] is for once the fingerprint matched.
  Future<({SpaceState state, List<SignedChainEntry> records, ChainAnchor? anchor})> chainForContact() async {
    final result = await _checkedChain(await loadAnchor(space));
    return (state: result.state, records: result.accepted, anchor: result.anchor);
  }

  /// Stores [anchor] for the space, the one [chainForContact] answered, and records that its fingerprint was compared: the
  /// only way a space becomes one this device trusts. Call it only after the digits matched, or for a space this device made
  /// ([rememberCreated]).
  Future<void> rememberAnchor(ChainAnchor anchor) => saveAnchor(space, anchor, compared: true);

  /// First contact of a space this device just made: its chain must begin with [created], the `create` record this device
  /// signed, which the creator knows without comparing anyone's fingerprint. Anything else is refused, and nothing is stored.
  Future<void> rememberCreated(SignedChainEntry created) async {
    final contact = await chainForContact();
    final anchor = contact.anchor;
    if (anchor == null || !constantTimeEquals(anchor.links.first, created.entry.hashed)) {
      throw const SpaceSyncError(
        SpaceSyncIssue.cantBeChecked,
        chain: ChainProblem.badLink,
        detail: 'the chain does not begin with the record this device made',
      );
    }
    await rememberAnchor(anchor);
  }

  /// The space's name, opened from the sealed [sealed] name the list gave, or null when it can't be shown: this account
  /// isn't a confirmed member (it holds no space key before that), the name isn't the one the chain committed to, or it
  /// doesn't open at the key version this phone holds. A [KmError] when the server's keys can't be read.
  Future<String?> openSpaceName(SpaceState chain, List<int> sealed) async {
    final me = chain.member(account.accountId);
    if (me == null || !me.isConfirmed) {
      return null;
    }
    final keyring = await _openKeyring(chain, me.id);
    try {
      final key = keyring.spaceKey;
      if (key == null) {
        return null;
      }
      return await openCommittedName(
        state: chain,
        target: const NameTarget.space(),
        sealed: sealed,
        spaceKey: key,
        spaceKeyVersion: keyring.spaceKeyVersion,
      );
    } finally {
      keyring.dispose();
    }
  }

  /// Opens the keys the server sealed to this account for the space: `GET /kem/v1/spaces/{id}`, each through the chain's
  /// commitment and at the chain's current key version, never the version the server names.
  Future<SpaceKeyring> _openKeyring(SpaceState chain, String member) async {
    final raw = await connection.call((token) => _api.callValue('GET', server, '/spaces/$space', token: token));
    if (raw is! Map<String, Object?>) {
      throw const KmError(KmProblem.server, message: 'a space answer');
    }
    final me = raw['me'];
    if (me is! Map<String, Object?>) {
      throw const KmError(KmProblem.server, message: 'a space answer');
    }
    try {
      final sealedSpaceKey = me['sealedSpaceKey'];
      final copies = raw['collectionKeys'];
      return await openKeyringFromChain(
        state: chain,
        member: member,
        kx1PrivateKey: account.kx1PrivateKey,
        bundleVersion: account.keyVersion,
        hashesAt: _sealHashes,
        spaceKeyBox: sealedSpaceKey is String ? b64urlDecode(sealedSpaceKey) : null,
        collectionBoxes: [
          if (copies is List<Object?>)
            for (final copy in copies.whereType<Map<String, Object?>>())
              if (copy['collection'] is String &&
                  isUuidText(copy['collection']! as String) &&
                  copy['keyVersion'] is int &&
                  copy['sealed'] is String)
                SealedCollectionKey(
                  collection: copy['collection']! as String,
                  keyVersion: copy['keyVersion']! as int,
                  sealed: b64urlDecode(copy['sealed']! as String),
                ),
        ],
      );
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// The seal hashes the record at [seq] committed: `GET /kem/v1/spaces/{id}/chain/{seq}/seals`.
  Future<List<ChainSealHash>> _sealHashes(int seq) => _chainRoutes.sealHashes(seq);

  // ─── The delta ─────────────────────────────────────────────────────────

  Future<void> _pull(KmCache work, SpaceItemCrypto crypto, SpaceState chain, int seenAt) async {
    var since = work.cursor;
    var full = false;
    // Items an older version kept opaque, of a kind this one reads, are opened by one full read: the server wouldn't send them again
    final reopen = work.unreadKnown(kmKnowsKind);
    if (reopen.isNotEmpty) {
      since = null;
      work.cursor = null;
      full = true;
    }
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
      if (page == null) {
        return;
      }
      for (final item in page.items) {
        // The vault's own items and the other spaces' come in the same answer
        if (item.owner == owner.toWire()) {
          await _apply(work, crypto, chain, item, seenAt, reopen);
        }
      }
      work.cursor = page.cursor;
      if (!page.more) {
        return;
      }
      since = page.cursor;
    }
  }

  Future<void> _apply(KmCache work, SpaceItemCrypto crypto, SpaceState chain, KmWireItem wire, int seenAt, Set<String> reopen) async {
    final existing = work.items[wire.id];
    final sum = wire.deleted ? '' : b64urlEncode(hash.sha256.convert(wire.ciphertext!).bytes);
    if (existing != null) {
      if (wire.revision < existing.revision) {
        throw SpaceSyncError(SpaceSyncIssue.older, detail: 'item ${wire.id} at ${wire.revision}, held at ${existing.revision}');
      }
      // The same revision again needs nothing, unless the server now marks it held, or no longer does
      if (wire.revision == existing.revision &&
          sum == existing.hash &&
          wire.held == (existing.extra[_heldKey] == true) &&
          !reopen.contains(wire.id)) {
        return;
      }
    }
    final collection = wire.collectionId ?? (existing?.extra[_collectionKey] as String?);
    final extra = {_collectionKey: ?collection};
    if (wire.deleted) {
      work.items[wire.id] = KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: '',
        entryId: existing?.entryId,
        deletedAt: wire.deletedAt ?? existing?.deletedAt ?? seenAt,
        extra: extra,
      );
      return;
    }
    if (wire.held) {
      // The server holds it, under an old key version this phone does not open: keep the last copy it accepted, if any,
      // and the server's revision, which a keep or a delete names. The held list reads it from here.
      work.items[wire.id] = KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: sum,
        entry: existing?.entry,
        entryId: existing?.entryId,
        opaque: existing?.entry == null,
        heldSince: existing?.heldSince ?? seenAt,
        extra: {...extra, _heldKey: true},
      );
      return;
    }
    if (itemRefusal(
          chain: chain,
          collection: collection,
          keyVersion: wire.keyVersion,
          revision: wire.revision,
          acceptedRevision: existing?.revision,
        ) !=
        null) {
      // Held and shown, as an unlisted item is: the accepted revision stays, and a new one is kept apart
      final kept = existing?.held(seenAt);
      work.items[wire.id] = kept == null
          ? KmCachedItem(
              revision: wire.revision,
              kind: wire.kind,
              keyVersion: wire.keyVersion,
              hash: sum,
              opaque: true,
              heldSince: seenAt,
              extra: extra,
            )
          : KmCachedItem(
              revision: kept.revision,
              kind: kept.kind,
              keyVersion: kept.keyVersion,
              hash: kept.hash,
              entry: kept.entry,
              entryId: kept.entryId,
              deletedAt: kept.deletedAt,
              heldSince: kept.heldSince,
              opaque: kept.opaque,
              extra: {...kept.extra, _refusedKey: wire.revision},
            );
      return;
    }
    work.items[wire.id] = await _open(crypto, wire, sum, existing, collection);
  }

  /// Opens [wire] under [collection]'s key into a cached entry, or keeps it opaque when it is of a kind this
  /// version doesn't read, or doesn't open.
  Future<KmCachedItem> _open(SpaceItemCrypto crypto, KmWireItem wire, String sum, KmCachedItem? existing, String? collection) async {
    final extra = {_collectionKey: ?collection};
    KmCachedItem opaque() => KmCachedItem(
      revision: wire.revision,
      kind: wire.kind,
      keyVersion: wire.keyVersion,
      hash: sum,
      opaque: true,
      heldSince: existing?.heldSince,
      extra: extra,
    );
    if (collection == null || !wire.isKem1 || !kmKnowsKind(wire.kind)) {
      return opaque();
    }
    try {
      final json = jsonDecode(utf8.decode(await crypto.openItem(wire.toKem1(), collection)));
      if (!kmReadable(wire.kind, json, wire.id, owner)) {
        return opaque();
      }
      final entry = json as Map<String, Object?>;
      return KmCachedItem(
        revision: wire.revision,
        kind: wire.kind,
        keyVersion: wire.keyVersion,
        hash: sum,
        entry: entry,
        entryId: entry['id'] as String,
        heldSince: existing?.heldSince,
        extra: extra,
      );
    } catch (e) {
      if (e is CorruptedException || e is MalformedException || e is FormatException || e is NoCollectionKey) {
        return opaque();
      }
      rethrow;
    }
  }

  // ─── The manifest ──────────────────────────────────────────────────────

  Future<FetchedSpaceManifest?> _fetchManifest() async {
    final json = await connection.call(
      (token) => _api.call('GET', server, '/manifests/${owner.toWire()}', token: token, absentIsNull: true),
    );
    if (json == null) {
      return null;
    }
    final manifest = json['manifest'];
    final signature = json['signature'];
    final signer = json['signer'];
    if (manifest is! String || signature is! String || signer is! String) {
      throw const KmError(KmProblem.server, message: 'a manifest answer');
    }
    try {
      return FetchedSpaceManifest(manifest: b64urlDecode(manifest), signature: b64urlDecode(signature), signer: signer);
    } on MalformedException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  ManifestRecord? _record(KmCache cache) {
    final bytes = cache.manifest;
    if (bytes == null) {
      return null;
    }
    try {
      return ManifestRecord(Manifest.parse(bytes));
    } on MalformedException {
      return null;
    }
  }

  /// Sorts every envelope the server sent for the space, readable or not, against the space's signed manifest.
  Future<void> _checkManifest(KmCache work, KmCache stored, SpaceState chain, int now) async {
    final fetched = await _fetchManifest();
    final answer = [
      for (final MapEntry(:key, :value) in work.items.entries)
        ServerItemState(
          itemId: uuidBytes(key),
          revision: value.revision,
          ciphertextHash: value.deleted ? Uint8List(32) : b64urlDecode(value.hash),
          deleted: value.deleted,
        ),
    ];
    final check = await checkSpaceManifest(
      state: chain,
      owner: owner,
      fetched: fetched,
      record: _record(stored),
      deleted: stored.deleted,
      answer: answer,
      crypto: manifestCrypto,
    );
    if (check.problem != null) {
      throw SpaceSyncError(SpaceSyncIssue.older, manifest: check.problem, detail: check.detail);
    }
    if (check.newer && fetched != null) {
      work.manifest = fetched.manifest;
      work.manifestSignature = fetched.signature;
    }
    for (final finding in check.findings) {
      final id = uuidText(finding.itemId);
      switch (finding.verdict) {
        case ItemVerdict.rolledBack || ItemVerdict.missing || ItemVerdict.resurrected:
          throw SpaceSyncError(SpaceSyncIssue.older, detail: '${finding.verdict.name} item $id');
        case ItemVerdict.unlisted:
          work.items[id] = work.items[id]!.held(now);
        case ItemVerdict.expected || ItemVerdict.sibling:
          work.items[id] = work.items[id]!.listed();
      }
    }
    for (final MapEntry(:key, :value) in work.items.entries) {
      final since = value.heldSince;
      if (since != null && value.extra[_heldKey] != true && now - since > _heldLimit.inMilliseconds) {
        throw SpaceSyncError(SpaceSyncIssue.older, detail: 'item $key unlisted since $since');
      }
    }
  }

  /// Signs one manifest of every item of the space, above every counter this phone saw, and sends it after the last
  /// batch. Held items are not listed: this phone doesn't vouch for what no permitted signer listed.
  Future<void> _signManifest(KmCache work) async {
    final record = _record(work);
    final manifest = buildSpaceManifest(
      owner: owner,
      counter: (record?.counter ?? 0) + 1,
      items: [
        for (final MapEntry(:key, :value) in work.items.entries)
          if (value.heldSince == null)
            ServerItemState(
              itemId: uuidBytes(key),
              revision: value.revision,
              ciphertextHash: value.deleted ? Uint8List(32) : b64urlDecode(value.hash),
              deleted: value.deleted,
            ),
      ],
    );
    final signature = await manifestCrypto.sign(manifest, account.sig1PrivateKey);
    try {
      await connection.call((token) => _api.putManifest(server, token, owner.toWire(), manifest.bytes, signature));
    } on KmError catch (e) {
      // 423: the space waits for new keys. The next run signs after the rotation. 409: another member signed first.
      if (e.status == 423 || e.problem == KmProblem.stale) {
        return;
      }
      rethrow;
    }
    work.manifest = manifest.bytes;
    work.manifestSignature = signature;
  }

  // ─── The diff and the batches ──────────────────────────────────────────

  ({List<_Write> writes, int removals, int removedHere, int scope, Map<String, String> collections}) _plan(
    KmCache work,
    Lists local,
    SyncDoc merged,
    SpaceState chain,
    SpaceKeyring keyring,
    String me,
    Map<String, String> collections,
  ) {
    final puts = <_Write>[];
    final deletes = <_Write>[];
    final liveIds = <String>{};
    final chosen = <String, String>{};
    // A new entry goes in the space's first collection, "Everyone", until a screen picks another
    final fallback = chain.collections.keys.firstOrNull;
    bool mayWrite(String collection) =>
        (chain.accessOf(me, collection)?.edit ?? false) &&
        keyring.currentVersion(collection) != null &&
        !chain.spaceKeyMarked &&
        !chain.markedCollections.contains(collection);

    for (final entry in kmEntriesOf(merged)) {
      final id = kmEntryId(entry);
      if (id.isEmpty) {
        continue;
      }
      liveIds.add(id);
      final uuid = kmItemId(id, owner);
      final cached = work.items[uuid];
      if (cached != null && (cached.opaque || cached.heldSince != null)) {
        continue;
      }
      final collection = collections[id] ?? (cached?.extra[_collectionKey] as String?) ?? fallback;
      if (collection == null) {
        continue;
      }
      chosen[id] = collection;
      if (cached != null && cached.applied && canonical(cached.entry) == canonical(entry.json)) {
        continue;
      }
      // Not granted edit on it, or no key of its current version: left as it is, never written under another
      if (!mayWrite(collection)) {
        continue;
      }
      puts.add(
        _Write(
          id: uuid,
          kind: cached?.kind ?? entry.kind,
          collection: collection,
          revision: (cached?.revision ?? 0) + 1,
          expected: cached?.revision,
          json: entry.json,
        ),
      );
    }
    for (final tomb in merged.deleted) {
      if (tomb.id.isEmpty || liveIds.contains(tomb.id)) {
        continue;
      }
      final uuid = kmItemId(tomb.id, owner);
      final cached = work.items[uuid];
      if (cached == null || !cached.applied) {
        continue;
      }
      final collection = cached.extra[_collectionKey] as String?;
      if (collection == null || !mayWrite(collection)) {
        continue;
      }
      deletes.add(_Write(id: uuid, kind: cached.kind, collection: collection, revision: cached.revision + 1, expected: cached.revision));
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
      collections: chosen,
    );
  }

  /// Seals and sends [writes] in batches, and puts what the server stored in [work]. Returns whether any went.
  Future<bool> _send(KmCache work, List<_Write> writes, SpaceItemCrypto crypto, SpaceKeyring keyring, int now) async {
    if (writes.isEmpty) {
      return false;
    }
    final byId = {for (final write in writes) write.id: write};
    for (var start = 0; start < writes.length; start += KmApi.batchSize) {
      final chunk = writes.sublist(start, min(start + KmApi.batchSize, writes.length));
      final sealed = [for (final write in chunk) await _seal(write, crypto, keyring)];
      final answer = await connection.call((token) => _api.call('POST', server, '/items:batch', token: token, body: {'writes': sealed}));
      final items = answer?['items'];
      if (items is! List<Object?>) {
        throw const KmError(KmProblem.server, message: 'a batch answer');
      }
      for (final raw in items) {
        final KmWireItem item;
        try {
          item = KmWireItem.fromJson(raw);
        } on FormatException catch (e) {
          throw KmError(KmProblem.server, message: e.message);
        }
        final write = byId[item.id];
        if (write == null) {
          continue;
        }
        final cached = work.items[item.id];
        final extra = {_collectionKey: write.collection};
        work.items[item.id] = item.deleted
            ? KmCachedItem(
                revision: item.revision,
                kind: item.kind,
                keyVersion: item.keyVersion,
                hash: '',
                entryId: cached?.entryId,
                deletedAt: now,
                extra: extra,
              )
            : KmCachedItem(
                revision: item.revision,
                kind: item.kind,
                keyVersion: item.keyVersion,
                hash: b64urlEncode(hash.sha256.convert(item.ciphertext!).bytes),
                entry: write.json,
                entryId: write.json!['id'] as String,
                extra: extra,
              );
      }
    }
    return true;
  }

  /// One write of a batch: `{expectedRevision, item}`, the item with the `collectionId` the server needs.
  Future<Map<String, Object?>> _seal(_Write write, SpaceItemCrypto crypto, SpaceKeyring keyring) async {
    final json = write.json;
    if (json == null) {
      final tombstone = Kem1Item.tombstone(
        id: write.id,
        owner: owner,
        kind: write.kind,
        revision: write.revision,
        keyVersion: keyring.currentVersion(write.collection)!,
      );
      return {
        'expectedRevision': write.expected,
        'item': {...tombstone.toJson(), 'collectionId': write.collection},
      };
    }
    final sealed = await crypto.sealItem(
      itemId: write.id,
      revision: write.revision,
      kind: write.kind,
      collection: write.collection,
      plaintext: Uint8List.fromList(utf8.encode(jsonEncode(json))),
    );
    final item = Kem1Item(
      id: write.id,
      owner: owner,
      kind: write.kind,
      revision: write.revision,
      keyVersion: sealed.keyVersion,
      ciphertext: sealed.ciphertext,
      itemKey: sealed.itemKey,
    );
    return {
      'expectedRevision': write.expected,
      'item': {...item.toJson(), 'collectionId': write.collection},
    };
  }
}

// ─── Who a key is sealed to ──────────────────────────────────────────────

/// A member of a space as the server's list shows it: the account and the bundle bytes it holds for it.
typedef ServerMemberKey = ({String id, Uint8List bundle});

/// A member the server lists that no seal goes to, and why. The caller logs it in the space's activity.
typedef IgnoredMember = ({String id, String reason});

/// Who a collection's key is sealed to.
typedef SealPlan = ({Map<String, KeyBundle> recipients, List<IgnoredMember> ignored});

/// Plans the seals of [collection]'s key: only to the members the verified [state] confirms and grants it, using
/// the `kx1` key in the bundle the chain recorded for them. A member the server lists but the chain doesn't confirm,
/// or whose server bundle isn't the one the chain recorded, gets no seal and is named in `ignored`. The server's list
/// is never what decides.
SealPlan planSeals({required SpaceState state, required String collection, Iterable<ServerMemberKey> serverMembers = const []}) {
  final recipients = {for (final id in state.recipients(collection)) id: state.member(id)!.bundle!};
  final ignored = <IgnoredMember>[];
  for (final listed in serverMembers) {
    final member = state.member(listed.id);
    final bundle = member?.bundle;
    if (member == null || !member.isConfirmed || bundle == null) {
      ignored.add((id: listed.id, reason: 'the server lists this account, and the chain does not confirm it'));
    } else if (!_same(bundle.bytes, listed.bundle)) {
      ignored.add((id: listed.id, reason: 'the server lists a key bundle other than the one the chain recorded'));
    }
  }
  return (recipients: recipients, ignored: ignored);
}

/// The seals of [collection]'s [key] at [keyVersion], one for each recipient of [plan].
Future<Map<String, Uint8List>> sealCollectionKeyFor({
  required SealPlan plan,
  required Uint8List key,
  required String space,
  required String collection,
  required int keyVersion,
}) async => {
  for (final entry in plan.recipients.entries)
    entry.key: await sealCollectionKey(to: entry.value, key: key, space: space, collection: collection, keyVersion: keyVersion),
};

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}
