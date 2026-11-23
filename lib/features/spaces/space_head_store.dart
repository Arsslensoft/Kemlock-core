// What the vault keeps of each space's chain (docs/plans/add-server-spaces.md, task 2.3; the space chain section
// of docs/crypto.md, "Hash link"): the **anchor**, the epoch and the link of every record this device accepted, by
// the space's UUID, so the next sync can refuse a chain that ends before it or holds another record at a sequence
// number it accepted (`space_verify.dart`).
//
// It is one sealed value of the vault, `backmycodes_space_heads` (the storage key keeps its old name), written
// through `VaultStore.saveEncryptedValue` as the duplicate cleaner's are: sealed to the vault's key pair, sealed again
// by a replacement of that pair (`sealedValueKeys` finds it by its shape, and an older build leaves a value under a
// key it doesn't know alone) and deleted with the vault (`VaultRegistry.removeVaultData`). It is in no export, QR
// transfer, sync file or server item.
//
// The stored format is version 2: `{"v": 2, "anchors": {<uuid>: {"epoch", "links", "compared"?}}, "exportPolicies"?: {...}}`.
// Version 1 kept only
// `(seq, hash)` of the last record, which holds no links to compare against a fork, so it can't be upgraded: a
// version-1 value is read as no anchors, and each space goes through first contact again.
//
// An anchor can't be made again: a device that lost it could be handed a rolled-back chain. So a value that can't be
// opened throws, and is never read as empty and saved over.
//
// An anchor says which chain a device accepted, not that anyone compared a fingerprint: a chain a server made up
// verifies and could be anchored like any other. So each space's entry may also carry `"compared": true`, set only where
// a fingerprint was compared (the first-contact screen, the creator's own device) and never by reading a chain. First
// contact is that record and nothing else ([SpaceAnchors.hasCompared]). An entry without it is an anchor no one
// compared, as an earlier build of this branch wrote by anchoring whatever it read: that space goes through first
// contact again.
//
// The top-level member `"exportPolicies": {<uuid>: {"disableExport", "epoch", "seq", "at"}}` holds the export policy of the last
// chain whose fingerprint was compared and that this account read (docs/plans/add-server-spaces.md, 7.4): a file export that
// can't read a space's chain now (offline, the server down, just after unlock) follows what that chain said, instead of
// leaving the space's items out ([RememberedExportPolicy]). It is optional and travels with the anchors, so the account's other
// phones have it too. It is a top-level member, not a field of each space's entry, because a build from before it reads an
// entry strictly and refuses one with a field it doesn't know, which would stop the anchors syncing; a top-level member it
// doesn't know it keeps as it was (`extra`). It is a memory of a verified chain and never a verdict: a chain read later replaces
// it, and it is never kept for a space with no anchor.
//
// Decided by the owner: the anchors sync between one account's devices through the personal vault, so a new phone of
// the account trusts what the account's other phones already confirmed and compares no fingerprint for a space the
// anchors carry with the `compared` record. A device that compared vouches for the chain; one that only read it doesn't.
// [SyncedSpaceAnchorStore] is that: besides the device's own value above, it keeps the anchors as one
// more sealed value, `backmycodes_space_anchors`, which the vault's own sync carries (Kemlock Server or WebDAV) and
// merges with the other devices' copies by [SpaceAnchors.mergedWith], never by the sync's own last-writer-wins. A phone
// with no vault sync keeps them on the device only, in [SpaceAnchorStore].
//
// The carried value holds only links, which anyone could compute from the chain, but it is the one thing that tells a
// new phone it needn't compare a fingerprint, so a server that could rewrite it could skip first contact. The vault's
// sync encrypts it with keys only the account's devices hold, as it does every entry, and a value that can't be read
// is refused, never read as empty.

library;

import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart' show constantTimeEquals;
import '../../models/json.dart';
import '../../vault/vault_store.dart';
import 'space_verify.dart';

/// The storage key of the anchors, under the vault's own suffix.
const keySpaceHeads = 'backmycodes_space_heads';

/// The storage key of the anchors the vault's sync carries between the account's devices, under the vault's own
/// suffix: the same value as [keySpaceHeads] holds, as this device last merged it with the others'. A sync engine
/// reads and writes it as a sealed value and merges two copies with [SpaceAnchors.mergeValues].
const keySpaceAnchorsSynced = 'backmycodes_space_anchors';

/// The version of the value.
const spaceAnchorsFormat = 2;

/// What the last verified chain of a space said of exporting its items, as this account read it: [disableExport], from the
/// chain's record [seq] of its [epoch], read at [at] (milliseconds since the epoch).
final class RememberedExportPolicy {
  const RememberedExportPolicy({required this.disableExport, required this.epoch, required this.seq, required this.at});

  /// Reads `{"disableExport", "seq", "at", "epoch"?}`, or null for anything else. A record that can't be read is none, which
  /// leaves the space's items out of an export and never refuses the anchors it rides in.
  static RememberedExportPolicy? tryRead(Object? json) {
    if (json is! Map<String, Object?>) {
      return null;
    }
    final disableExport = json['disableExport'];
    final epoch = json['epoch'];
    final seq = json['seq'];
    final at = json['at'];
    if (disableExport is! bool || seq is! int || seq < 0 || at is! int) {
      return null;
    }
    return RememberedExportPolicy(disableExport: disableExport, epoch: epoch is int && epoch >= 1 ? epoch : 1, seq: seq, at: at);
  }

  /// Whether the space forbade exporting its items.
  final bool disableExport;

  /// The epoch and the `seq` of the chain's last record this was read from.
  final int epoch;
  final int seq;

  /// When it was read, in milliseconds since the epoch.
  final int at;

  /// Whether this was read from a chain at least as far on as [other]'s.
  bool supersedes(RememberedExportPolicy other) => epoch != other.epoch ? epoch > other.epoch : seq >= other.seq;

  /// Of two records two devices made, the one from the chain further on; a tie goes to the one that forbids export, then to
  /// the later read.
  static RememberedExportPolicy newer(RememberedExportPolicy a, RememberedExportPolicy b) {
    if (a.epoch != b.epoch) {
      return a.epoch > b.epoch ? a : b;
    }
    if (a.seq != b.seq) {
      return a.seq > b.seq ? a : b;
    }
    if (a.disableExport != b.disableExport) {
      return a.disableExport ? a : b;
    }
    return a.at >= b.at ? a : b;
  }

  Map<String, Object?> toJson() => {'disableExport': disableExport, 'epoch': epoch, 'seq': seq, 'at': at};

  @override
  bool operator ==(Object other) =>
      other is RememberedExportPolicy && other.disableExport == disableExport && other.epoch == epoch && other.seq == seq && other.at == at;

  @override
  int get hashCode => Object.hash(disableExport, epoch, seq, at);
}

/// The anchor of each space's chain this device accepted, by the space's UUID.
final class SpaceAnchors {
  SpaceAnchors([
    Map<String, ChainAnchor> anchors = const {},
    this.extra = const {},
    Set<String> compared = const {},
    Map<String, RememberedExportPolicy> exportPolicies = const {},
  ]) : _anchors = Map.unmodifiable(anchors),
       // A record of a comparison means nothing without the anchor it was made for, nor does a remembered export policy
       _compared = Set.unmodifiable(compared.where(anchors.containsKey)),
       _exportPolicies = Map.unmodifiable({
         for (final entry in exportPolicies.entries)
           if (anchors.containsKey(entry.key)) entry.key: entry.value,
       });

  /// Reads the stored form. Anything that isn't `{"v": 2, "anchors": {<uuid>: {"epoch", "links"}}}` is a
  /// [MalformedException], never an empty set of anchors; a version-1 value is read as none, as the file's comment says.
  factory SpaceAnchors.fromJson(Object? json) {
    if (json == null) {
      return SpaceAnchors();
    }
    if (json is! Map<String, Object?>) {
      throw const MalformedException('the space anchors are an object');
    }
    final version = json['v'];
    if (version == 1) {
      return SpaceAnchors();
    }
    if (version is int && version > spaceAnchorsFormat) {
      // A newer build wrote it: read nothing of it and keep it as it is, so this one never saves over it
      throw MalformedException('the space anchors are of version $version');
    }
    final anchors = json['anchors'];
    if (anchors is! Map<String, Object?>) {
      throw const MalformedException('anchors is an object');
    }
    final read = <String, ChainAnchor>{};
    final compared = <String>{};
    for (final MapEntry(:key, :value) in anchors.entries) {
      if (!isUuidText(key)) {
        throw MalformedException('not a space id: $key');
      }
      if (value is Map<String, Object?> && value.containsKey(_comparedKey)) {
        // Only `true` is a comparison; anything else reads as none, which asks for the comparison again
        if (value[_comparedKey] == true) {
          compared.add(key);
        }
        read[key] = ChainAnchor.fromJson({...value}..remove(_comparedKey));
      } else {
        read[key] = ChainAnchor.fromJson(value);
      }
    }
    final extra = extraKeys(json, const {'v', 'anchors', _exportPoliciesKey});
    return SpaceAnchors(read, extra, compared, _readPolicies(json[_exportPoliciesKey]));
  }

  /// Reads the `exportPolicies` member: each record that can be read, and none for a member that isn't an object. A record that
  /// can't be read is none, so the space's items then stay out of an export, and the anchors it rides in are never refused.
  static Map<String, RememberedExportPolicy> _readPolicies(Object? json) {
    if (json is! Map<String, Object?>) {
      return const {};
    }
    final policies = <String, RememberedExportPolicy>{};
    for (final MapEntry(:key, :value) in json.entries) {
      final policy = RememberedExportPolicy.tryRead(value);
      if (policy != null) {
        policies[key] = policy;
      }
    }
    return policies;
  }

  static const _comparedKey = 'compared';

  /// The top-level member that carries the remembered export policies. Not a field of each space's entry: a build from before
  /// it refuses an entry with a field it doesn't know (`ChainAnchor.fromJson` is strict) and would stop syncing the anchors,
  /// while it keeps a top-level member it doesn't know as it was ([extra]).
  static const _exportPoliciesKey = 'exportPolicies';

  final Map<String, ChainAnchor> _anchors;
  final Set<String> _compared;
  final Map<String, RememberedExportPolicy> _exportPolicies;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, ChainAnchor> get anchors => _anchors;

  int get length => _anchors.length;

  /// The anchor accepted for [space], or null.
  ChainAnchor? of(String space) => _anchors[space];

  /// These anchors with [anchor] for [space]. An anchor never goes back: one that ends before the one held, at a lower
  /// `seq`, is left out and these anchors come back as they were, except by a fence: [afterFence] takes the new anchor
  /// whatever it holds, because the fence dropped the device's records from where it diverged.
  ///
  /// [compared] is true only where a fingerprint was just compared, and the record then stays with the space. False keeps
  /// what was recorded before and never makes the record: remembering a chain that was only read leaves it uncompared.
  SpaceAnchors remembering(String space, ChainAnchor anchor, {bool afterFence = false, bool compared = false}) {
    final held = _anchors[space];
    final wasCompared = _compared.contains(space);
    if (held != null && !afterFence && held.seq > anchor.seq) {
      return compared && !wasCompared ? SpaceAnchors(_anchors, extra, {..._compared, space}, _exportPolicies) : this;
    }
    return SpaceAnchors({..._anchors, space: anchor}, extra, {..._compared, if (compared) space}, _exportPolicies);
  }

  /// The export policy remembered for [space], or null.
  RememberedExportPolicy? exportPolicyOf(String space) => _exportPolicies[space];

  /// The remembered export policies, by the space's UUID.
  Map<String, RememberedExportPolicy> get exportPolicies => _exportPolicies;

  /// These anchors with [policy] remembered for [space], which a chain compared for it just gave. A record from a chain
  /// further on than [policy]'s stays, and a space with no anchor takes none.
  SpaceAnchors rememberingExport(String space, RememberedExportPolicy policy) {
    final held = _exportPolicies[space];
    if (held != null && !policy.supersedes(held)) {
      return this;
    }
    return SpaceAnchors(_anchors, extra, _compared, {..._exportPolicies, space: policy});
  }

  /// These anchors with the export policies of [other] as well, the one from the chain further on where both have one
  /// ([RememberedExportPolicy.newer]). The anchors themselves are these.
  SpaceAnchors withPoliciesOf(SpaceAnchors other) => SpaceAnchors(_anchors, extra, _compared, _policiesWith(other));

  Map<String, RememberedExportPolicy> _policiesWith(SpaceAnchors other) {
    final merged = {..._exportPolicies};
    for (final MapEntry(:key, :value) in other._exportPolicies.entries) {
      final mine = merged[key];
      merged[key] = mine == null ? value : RememberedExportPolicy.newer(mine, value);
    }
    return merged;
  }

  /// Whether a fingerprint was compared for [space], on this device or on another device of the account whose anchor was
  /// merged in. This is first contact: an anchor alone is not.
  bool hasCompared(String space) => _compared.contains(space);

  /// The spaces whose fingerprint was compared.
  Set<String> get compared => _compared;

  /// These anchors and [other]'s, as two devices of one account meet them in the vault's sync. For each space:
  ///
  /// - held by one of them: that anchor;
  /// - held by both, one's links a prefix of the other's: the longer, since both saw one chain and one is further on;
  /// - held by both, the links differing at a `seq` both hold: the one of the higher epoch, since a fence moved the
  ///   chain on and the device behind meets the fence when it next verifies; and when the epochs are equal, this
  ///   device's own, with the space named in `forked`: two devices of one account were served two chains, and the
  ///   next verification refuses the one that doesn't match.
  ///
  /// The record that a fingerprint was compared follows the anchor it was made for: a space only one of them holds keeps its
  /// own record; when both hold one chain a comparison on either counts, since a device that compared vouches for the chain
  /// and the other holds a prefix or the same of it; and when the chains differ it is the taken anchor's own.
  ///
  /// The remembered export policies of both are kept, the one from the chain further on where both have one, whichever anchor
  /// was taken: it is a memory of what a verified chain said, and the next chain read replaces it.
  ///
  /// Keys one of them doesn't know are kept, this device's first.
  ({SpaceAnchors anchors, Set<String> forked}) mergedWith(SpaceAnchors other) {
    final merged = <String, ChainAnchor>{};
    final compared = <String>{};
    final forked = <String>{};
    for (final space in {..._anchors.keys, ...other._anchors.keys}) {
      final mine = _anchors[space];
      final theirs = other._anchors[space];
      final minesCompared = _compared.contains(space);
      final theirsCompared = other._compared.contains(space);
      if (mine == null || theirs == null) {
        merged[space] = (mine ?? theirs)!;
        if (mine == null ? theirsCompared : minesCompared) {
          compared.add(space);
        }
        continue;
      }
      final shared = mine.links.length < theirs.links.length ? mine.links.length : theirs.links.length;
      var agree = true;
      for (var i = 0; i < shared && agree; i++) {
        agree = constantTimeEquals(mine.links[i], theirs.links[i]);
      }
      if (agree) {
        merged[space] = theirs.links.length > mine.links.length ? theirs : mine;
        if (minesCompared || theirsCompared) {
          compared.add(space);
        }
      } else if (theirs.epoch > mine.epoch) {
        merged[space] = theirs;
        if (theirsCompared) {
          compared.add(space);
        }
      } else {
        merged[space] = mine;
        if (minesCompared) {
          compared.add(space);
        }
        if (theirs.epoch == mine.epoch) {
          forked.add(space);
        }
      }
    }
    return (anchors: SpaceAnchors(merged, {...other.extra, ...extra}, compared, _policiesWith(other)), forked: forked);
  }

  /// [ours] and [theirs], two copies of the carried value as the sync reads them, merged by [mergedWith] and written
  /// in the stored form. A copy that can't be read is a [MalformedException]: the sync keeps its own and writes nothing
  /// over the other, never reads one as empty.
  static Map<String, Object?> mergeValues(Object? ours, Object? theirs) =>
      SpaceAnchors.fromJson(ours).mergedWith(SpaceAnchors.fromJson(theirs)).anchors.toJson();

  /// These anchors without [space]'s, for a space this device left or was removed from.
  SpaceAnchors forgetting(String space) => SpaceAnchors(
    {
      for (final entry in _anchors.entries)
        if (entry.key != space) entry.key: entry.value,
    },
    extra,
    _compared,
    _exportPolicies,
  );

  Map<String, Object?> toJson() => {
    'v': spaceAnchorsFormat,
    'anchors': {
      for (final MapEntry(:key, :value) in _anchors.entries) key: {...value.toJson(), if (_compared.contains(key)) _comparedKey: true},
    },
    ...extra,
    if (_exportPolicies.isNotEmpty) _exportPoliciesKey: {for (final MapEntry(:key, :value) in _exportPolicies.entries) key: value.toJson()},
  };
}

/// Where a device keeps the anchors of the spaces it syncs: on the device only ([SpaceAnchorStore]), or also in the
/// value the personal vault's sync carries to the account's other devices ([SyncedSpaceAnchorStore]); see the file's
/// comment.
abstract interface class SpaceAnchorStorage {
  /// The anchors, empty when none are saved. A value that can't be opened or read throws.
  Future<SpaceAnchors> load(VaultSession session);

  Future<void> save(SpaceAnchors anchors, VaultSession session);

  /// Remembers [anchor] for [space] and saves it, unless the anchor held is further on (and [afterFence] is false).
  /// [compared] records that a fingerprint was compared for the space (see [SpaceAnchors.remembering]).
  Future<SpaceAnchors> remember(String space, ChainAnchor anchor, VaultSession session, {bool afterFence = false, bool compared = false});

  /// Remembers [policy] as the export policy of [space]'s last chain a fingerprint was compared for, and saves it
  /// (see [SpaceAnchors.rememberingExport]).
  Future<SpaceAnchors> rememberExport(String space, RememberedExportPolicy policy, VaultSession session);
}

/// Runs one load-modify-save of a vault's anchors at a time. Two of them interleaving, such as a run's anchor save and the
/// export policy a compared chain leaves, would each save what it loaded and lose the other's change, or move an anchor back.
/// Every write of the anchors, by either store, goes through the lock of the [VaultStore] it is made through.
final class _AnchorLock {
  Future<void> _tail = Future.value();

  Future<T> run<T>(Future<T> Function() action) {
    final result = _tail.then((_) => action());
    _tail = result.then<void>((_) {}, onError: (Object _) {});
    return result;
  }
}

/// The lock of [store]: one per vault store, which every anchor write of the app goes through (the app has one, so it is one
/// per phone, and so one per vault while one vault is open).
final _anchorLocks = Expando<_AnchorLock>('the anchor locks');

_AnchorLock _lockOf(VaultStore store) => _anchorLocks[store] ??= _AnchorLock();

/// The vault's anchors of the spaces' chains, kept on this device only.
class SpaceAnchorStore implements SpaceAnchorStorage {
  const SpaceAnchorStore(this._store);

  final VaultStore _store;

  @override
  Future<SpaceAnchors> load(VaultSession session) async => SpaceAnchors.fromJson(await _store.loadEncryptedValue(keySpaceHeads, session));

  @override
  Future<void> save(SpaceAnchors anchors, VaultSession session) => _lockOf(_store).run(() => _write(anchors, session));

  /// Saves [anchors] with the export policies the device holds, which a run that loaded the anchors before one was
  /// remembered doesn't know. A value that can't be read is saved over as it always was. Returns what was saved. Takes no lock:
  /// the caller holds it.
  Future<SpaceAnchors> _write(SpaceAnchors anchors, VaultSession session) async {
    var kept = anchors;
    try {
      kept = anchors.withPoliciesOf(await load(session));
    } catch (_) {
      // Nothing held can be read: these anchors are saved as they are
    }
    await _store.saveEncryptedValue(keySpaceHeads, kept.toJson(), session);
    return kept;
  }

  @override
  Future<SpaceAnchors> remember(String space, ChainAnchor anchor, VaultSession session, {bool afterFence = false, bool compared = false}) =>
      _lockOf(_store).run(() async {
        final anchors = (await load(session)).remembering(space, anchor, afterFence: afterFence, compared: compared);
        await _write(anchors, session);
        return anchors;
      });

  @override
  Future<SpaceAnchors> rememberExport(String space, RememberedExportPolicy policy, VaultSession session) => _lockOf(_store).run(() async {
    final anchors = (await load(session)).rememberingExport(space, policy);
    await _write(anchors, session);
    return anchors;
  });
}

/// The anchors of the spaces' chains, kept on this device and in the value the personal vault's sync carries, so a new
/// device of the account starts from what its other devices accepted.
///
/// [syncs] says whether the vault syncs with Kemlock Server or WebDAV: a phone with no vault sync keeps them on the
/// device only, as [SpaceAnchorStore] does. Reading merges the two values with [SpaceAnchors.mergedWith]: what the
/// sync brought from the other devices is read as anchors, so a new device finds its spaces anchored. Saving writes
/// the merge to both, since an anchor never goes back, so a copy the sync brought that is further on isn't lost.
class SyncedSpaceAnchorStore implements SpaceAnchorStorage {
  const SyncedSpaceAnchorStore(this._store, {required this._syncs});

  final VaultStore _store;
  final bool Function() _syncs;

  SpaceAnchorStore get _device => SpaceAnchorStore(_store);

  Future<SpaceAnchors> _carried(VaultSession session) async =>
      SpaceAnchors.fromJson(await _store.loadEncryptedValue(keySpaceAnchorsSynced, session));

  @override
  Future<SpaceAnchors> load(VaultSession session) async {
    final device = await _device.load(session);
    return _syncs() ? device.mergedWith(await _carried(session)).anchors : device;
  }

  /// The spaces whose chain two devices of this account were served differently (see [SpaceAnchors.mergedWith]): the
  /// Spaces sheet shows them as "Can't be checked".
  Future<Set<String>> disagreements(VaultSession session) async =>
      _syncs() ? (await _device.load(session)).mergedWith(await _carried(session)).forked : const {};

  @override
  Future<void> save(SpaceAnchors anchors, VaultSession session) => _lockOf(_store).run(() => _write(anchors, session));

  /// Writes [anchors] to the device and, when the vault syncs, the merge with the carried value. Takes no lock: the caller
  /// holds it.
  Future<void> _write(SpaceAnchors anchors, VaultSession session) async {
    final kept = await _device._write(anchors, session);
    if (_syncs()) {
      final merged = kept.mergedWith(await _carried(session)).anchors;
      await _store.saveEncryptedValue(keySpaceAnchorsSynced, merged.toJson(), session);
    }
  }

  @override
  Future<SpaceAnchors> remember(String space, ChainAnchor anchor, VaultSession session, {bool afterFence = false, bool compared = false}) =>
      _lockOf(_store).run(() async {
        final anchors = (await load(session)).remembering(space, anchor, afterFence: afterFence, compared: compared);
        await _write(anchors, session);
        return anchors;
      });

  @override
  Future<SpaceAnchors> rememberExport(String space, RememberedExportPolicy policy, VaultSession session) => _lockOf(_store).run(() async {
    final anchors = (await load(session)).rememberingExport(space, policy);
    await _write(anchors, session);
    return anchors;
  });
}
