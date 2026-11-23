// A WebDAV space that moved to Kemlock Server, as this phone keeps it (docs/plans/add-server-spaces.md, design 7 and
// tasks 8.1 to 8.4). The space keeps its WebDAV id and its place in the settings; what changes is where it syncs, and that
// is the [SpaceOnServer] note in the space's settings entry, under the key [spaceOnServerKey]. It lives with the settings, in
// the vault's sealed store, and never in the space's WebDAV file or in an invite, which stay byte for byte what the app has
// always written.
//
// The note has six states, per phone:
//
// - `moving`: this phone began the move and it isn't verified. The space still syncs the WebDAV file alone. A move that
//   fails its read-back leaves it here, and the person can try again; the server space that was made stays and is filled
//   again, by id.
// - `bridged`: the move was verified. This phone, which made the server space, syncs both the server space and the WebDAV
//   file, each way, until the WebDAV copy is closed. Members who haven't moved keep working through the file.
// - `offered`: this phone found a server space under the UUID the WebDAV id gives, whose chain this account already compared a
//   fingerprint for (an anchor is stored), and asks the person, naming the space's Owner, whether to merge into it. The space
//   still syncs the WebDAV file alone. That UUID is computable by anyone who can list the folder, so nothing joins on the
//   server's word alone: not on an anchor made here, and not without the person.
// - `joining`: the person agreed. The space's entries are a server space's from now on (hidden passwords, no export), and the
//   next run merges the file in once; when it has, the state is `joined`.
// - `joined`: this phone found the server space by the WebDAV id and merged the file in once. It writes the file no more; it
//   syncs the server space.
// - `closed`: the WebDAV copy is closed, by the Owner or because a member was removed or keys were replaced. This phone
//   reads and writes the file no more, and offers to delete it. The server space is all that syncs.
//
// How a phone learns a copy is closed, with no new chain kind (the chain has 21 and no other policy names):
//
// - from the chain, which cannot be forged: a removal that marked keys, a key replacement, a second collection or a grant that
//   hides passwords (`chainClosure`). Every
//   member's app derives the same, so the removal closes the bridge on every phone at once;
// - from one item of the space, `KmKind.bridgeClosed`, that the Owner's app writes when the Owner closes the copy. Only its
//   existence is read. Any member who may edit "Everyone" can write one, so it can stop the bridge but never carry anything;
//   it is marked `server: to confirm`.
//
// `KmKind.bridgeOpen` is written once by the mover after the read-back, so a phone that finds the server space finds it whole.
//
// Pure Dart, no Flutter.

library;

import '../../crypto/account/encoding.dart' show Owner;
import '../../models/json.dart';
import '../sync/kemlock/km_cache.dart';
import '../sync/kemlock/km_kinds.dart';
import '../sync/sync.dart' show Space;
import 'space_state.dart';

/// The key of a space's settings entry that holds the [SpaceOnServer] note. Builds from before Kemlock Server spaces keep
/// it as a key they don't know.
const spaceOnServerKey = 'server';

/// Where a space's WebDAV copy stands on this phone.
enum SpaceCopy {
  /// A move began here and isn't verified: the space syncs the WebDAV file alone.
  moving,

  /// This phone made the server space: it syncs both, each way.
  bridged,

  /// A server space was found for this one and waits for the person to merge into it: the space syncs the file alone.
  offered,

  /// The person agreed to merge into the server space it was offered: its entries are a server space's, and the next run
  /// merges the file in once.
  joining,

  /// Another phone made it and this one found it by id: the file was merged in once and is written no more.
  joined,

  /// The WebDAV copy is closed: the file is neither read nor written.
  closed,
}

/// Why a WebDAV copy was closed.
enum SpaceCopyClosed {
  /// The space's Owner closed it.
  owner,

  /// A member was removed or left (whether or not any key was marked for replacement).
  removal,

  /// The space's keys were replaced.
  keys,

  /// The space has more than one collection, or a grant that hides passwords: the WebDAV file holds the space's entries as one
  /// set that everyone who has its key reads in full, so it can keep neither.
  restricted,

  /// This account is no longer a member of the server space.
  left,
}

/// What this phone knows of a space that has a Kemlock Server copy.
class SpaceOnServer {
  const SpaceOnServer({
    required this.state,
    required this.uuid,
    required this.at,
    this.reason,
    this.fileDeleted = false,
    this.owner,
    this.extra = const {},
  });

  /// The note stored under [spaceOnServerKey], or null when [json] is none or a state this version doesn't know.
  static SpaceOnServer? read(Object? json) {
    if (json is! Map<String, Object?>) {
      return null;
    }
    final state = [
      for (final candidate in SpaceCopy.values)
        if (candidate.name == json['state']) candidate,
    ].firstOrNull;
    final uuid = json['uuid'];
    if (state == null || uuid is! String || uuid.isEmpty) {
      return null;
    }
    final reason = [
      for (final candidate in SpaceCopyClosed.values)
        if (candidate.name == json['reason']) candidate,
    ].firstOrNull;
    return SpaceOnServer(
      state: state,
      uuid: uuid,
      at: asInt(json['at']) ?? 0,
      reason: reason,
      fileDeleted: json['fileDeleted'] == true,
      owner: asOptionalString(json['owner']),
      extra: extraKeys(json, const {'state', 'uuid', 'at', 'reason', 'fileDeleted', 'owner'}),
    );
  }

  final SpaceCopy state;

  /// The UUID of the space on the server (`serverSpaceUuid` of the space's WebDAV id).
  final String uuid;

  /// Epoch ms of the last change of [state].
  final int at;

  /// For a closed copy, why.
  final SpaceCopyClosed? reason;

  /// Whether the file was deleted from the folder, for a closed copy.
  final bool fileDeleted;

  /// For an offered space, who owns the server space, as the person is shown it: the Owner's name, or the start of the account's
  /// id when the server doesn't tell it.
  final String? owner;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// Whether the space's entries sync with the server, which also makes them a server space's: governed by its chain, left
  /// out of exports as such, and with passwords hidden as its grants say. A joining space counts from the moment the person
  /// agrees, before any of the server's entries is applied.
  bool get onServer => state == SpaceCopy.bridged || state == SpaceCopy.joining || state == SpaceCopy.joined || state == SpaceCopy.closed;

  /// Whether this phone reads and writes the WebDAV file beside the server space.
  bool get bridging => state == SpaceCopy.bridged;

  /// The same space in [next] at [now].
  SpaceOnServer to(SpaceCopy next, int now, {SpaceCopyClosed? reason}) =>
      SpaceOnServer(state: next, uuid: uuid, at: now, reason: reason, fileDeleted: fileDeleted, owner: owner, extra: extra);

  /// The same, with the file deleted from the folder.
  SpaceOnServer withFileDeleted() =>
      SpaceOnServer(state: state, uuid: uuid, at: at, reason: reason, fileDeleted: true, owner: owner, extra: extra);

  Map<String, Object?> toJson() => {
    'state': state.name,
    'uuid': uuid,
    'at': at,
    if (reason != null) 'reason': reason!.name,
    if (fileDeleted) 'fileDeleted': true,
    if (owner != null) 'owner': owner,
    ...extra,
  };

  @override
  bool operator ==(Object other) => other is SpaceOnServer && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(state, uuid, at);

  @override
  String toString() => 'SpaceOnServer(${toJson()})';
}

/// The note a space's settings entry keeps about its Kemlock Server copy, or null for a space that has none.
extension SpaceOnServerNote on Space {
  SpaceOnServer? get onServer => SpaceOnServer.read(extra[spaceOnServerKey]);

  /// The same space with [next] as its note, or with none.
  Space withOnServer(SpaceOnServer? next) => Space(
    id: id,
    name: name,
    target: target,
    joinedAt: joinedAt,
    extra: {...extra}
      ..remove(spaceOnServerKey)
      ..addAll({if (next != null) spaceOnServerKey: next.toJson()}),
  );

  /// Whether the space's entries are a server space's now: moved, joining, joined or closed. A `moving` or an `offered` space is
  /// still a WebDAV space.
  bool get movedToServer => onServer?.onServer ?? false;
}

/// The ids of the WebDAV spaces among [spaces] whose entries are still a WebDAV space's: no rules, no grants, and every
/// password open to whoever holds the key. A space that moved is a server space's, whatever its id.
Set<String> plainWebDavSpaceIds(Iterable<Space> spaces) => {
  for (final space in spaces)
    if (!space.movedToServer) space.id,
};

/// A server space found for a WebDAV space this phone holds, which the person is asked to merge into: who owns it, as they are
/// shown it (the Owner's name, or the start of their account id).
typedef JoinOffer = ({String owner});

// ─── What a run of the space tells the scheduler ─────────────────────────

/// The key of a space run's state that carries a [BridgeSignal], and the one that carries the reason of a closed one. The
/// scheduler takes both out ([takeBridgeSignal]) before it keeps the state.
const bridgeStateKey = 'bridge';
const bridgeReasonKey = 'bridgeReason';

/// What a run of the server space found out about the WebDAV copy.
enum BridgeSignal {
  /// The move was finished: its marker is on the server.
  open,

  /// The copy is closed, for the reason that came with it.
  closed,

  /// This account isn't a confirmed member of the space. The file must not be touched with what that run returned.
  gone,

  /// No fingerprint was compared for the space on this account (an anchor with no record of a comparison): nothing of the space
  /// is held here, and what the chain says of the account or the copy is no one's checked word. It is no leaving: the note stays
  /// as it is, the file is read and never written, and the person goes through first contact.
  uncompared,

  /// A joining phone found the move unfinished: no marker says it is whole, and the chain closes nothing. Nothing was merged or
  /// written, and the run returned no document to take.
  pending,
}

/// [state] with [signal] (and the [reason] of a closed one) as a run reports it.
Map<String, Object?> withBridgeSignal(Map<String, Object?> state, BridgeSignal? signal, [SpaceCopyClosed? reason]) => {
  ...state,
  if (signal != null) bridgeStateKey: signal.name,
  if (signal != null && reason != null) bridgeReasonKey: reason.name,
};

/// [state] without the signal a run put in it, and the signal and reason that were in it.
({Map<String, Object?> state, BridgeSignal? signal, SpaceCopyClosed? reason}) takeBridgeSignal(Map<String, Object?> state) {
  final signal = [
    for (final candidate in BridgeSignal.values)
      if (candidate.name == state[bridgeStateKey]) candidate,
  ].firstOrNull;
  final reason = [
    for (final candidate in SpaceCopyClosed.values)
      if (candidate.name == state[bridgeReasonKey]) candidate,
  ].firstOrNull;
  return (
    state: {...state}
      ..remove(bridgeStateKey)
      ..remove(bridgeReasonKey),
    signal: signal,
    reason: reason,
  );
}

/// Why the verified chain closes the WebDAV copy, or null when it doesn't. The WebDAV key can't be taken back, so a removal of
/// anyone, whether or not they held keys, and a replacement of the keys, which only follows a removal, close it.
/// Every member's app derives the same from the same chain, so it needs nothing the server could forge or withhold.
///
/// A space with a second collection, or a grant that hides passwords, closes it too: the file holds every entry of the space for
/// whoever holds its key, so a collection's restriction or a hidden password can't cross into it. The bridge doesn't carry
/// "Everyone" alone, since an entry moved out of Everyone would then look deleted in the file and push its deletion back.
SpaceCopyClosed? chainClosure(SpaceState chain) {
  // Keys that await their replacement are a removal's: the replacement is not done, so the reason is still the removal
  if (chain.keysNeedReplacing) {
    return SpaceCopyClosed.removal;
  }
  // Once the replacement is done, the reason is the keys: a removed member stays in the chain, so a removal found first would
  // hide the replacement that followed it
  if (chain.spaceKeyVersion > 1 || chain.collections.values.any((collection) => collection.keyVersion > 1)) {
    return SpaceCopyClosed.keys;
  }
  // Someone was removed or left and the chain marked no key for them: the WebDAV key can't be taken back from them. A member who
  // held no key seal has nothing to replace, yet the file's key is theirs too
  if (chain.members.values.any((member) => member.status == MemberStatus.removed)) {
    return SpaceCopyClosed.removal;
  }
  if (chain.collections.length > 1 || chain.grants.values.any((granted) => granted.values.any((grant) => grant.hidesPasswords))) {
    return SpaceCopyClosed.restricted;
  }
  return null;
}

/// What the server space says about its WebDAV copy: the chain's closure first, then the Owner's marker, then the mover's
/// marker. Null while the space shows none of them. [items] is the run's cache.
///
/// A marker is told by its kind as well as its id: an entry of the space may carry the id `space-bridge` and must not pass for one.
/// An item ever seen at the closed marker's id, deleted or not, closes the copy: a copy that was closed is not opened again by
/// deleting the marker, since a phone that missed the marker would then see the copy open. The open marker counts while it is live.
({BridgeSignal signal, SpaceCopyClosed? reason})? bridgeSignalOf(SpaceState chain, Map<String, KmCachedItem> items, Owner owner) {
  final byChain = chainClosure(chain);
  if (byChain != null) {
    return (signal: BridgeSignal.closed, reason: byChain);
  }
  final closed = items[kmItemId(kmBridgeClosedId, owner)];
  // A tombstone carries no kind this phone can trust, so a deleted item at that id counts whatever it says
  if (closed != null && (closed.deleted || closed.kind == KmKind.bridgeClosed)) {
    return (signal: BridgeSignal.closed, reason: SpaceCopyClosed.owner);
  }
  final open = items[kmItemId(kmBridgeOpenId, owner)];
  if (open != null && !open.deleted && open.kind == KmKind.bridgeOpen) {
    return (signal: BridgeSignal.open, reason: null);
  }
  return null;
}

/// The ids of the items that are the space's bridge markers, which are no entries: no count of items left alone includes them.
Set<String> bridgeMarkerIds(Owner owner) => {kmItemId(kmBridgeOpenId, owner), kmItemId(kmBridgeClosedId, owner)};

/// A run of the server space that failed after its verified chain had shown that the WebDAV copy is closed ([reason], from
/// [chainClosure]). The chain can't be forged, so the closure holds whatever failed after it: the caller keeps it and never
/// writes the file, and shows [cause] as the run's problem (`problemOf` reads it through).
class ClosedRunError implements Exception {
  const ClosedRunError(this.reason, this.cause);

  final SpaceCopyClosed reason;

  /// What the run threw.
  final Object cause;

  @override
  String toString() => 'ClosedRunError(${reason.name}: $cause)';
}
