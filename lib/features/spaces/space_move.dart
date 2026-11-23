// Moving a WebDAV space to Kemlock Server, and closing its WebDAV copy (docs/plans/add-server-spaces.md, design 7, tasks 8.1
// and 8.4). What a screen needs of it comes in through [SpaceMover], so the Spaces sheet gets the open vault's connection and
// keys, and a test gives it a fake.
//
// A move, which `KmServerSpaces.moveSpace` runs and which every step of is safe to run again:
//
// 1. Makes the server space under the UUID `crypto.md` "Legacy ids" gives the WebDAV id, with "Everyone" and the mover as
//    Owner, unless it is already there (a move that was stopped, or failed its check, is run again from here).
// 2. Uploads every entry of the space to "Everyone" as a `kem1` item, under its own id when that is a UUID and its legacy-id
//    UUID otherwise, each with its own id inside, and signs the space's manifest once after the last batch. It is the
//    server space's own sync run (`KmSpaceSync.sync`), so it seals, batches and signs as every run does.
// 3. Reads the space back from the start and compares every entry: it came back, live, listed by the signed manifest, and
//    with the hash of what was sent. A difference throws [SpaceMoveProblem.mismatch] and the space stays on WebDAV.
// 4. Writes the marker that the move is complete (`KmKind.bridgeOpen`), which a phone that finds the space by id waits for.
//
// Nothing on this phone changes before the check passes: the caller marks the space `moving` before step 1 and `bridged` after
// step 4, so a phone that dies in between still syncs the WebDAV file, and the move runs again from the button.
//
// Pure Dart, no Flutter.

library;

import '../sync/sync.dart' show Space;
import '../sync/sync_merge.dart' show Lists, scopeLists;
import 'space_bridge.dart';
import 'space_scope.dart' show serverSpaceUuidOrNull;

/// The steps a move reports.
enum SpaceMoveStep { create, upload, check, finish }

/// A moved space: its UUID on the server, how many entries were checked, and the document the move's run merged (what the server
/// holds after it, which the phone takes in place of what it held before).
typedef SpaceMoveResult = ({String uuid, int moved, Lists doc});

/// Why a move, or closing a copy, didn't happen.
enum SpaceMoveProblem {
  /// This account isn't a confirmed member of the server space.
  notMember,

  /// Only the space's Owner may do this.
  notOwner,

  /// The server space exists and this account isn't confirmed in it: someone else made it, or this account was invited.
  exists,

  /// The server space read back differs from what was sent, or its signed manifest doesn't list it.
  mismatch,

  /// The space's keys wait for a replacement, so nothing can be written under them.
  keysPending,
}

/// A move or a close that stopped, and why. [ids] are the entries that differ, for a mismatch.
class SpaceMoveError implements Exception {
  const SpaceMoveError(this.problem, {this.ids = const [], this.detail});

  final SpaceMoveProblem problem;
  final List<String> ids;
  final String? detail;

  @override
  String toString() =>
      'SpaceMoveError(${problem.name}${detail != null ? ': $detail' : ''}${ids.isNotEmpty ? ', ${ids.length} entries' : ''})';
}

/// What the Spaces sheet asks of the open vault to move a WebDAV space and close its copy.
abstract interface class SpaceMover {
  /// Moves the WebDAV space [appSpaceId], named [name], whose entries are [local] (the space's scope of the vault). Throws a
  /// [SpaceMoveError] when it can't be done or the read-back differs, and what the server's client throws when it can't be
  /// reached.
  Future<SpaceMoveResult> moveSpace({
    required String appSpaceId,
    required String name,
    required Lists local,
    void Function(SpaceMoveStep step, int done, int total)? onProgress,
  });

  /// Closes the WebDAV copy of the moved space [appSpaceId] for every member: only the Owner may. Throws a [SpaceMoveError].
  Future<void> closeCopy(String appSpaceId);
}

/// Moves the WebDAV space [space] through [mover], keeping the note of where its copies stand ([SpaceOnServer]) in step with
/// what happened, through [save], and answers the space as it is now. [lists] is the vault's entries; the space's own are
/// what moves. [now] is epoch ms.
///
/// The space is marked `moving` before anything is written to the server, so a phone that stops midway still syncs the file
/// alone, and the move runs again. It is marked `bridged` only once the server's copy read back the same; an error, a
/// mismatch included, leaves it `moving`, which is a WebDAV space that syncs the file alone, and is thrown again.
Future<Space> moveWebDavSpace({
  required Space space,
  required SpaceMover mover,
  required Lists lists,
  required Future<void> Function(Space next) save,
  required int Function() now,
  Future<void> Function(Lists merged)? applyMerged,
  void Function(SpaceMoveStep step, int done, int total)? onProgress,
}) async {
  final uuid = serverSpaceUuidOrNull(space.id);
  if (uuid == null) {
    throw const SpaceMoveError(SpaceMoveProblem.notMember, detail: 'the space id has no UUID');
  }
  await save(space.withOnServer(SpaceOnServer(state: SpaceCopy.moving, uuid: uuid, at: now())));
  final result = await mover.moveSpace(appSpaceId: space.id, name: space.name, local: scopeLists(lists, space.id), onProgress: onProgress);
  // What the server holds after the run is the move's merge of the file's entries with what the space already had: the phone takes it
  await applyMerged?.call(result.doc);
  final moved = space.withOnServer(SpaceOnServer(state: SpaceCopy.bridged, uuid: result.uuid, at: now()));
  await save(moved);
  return moved;
}
