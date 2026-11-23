/// What the scheduler asks of Kemlock Server sync: one run of the vault's own
/// scope, as `VaultwardenBackend.sync` is for Vaultwarden. `km_sync.dart`
/// holds the run, and the app's host makes the backend that signs in, keeps
/// the session sealed and calls it.
///
/// Pure Dart, no Flutter.
library;

import '../../spaces/space_bridge.dart' show JoinOffer;
import '../removal_guard.dart';
import '../sync.dart';
import '../sync_merge.dart';
import 'km_models.dart';

/// What a Kemlock Server run returns: the merged document to take locally,
/// the ids the scope now holds, the state to keep for next time, and how many
/// items were left alone (held, or of a kind or shape this version can't
/// read).
typedef KmSyncResult = ({SyncDoc doc, List<String> known, Map<String, Object?> state, int skipped});

/// Runs the vault's own scope against Kemlock Server.
abstract interface class KemlockBackend {
  /// Syncs once. [local] is this phone's entries in the scope and [state]
  /// what the last run kept. Throws what `problemOf` reads: a `KmError`
  /// when the server can't be reached or refuses, a `KmSyncError` when the
  /// run stops before changing anything.
  Future<KmSyncResult> sync(KemlockTarget target, Lists local, ScopeState state, {required int now, RemovalChoice? choice});

  /// Lets go of what the backend holds when the vault locks or its session is replaced.
  void dispose();
}

/// Runs the server spaces of the vault's account, one scope each, beside the vault's own scope
/// (docs/plans/add-server-spaces.md, "Server spaces as a sync scope"). A space is the scheduler's scope under its UUID.
abstract interface class KemlockSpacesBackend {
  /// The ids of the spaces the server lists with the account a confirmed member. A space whose invitation waits, or
  /// that the account left, is not among them. Throws what `problemOf` reads when the server can't be reached.
  Future<List<String>> confirmedSpaces(KemlockTarget target);

  /// Syncs the space [space] once: [local] is this phone's entries in it and [state] what the last run kept. [joining] is for a
  /// phone that holds the space's WebDAV copy and has not joined: it needs a stored anchor and makes none. [bridged] is for a moved
  /// space whose WebDAV copy this phone still syncs: a failure after its chain closed the copy is a `ClosedRunError`. Throws what
  /// `problemOf` reads: a `KmError` when the server can't be reached or refuses, a `SpaceSyncError` when the run stops
  /// before changing anything (a chain that doesn't verify, an older copy, keys being replaced).
  Future<KmSyncResult> syncSpace(
    KemlockTarget target,
    String space,
    Lists local,
    ScopeState state, {
    required int now,
    RemovalChoice? choice,
    bool joining = false,
    bool bridged = false,
  });

  /// Whether the server space [space], which the list says this account is confirmed in, may be offered to the person to merge a
  /// WebDAV space's copy into, and who owns it: null unless an anchor from a real fingerprint comparison is stored for it. Nothing
  /// is merged, opened or written. Throws what `problemOf` reads when the server can't be reached.
  Future<JoinOffer?> joinOffer(KemlockTarget target, String space, {required int now});
}
