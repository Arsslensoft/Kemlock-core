/// The last step of a move (move-off-vaultwarden-sync, designs 6, 7 and 10, tasks 4.1 to 4.3): what
/// happens to the old store once the check passed.
///
/// - **A sealed Vaultwarden home is closed**, home note first (`VwAccountSetup.closeHome`), unless it
///   holds an item this build can't read or an entry the check didn't confirm: then it is left open, keeps
///   syncing beside the Kemlock API, and the result says why.
/// - **A plain Vaultwarden home stays** as a Bitwarden copy: Amethystora Vault and Bitwarden apps read its
///   items, and trashing them would make Amethystora trash its own copies. Nothing is written. The
///   Vaultwarden scope goes on beside the Kemlock one with today's code, which keeps logins and other
///   entries Vaultwarden sync never wrote out of the copy (`_keepOnKey`); its scope state is marked as a
///   copy ([markedAsCopy]) so the rule of `SyncSettings` (`ownEntriesClash`) is kept.
/// - **A WebDAV file stays as it is.** The wiring stops syncing it (task 5.3); nothing is written to the
///   folder.
///
/// Pure Dart, no Flutter.
library;

import '../sync.dart';
import '../vaultwarden/vw_backend.dart' show VwCloseOutcome, VwCloseResult;
import '../vaultwarden/vw_models.dart' show VaultwardenMode;

/// What happened to the old store.
enum KmOldStore {
  /// A sealed home was closed: its note and items are in the Bitwarden trash.
  closed,

  /// A sealed home was already closed, by another phone.
  gone,

  /// A plain home stays, as a Bitwarden copy that keeps syncing.
  copyKept,

  /// A WebDAV file stays as it is, and this phone stops syncing it.
  fileLeft,

  /// A sealed home was left open: it holds something that can't be moved safely.
  blocked;

  static KmOldStore? parse(Object? name) {
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

/// The result of the step, for the record and the result screen.
class KmOldStoreResult {
  const KmOldStoreResult(this.outcome, {this.changed = 0, this.unreadable = 0, this.unconfirmed = 0});

  final KmOldStore outcome;

  /// Items put in the trash or unlinked.
  final int changed;

  /// For [KmOldStore.blocked]: items this build can't read, which one newer Kemlock may.
  final int unreadable;

  /// For [KmOldStore.blocked]: live entries the check didn't confirm, added since the last sync.
  final int unconfirmed;

  /// Whether the old store goes on syncing beside the Kemlock API.
  bool get keepsSyncing => outcome == KmOldStore.copyKept || outcome == KmOldStore.blocked;

  @override
  String toString() => 'KmOldStoreResult(${outcome.name}, $changed changed, $unreadable unreadable, $unconfirmed unconfirmed)';
}

/// What the move does to the old store after the check.
abstract interface class KmMoveOldStore {
  /// [confirmed] is the entry ids the check read back.
  Future<KmOldStoreResult> finish(Set<String> confirmed);
}

/// Closes a sealed home, or keeps a plain one.
class VaultwardenOldStore implements KmMoveOldStore {
  VaultwardenOldStore({required this.mode, required this.close});

  final VaultwardenMode mode;

  /// `VaultwardenBackend.closeHome` for the home.
  final Future<VwCloseResult> Function(Set<String> confirmed) close;

  @override
  Future<KmOldStoreResult> finish(Set<String> confirmed) async {
    if (mode == VaultwardenMode.plain) {
      return const KmOldStoreResult(KmOldStore.copyKept);
    }
    final result = await close(confirmed);
    return switch (result.outcome) {
      VwCloseOutcome.closed => KmOldStoreResult(KmOldStore.closed, changed: result.changed),
      VwCloseOutcome.alreadyGone => const KmOldStoreResult(KmOldStore.gone),
      VwCloseOutcome.blocked => KmOldStoreResult(KmOldStore.blocked, unreadable: result.unreadable, unconfirmed: result.unconfirmed),
    };
  }
}

/// Leaves a WebDAV file as it is.
class WebDavOldStore implements KmMoveOldStore {
  const WebDavOldStore();

  @override
  Future<KmOldStoreResult> finish(Set<String> confirmed) async => const KmOldStoreResult(KmOldStore.fileLeft);
}

/// [state], the Vaultwarden scope's, marked as the copy of a vault whose own entries sync with Kemlock Server.
ScopeState markedAsCopy(ScopeState state) =>
    ScopeState(known: state.known, lastSyncAt: state.lastSyncAt, extra: {...state.extra, copyOfKey: true});

/// Whether [state] is the Vaultwarden scope of a Bitwarden copy.
bool isCopyScope(ScopeState state) => state.extra[copyOfKey] == true;
