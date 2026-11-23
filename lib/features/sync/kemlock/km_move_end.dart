/// What a finished move leaves in the sync settings and the scope states (move-off-vaultwarden-sync,
/// tasks 5.1 and 5.3, designs 7 and 10), kept apart from the wiring so it can be read and tested alone.
///
/// - The Kemlock target now holds the vault's own entries, so the Kemlock scope starts from the entries
///   the check confirmed as its `known` ids, and nothing counts as removed at its first sync.
/// - **A plain home stays** (and a sealed home left open): `SyncSettings.vaultwarden` stays beside the
///   Kemlock target, and its scope state is marked [copyOfKey], the one place `SyncSettings` allows it.
///   Nothing is written into any Vaultwarden item for that.
/// - **A closed sealed home** is no longer synced: the target is dropped and the scope forgotten. The
///   target is kept in the move record for 30 days, for "Go back to Vaultwarden".
/// - **A WebDAV file is left as it is** (owner decision 1): `personal` is set to null, its scope
///   forgotten, and nothing is written to the folder. Spaces are untouched.
///
/// Pure Dart, no Flutter.
library;

import '../sync.dart';
import '../vaultwarden/vw_models.dart' show VaultwardenTarget;
import 'km_api.dart' show kmHost;
import 'km_models.dart' show KemlockTarget;
import 'km_move_old_store.dart';
import 'km_move_record.dart' show vaultwardenSource, webdavSource;

/// The settings and scope states after the move.
typedef KmMoveEnd = ({SyncSettings settings, Map<String, ScopeState> states});

/// [settings] and [states] once the old store was dealt with ([result]) and the check confirmed [confirmed], at
/// [now] (epoch ms).
KmMoveEnd kmEndOfMove({
  required SyncSettings settings,
  required Map<String, ScopeState> states,
  required KmOldStoreResult result,
  required Iterable<String> confirmed,
  required int now,
}) {
  final next = {...states, kemlockScope: ScopeState(known: confirmed.toList(), lastSyncAt: now)};
  var kept = settings.copyWith(personal: null);
  switch (result.outcome) {
    case KmOldStore.copyKept || KmOldStore.blocked:
      next[vaultwardenScope] = markedAsCopy(next[vaultwardenScope] ?? const ScopeState(known: []));
    case KmOldStore.closed || KmOldStore.gone:
      kept = kept.copyWith(vaultwarden: null);
      next.remove(vaultwardenScope);
    case KmOldStore.fileLeft:
      next.remove(personalScope);
  }
  return (settings: kept, states: next);
}

/// The old store a move off [settings] comes from, for signing in to [target]'s server: a Vaultwarden home
/// on that server, else a WebDAV personal vault. A Vaultwarden on another address is no source: the phone
/// has no access to that store through this server, so the person keeps both syncs or turns the old one
/// off. Null when there is nothing to move.
({String name, String server, String? home, String? mode, VaultwardenTarget? vaultwarden})? kmMoveSourceOf(
  SyncSettings settings,
  KemlockTarget target,
) {
  final vaultwarden = settings.vaultwarden;
  if (vaultwarden != null && kmHost(vaultwarden.server) == kmHost(target.home.url)) {
    return (
      name: vaultwardenSource,
      server: vaultwarden.server,
      home: vaultwarden.home,
      mode: vaultwarden.mode.name,
      vaultwarden: vaultwarden,
    );
  }
  final personal = settings.personal;
  if (personal != null) {
    return (name: webdavSource, server: personal.dav.url, home: null, mode: null, vaultwarden: null);
  }
  return null;
}
