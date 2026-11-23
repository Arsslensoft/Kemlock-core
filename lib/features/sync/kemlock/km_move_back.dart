/// "Go back to Vaultwarden" (move-off-vaultwarden-sync, design 9, task 4.4, owner decision 2): for 30 days
/// after a sealed home was closed, the phone takes the home note and the sealed items out of the Bitwarden
/// trash again and turns the Kemlock target off for the vault's own entries.
///
/// The `kem1` items stay on the server and nothing is deleted anywhere: the close only trashed, which is
/// what makes this cheap. A phone that moved later merges in by id, so going back loses nothing on the
/// Kemlock side either; what the vault gained on the Kemlock API since the move reaches Vaultwarden at
/// the next Vaultwarden sync, which merges as it always does.
///
/// Pure Dart, no Flutter.
library;

import '../sync.dart';
import '../vaultwarden/vw_models.dart';
import 'km_move_record.dart';

/// What going back did: the settings to keep, the record, and how many items came back from the trash.
typedef KmGoBackResult = ({SyncSettings settings, KmMoveRecord record, int restored});

/// Whether "Go back to Vaultwarden" is offered for [record] at [now].
bool kmGoBackOffered(KmMoveRecord? record, DateTime now) => record != null && record.sealedHome && record.goBackOpen(now);

/// Goes back to the sealed home [target]. [restore] takes the home note and its items out of the trash
/// (`VaultwardenBackend.restoreHome`). The settings come back with [target] as the Vaultwarden target and
/// no Kemlock target; `personal` and the spaces are as they were. Throws a [StateError] when going back
/// isn't offered ([kmGoBackOffered]), and what [restore] throws.
Future<KmGoBackResult> goBackToVaultwarden({
  required KmMoveRecord record,
  required VaultwardenTarget target,
  required SyncSettings settings,
  required Future<int> Function() restore,
  required DateTime now,
}) async {
  if (!kmGoBackOffered(record, now)) {
    throw StateError('going back is offered for 30 days after a sealed home was closed');
  }
  final restored = await restore();
  return (
    settings: settings.copyWith(vaultwarden: target, kemlock: null),
    record: record.copyWith(closed: false, result: {...?record.result, 'oldStore': 'wentBack', 'wentBack': true}),
    restored: restored,
  );
}
