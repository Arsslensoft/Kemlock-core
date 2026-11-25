// What a file export may hold of the open vault, for a host with no spaces' rules to read (`space_export.dart` in the app reads the
// verified chains' no-export policies, with Riverpod). An item of a shared space may be under a policy that forbids exporting it,
// and a host that can't read the chain can't know, so it fails closed as the app does for a server space whose policy is unknown:
// every item of a space stays out of every export, and the export says how many. The vault's own items, its contacts and its
// accounts kept on a security key (never in a space) go as they are.
import '../sync/sync_merge.dart' show Lists;

/// What an export may hold, and how many items of spaces it leaves out.
class ExportScope {
  const ExportScope({required this.lists, required this.spaceItems});

  /// The vault's own items.
  final Lists lists;

  /// How many items of shared spaces were left out, whatever their kind.
  final int spaceItems;
}

bool _inSpace(String? spaceId) => spaceId != null && spaceId.isNotEmpty;

/// [vault] less the items of shared spaces. With [codesOnly], as for the QR codes, which carry the codes and backup services
/// alone, the other kinds are left out whole and uncounted, so what is said to be left out is only codes.
ExportScope exportScope(Lists vault, {bool codesOnly = false}) {
  var spaceItems = 0;
  List<T> keep<T>(List<T> items, String? Function(T item) spaceOf) {
    final kept = <T>[];
    for (final item in items) {
      if (_inSpace(spaceOf(item))) {
        spaceItems++;
      } else {
        kept.add(item);
      }
    }
    return kept;
  }

  final lists = Lists(
    accounts: keep(vault.accounts, (item) => item.spaceId),
    backupServices: keep(vault.backupServices, (item) => item.spaceId),
    notes: codesOnly ? const [] : keep(vault.notes, (item) => item.spaceId),
    passkeys: codesOnly ? const [] : keep(vault.passkeys, (item) => item.spaceId),
    keys: codesOnly ? const [] : keep(vault.keys, (item) => item.spaceId),
    logins: codesOnly ? const [] : keep(vault.logins, (item) => item.spaceId),
    cards: codesOnly ? const [] : keep(vault.cards, (item) => item.spaceId),
    identities: codesOnly ? const [] : keep(vault.identities, (item) => item.spaceId),
    keyAccounts: codesOnly ? const [] : vault.keyAccounts,
    contacts: codesOnly ? const [] : vault.contacts,
  );
  return ExportScope(lists: lists, spaceItems: spaceItems);
}
