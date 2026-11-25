// What a Credential Exchange export of the open vault could hold, and what it could not (the pure part of the app's
// `credential_export.dart`, whose providers, targets and switches belong to the phone's hand-off to another app): the kinds the
// person picks among, what each would write, and what is left out and why. The writer is `formats/cxf_writer.dart`.
import '../import/formats/cxf_writer.dart';
import '../sync/sync_merge.dart' show Lists;
import 'export_scope.dart';

/// The kinds of item the person picks among. Backup codes, contacts and security-key accounts have no Credential Exchange type and
/// are never offered (they are listed as not carried).
enum ExportKind {
  logins('basic-auth'),
  codes('totp'),
  passkeys('passkey'),
  notes('note'),
  cards('credit-card'),
  identities('person-name'),
  keys('ssh-key');

  const ExportKind(this.main);

  /// The Credential Exchange credential type this kind is made of.
  final String main;
}

/// What the vault holds that has no Credential Exchange type, by how it is told to the person.
enum ExportNotCarried { backupServices, contacts, onKey }

/// What an export of the open vault could hold, and what it could not.
class CredentialExportPlan {
  const CredentialExportPlan._({required this.all, required this.counts, required this.spaceItems, required this.notCarried});

  /// Plans an export of [vault]: the items of shared spaces stay out (see [exportScope]) and are counted.
  factory CredentialExportPlan.of(Lists vault) {
    final scope = exportScope(vault);
    final lists = scope.lists;
    final all = CxfExportItems(
      logins: lists.logins,
      codes: lists.accounts,
      passkeys: lists.passkeys,
      notes: lists.notes,
      cards: lists.cards,
      identities: lists.identities,
      keys: lists.keys,
    );
    return CredentialExportPlan._(
      all: all,
      counts: {
        ExportKind.logins: all.logins.length,
        ExportKind.codes: all.codes.length,
        ExportKind.passkeys: all.passkeys.length,
        ExportKind.notes: all.notes.length,
        ExportKind.cards: all.cards.length,
        ExportKind.identities: all.identities.length,
        ExportKind.keys: all.keys.length,
      },
      spaceItems: scope.spaceItems,
      notCarried: {
        ExportNotCarried.backupServices: lists.backupServices.length,
        ExportNotCarried.contacts: lists.contacts.length,
        ExportNotCarried.onKey: lists.keyAccounts.length,
      },
    );
  }

  /// Every item that may leave: the vault's own.
  final CxfExportItems all;

  /// How many items of each kind may leave.
  final Map<ExportKind, int> counts;

  /// How many items of shared spaces were left out, whatever their kind.
  final int spaceItems;

  /// What no Credential Exchange type carries, by kind, with its count.
  final Map<ExportNotCarried, int> notCarried;

  /// [all] cut to the [kinds] picked.
  CxfExportItems pick(Set<ExportKind> kinds) => CxfExportItems(
    logins: kinds.contains(ExportKind.logins) ? all.logins : const [],
    codes: kinds.contains(ExportKind.codes) ? all.codes : const [],
    passkeys: kinds.contains(ExportKind.passkeys) ? all.passkeys : const [],
    notes: kinds.contains(ExportKind.notes) ? all.notes : const [],
    cards: kinds.contains(ExportKind.cards) ? all.cards : const [],
    identities: kinds.contains(ExportKind.identities) ? all.identities : const [],
    keys: kinds.contains(ExportKind.keys) ? all.keys : const [],
  );

  /// How many items of [kind] the writer would write: all of them, less the codes, passkeys and keys it leaves out.
  int sendable(ExportKind kind) {
    final count = counts[kind] ?? 0;
    return switch (kind) {
      ExportKind.codes => count - cxfLeftOut(CxfExportItems(codes: all.codes)).length,
      ExportKind.passkeys => count - cxfLeftOut(CxfExportItems(passkeys: all.passkeys)).length,
      ExportKind.keys => count - cxfLeftOut(CxfExportItems(keys: all.keys)).length,
      _ => count,
    };
  }

  /// How many items go for [kinds].
  int sending(Set<ExportKind> kinds) => kinds.fold(0, (sum, kind) => sum + sendable(kind));

  /// What the writer would leave out of [kinds], by reason, with each count.
  Map<CxfLeftOutReason, int> leftOut(Set<ExportKind> kinds) {
    final counts = <CxfLeftOutReason, int>{};
    for (final item in cxfLeftOut(pick(kinds))) {
      counts[item.reason] = (counts[item.reason] ?? 0) + 1;
    }
    return counts;
  }
}
