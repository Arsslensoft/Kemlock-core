// Where the entries of a Credential Exchange import go, place by place (the
// add-credential-exchange plan, design decision 6): each exported account is
// one row of the preview's "Into" choice, the vault or a new space, and a
// collection the person shared with others in the old app is a row of its
// own with a new space preselected. An item lands where its first collection
// lands, or else where its account lands; the mapper has already put each
// entry's id in its place (`ForeignImport.unitOf`).
//
// Pure Dart. Making a space is the flow's business, not this file's.
import 'formats/import_extras.dart';
import 'import_merge.dart';

/// Where a place's entries go: this vault, or a new space of this name.
class ImportDestination {
  const ImportDestination.vault() : spaceName = null;
  const ImportDestination.newSpace(String this.spaceName);

  /// The name of the space to make; null for the vault.
  final String? spaceName;

  bool get isSpace => spaceName != null;

  @override
  bool operator ==(Object other) => other is ImportDestination && other.spaceName == spaceName;

  @override
  int get hashCode => spaceName.hashCode;

  @override
  String toString() => isSpace ? 'ImportDestination.newSpace' : 'ImportDestination.vault';
}

/// The destination chosen for each place of an import.
class ImportDestinations {
  const ImportDestinations({required this.byUnit});

  /// The destination of each [ImportUnit.id].
  final Map<String, ImportDestination> byUnit;

  ImportDestination of(String unitId) => byUnit[unitId] ?? const ImportDestination.vault();

  /// These destinations with [unitId] going to [destination].
  ImportDestinations choose(String unitId, ImportDestination destination) => ImportDestinations(byUnit: {...byUnit, unitId: destination});
}

/// The destinations before the person changes any: the vault for each
/// account, the first included, and a new space named after the collection
/// for each shared one.
ImportDestinations defaultDestinations(List<ImportUnit> units) => ImportDestinations(
  byUnit: {for (final unit in units) unit.id: unit.shared ? ImportDestination.newSpace(unit.name) : const ImportDestination.vault()},
);

/// A part of an import and where it goes.
typedef PlacedImport = ({ImportDestination destination, ImportPreview preview});

/// [preview] cut by destination, the vault's part first. Each entry goes where
/// its place does ([ImportPreview.unitOf]); one with no place, and every
/// passkey (which never belongs to a space), goes to the vault, which also
/// takes the backup services, on-key accounts and contacts. What was skipped,
/// the notices and the cuts are in the first part, so that nothing is counted
/// twice. A destination with nothing in it isn't returned.
List<PlacedImport> placeImport(ImportPreview preview, ImportDestinations destinations) {
  const vault = ImportDestination.vault();
  ImportDestination whereIs(String id) => destinations.of(preview.unitOf[id] ?? '');
  List<T> of<T>(List<T> entries, String Function(T entry) idOf, ImportDestination destination) => [
    for (final entry in entries)
      if (whereIs(idOf(entry)) == destination) entry,
  ];

  final targets = <ImportDestination>[vault];
  for (final unit in preview.units) {
    final destination = destinations.of(unit.id);
    if (!targets.contains(destination)) {
      targets.add(destination);
    }
  }

  final placed = <PlacedImport>[];
  for (final destination in targets) {
    final home = destination == vault;
    final part = ImportPreview(
      accounts: of(preview.accounts, (entry) => entry.id, destination),
      backupServices: home ? preview.backupServices : const [],
      passkeys: home ? preview.passkeys : const [],
      keys: of(preview.keys, (entry) => entry.id, destination),
      notes: of(preview.notes, (entry) => entry.id, destination),
      keyAccounts: home ? preview.keyAccounts : const [],
      contacts: home ? preview.contacts : const [],
      logins: of(preview.logins, (entry) => entry.id, destination),
      cards: of(preview.cards, (entry) => entry.id, destination),
      identities: of(preview.identities, (entry) => entry.id, destination),
      unitOf: preview.unitOf,
      units: preview.units,
    );
    final empty =
        part.accounts.isEmpty &&
        part.backupServices.isEmpty &&
        part.passkeys.isEmpty &&
        part.keys.isEmpty &&
        part.notes.isEmpty &&
        part.keyAccounts.isEmpty &&
        part.contacts.isEmpty &&
        part.logins.isEmpty &&
        part.cards.isEmpty &&
        part.identities.isEmpty;
    if (!empty) {
      placed.add((destination: destination, preview: part));
    }
  }
  if (placed.isEmpty) {
    return placed;
  }
  final first = placed.first;
  placed[0] = (
    destination: first.destination,
    preview: ImportPreview(
      accounts: first.preview.accounts,
      backupServices: first.preview.backupServices,
      skipped: preview.skipped,
      passkeys: first.preview.passkeys,
      keys: first.preview.keys,
      notes: first.preview.notes,
      keyAccounts: first.preview.keyAccounts,
      contacts: first.preview.contacts,
      logins: first.preview.logins,
      cards: first.preview.cards,
      identities: first.preview.identities,
      skips: preview.skips,
      notices: preview.notices,
      units: preview.units,
      unitOf: preview.unitOf,
      cuts: preview.cuts,
    ),
  );
  return placed;
}
