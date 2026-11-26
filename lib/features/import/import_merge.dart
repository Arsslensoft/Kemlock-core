import 'dart:convert';

import 'package:collection/collection.dart';

import '../../core/ids.dart';
import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/json.dart' show unset;
import '../../models/key_account.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_file.dart';
import '../../models/vault_key.dart';
import '../../vault/vault_export.dart' show VaultExportPayload;
import '../contacts/contact_key_info.dart' show contactKeyInfo;
import '../duplicates/duplicate_normalise.dart';
import '../duplicates/duplicate_rules.dart';
import '../duplicates/duplicate_sites.dart';
import '../keys/key_bridge.dart' show keyIdentity;
import 'formats/cxf.dart' show CxfCuts;
import 'formats/import_extras.dart';
import 'importers.dart' show ForeignImport;

/// How an import meets what the vault holds.
enum ImportMode {
  /// Keep everything, and add what isn't there yet.
  merge,

  /// Put the import in place of the vault's accounts (and, usually, its backup services).
  replace,
}

/// Two entries are the same account when their secrets are: the decoded bytes, whatever the
/// issuer, the label or how the secret was typed. A secret is per account, so "Google" and
/// "google.com" with one secret are one (the duplicate cleaner plan, decision 3).
bool isSameAccount(OtpAccount a, OtpAccount b) => sameCode(a, b);

/// Whether [account] is in [current] already.
bool isDuplicateAccount(OtpAccount account, List<OtpAccount> current) => current.any((e) => isSameAccount(e, account));

/// What an import holds, before it is merged into the vault.
class ImportPreview {
  const ImportPreview({
    required this.accounts,
    required this.backupServices,
    this.skipped = 0,
    this.passkeys = const [],
    this.keys = const [],
    this.notes = const [],
    this.keyAccounts = const [],
    this.contacts = const [],
    this.logins = const [],
    this.cards = const [],
    this.identities = const [],
    this.files = const [],
    this.skips = const [],
    this.notices = const [],
    this.units = const [],
    this.unitOf = const {},
    this.cuts,
  });

  /// What a foreign import holds as a preview, entries and remarks as they come.
  /// The caller has given the other importers' accounts and passkeys their ids.
  ImportPreview.ofForeign(ForeignImport result)
    : this(
        accounts: result.accounts,
        backupServices: const [],
        skipped: result.skipped,
        passkeys: result.passkeys,
        keys: result.keys,
        notes: result.notes,
        logins: result.logins,
        cards: result.cards,
        identities: result.identities,
        skips: result.skips,
        notices: result.notices,
        units: result.units,
        unitOf: result.unitOf,
        cuts: result.cuts,
      );

  /// A Kemlock export's contents as a preview.
  ImportPreview.of(VaultExportPayload payload)
    : this(
        accounts: payload.accounts,
        backupServices: payload.backupServices,
        keys: payload.keys,
        notes: payload.notes,
        passkeys: payload.passkeys,
        keyAccounts: payload.keyAccounts,
        contacts: payload.contacts,
        logins: payload.logins,
        cards: payload.cards,
        identities: payload.identities,
        files: payload.files,
      );

  /// The accounts kept on a security key, by name: "on your key, not in
  /// this file". Like passkeys, only ever added.
  final List<KeyAccount> keyAccounts;

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;

  /// Passkeys, keys and notes, which an import only ever adds, whatever its
  /// mode: replacing them would take sign-ins, keys and files away that the
  /// file may not give back.
  final List<Passkey> passkeys;
  final List<VaultKey> keys;
  final List<SecureNote> notes;

  /// Other people's public keys, which an import only ever adds too.
  final List<Contact> contacts;

  /// Logins, which an import only ever adds too (openspec: add-passwords).
  final List<Login> logins;

  /// Cards and identities, which an import only ever adds too.
  final List<PaymentCard> cards;
  final List<Identity> identities;

  /// File items, which an import only ever adds too. The attached files come beside them, as they do for notes.
  final List<VaultFile> files;

  /// Each credential and item a Credential Exchange payload held that
  /// Kemlock doesn't keep, with the reason; entries kept with a caveat; the
  /// places it asks about, and where each entry's id goes; what a limit cut.
  final List<ImportSkip> skips;
  final List<ImportNotice> notices;
  final List<ImportUnit> units;
  final Map<String, String> unitOf;
  final CxfCuts? cuts;

  /// How many keys, notes and passkeys it holds.
  int get items => keys.length + notes.length + passkeys.length;

  /// Entries in another app's backup that Kemlock can't represent.
  final int skipped;
}

/// Whether the vault's [services] hold [service] already: a list with its id or its set of codes.
bool _isHeldList(BackupService service, List<BackupService> services) => services.any((held) => sameBackupCodes(held, service));

/// How many accounts and services an import would add in [mode], as the
/// import dialogs counted them: every one when replacing, those not in the
/// vault yet when merging.
({int newAccounts, int duplicates, int newServices}) countImport(
  ImportPreview preview, {
  required List<OtpAccount> accounts,
  required List<BackupService> services,
  required ImportMode mode,
}) {
  final replace = mode == ImportMode.replace;
  final newAccounts = replace ? preview.accounts.length : preview.accounts.where((a) => !isDuplicateAccount(a, accounts)).length;
  final newServices = replace ? preview.backupServices.length : preview.backupServices.where((s) => !_isHeldList(s, services)).length;
  return (newAccounts: newAccounts, duplicates: preview.accounts.length - newAccounts, newServices: newServices);
}

/// The vault's lists after the import: in [ImportMode.replace], the
/// import's accounts and services (the vault's own services when
/// [keepServices], as another app's backup holds none); in
/// [ImportMode.merge], the vault's entries followed by the imported ones it
/// doesn't have. Accounts match by their secret, so a held HOTP code takes
/// the import's counter when that is higher, and services by id or by the
/// same set of codes, whatever the service's name.
({List<OtpAccount> accounts, List<BackupService> backupServices}) mergeImport(
  ImportPreview preview, {
  required List<OtpAccount> accounts,
  required List<BackupService> services,
  required ImportMode mode,
  bool keepServices = false,
}) {
  if (mode == ImportMode.replace) {
    return (accounts: preview.accounts, backupServices: keepServices ? services : preview.backupServices);
  }
  final held = [...accounts];
  final index = <String, int>{};
  for (var i = 0; i < held.length; i++) {
    if (codeSecret(held[i]) case final secret?) {
      index.putIfAbsent(secret, () => i);
    }
  }
  final added = <OtpAccount>[];
  for (final account in preview.accounts) {
    final secret = codeSecret(account);
    final at = secret == null ? null : index[secret];
    if (at == null) {
      added.add(account);
    } else if (raisedCounter(held[at], account) case final counter?) {
      held[at] = held[at].copyWith(counter: counter);
    }
  }
  return (accounts: [...held, ...added], backupServices: [...services, ...preview.backupServices.where((s) => !_isHeldList(s, services))]);
}

/// The passkeys of [preview] that [current] doesn't hold, by relying party
/// and credential id (or by id), each once.
List<Passkey> newPasskeys(ImportPreview preview, List<Passkey> current) {
  String key(Passkey passkey) => jsonEncode(passkeyTagInput(passkey).values);
  final heldIds = {for (final passkey in current) passkey.id};
  final held = {for (final passkey in current) key(passkey)};
  return [
    for (final passkey in preview.passkeys)
      if (!heldIds.contains(passkey.id) && held.add(key(passkey))) passkey,
  ];
}

/// The keys of [preview] that [current] doesn't hold, by [keyIdentity]: a
/// PGP key by its fingerprint, any other by its key pair.
List<VaultKey> newKeys(ImportPreview preview, List<VaultKey> current) {
  final held = {for (final key in current) keyIdentity(key)};
  return [
    for (final key in preview.keys)
      if (held.add(keyIdentity(key))) key,
  ];
}

/// The PGP keys of [preview] that are keys [current] holds, by [keyIdentity],
/// with other halves: an import combines each with the held copy, as it
/// may hold user IDs, subkeys or signatures the vault's copy lacks
/// (openspec: add-pgp-key-editing, design decision 9).
List<VaultKey> keysToCombine(ImportPreview preview, List<VaultKey> current) {
  final held = {for (final key in current) keyIdentity(key): key};
  return [
    for (final key in preview.keys)
      if (key.kind == KeyKind.pgp && (held[keyIdentity(key)]?.privateKey ?? key.privateKey) != key.privateKey) key,
  ];
}

/// The on-key accounts of [preview] that [current] doesn't hold, by key and
/// name, each once (openspec: add-security-key-codes, decision 10).
List<KeyAccount> newKeyAccounts(ImportPreview preview, List<KeyAccount> current) {
  final held = {for (final account in current) (account.device, account.name)};
  return [
    for (final account in preview.keyAccounts)
      if (held.add((account.device, account.name))) account,
  ];
}

/// The notes of [preview] that [current] doesn't hold, by id.
List<SecureNote> newNotes(ImportPreview preview, List<SecureNote> current) {
  final held = {for (final note in current) note.id};
  return [
    for (final note in preview.notes)
      if (held.add(note.id)) note,
  ];
}

/// The logins of [preview] that [current] doesn't hold, each once: those whose
/// id isn't held and whose site, username and password the vault doesn't hold
/// either (sites as [sites] reads them, the Public Suffix List's registrable
/// domains by default). One that matches in site and username alone is added,
/// for the duplicate cleaner to show.
/// When merging, a login linked to an imported account that the vault holds
/// already, so that the import skips it, is linked to the vault's copy
/// instead, so its code still goes with it ([accounts] is the vault's before
/// the import). Replacing takes the imported accounts as they are.
List<Login> newLogins(
  ImportPreview preview,
  List<Login> current, {
  required List<OtpAccount> accounts,
  required ImportMode mode,
  SiteResolver? sites,
}) {
  final resolver = sites ?? siteResolver();
  final held = {for (final login in current) login.id};
  final heldCredentials = {for (final login in current) ...loginCredKeys(login, resolver)};
  final imported = {for (final account in preview.accounts) account.id: account};
  final vaultIds = {for (final account in accounts) account.id};
  String? linked(String? id) {
    final account = imported[id];
    if (mode == ImportMode.replace || id == null || account == null || vaultIds.contains(id)) return id;
    return accounts.firstWhereOrNull((existing) => isSameAccount(existing, account))?.id ?? id;
  }

  return [
    for (final login in preview.logins)
      if (held.add(login.id) && !loginCredKeys(login, resolver).any(heldCredentials.contains))
        linked(login.accountId) == login.accountId ? login : login.copyWith(accountId: linked(login.accountId)),
  ];
}

/// The cards of [preview] that [current] doesn't hold, by id, each once. An
/// import only ever adds them.
List<PaymentCard> newCards(ImportPreview preview, List<PaymentCard> current) {
  final held = {for (final card in current) card.id};
  return [
    for (final card in preview.cards)
      if (held.add(card.id)) card,
  ];
}

/// The identities of [preview] that [current] doesn't hold, by id, each once.
List<Identity> newIdentities(ImportPreview preview, List<Identity> current) {
  final held = {for (final identity in current) identity.id};
  return [
    for (final identity in preview.identities)
      if (held.add(identity.id)) identity,
  ];
}

/// The File items of [preview] that [current] doesn't hold, by id, each once.
List<VaultFile> newFiles(ImportPreview preview, List<VaultFile> current) {
  final held = {for (final file in current) file.id};
  return [
    for (final file in preview.files)
      if (held.add(file.id)) file,
  ];
}

/// The contacts of [preview] whose key [current] doesn't hold, by
/// fingerprint, each key once. A contact the vault already has is left as
/// it is, check and all; one whose key can't be read is left out.
List<Contact> newContacts(ImportPreview preview, List<Contact> current) {
  String? fingerprint(Contact contact) => contactKeyInfo(contact)?.primary.fingerprintHex;
  final held = {for (final contact in current) ?fingerprint(contact)};
  return [
    for (final contact in preview.contacts)
      if (fingerprint(contact) case final print? when held.add(print)) contact,
  ];
}

/// What to do with an imported entry the vault holds already.
enum DuplicateChoice {
  /// Leave the vault's entry as it is and don't add the import's.
  skip,

  /// Add the import's entry beside the vault's.
  keepBoth,

  /// Put the import's entry in place of the vault's, which keeps its id.
  replace,
}

/// An import of one kind matched against the vault by [matchImport].
class MatchPlan<T> {
  const MatchPlan({required this.adds, required this.replaces, required this.matches});

  /// What is added: entries the vault doesn't hold, and those kept beside a match.
  final List<T> adds;

  /// The vault's entries to put an import's in place of, in order.
  final List<({T held, T incoming})> replaces;

  /// Every match, whatever was chosen for it, for the preview to show.
  final List<({T held, T incoming})> matches;
}

/// Matches [incoming] against [held] by the keys of the shared duplicate
/// rules (`keys` gives the texts that stand for an entry: equal in one of
/// them, or the same id, is a match), and sorts each match by what [choose]
/// says (skip when it is null). An entry of the import whose id repeats an
/// earlier one is taken once. An entry kept beside a match whose id is the
/// vault's gets a new one from [newId] through [withId].
///
/// No rule of its own is here: the keys come from `duplicate_rules.dart`, so
/// import and the duplicate cleaner can't disagree.
MatchPlan<T> matchImport<T>({
  required Iterable<T> incoming,
  required Iterable<T> held,
  required Iterable<String> Function(T entry) keys,
  required String Function(T entry) idOf,
  required T Function(T entry, String id) withId,
  String Function()? newId,
  DuplicateChoice Function(T entry)? choose,
}) {
  String idKey(T entry) => '\u0000id\u0000${idOf(entry)}';
  final index = <String, T>{};
  for (final entry in held) {
    index.putIfAbsent(idKey(entry), () => entry);
    for (final key in keys(entry)) {
      index.putIfAbsent(key, () => entry);
    }
  }
  final taken = <String>{};
  final adds = <T>[];
  final replaces = <({T held, T incoming})>[];
  final matches = <({T held, T incoming})>[];
  for (final entry in incoming) {
    if (!taken.add(idOf(entry))) {
      continue;
    }
    T? match = index[idKey(entry)];
    if (match == null) {
      for (final key in keys(entry)) {
        match = index[key];
        if (match != null) {
          break;
        }
      }
    }
    if (match == null) {
      adds.add(entry);
      continue;
    }
    matches.add((held: match, incoming: entry));
    switch (choose?.call(entry) ?? DuplicateChoice.skip) {
      case DuplicateChoice.skip:
        break;
      case DuplicateChoice.keepBoth:
        adds.add(index.containsKey(idKey(entry)) ? withId(entry, (newId ?? newUuid)()) : entry);
      case DuplicateChoice.replace:
        replaces.add((held: match, incoming: entry));
    }
  }
  return MatchPlan(adds: adds, replaces: replaces, matches: matches);
}

/// The logins of [preview] against [current]: a match is the same id, or the
/// same site, username and password. One that shares only the site and
/// username is added, and the cleaner shows the pair.
MatchPlan<Login> planLogins(
  ImportPreview preview,
  List<Login> current, {
  SiteResolver? sites,
  DuplicateChoice Function(Login entry)? choose,
  String Function()? newId,
}) {
  final resolver = sites ?? siteResolver();
  return matchImport(
    incoming: preview.logins,
    held: current,
    keys: (login) => loginCredKeys(login, resolver),
    idOf: (login) => login.id,
    withId: (login, id) => login.copyWith(id: id),
    newId: newId,
    choose: choose,
  );
}

/// The codes of [preview] against [current], matched by secret.
MatchPlan<OtpAccount> planCodes(
  ImportPreview preview,
  List<OtpAccount> current, {
  DuplicateChoice Function(OtpAccount entry)? choose,
  String Function()? newId,
}) => matchImport(
  incoming: preview.accounts,
  held: current,
  keys: (account) => [?codeSecret(account)],
  idOf: (account) => account.id,
  withId: (account, id) => account.copyWith(id: id),
  newId: newId,
  choose: choose,
);

/// The passkeys of [preview] against [current], matched by relying party and credential id.
MatchPlan<Passkey> planPasskeys(
  ImportPreview preview,
  List<Passkey> current, {
  DuplicateChoice Function(Passkey entry)? choose,
  String Function()? newId,
}) => matchImport(
  incoming: preview.passkeys,
  held: current,
  keys: (passkey) => [jsonEncode(passkeyTagInput(passkey).values)],
  idOf: (passkey) => passkey.id,
  withId: (passkey, id) => passkey.copyWith(id: id),
  newId: newId,
  choose: choose,
);

/// The cards of [preview] against [current], matched by number and expiry.
MatchPlan<PaymentCard> planCards(
  ImportPreview preview,
  List<PaymentCard> current, {
  DuplicateChoice Function(PaymentCard entry)? choose,
  String Function()? newId,
}) => matchImport(
  incoming: preview.cards,
  held: current,
  keys: (card) => [if (cardTagInput(card) case final input?) jsonEncode(input.values)],
  idOf: (card) => card.id,
  withId: (card, id) => card.copyWith(id: id),
  newId: newId,
  choose: choose,
);

/// [held] with [incoming] in its place at [at] (epoch ms): [held]'s id,
/// space, time added and link to its code, and the password history it had.
/// A password the import brings that differs from [held]'s becomes the
/// login's, and the one it replaces goes first into the previous passwords,
/// as sync's merge keeps them.
Login replacingLogin(Login held, Login incoming, int at) {
  final merged = incoming.copyWith(
    id: held.id,
    addedAt: held.addedAt,
    spaceId: held.spaceId ?? unset,
    accountId: held.accountId ?? unset,
    password: held.password ?? unset,
    passwordChangedAt: held.passwordChangedAt ?? unset,
    previousPasswords: held.previousPasswords ?? unset,
    updatedAt: at,
  );
  final next = incoming.password;
  return next == null || next.isEmpty ? merged : merged.withPassword(next, at);
}

/// [held] with [incoming] in its place at [at]: [held]'s id, space, order and
/// time added, and the higher counter of the two for a counter-based code.
OtpAccount replacingCode(OtpAccount held, OtpAccount incoming, int at) => incoming.copyWith(
  id: held.id,
  addedAt: held.addedAt,
  spaceId: held.spaceId ?? unset,
  order: held.order ?? unset,
  counter: raisedCounter(held, incoming) ?? held.counter ?? unset,
  updatedAt: at,
);

/// [held] with [incoming] in its place at [at]: [held]'s id and time added.
Passkey replacingPasskey(Passkey held, Passkey incoming, int at) => incoming.copyWith(id: held.id, addedAt: held.addedAt, updatedAt: at);

/// [held] with [incoming] in its place at [at]: [held]'s id, space and time added.
PaymentCard replacingCard(PaymentCard held, PaymentCard incoming, int at) =>
    incoming.copyWith(id: held.id, addedAt: held.addedAt, spaceId: held.spaceId ?? unset, updatedAt: at);
