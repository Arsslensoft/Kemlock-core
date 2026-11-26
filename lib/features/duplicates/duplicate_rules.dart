// The one rule set for finding an item the vault holds twice (the
// add-duplicate-cleaner plan, design 8). Import calls `sameCredential` to
// skip an entry the vault already has, and the cleaner makes its tags from
// the same inputs, so any pair import skips is a group the cleaner shows.
//
// Pure Dart, no Flutter package: it moves into `kemlock_core` unchanged.
// Sync's `_dropDuplicateAccounts` is a third rule, which stays as it is on
// purpose (design 8).
import 'dart:convert';

import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_file.dart';
import 'duplicate_normalise.dart';

/// The kinds of tag, in the order of how strongly each says two items are
/// one (`cred` before `account`). Their names are the first element of the
/// tag's input, as `crypto.md` "Duplicate tags" has them, plus `identity`.
enum TagKind {
  /// A site, a username and a password.
  cred,

  /// A site and a username: the same account, perhaps with two passwords.
  account,

  /// A code's secret.
  secret,
  passkey,
  card,
  note,

  /// A key's or a contact's fingerprint: SSH `SHA256:` or PGP hex.
  key,

  /// A backup-code list's codes.
  codes,

  /// An identity's full name and email.
  identity,

  /// A contact's email and phone.
  contact,

  /// One identity document's number.
  document,

  /// A File item's content hash (the SHA-256 of the file's plain bytes).
  file,
}

/// Why a group of items is shown (design 5).
enum DuplicateReason {
  sameSignIn(TagKind.cred),
  sameAccount(TagKind.account),
  sameCode(TagKind.secret),
  samePasskey(TagKind.passkey),
  sameCard(TagKind.card),
  sameNote(TagKind.note),
  sameKey(TagKind.key),
  sameCodes(TagKind.codes),
  sameIdentity(TagKind.identity),
  sameContact(TagKind.contact),
  sameDocument(TagKind.document),
  sameFile(TagKind.file),

  /// One item held in the vault and in a space, or in two spaces.
  inTwoPlaces(null);

  const DuplicateReason(this.kind);

  /// The kind of tag that says it; null for [inTwoPlaces], which is about where the items are.
  final TagKind? kind;

  /// The reason a tag of [kind] gives.
  static DuplicateReason of(TagKind kind) => values.firstWhere((reason) => reason.kind == kind);

  /// The reason of the strongest of [kinds], which is the one first in [TagKind]; null for none.
  static DuplicateReason? strongest(Iterable<TagKind> kinds) {
    if (kinds.isEmpty) {
      return null;
    }
    return of(kinds.reduce((a, b) => a.index <= b.index ? a : b));
  }
}

/// The most tags one item makes.
const maxTagsPerItem = 32;

/// The most websites of a login that make tags: two each, `cred` and `account`.
const maxTagSites = maxTagsPerItem ~/ 2;

/// One tag's input before it is keyed: its [kind] and its normalised [values]. The canonical
/// array is `[kind.name, ...values]`.
class TagInput {
  const TagInput(this.kind, this.values);

  final TagKind kind;
  final List<String> values;

  /// The array the tag is made over.
  List<String> get array => [kind.name, ...values];

  @override
  bool operator ==(Object other) => other is TagInput && other.kind == kind && _sameStrings(other.values, values);

  @override
  int get hashCode => Object.hash(kind, Object.hashAll(values));

  @override
  String toString() => 'TagInput(${kind.name})';
}

bool _sameStrings(List<String> a, List<String> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

// Logins

/// The sites a login makes tags for: the site of each website whose rule fills on a host,
/// each once, at most [maxTagSites]. A login with no website has the one empty site; one whose
/// websites are all regular expressions or never has none.
List<String> loginSites(Login login, SiteResolver sites) {
  final rules = login.rules;
  if (rules.isEmpty) {
    return const [''];
  }
  final out = <String>[];
  for (final rule in rules) {
    final host = rule.host;
    if (host == null) {
      continue;
    }
    final site = sites.site(host);
    if (!out.contains(site)) {
      out.add(site);
    }
    if (out.length == maxTagSites) {
      break;
    }
  }
  return out;
}

/// The login's `cred` inputs, `[site, username, password]` for each of its sites. A login
/// with no password has none: a password never makes a tag alone, and a missing one is no match.
List<TagInput> loginCredInputs(Login login, SiteResolver sites) {
  final password = login.password;
  if (password == null || password.isEmpty) {
    return const [];
  }
  final user = normaliseUsername(login.username ?? '');
  return [
    for (final site in loginSites(login, sites)) TagInput(TagKind.cred, [site, user, password]),
  ];
}

/// The login's `account` inputs, `[site, username]` for each of its sites.
List<TagInput> loginAccountInputs(Login login, SiteResolver sites) {
  final user = normaliseUsername(login.username ?? '');
  return [
    for (final site in loginSites(login, sites)) TagInput(TagKind.account, [site, user]),
  ];
}

/// Every tag input of [login], `cred` then `account` for each site, at most [maxTagsPerItem].
List<TagInput> loginTagInputs(Login login, SiteResolver sites) {
  final cred = loginCredInputs(login, sites);
  final account = loginAccountInputs(login, sites);
  final password = cred.isNotEmpty;
  return [
    for (var i = 0; i < account.length; i++) ...[if (password) cred[i], account[i]],
  ].take(maxTagsPerItem).toList();
}

/// The texts that stand for the login's credentials: equal in one of them when the logins have
/// a website in common (by its site), the username and the password.
Set<String> loginCredKeys(Login login, SiteResolver sites) => {for (final input in loginCredInputs(login, sites)) jsonEncode(input.values)};

/// Whether [a] and [b] are one login: the same id, or the same site, username and password.
/// A weaker match (one site and username, two passwords) is left to the cleaner.
bool sameLogin(Login a, Login b, {SiteResolver sites = const SiteResolver()}) {
  if (a.id == b.id) {
    return true;
  }
  final keys = loginCredKeys(a, sites);
  return keys.isNotEmpty && loginCredKeys(b, sites).any(keys.contains);
}

// Codes

final _secrets = Expando<String>();

/// The secret of [account] as base32 of its decoded bytes, or null for an empty one. Worked out once
/// per account, as an import compares each of its codes with every code the vault holds.
String? codeSecret(OtpAccount account) {
  final known = _secrets[account];
  if (known != null) {
    return known.isEmpty ? null : known;
  }
  final secret = secretBase32(account.secret) ?? '';
  _secrets[account] = secret;
  return secret.isEmpty ? null : secret;
}

/// The tag input of a code: its secret as base32 of the decoded bytes, whatever its issuer or label.
TagInput? codeTagInput(OtpAccount account) {
  final secret = codeSecret(account);
  return secret == null ? null : TagInput(TagKind.secret, [secret]);
}

/// Whether [a] and [b] are one code: the same secret, whatever the issuer, label, type or id.
bool sameCode(OtpAccount a, OtpAccount b) {
  final secret = codeSecret(a);
  return secret != null && secret == codeSecret(b);
}

/// The counter a held HOTP code takes when [incoming], the same secret, brings a higher one,
/// so a code that was used on another phone isn't taken back; null when [held] keeps its own.
int? raisedCounter(OtpAccount held, OtpAccount incoming) {
  if (held.kind != OtpType.hotp || incoming.kind != OtpType.hotp) {
    return null;
  }
  final next = incoming.counter;
  return next != null && next > (held.counter ?? 0) ? next : null;
}

// Passkeys

/// The tag input of a passkey: its relying party in lower case, and its credential id as base64url
/// without padding, as `crypto.md` "Normalisation" has them. The relying party is lower-cased and
/// nothing else: it isn't trimmed or put in NFC. The app keeps the id in that form already, so
/// only a padded or standard-alphabet one from another source changes.
TagInput passkeyTagInput(Passkey passkey) => TagInput(TagKind.passkey, [lowerCase(passkey.rpId), _base64Url(passkey.credentialId)]);

String _base64Url(String id) => id.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

/// Whether [a] and [b] are one passkey: the same relying party and credential id.
bool samePasskey(Passkey a, Passkey b) => a.id == b.id || (passkeyTagInput(a) == passkeyTagInput(b));

// Backup codes

/// The tag input of a backup-code list: its codes, sorted; null for a list with none.
TagInput? codesTagInput(BackupService service) {
  final codes = normaliseCodes([for (final code in service.codes) code.code]);
  return codes.isEmpty ? null : TagInput(TagKind.codes, codes);
}

/// Whether [a] and [b] are one list of backup codes: the same id, or the same set of codes. The
/// service's name doesn't count: a second list for one service with other codes is its own.
bool sameBackupCodes(BackupService a, BackupService b) {
  if (a.id == b.id) {
    return true;
  }
  final codes = codesTagInput(a);
  return codes != null && codes == codesTagInput(b);
}

// Notes, cards, keys and identities

/// The tag input of a note: its text; null for a note with none.
TagInput? noteTagInput(SecureNote note) {
  final text = normaliseNote(note.text);
  return text.isEmpty ? null : TagInput(TagKind.note, [text]);
}

/// Whether [a] and [b] are one note, which is by id alone. A note with another id and the same
/// text is added, and the cleaner shows the two.
bool sameNote(SecureNote a, SecureNote b) => a.id == b.id;

/// The tag input of a card: its number's digits and its expiry; null for a card with no number.
TagInput? cardTagInput(PaymentCard card) {
  final number = normaliseCardNumber(card.number);
  return number == null ? null : TagInput(TagKind.card, [number, normaliseCardExpiry(card.expMonth, card.expYear)]);
}

/// The tag input of a key or a contact, from [identity]: its fingerprint as `crypto.md`
/// "Normalisation" has it, which the caller reads (that takes the key apart) and which is used as
/// it is. Null for none.
TagInput? keyTagInput(String? identity) {
  return identity == null || identity.isEmpty ? null : TagInput(TagKind.key, [identity]);
}

/// The tag input of an identity: its full name and its email, each trimmed, in NFC and in lower
/// case, as `crypto.md` "Normalisation" has them. The full name is the given, middle and family
/// names in order, one space apart, as [Identity.fullName] has it; null for an identity with
/// neither a full name nor an email.
TagInput? identityTagInput(Identity identity) {
  final values = [normaliseUsername(identity.fullName ?? ''), normaliseUsername(identity.email ?? '')];
  return values.every((value) => value.isEmpty) ? null : TagInput(TagKind.identity, values);
}

/// The tag inputs of an identity's documents: one `document` input for each document number, each number once, in
/// order. A document whose number has too few letters and digits makes none.
List<TagInput> documentTagInputs(Identity identity) {
  final numbers = <String>{
    for (final document in identity.documents ?? const <IdentityDocument>[]) ?normaliseDocumentNumber(document.number),
  };
  return [for (final number in numbers) TagInput(TagKind.document, [number])];
}

/// The tag input of a contact: its email, trimmed, in NFC and in lower case as a username is, and its phone as its digits
/// only; the one is the empty string when the other is all there is. Null for a contact with neither. The address a key
/// was looked up by (`sourceEmail`) is not read.
TagInput? contactTagInput(Contact contact) {
  final email = normaliseUsername(contact.email ?? '');
  final phone = normalisePhone(contact.phone ?? '');
  return email.isEmpty && phone.isEmpty ? null : TagInput(TagKind.contact, [email, phone]);
}

/// The tag input of a File item: the SHA-256 of its file's plain bytes as 64 lower-case hex digits, which the entry's `sha256`
/// holds (any case is read); null for a file with none, or one that isn't 64 hex digits, which makes no tag.
TagInput? fileTagInput(VaultFile item) {
  final hash = item.file.sha256?.trim().toLowerCase();
  return hash == null || !_sha256Hex.hasMatch(hash) ? null : TagInput(TagKind.file, [hash]);
}

final _sha256Hex = RegExp(r'^[0-9a-f]{64}$');

/// Whether [a] and [b] are one File item: the same id, or the same file hash. A file with no hash is its own.
bool sameFile(VaultFile a, VaultFile b) {
  if (a.id == b.id) {
    return true;
  }
  final hash = fileTagInput(a);
  return hash != null && hash == fileTagInput(b);
}

/// Whether [a] and [b] are one credential, by the rules import and the cleaner share. [a] and
/// [b] are the same kind of item, one of the kinds whose rule is here: a login, a code, a passkey,
/// a backup-code list, a note or a File item. Two items of other kinds, or of two kinds, are not.
bool sameCredential(Object a, Object b, {SiteResolver sites = const SiteResolver()}) => switch ((a, b)) {
  (final Login a, final Login b) => sameLogin(a, b, sites: sites),
  (final OtpAccount a, final OtpAccount b) => sameCode(a, b),
  (final Passkey a, final Passkey b) => samePasskey(a, b),
  (final BackupService a, final BackupService b) => sameBackupCodes(a, b),
  (final SecureNote a, final SecureNote b) => sameNote(a, b),
  (final VaultFile a, final VaultFile b) => sameFile(a, b),
  _ => false,
};
