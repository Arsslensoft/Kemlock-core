/// How keys, notes and passkeys look as plain Vaultwarden items, the ones
/// Bitwarden's apps show and use:
///
/// | Entry | Item |
/// |---|---|
/// | Note | A secure note: its title, text and pin as the item's name, notes and favourite |
/// | SSH key | An SSH key item (the private key in OpenSSH form, the public line, the fingerprint), where the server keeps them ([keepsSshKeyItems]); else as other keys |
/// | Other key | A secure note: the public half in its text, the private half in a hidden field named [privateKeyFieldName] |
/// | Passkey | A login for the site: its name and URI from the relying party, the user name, and one `fido2Credentials` entry |
/// | Contact | A secure note: someone's armored public key, then the contact's note, in its text; no hidden field |
///
/// Each also carries the `Kemlock` field with the whole entry
/// (`PlainField`), and a `sum` of the values below, which tells an edit
/// made in Bitwarden: the values that changed then come back, as of the
/// item's revision. The credential of a passkey and the halves of a key
/// are written at creation and left out of the sum. A passkey's credential
/// never changes, nor do the halves of any key but a PGP key, which grow
/// when it is changed (openspec: add-pgp-key-editing): its public half is
/// in the notes, which the sum covers, and its hidden private half is
/// written again whenever it changed, so the item never shows two states
/// of the key.
library;

import 'dart:convert';

import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../crypto/keys/keys.dart' as keys;
import '../../../models/contact.dart';
import '../../../models/json.dart';
import '../../../models/passkey.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_key.dart';

/// Bitwarden's type for an SSH key item.
const sshKeyCipherType = 5;

/// The hidden field a key kept as a secure note holds its private half in.
const privateKeyFieldName = 'Private key';

/// The first Bitwarden server version with SSH key items. Vaultwarden shows
/// them in `/api/sync` only to clients that say they are at least this
/// version.
const sshKeyItemsVersion = '2024.12.0';

/// The longest `notes` Vaultwarden takes, as encrypted text: its default
/// `_max_note_size`, which is Bitwarden's limit too.
const maxEncryptedNotes = 10000;

/// What an item gets called when its entry has no name.
const untitledNoteName = 'Note';
const untitledKeyName = 'Key';

const _noteRule = '---';

/// Whether a server whose `/api/config` is [config] keeps SSH key items:
/// it reports a Bitwarden server version of [sshKeyItemsVersion] or later.
/// Vaultwarden sets no feature flag for them (1.37.5 reports 2026.6.0).
bool keepsSshKeyItems(Map<String, Object?> config) {
  final version = config['version'] ?? config['Version'];
  return version is String && versionAtLeast(version, sshKeyItemsVersion);
}

/// Whether the dotted version [version] is [minimum] or later. Anything
/// after the numbers (`-beta`, a build) is ignored; what doesn't read as
/// numbers is earlier than everything.
bool versionAtLeast(String version, String minimum) {
  List<int>? parts(String text) {
    final match = RegExp(r'^\s*(\d+)(?:\.(\d+))?(?:\.(\d+))?').firstMatch(text);
    if (match == null) return null;
    return [for (var i = 1; i <= 3; i++) int.parse(match[i] ?? '0')];
  }

  final a = parts(version);
  final b = parts(minimum)!;
  if (a == null) return false;
  for (var i = 0; i < 3; i++) {
    if (a[i] != b[i]) return a[i] > b[i];
  }
  return true;
}

/// How long [plain] is once encrypted as a Bitwarden string,
/// `2.<iv>|<ct>|<mac>`, which is what the server's limits count.
int encryptedLength(String plain) {
  int base64Length(int bytes) => (bytes + 2) ~/ 3 * 4;
  final cipherText = (utf8.encode(plain).length ~/ 16 + 1) * 16;
  return 2 + base64Length(16) + 1 + base64Length(cipherText) + 1 + base64Length(32);
}

/// Whether [notes] is more than the server keeps in an item's notes.
bool tooLongForNotes(String? notes) => notes != null && encryptedLength(notes) > maxEncryptedNotes;

// ─── Values ──────────────────────────────────────────────────────────────────

/// What a plain item of a key, note or passkey shows, as Kemlock writes it
/// and its `sum` hashes it. [sshItem]: the key is an SSH key item, whose
/// notes are the key's note; as a secure note, they start with the public
/// half.
Map<String, Object?> laterValues(Object entry, {bool sshItem = false}) => switch (entry) {
  SecureNote() => {
    'name': entry.title.trim().isEmpty ? untitledNoteName : entry.title,
    'notes': _orNull(entry.text),
    'favorite': entry.isPinned,
  },
  VaultKey() => {
    'name': entry.name.trim().isEmpty ? untitledKeyName : entry.name,
    'notes': sshItem ? _orNull(entry.note) : _orNull(keyNoteText(entry)),
    'favorite': entry.isPinned,
  },
  Passkey() => {'name': entry.displayName, 'username': _orNull(entry.userName), 'notes': _orNull(entry.note), 'favorite': false},
  // Someone's public key: nothing in it is secret, so there is no hidden field, and it is never a favourite
  Contact() => {
    'name': entry.name.trim().isEmpty ? untitledKeyName : entry.name,
    'notes': _orNull(contactNoteText(entry)),
    'favorite': false,
  },
  _ => throw ArgumentError.value(entry, 'entry', 'Not a key, a note or a passkey'),
};

String? _orNull(String? text) => text == null || text.isEmpty ? null : text;

/// [previous] with what a Bitwarden app changed: each of [values] that
/// differs from what Kemlock wrote for [previous] wins, as of [at]. Returns
/// [previous] itself when nothing it holds changed.
Object laterEdited(Object previous, Map<String, Object?> values, {required int at, bool sshItem = false}) {
  final wrote = laterValues(previous, sshItem: sshItem);
  bool changed(String name) => values[name] != wrote[name];
  String text(String name) => values[name] as String? ?? '';
  switch (previous) {
    case final SecureNote note:
      if (!changed('name') && !changed('notes') && !changed('favorite')) return note;
      return note.copyWith(
        title: changed('name') ? text('name') : null,
        text: changed('notes') ? text('notes') : null,
        pinned: changed('favorite') ? (values['favorite'] == true ? true : unset) : keep,
        updatedAt: at,
      );
    case final VaultKey key:
      if (!changed('name') && !changed('notes') && !changed('favorite')) return key;
      final note = sshItem ? text('notes') : readKeyNote(text('notes'));
      return key.copyWith(
        name: changed('name') ? text('name') : null,
        note: changed('notes') ? (note.isEmpty ? unset : note) : keep,
        pinned: changed('favorite') ? (values['favorite'] == true ? true : unset) : keep,
        updatedAt: at,
      );
    case final Passkey passkey:
      if (!changed('name') && !changed('username') && !changed('notes')) return passkey;
      return passkey.copyWith(
        label: changed('name') ? (text('name').trim().isEmpty ? unset : text('name')) : keep,
        userName: changed('username') ? text('username') : null,
        note: changed('notes') ? (text('notes').isEmpty ? unset : text('notes')) : keep,
        updatedAt: at,
      );
    case final Contact contact:
      // The name and the note come back. The key and its check are the `Kemlock` field's alone:
      // another key pasted into the notes changes neither.
      if (!changed('name') && !changed('notes')) return contact;
      final note = readKeyNote(text('notes'));
      return contact.copyWith(
        name: changed('name') ? (text('name').trim().isEmpty ? null : text('name')) : null,
        note: changed('notes') ? (note.isEmpty ? unset : note) : keep,
        updatedAt: at,
      );
  }
  throw ArgumentError.value(previous, 'previous', 'Not a key, a note or a passkey');
}

// ─── Keys ────────────────────────────────────────────────────────────────────

/// [key] as the key codecs take it.
keys.ParsedKey parsedKey(VaultKey key) => keys.ParsedKey(
  kind: keys.KeyKind.values.firstWhere((kind) => kind.name == key.kind, orElse: () => keys.KeyKind.other),
  algorithm: key.algorithm,
  bits: key.bits,
  private: unb64(key.privateKey),
  public: key.publicKey == null ? null : unb64(key.publicKey!),
  comment: key.name,
);

/// A key's public half as text: an SSH key's `ssh` line, a PGP key armored,
/// any other as a `PUBLIC KEY` block; null when it has none Kemlock reads.
String? publicKeyText(VaultKey key) {
  try {
    final parsed = parsedKey(key);
    if (parsed.kind == keys.KeyKind.ssh && parsed.hasSshForm) return keys.sshPublicKeyLine(parsed);
    return keys.publicKeyPem(parsed);
  } catch (_) {
    return null;
  }
}

/// A key kept as a secure note: its public half, then its own note after a
/// `---` line.
String keyNoteText(VaultKey key) {
  final note = key.note?.trim() ?? '';
  return [?publicKeyText(key), if (note.isNotEmpty) '$_noteRule\n$note'].join('\n\n');
}

/// The key's own note in a key note's [text]: what follows the `---` line.
String readKeyNote(String text) {
  final lines = const LineSplitter().convert(text);
  final rule = lines.indexWhere((line) => line.trim() == _noteRule);
  return rule < 0 ? '' : lines.sublist(rule + 1).join('\n').trim();
}

/// The private half as a key note's hidden field holds it, unprotected: an
/// SSH key in OpenSSH form, a PGP key armored, any other as PKCS#8 PEM. A
/// key the codecs can't write goes as the base64 the vault keeps.
Future<String> privateKeyText(VaultKey key) async {
  try {
    return await keys.exportPrivateKey(parsedKey(key));
  } catch (_) {
    return key.privateKey;
  }
}

/// An SSH key item's `sshKey`, unencrypted: the private key in OpenSSH form,
/// the public line without a comment, and its `SHA256:` fingerprint; null
/// for a key that has no SSH form.
Future<({String privateKey, String publicKey, String fingerprint})?> sshKeyValues(VaultKey key) async {
  if (key.kind != KeyKind.ssh) return null;
  try {
    final parsed = parsedKey(key);
    if (!parsed.hasSshForm) return null;
    final public = keys.sshPublicKeyLine(parsed, comment: '');
    final fingerprint = keys.keyFingerprint(parsed);
    if (public == null || fingerprint == null) return null;
    return (privateKey: await keys.exportOpenSsh(parsed, comment: key.name), publicKey: public, fingerprint: fingerprint.text);
  } catch (_) {
    return null;
  }
}

// ─── Contacts ────────────────────────────────────────────────────────────────

/// A contact kept as a secure note: its armored public key, then its own
/// note after a `---` line, as [keyNoteText] writes a key.
String contactNoteText(Contact contact) {
  String? armored;
  try {
    armored = contact.hasKey ? keys.writeArmor(keys.pgpPublicKeyBlock, unb64(contact.publicKey)).trimRight() : null;
  } on FormatException {
    armored = null;
  }
  final note = contact.note?.trim() ?? '';
  return [?armored, if (note.isNotEmpty) '$_noteRule\n$note'].join('\n\n');
}

// ─── Passkeys ────────────────────────────────────────────────────────────────

/// A credential id as Bitwarden writes it: 16 bytes as a GUID, any other
/// length as `b64.` and base64url, the inverse of the Bitwarden importer.
String bitwardenCredentialId(String credentialId) {
  final bytes = unb64url(credentialId);
  if (bytes.length != 16) return 'b64.${b64url(bytes)}';
  final hex = [for (final byte in bytes) byte.toRadixString(16).padLeft(2, '0')].join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

/// [passkey] as one of a login's `fido2Credentials`, its values encrypted
/// with [key] but `creationDate`, as Bitwarden keeps them: an ES256 key,
/// PKCS#8 in base64url, discoverable, its counter at 0.
Future<Map<String, Object?>> fido2Credential(Passkey passkey, BwKey key) async {
  Future<String> enc(String value) => bwEncryptString(value, key);
  Future<String?> encOrNull(String? value) async => value == null || value.isEmpty ? null : enc(value);
  return {
    'credentialId': await enc(bitwardenCredentialId(passkey.credentialId)),
    'keyType': await enc('public-key'),
    'keyAlgorithm': await enc('ECDSA'),
    'keyCurve': await enc('P-256'),
    'keyValue': await enc(b64url(unb64(passkey.privateKey))),
    'rpId': await enc(passkey.rpId),
    'rpName': await encOrNull(passkey.rpName),
    'userHandle': await enc(passkey.userHandle),
    'userName': await encOrNull(passkey.userName),
    'userDisplayName': await encOrNull(passkey.userDisplayName),
    'counter': await enc('0'),
    'discoverable': await enc('true'),
    'creationDate': DateTime.fromMillisecondsSinceEpoch(passkey.addedAt, isUtc: true).toIso8601String(),
  };
}

/// The site a passkey signs in to, as a login's URI.
String passkeyWebsite(Passkey passkey) => 'https://${passkey.rpId}';

/// Whether [login] (a login item's `login`) still holds a passkey.
bool holdsPasskey(Map<String, Object?>? login) {
  final credentials = login?['fido2Credentials'];
  return credentials is List && credentials.isNotEmpty;
}
