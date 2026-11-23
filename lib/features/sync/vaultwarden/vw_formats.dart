/// What Kemlock writes inside Vaultwarden items. Other phones, running other
/// versions, read these, so once released they don't change: the fixtures
/// in test/fixtures/vaultwarden pin them.
///
/// Every item Kemlock claims carries a hidden custom field named [fieldName]:
///
/// - the *home* note's holds a [HomeNote], the JSON that says how a home
///   keeps its entries and, sealed, the passphrase's salt;
/// - a sealed entry's holds `kemlock-sealed:1:<home>:<id>:<nonce>:<ct>`, the
///   entry encrypted again with the home's key ([sealEntry]);
/// - a plain entry's holds a [PlainField], the entry's JSON and which home it
///   belongs to, beside the item's own values: a login's name, username, code
///   and notes, a note's title and text, a key's or a passkey's.
///
/// An entry is any [EntryKind]: an account, a list of backup codes, a key, a
/// note, a passkey or a contact (someone else's public key). Builds from before
/// a kind read an
/// item of that kind as one they can't read, and leave it alone.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../../crypto/aes_gcm.dart';
import '../../../crypto/bytes.dart';
import '../../../models/backup_service.dart';
import '../../../models/contact.dart';
import '../../../models/json.dart';
import '../../../models/otp_account.dart';
import '../../../models/passkey.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_entry.dart';
import '../../../models/vault_key.dart';
import '../sync_merge.dart' show canonical;
import 'vw_models.dart';

/// The hidden field on every item Kemlock claims.
const fieldName = 'Kemlock';

/// The folder a new home's items go in.
const defaultFolderName = 'Kemlock';

/// The home note's name.
const homeNoteName = 'Kemlock';

/// What the home note's text says.
const homeNoteText = 'Kemlock keeps its sync settings for this vault in this note. Don’t edit or delete it.';

/// A sealed entry's name.
const sealedEntryName = 'Kemlock sealed entry';

/// What a sealed entry's text says.
const sealedEntryText = 'Sealed by Kemlock: open and edit it in Kemlock. Changes made here are lost.';

/// What a list of backup codes is called in Vaultwarden: "GitHub backup codes".
const backupCodesSuffix = ' backup codes';

const _sealedPrefix = 'kemlock-sealed:1:';

/// A new random id for a home, in base64url.
String newHomeId() => b64url(randomBytes(12));

/// Which kind of entry an item holds. The names are what the formats write.
enum EntryKind {
  account,
  backupService,
  key,
  note,
  passkey,

  /// Someone else's public key.
  contact;

  static EntryKind? parse(Object? value) => switch (value) {
    'account' => account,
    'backupService' => backupService,
    'key' => key,
    'note' => note,
    'passkey' => passkey,
    'contact' => contact,
    _ => null,
  };

  /// The kind [entry] is: an [OtpAccount], a [BackupService], a [VaultKey],
  /// a [SecureNote], a [Passkey] or a [Contact].
  static EntryKind of(Object entry) => switch (entry) {
    OtpAccount() => account,
    BackupService() => backupService,
    VaultKey() => key,
    SecureNote() => note,
    Passkey() => passkey,
    Contact() => contact,
    _ => throw ArgumentError.value(entry, 'entry', 'Not an entry'),
  };

  /// Whether builds from before keys, notes and passkeys know the kind.
  bool get isLater => index > backupService.index;
}

// ─── The home note ───────────────────────────────────────────────────────────

/// The home note's field: how a home keeps its entries.
class HomeNote {
  const HomeNote({required this.id, required this.name, required this.mode, this.seal, this.extra = const {}});

  /// Reads a home note's field, or null when [text] isn't one.
  static HomeNote? tryParse(String text) {
    Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException {
      return null;
    }
    if (json is! Map<String, Object?> || json['app'] != 'Kemlock' || json['kind'] != 'home' || json['version'] != 1) return null;
    final id = json['id'];
    final mode = VaultwardenMode.parse(json['mode']);
    if (id is! String || id.isEmpty || mode == null) return null;
    return HomeNote(
      id: id,
      name: asString(json['name']),
      mode: mode,
      seal: json['seal'] is Map<String, Object?> ? json['seal']! as Map<String, Object?> : null,
      extra: extraKeys(json, const {'app', 'kind', 'version', 'id', 'name', 'mode', 'seal'}),
    );
  }

  final String id;
  final String name;
  final VaultwardenMode mode;

  /// Sealed: a sync file for an empty document, whose `kdf` is the
  /// passphrase's salt and which opening checks the passphrase.
  final Map<String, Object?>? seal;

  final Map<String, Object?> extra;

  String toText() =>
      jsonEncode({'app': 'Kemlock', 'kind': 'home', 'version': 1, 'id': id, 'name': name, 'mode': mode.name, 'seal': ?seal, ...extra});

  HomeNote copyWith({VaultwardenMode? mode, Object? seal = keep}) =>
      HomeNote(id: id, name: name, mode: mode ?? this.mode, seal: pick(seal, this.seal), extra: extra);

  @override
  String toString() => 'HomeNote($id, $name, ${mode.name})';
}

// ─── Sealed entries ──────────────────────────────────────────────────────────

/// What a sealed value says about itself without opening it.
typedef SealedHeader = ({String home, String id});

/// The home and entry id a sealed value names, or null when [text] isn't one.
SealedHeader? sealedHeader(String text) {
  final parts = _sealedParts(text);
  return parts == null ? null : (home: parts.$1, id: parts.$2);
}

(String, String, String, String)? _sealedParts(String text) {
  if (!text.startsWith(_sealedPrefix)) return null;
  final parts = text.substring(_sealedPrefix.length).split(':');
  if (parts.length != 4 || parts.any((part) => part.isEmpty)) return null;
  return (parts[0], parts[1], parts[2], parts[3]);
}

/// [entry] (any [EntryKind]) sealed with the home's 32-byte [key]: AES-256-GCM
/// of `{"kind": …, "entry": …}` with a fresh nonce.
Future<String> sealEntry(Object entry, String home, Uint8List key) async {
  final (kind, id, json) = _entryJson(entry);
  final sealed = await aesGcmEncrypt(key, utf8.encode(jsonEncode({'kind': kind.name, 'entry': json})));
  return '$_sealedPrefix$home:$id:${b64(sealed.nonce)}:${b64(sealed.ct)}';
}

/// A sealed value that doesn't open, or holds something else.
class SealedEntryError implements Exception {
  const SealedEntryError(this.message);

  final String message;

  @override
  String toString() => 'SealedEntryError: $message';
}

/// Opens a sealed value: an entry of any [EntryKind]. Throws a
/// [SealedEntryError] when [key] doesn't open it, or what's inside isn't an
/// entry with the id the value names, or one of a kind this build doesn't
/// know.
Future<Object> openSealedEntry(String text, Uint8List key) async {
  final parts = _sealedParts(text);
  if (parts == null) throw const SealedEntryError('Not a sealed entry');
  final (_, id, nonce, ct) = parts;
  Object? json;
  try {
    json = jsonDecode(utf8.decode(await aesGcmDecrypt(key, unb64(nonce), unb64(ct))));
  } catch (_) {
    throw const SealedEntryError('The key does not open it');
  }
  final entry = json is Map<String, Object?> ? _entryFrom(EntryKind.parse(json['kind']), json['entry']) : null;
  if (entry == null || _idOf(entry) != id) throw const SealedEntryError('Not an entry');
  return entry;
}

// ─── Plain entries ───────────────────────────────────────────────────────────

/// A plain entry's field: the entry as the vault keeps it, which home it
/// belongs to, whether Kemlock made the item ([own]) or the user's own login
/// holds its code (linked), and a hash of what Kemlock last wrote to the
/// item's own values ([sum]), which tells an edit made in Bitwarden.
class PlainField {
  const PlainField({required this.home, required this.own, required this.sum, required this.entry, this.extra = const {}});

  /// Reads a plain field, or null when [text] isn't one.
  static PlainField? tryParse(String text) {
    Object? json;
    try {
      json = jsonDecode(text);
    } on FormatException {
      return null;
    }
    if (json is! Map<String, Object?> || json['v'] != 1) return null;
    final home = json['home'];
    final id = json['id'];
    final entry = _entryFrom(EntryKind.parse(json['kind']), json['entry']);
    if (home is! String || id is! String || entry == null || _idOf(entry) != id) return null;
    return PlainField(
      home: home,
      own: json['own'] == true,
      sum: asString(json['sum']),
      entry: entry,
      extra: extraKeys(json, const {'v', 'home', 'id', 'own', 'kind', 'sum', 'entry'}),
    );
  }

  final String home;
  final bool own;
  final String sum;

  /// An entry of any [EntryKind].
  final Object entry;
  final Map<String, Object?> extra;

  String get id => _idOf(entry);

  EntryKind get kind => EntryKind.of(entry);

  /// The sum of the URIs after the first as Kemlock last saw them (see [urisSum]), kept in
  /// [extra]: only an item whose code has websites of its own carries one, and builds from
  /// before it keep it with the other keys they don't know. Null for any other.
  String? get uriSum => asOptionalString(extra['uriSum']);

  String toText() {
    final (kind, id, json) = _entryJson(entry);
    return jsonEncode({'v': 1, 'home': home, 'id': id, 'own': own, 'kind': kind.name, 'sum': sum, 'entry': json, ...extra});
  }
}

/// The home and entry id a plain field names, even one this version can't
/// read, such as a kind added later; null when [text] isn't a plain field.
SealedHeader? plainHeader(String text) {
  Object? json;
  try {
    json = jsonDecode(text);
  } on FormatException {
    return null;
  }
  if (json is! Map<String, Object?> || json['v'] is! num) return null;
  final home = json['home'];
  final id = json['id'];
  if (home is! String || id is! String || home.isEmpty || id.isEmpty) return null;
  return (home: home, id: id);
}

/// The hash of an item's own values as Kemlock wrote them: the first 16 bytes
/// of the SHA-256 of their canonical JSON, base64.
String valuesSum(Map<String, Object?> values) => b64(sha256.convert(utf8.encode(canonical(values))).bytes.sublist(0, 16));

/// The hash of the URIs after the first of a code's item, with their rule numbers, as
/// Kemlock saw them after its last write: [valuesSum] of their canonical JSON. A URI
/// edited in another app makes it differ.
String urisSum(Iterable<({String uri, int? match})> uris) => valuesSum({
  'uris': [
    for (final item in uris) {'uri': item.uri, 'match': item.match},
  ],
});

// ─── Backup codes as text ────────────────────────────────────────────────────

const _usedMark = '✓';
const _noteRule = '---';

/// A list of backup codes as a note's text: one code per line, used ones
/// marked `✓ `, then the list's own note after a `---` line.
String backupCodesText(BackupService service) {
  final codes = [for (final code in service.codes) code.used ? '$_usedMark ${code.code}' : code.code].join('\n');
  final note = service.note?.trim() ?? '';
  return note.isEmpty ? codes : '$codes\n\n$_noteRule\n$note';
}

/// Reads [text] back into [previous]'s codes: lines in order, a code marked
/// `✓` used. A code newly marked is used [at]; one that stays used keeps its
/// date. The text after a `---` line is the note.
BackupService readBackupCodesText(String text, BackupService previous, {required int at}) {
  final lines = const LineSplitter().convert(text);
  final rule = lines.indexWhere((line) => line.trim() == _noteRule);
  final codeLines = rule < 0 ? lines : lines.sublist(0, rule);
  final note = rule < 0 ? '' : lines.sublist(rule + 1).join('\n').trim();
  final before = {for (final code in previous.codes) code.code: code};
  final codes = <BackupCode>[];
  for (final raw in codeLines) {
    var line = raw.trim();
    if (line.isEmpty) continue;
    final used = line.startsWith(_usedMark);
    if (used) line = line.substring(_usedMark.length).trim();
    if (line.isEmpty) continue;
    final old = before[line];
    if (old != null && old.used == used) {
      codes.add(old);
    } else if (old != null) {
      codes.add(old.copyWith(used: used, usedAt: used ? at : unset));
    } else {
      codes.add(BackupCode(code: line, used: used, usedAt: used ? at : null));
    }
  }
  return previous.copyWith(codes: codes, note: note.isEmpty ? unset : note);
}

// ─── Entries ─────────────────────────────────────────────────────────────────

String _idOf(Object entry) => switch (entry) {
  VaultEntry(:final id) => id,
  _ => throw ArgumentError.value(entry, 'entry', 'Not an entry'),
};

(EntryKind, String, Map<String, Object?>) _entryJson(Object entry) => switch (entry) {
  VaultEntry() => (EntryKind.of(entry), entry.id, entry.toJson()),
  _ => throw ArgumentError.value(entry, 'entry', 'Not an entry'),
};

Object? _entryFrom(EntryKind? kind, Object? json) {
  if (json is! Map<String, Object?> || json['id'] is! String || (json['id']! as String).isEmpty) return null;
  try {
    return switch (kind) {
      EntryKind.account => OtpAccount.fromJson(json),
      EntryKind.backupService => BackupService.fromJson(json),
      EntryKind.key => VaultKey.fromJson(json),
      EntryKind.note => SecureNote.fromJson(json),
      EntryKind.passkey => Passkey.fromJson(json),
      EntryKind.contact => Contact.fromJson(json),
      null => null,
    };
  } catch (_) {
    return null;
  }
}
