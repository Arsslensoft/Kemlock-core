// Exports from other authenticator apps, read as `src/lib/importers.ts`
// reads them: Google Authenticator transfer QR codes, Aegis and 2FAS
// backups (plain or encrypted), unencrypted Bitwarden JSON, and text files
// of otpauth:// links.
//
// The TypeScript reads loosely typed JSON through JavaScript's coercions
// (`Number(v)`, `String(v)`, `trim()`) and URLs through the WHATWG parser;
// the helpers at the bottom do the same, so a file that imports in one app
// imports the same way in the other.
import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';

import '../../core/ids.dart';
import '../../crypto/bytes.dart';
import '../../crypto/kdf.dart';
import '../../models/identity.dart';
import '../../models/json.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_key.dart';
import '../../vault/vault_export.dart' show formatAppName;
import '../accounts/otp.dart';
import '../accounts/otpauth.dart';
import 'formats/csv_logins.dart';
import 'formats/cxf.dart';
import 'formats/cxf_map.dart';
import 'formats/import_extras.dart';

/// The app an import came from.
enum ImportSource {
  google,
  aegis,
  twoFas,
  bitwarden,

  /// A text file of otpauth:// links, which may also hold transfer payloads.
  uris,

  /// A Credential Exchange payload; the sheet names it after its exporter.
  cxf,

  /// A CSV file of logins, as other password managers export them (`formats/csv_logins.dart`). Added in Kemlock-core: the app's own
  /// copy of this file has no such source yet.
  csv,
}

/// What another app's export held.
class ForeignImport {
  const ForeignImport({
    required this.source,
    required this.accounts,
    required this.skipped,
    this.passkeys = const [],
    this.logins = const [],
    this.cards = const [],
    this.identities = const [],
    this.keys = const [],
    this.notes = const [],
    this.skips = const [],
    this.notices = const [],
    this.units = const [],
    this.unitOf = const {},
    this.cuts,
    this.sourceName,
  });

  final ImportSource source;

  /// New accounts, whose `id` is '' and `addedAt` 0, as [parseOtpUri] makes
  /// them, for the caller to set when it adds them.
  final List<OtpAccount> accounts;

  /// Entries that can't be represented (unsupported type, algorithm or digits,
  /// bad secret), passkeys among them.
  final int skipped;

  /// Passkeys, from a Bitwarden export, whose `id` is '' and `addedAt` when
  /// the passkey was made, for the caller to give an id when it adds them.
  final List<Passkey> passkeys;

  /// What a Credential Exchange payload also holds: logins, cards,
  /// identities, SSH keys and notes. They come with their ids and times,
  /// where the other importers leave those to the caller.
  final List<Login> logins;
  final List<PaymentCard> cards;
  final List<Identity> identities;
  final List<VaultKey> keys;
  final List<SecureNote> notes;

  /// Each credential and item left out, with its reason. [skipped] counts
  /// them for the importers that don't list theirs.
  final List<ImportSkip> skips;

  /// Entries kept with a caveat.
  final List<ImportNotice> notices;

  /// The places the preview asks about, and which one each entry's id goes to
  /// ([unitOf]). Empty for a file with one source of entries.
  final List<ImportUnit> units;
  final Map<String, String> unitOf;

  /// What a limit cut, for a Credential Exchange payload.
  final CxfCuts? cuts;

  /// What the sheet calls the source when its own name isn't enough: the exporter's.
  final String? sourceName;

  /// Whether the import holds no entry of any kind and left nothing out.
  bool get holdsNothing =>
      accounts.isEmpty &&
      passkeys.isEmpty &&
      logins.isEmpty &&
      cards.isEmpty &&
      identities.isEmpty &&
      keys.isEmpty &&
      notes.isEmpty &&
      skipped == 0;

  @override
  bool operator ==(Object other) =>
      other is ForeignImport &&
      other.source == source &&
      other.skipped == skipped &&
      const ListEquality<OtpAccount>().equals(other.accounts, accounts) &&
      const ListEquality<Passkey>().equals(other.passkeys, passkeys) &&
      const ListEquality<Login>().equals(other.logins, logins) &&
      const ListEquality<PaymentCard>().equals(other.cards, cards) &&
      const ListEquality<Identity>().equals(other.identities, identities) &&
      const ListEquality<VaultKey>().equals(other.keys, keys) &&
      const ListEquality<SecureNote>().equals(other.notes, notes) &&
      const ListEquality<ImportSkip>().equals(other.skips, skips);

  @override
  int get hashCode => Object.hash(source, skipped, accounts.length);

  @override
  String toString() => 'ForeignImport(${source.name}, skipped: $skipped, $accounts)';
}

/// A file's format, found without decrypting it.
typedef DetectedFormat = ({ImportSource source, bool encrypted});

/// Why another app's export couldn't be read.
enum ImportErrorCode {
  /// Not a format this app reads, including Kemlock's own exports, which have their own importer.
  unsupported,

  /// A known format without any 2FA entries.
  empty,

  /// An encrypted Aegis or 2FAS file, and no password.
  passwordRequired,

  /// The password doesn't open the file, or the encrypted part is damaged.
  badPassword,

  /// Bitwarden's encrypted exports can't be read.
  bitwardenEncrypted,
}

/// Why another app's export couldn't be read; [code] picks the message to show.
class ImportError implements Exception {
  const ImportError(this.code, [this._message]);

  final ImportErrorCode code;
  final String? _message;

  /// English, for logs; the import dialog shows its own copy for [code].
  String get message =>
      _message ??
      switch (code) {
        ImportErrorCode.unsupported => 'Not an export this app can read',
        ImportErrorCode.empty => 'The export has no 2FA accounts',
        ImportErrorCode.passwordRequired => 'The export is encrypted and needs its password',
        ImportErrorCode.badPassword => 'Wrong password',
        ImportErrorCode.bitwardenEncrypted => 'Encrypted Bitwarden exports can’t be read',
      };

  @override
  String toString() => 'ImportError: $message';
}

typedef _Json = Map<String, Object?>;

/// What [_parseJson] returns for text that isn't JSON at all, as `undefined` in the TypeScript.
const _notJson = Object();

Object? _parseJson(String text) {
  try {
    return jsonDecode(text);
  } on FormatException {
    return _notJson;
  }
}

String _stripBom(String text) => text.isNotEmpty && text.codeUnitAt(0) == 0xfeff ? text.substring(1) : text;

_Json _object(Object? v) => v is _Json ? v : const {};

/// A trimmed string, or '' for anything else.
String _str(Object? v) => v is String ? _jsTrim(v) : '';

List<Object?> _list(Object? v) => v is List<Object?> ? v : const [];

// The schemes are spelled out in both cases: Dart's case-blind matching also
// folds some other letters onto ASCII ones, which JavaScript's doesn't.
final _uriLine = RegExp(r'^(?:[Oo][Tt][Pp][Aa][Uu][Tt][Hh](?:-[Mm][Ii][Gg][Rr][Aa][Tt][Ii][Oo][Nn])?|[Ss][Tt][Ee][Aa][Mm])://');
final _migrationLine = RegExp(r'^[Oo][Tt][Pp][Aa][Uu][Tt][Hh]-[Mm][Ii][Gg][Rr][Aa][Tt][Ii][Oo][Nn]://');
final _lineBreak = RegExp(r'\r?\n');

List<String> _uriLines(String text) => [
  for (final line in text.split(_lineBreak))
    if (_jsTrim(line).isNotEmpty) _jsTrim(line),
];

/// Identifies a file's format without decrypting it. Null when it's not a
/// format this app reads, including Kemlock's own exports, which have
/// their own importer.
DetectedFormat? detectFormat(String text) {
  final clean = _stripBom(text);
  final json = _parseJson(clean);
  if (!identical(json, _notJson)) return json is _Json ? _detectJson(json) : null;

  final lines = _uriLines(clean);
  if (!lines.any(_uriLine.hasMatch)) return looksLikeLoginCsv(clean) ? (source: ImportSource.csv, encrypted: false) : null;
  final source = lines.every(_migrationLine.hasMatch) ? ImportSource.google : ImportSource.uris;
  return (source: source, encrypted: false);
}

DetectedFormat? _detectJson(_Json json) {
  if (json['app'] == formatAppName) return null;
  // Before Bitwarden's JSON: neither format has the other's keys
  if (looksLikeCxf(json)) return (source: ImportSource.cxf, encrypted: false);
  final db = json['db'];
  if (json['header'] is _Json && (db is _Json || db is String)) {
    return (source: ImportSource.aegis, encrypted: db is String);
  }
  if (json['services'] is List<Object?> && (json.containsKey('schemaVersion') || json.containsKey('servicesEncrypted'))) {
    return (source: ImportSource.twoFas, encrypted: _is2fasEncrypted(json));
  }
  final bitwarden = json['items'] is List<Object?> || json['passwordProtected'] == true || json.containsKey('encKeyValidation_DO_NOT_EDIT');
  if (json['encrypted'] case final bool encrypted when bitwarden) {
    return (source: ImportSource.bitwarden, encrypted: encrypted);
  }
  return null;
}

bool _is2fasEncrypted(_Json json) => switch (json['servicesEncrypted']) {
  final String blob => blob.isNotEmpty,
  _ => false,
};

/// Reads an export from another authenticator app. Throws an [ImportError]:
/// [ImportErrorCode.unsupported] when [detectFormat] doesn't recognise it,
/// [ImportErrorCode.passwordRequired] or [ImportErrorCode.badPassword] for
/// encrypted Aegis and 2FAS files, [ImportErrorCode.bitwardenEncrypted] for
/// encrypted Bitwarden files, and [ImportErrorCode.empty] when it holds no
/// 2FA entries at all. The key derivations run in a background isolate.
///
/// A Credential Exchange payload that can't be read throws a [CxfException]
/// instead, which says why (a version Kemlock doesn't read, a limit, a
/// structure of the wrong shape). Its entries get ids from [newId] (a new
/// UUID by default) and the time [now] (epoch ms, the clock by default)
/// where the payload gives none.
Future<ForeignImport> parseForeignExport(String text, {String? password, String Function()? newId, int? now}) async {
  final clean = _stripBom(text);
  final format = detectFormat(clean);
  if (format == null) throw const ImportError(ImportErrorCode.unsupported);
  if (format.source == ImportSource.bitwarden && format.encrypted) {
    throw const ImportError(ImportErrorCode.bitwardenEncrypted);
  }
  if (format.encrypted && (password == null || password.isEmpty)) {
    throw const ImportError(ImportErrorCode.passwordRequired);
  }

  final result = await _parseFormat(format.source, clean, password ?? '', newId ?? newUuid, now ?? DateTime.now().millisecondsSinceEpoch);
  if (result.holdsNothing) throw const ImportError(ImportErrorCode.empty);
  return result;
}

Future<ForeignImport> _parseFormat(ImportSource source, String text, String password, String Function() newId, int now) async {
  if (source == ImportSource.google || source == ImportSource.uris) return _parseUriList(text, source);
  if (source == ImportSource.cxf) return mapCxf(parseCxf(text), newId: newId, now: now);
  if (source == ImportSource.csv) return readLoginCsv(text, newId: newId, now: now);
  // Only a second byte order mark gets here without an object, where the TypeScript fails reading it
  final json = _parseJson(text);
  if (json is! _Json) throw const ImportError(ImportErrorCode.unsupported);
  return switch (source) {
    ImportSource.aegis => _parseAegis(json, password),
    ImportSource.twoFas => _parse2fas(json, password),
    _ => _parseBitwarden(json),
  };
}

ForeignImport _tally(ImportSource source, List<OtpAccount?> entries) {
  final accounts = entries.nonNulls.toList();
  return ForeignImport(source: source, accounts: accounts, skipped: entries.length - accounts.length);
}

// ─── Shared field checks ─────────────────────────────────────────────────────

const _algorithms = {'SHA1', 'SHA256', 'SHA512'};

final _trailingPadding = RegExp(r'=+$');
final _base32 = RegExp(r'^[A-Z2-7]+$');

/// A base32 secret from a structured export; lenient like [parseOtpUri], unlike [isValidSecret].
String? _secretOf(Object? v) {
  if (v is! String) return null;
  final secret = normalizeSecret(v).replaceFirst(_trailingPadding, '');
  if (!_base32.hasMatch(secret)) return null;
  return base32Decode(secret).isNotEmpty ? secret : null;
}

bool _missing(Object? v) => v == null || v == '';

String? _algorithmOf(Object? v) {
  if (_missing(v)) return 'SHA1';
  final name = _jsString(v).toUpperCase().replaceFirst('-', '');
  return _algorithms.contains(name) ? name : null;
}

int? _digitsOf(Object? v) {
  final digits = _missing(v) ? 6.0 : _jsNumber(v);
  return digits == 6 || digits == 8 ? digits.toInt() : null;
}

int? _periodOf(Object? v) {
  final period = _missing(v) ? 30.0 : _jsNumber(v);
  return _isInteger(period) && period > 0 ? period.toInt() : null;
}

int? _counterOf(Object? v) {
  final counter = _missing(v) ? 0.0 : _jsNumber(v);
  return _isSafeInteger(counter) && counter >= 0 ? counter.toInt() : null;
}

typedef _OtpFields = ({OtpType type, String secret, String algorithm, int digits, int period, int? counter});

/// The code parameters of an Aegis or 2FAS entry, or null when this app can't generate them.
_OtpFields? _otpFields({
  required String type,
  required Object? secret,
  required Object? algorithm,
  required Object? digits,
  required Object? period,
  required Object? counter,
}) {
  final base32 = _secretOf(secret);
  if (base32 == null) return null;
  final kind = type.toLowerCase();
  if (kind == 'steam') {
    final seconds = _periodOf(period);
    if (seconds == null) return null;
    return (type: OtpType.steam, secret: base32, algorithm: 'SHA1', digits: 6, period: seconds, counter: null);
  }

  final hash = _algorithmOf(algorithm);
  final length = _digitsOf(digits);
  if (hash == null || length == null) return null;
  if (kind == 'hotp') {
    final count = _counterOf(counter);
    if (count == null) return null;
    return (type: OtpType.hotp, secret: base32, algorithm: hash, digits: length, period: 30, counter: count);
  }
  final seconds = _periodOf(period);
  if (kind != 'totp' || seconds == null) return null;
  return (type: OtpType.totp, secret: base32, algorithm: hash, digits: length, period: seconds, counter: null);
}

/// Tags trimmed, without blanks or repeats; null when none are left, so the field is left out.
List<String>? _tags(List<String> tags) {
  final unique = {
    for (final tag in tags)
      if (_jsTrim(tag).isNotEmpty) _jsTrim(tag),
  };
  return unique.isEmpty ? null : unique.toList();
}

/// A new account from an entry's code parameters, with the optional fields left out when empty.
OtpAccount _newAccount(
  _OtpFields otp, {
  required String issuer,
  required String label,
  Object? note,
  bool pinned = false,
  List<String> tags = const [],
}) => OtpAccount(
  id: '',
  type: otp.type,
  issuer: issuer,
  label: label,
  secret: otp.secret,
  algorithm: otp.algorithm,
  digits: otp.digits,
  period: otp.period,
  counter: otp.counter,
  note: _str(note).isEmpty ? null : _str(note),
  pinned: pinned ? true : null,
  tags: _tags(tags),
  addedAt: 0,
);

/// "Google:alice@example.com" → "alice@example.com" when the issuer is Google.
String _stripIssuer(String name, String issuer) =>
    issuer.isNotEmpty && name.startsWith('$issuer:') ? _jsTrim(name.substring(issuer.length + 1)) : name;

/// Group or folder id → name.
Map<String, String> _namesById(Object? v, String idKey) => {
  for (final group in _list(v))
    if (group is _Json && _str(group[idKey]).isNotEmpty) _str(group[idKey]): _str(group['name']),
};

// ─── Crypto helpers ──────────────────────────────────────────────────────────

final _jsSpace = RegExp(r'\s');

/// Base64 in either alphabet, with or without padding, read as `atob` reads it.
Uint8List _fromBase64(String s) {
  final b64 = s.replaceAll(_jsSpace, '').replaceAll('-', '+').replaceAll('_', '/');
  return _atob(b64.padRight((b64.length / 4).ceil() * 4, '='));
}

final _asciiSpace = RegExp('[\t\n\f\r ]');
final _base64Alphabet = RegExp(r'^[A-Za-z0-9+/]*$');

/// The browser's `atob` (forgiving base64), which, unlike `unb64` in
/// lib/crypto, ignores bits past the last whole byte instead of refusing them.
Uint8List _atob(String input) {
  var data = input.replaceAll(_asciiSpace, '');
  if (data.length % 4 == 0 && data.endsWith('=')) {
    data = data.substring(0, data.length - (data.endsWith('==') ? 2 : 1));
  }
  if (data.length % 4 == 1 || !_base64Alphabet.hasMatch(data)) throw FormatException('Invalid base64', input);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final out = Uint8List(data.length * 6 ~/ 8);
  var buffer = 0;
  var bits = 0;
  var index = 0;
  for (var i = 0; i < data.length; i++) {
    buffer = (buffer << 6 | alphabet.indexOf(data[i])) & 0xffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = buffer >> bits & 0xff;
    }
  }
  return out;
}

/// noble's `hexToBytes`, for anything: a value that isn't a string reads as ''.
Uint8List _hex(Object? v) {
  final text = v is String ? v : '';
  if (text.length.isOdd) throw FormatException('Unpadded hex', text);
  final out = Uint8List(text.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final high = _hexValue(text.codeUnitAt(2 * i));
    final low = _hexValue(text.codeUnitAt(2 * i + 1));
    if (high < 0 || low < 0) throw FormatException('Invalid hex', text, 2 * i);
    out[i] = high << 4 | low;
  }
  return out;
}

const _tagLength = 16;

/// AES-GCM as WebCrypto decrypts it: [data] is the ciphertext with the
/// 16-byte tag appended, and the key may be 128, 192 or 256 bits. Aegis's
/// master key comes out of the file, so it isn't always 256 bits like the
/// keys `aesGcmDecrypt` in lib/crypto takes. Throws when the key or nonce
/// can't be used or the tag doesn't verify.
Future<Uint8List> _aesGcmDecrypt(List<int> key, List<int> nonce, List<int> data) async {
  final cipher = switch (key.length) {
    16 => AesGcm.with128bits(),
    24 => AesGcm.with192bits(),
    32 => AesGcm.with256bits(),
    _ => throw ArgumentError.value(key.length, 'key', 'AES needs a 128, 192 or 256-bit key'),
  };
  if (nonce.isEmpty) throw ArgumentError.value(nonce.length, 'nonce', 'must not be empty');
  if (data.length < _tagLength) throw ArgumentError.value(data.length, 'data', 'too short for the tag');
  final split = data.length - _tagLength;
  final box = SecretBox(data.sublist(0, split), nonce: List<int>.of(nonce), mac: Mac(data.sublist(split)));
  return Uint8List.fromList(await cipher.decrypt(box, secretKey: SecretKeyData(List<int>.of(key))));
}

/// `TextDecoder` drops a leading byte order mark and replaces bad UTF-8, as `utf8.decode` does here.
Object? _parseJsonBytes(List<int> bytes) => _parseJson(utf8.decode(bytes, allowMalformed: true));

// ─── Google Authenticator ────────────────────────────────────────────────────

/// Field number → values: varints as numbers, length-delimited fields as bytes.
typedef _ProtoFields = Map<int, List<Object>>;

/// Decodes one protobuf message. Varints are added up in doubles, as the
/// TypeScript does, so values past 2^53 round the same way. Fixed-width
/// fields are skipped. Throws a [FormatException] on bad input.
_ProtoFields _decodeProto(Uint8List buf) {
  final fields = <int, List<Object>>{};
  var pos = 0;
  double varint() {
    var value = 0.0;
    var scale = 1.0;
    for (var shift = 0; shift < 70; shift += 7, scale *= 128) {
      if (pos >= buf.length) break;
      final byte = buf[pos++];
      value += (byte & 0x7f) * scale;
      if (byte < 0x80) return value;
    }
    throw const FormatException('Bad varint');
  }

  while (pos < buf.length) {
    final key = varint();
    final wireType = key % 8;
    Object? value;
    if (wireType == 0) {
      value = varint();
    } else if (wireType == 1) {
      pos += 8;
    } else if (wireType == 5) {
      pos += 4;
    } else if (wireType == 2) {
      final length = varint();
      if (length > buf.length - pos) throw const FormatException('Truncated message');
      value = Uint8List.sublistView(buf, pos, pos + length.toInt());
      pos += length.toInt();
    } else {
      throw FormatException('Unsupported wire type $wireType');
    }
    if (pos > buf.length) throw const FormatException('Truncated message');

    if (value == null) continue;
    // Only fields 1 to 7 are read, so a huge number landing on the largest int doesn't matter
    (fields[(key / 8).floor()] ??= []).add(value);
  }
  return fields;
}

/// The last value wins for a non-repeated protobuf field.
double _protoInt(_ProtoFields fields, int no) => switch (fields[no]?.last) {
  final double value => value,
  _ => 0,
};

Uint8List _protoBytes(_ProtoFields fields, int no) => switch (fields[no]?.last) {
  final Uint8List value => value,
  _ => Uint8List(0),
};

String _protoString(_ProtoFields fields, int no) => _jsTrim(utf8.decode(_protoBytes(fields, no), allowMalformed: true));

// Indexed by the enum values of Google's migration.proto; MD5 (4) is left out
const _googleAlgorithms = ['SHA1', 'SHA1', 'SHA256', 'SHA512'];
const _googleDigits = [6, 6, 8];
const _googleTypes = [OtpType.totp, OtpType.hotp, OtpType.totp];

T? _enumAt<T>(List<T> values, double index) => index < values.length ? values[index.toInt()] : null;

OtpAccount? _googleAccount(_ProtoFields otp) {
  final secretBytes = _protoBytes(otp, 1);
  final algorithm = _enumAt(_googleAlgorithms, _protoInt(otp, 4));
  final digits = _enumAt(_googleDigits, _protoInt(otp, 5));
  final type = _enumAt(_googleTypes, _protoInt(otp, 6));
  if (secretBytes.isEmpty || algorithm == null || digits == null || type == null) return null;

  final name = _protoString(otp, 2);
  var issuer = _protoString(otp, 3);
  var label = _stripIssuer(name, issuer);
  final colon = name.indexOf(':');
  if (issuer.isEmpty && colon >= 0) {
    issuer = _jsTrim(name.substring(0, colon));
    label = _jsTrim(name.substring(colon + 1));
  }

  int? counter;
  if (type == OtpType.hotp) {
    final value = _protoInt(otp, 7);
    if (!_isSafeInteger(value)) return null;
    counter = value.toInt();
  }
  return OtpAccount(
    id: '',
    type: type,
    issuer: issuer,
    label: label,
    secret: base32Encode(secretBytes),
    algorithm: algorithm,
    digits: digits,
    counter: counter,
    addedAt: 0,
  );
}

/// One Google Authenticator "Transfer accounts" QR payload
/// (otpauth-migration://offline?data=…). Null if it isn't one or is malformed.
ForeignImport? parseGoogleMigration(String uri) {
  final query = _migrationQuery(_jsTrim(uri));
  if (query == null) return null;
  final data = _searchParam(query, 'data');
  if (data == null || data.isEmpty) return null;
  try {
    // The query reads an unescaped '+' as a space
    final payload = _decodeProto(_fromBase64(data.replaceAll(' ', '+')));
    return _tally(ImportSource.google, [
      for (final otp in payload[1] ?? const <Object>[]) otp is Uint8List ? _googleAccount(_decodeProto(otp)) : null,
    ]);
  } on FormatException {
    return null;
  }
}

// ─── Plain text list of URIs ─────────────────────────────────────────────────

ForeignImport _parseUriList(String text, ImportSource source) {
  final accounts = <OtpAccount>[];
  var skipped = 0;
  for (final line in _uriLines(text)) {
    if (_migrationLine.hasMatch(line)) {
      final batch = parseGoogleMigration(line);
      if (batch == null) {
        skipped++;
      } else {
        accounts.addAll(batch.accounts);
        skipped += batch.skipped;
      }
    } else {
      final account = parseOtpUri(line);
      if (account == null) {
        skipped++;
      } else {
        accounts.add(account);
      }
    }
  }
  return ForeignImport(source: source, accounts: accounts, skipped: skipped);
}

// ─── Aegis ───────────────────────────────────────────────────────────────────

const _aegisPasswordSlot = 1;

// The file sets its own scrypt cost; a crafted one could ask for gigabytes of memory.
// Aegis itself uses N=2^15, r=8, p=1: four times that N is 128 MB, the most a slot is given.
bool _sensibleScrypt(_Json slot) => _jsNumber(slot['n']) <= (1 << 17) && _jsNumber(slot['r']) <= 8 && _jsNumber(slot['p']) <= 4;

/// The most password slots tried: each costs a scrypt run, and a file can list any number of them.
const _maxAegisSlots = 8;

/// A scrypt cost as noble takes it: a whole number from 0 up; the derivation checks the rest.
int _scryptParam(Object? v) {
  final value = _jsNumber(v);
  if (!_isSafeInteger(value) || value < 0) throw ArgumentError.value(v, 'scrypt parameter');
  return value.toInt();
}

Future<Object?> _decryptAegis(_Json json, String password) async {
  final header = _object(json['header']);
  Uint8List? masterKey;
  var tried = 0;
  for (final slot in _list(header['slots'])) {
    if (slot is! _Json || slot['type'] != _aegisPasswordSlot || !_sensibleScrypt(slot)) continue;
    if (++tried > _maxAegisSlots) break;
    final keyParams = _object(slot['key_params']);
    try {
      final derived = await scryptInBackground(
        utf8.encode(password),
        _hex(slot['salt']),
        n: _scryptParam(slot['n']),
        r: _scryptParam(slot['r']),
        p: _scryptParam(slot['p']),
      );
      masterKey = await _aesGcmDecrypt(derived, _hex(keyParams['nonce']), concatBytes([_hex(slot['key']), _hex(keyParams['tag'])]));
      break;
    } catch (_) {
      // Not this slot's password
    }
  }
  if (masterKey == null) throw const ImportError(ImportErrorCode.badPassword);

  final params = _object(header['params']);
  Uint8List plain;
  try {
    final data = concatBytes([_fromBase64(json['db']! as String), _hex(params['tag'])]);
    plain = await _aesGcmDecrypt(masterKey, _hex(params['nonce']), data);
  } catch (_) {
    throw const ImportError(ImportErrorCode.badPassword);
  }
  return _parseJsonBytes(plain);
}

OtpAccount? _aegisAccount(_Json entry, Map<String, String> groups) {
  final info = _object(entry['info']);
  final otp = _otpFields(
    type: _str(entry['type']),
    secret: info['secret'],
    algorithm: info['algo'],
    digits: info['digits'],
    period: info['period'],
    counter: info['counter'],
  );
  if (otp == null) return null;
  // Vaults before groups were introduced store one group name per entry
  final tags = [for (final id in _list(entry['groups'])) groups[_str(id)] ?? '', _str(entry['group'])];
  return _newAccount(
    otp,
    issuer: _str(entry['issuer']),
    label: _str(entry['name']),
    note: entry['note'],
    pinned: entry['favorite'] == true,
    tags: tags,
  );
}

Future<ForeignImport> _parseAegis(_Json json, String password) async {
  final db = json['db'] is String ? await _decryptAegis(json, password) : json['db'];
  if (db is! _Json) throw const ImportError(ImportErrorCode.unsupported);
  final groups = _namesById(db['groups'], 'uuid');
  return _tally(ImportSource.aegis, [for (final entry in _list(db['entries'])) entry is _Json ? _aegisAccount(entry, groups) : null]);
}

// ─── 2FAS ────────────────────────────────────────────────────────────────────

Future<Object?> _decrypt2fas(String blob, String password) async {
  final parts = blob.split(':');
  if (parts.length != 3) throw const ImportError(ImportErrorCode.unsupported);
  final [data, salt, iv] = parts;
  Uint8List plain;
  try {
    final key = await pbkdf2Sha256InBackground(utf8.encode(password), _fromBase64(salt), 10000, 32);
    plain = await _aesGcmDecrypt(key, _fromBase64(iv), _fromBase64(data));
  } catch (_) {
    throw const ImportError(ImportErrorCode.badPassword);
  }
  return _parseJsonBytes(plain);
}

OtpAccount? _twoFasAccount(_Json service, Map<String, String> groups) {
  final otp = _object(service['otp']);
  final tokenType = _str(otp['tokenType']);
  final fields = _otpFields(
    type: tokenType.isEmpty ? 'TOTP' : tokenType,
    secret: service['secret'],
    algorithm: otp['algorithm'],
    digits: otp['digits'],
    period: otp['period'],
    counter: otp['counter'],
  );
  if (fields == null) return null;
  final issuer = _str(otp['issuer']).isEmpty ? _str(service['name']) : _str(otp['issuer']);
  final account = _str(otp['account']);
  final label = account.isEmpty ? _stripIssuer(_str(otp['label']), issuer) : account;
  final group = groups[_str(service['groupId'])];
  return _newAccount(fields, issuer: issuer, label: label, tags: [?group]);
}

/// The service's place in the app's list; services without one go last.
double _position(Object? service) => switch (service) {
  {'order': {'position': final num position}} => position.toDouble(),
  _ => _maxSafeInteger.toDouble(),
};

Future<ForeignImport> _parse2fas(_Json json, String password) async {
  final services = _is2fasEncrypted(json) ? await _decrypt2fas(json['servicesEncrypted']! as String, password) : json['services'];
  if (services is! List<Object?>) throw const ImportError(ImportErrorCode.unsupported);
  final groups = _namesById(json['groups'], 'id');
  // A stable sort, as JavaScript's is
  final sorted = [...services];
  mergeSort(sorted, compare: (a, b) => _sign(_position(a) - _position(b)));
  return _tally(ImportSource.twoFas, [for (final service in sorted) service is _Json ? _twoFasAccount(service, groups) : null]);
}

// ─── Bitwarden ───────────────────────────────────────────────────────────────

OtpAccount? _bitwardenAccount(String totp, String name, String username, String? folder) {
  final tags = _tags([?folder]);
  return parseBitwardenTotp(totp, name: name, username: username)?.copyWith(tags: tags ?? keep);
}

ForeignImport _parseBitwarden(_Json json) {
  final folders = _namesById(json['folders'], 'id');
  final entries = <OtpAccount?>[];
  final passkeys = <Passkey?>[];
  for (final item in _list(json['items'])) {
    if (item is! _Json) continue;
    final login = _object(item['login']);
    for (final credential in _list(login['fido2Credentials'])) {
      passkeys.add(credential is _Json ? _bitwardenPasskey(credential) : null);
    }
    final totp = _str(login['totp']);
    if (totp.isEmpty) continue;
    entries.add(_bitwardenAccount(totp, _str(item['name']), _str(login['username']), folders[_str(item['folderId'])]));
  }
  final tally = _tally(ImportSource.bitwarden, entries);
  final readable = passkeys.nonNulls.toList();
  return ForeignImport(
    source: ImportSource.bitwarden,
    accounts: tally.accounts,
    skipped: tally.skipped + passkeys.length - readable.length,
    passkeys: readable,
  );
}

final _guid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');

/// A passkey Bitwarden keeps in a login's `fido2Credentials`, or null for
/// one Kemlock can't use: anything but an ES256 key, or one missing what
/// signing in needs. Bitwarden writes a 16-byte credential id as a GUID and
/// any other as `b64.` and base64url; the key is PKCS#8 in base64url.
Passkey? _bitwardenPasskey(_Json credential) {
  if (_str(credential['keyType']) != 'public-key' ||
      _str(credential['keyAlgorithm']) != 'ECDSA' ||
      _str(credential['keyCurve']) != 'P-256') {
    return null;
  }
  try {
    final rawId = _str(credential['credentialId']);
    final Uint8List id;
    if (rawId.startsWith('b64.')) {
      id = unb64url(rawId.substring(4));
    } else if (_guid.hasMatch(rawId)) {
      id = _hex(rawId.replaceAll('-', ''));
    } else {
      return null;
    }
    final key = unb64url(_str(credential['keyValue']));
    final rpId = _str(credential['rpId']).toLowerCase();
    final userHandle = unb64url(_str(credential['userHandle']));
    if (id.isEmpty || key.isEmpty || rpId.isEmpty || userHandle.isEmpty) return null;
    final rpName = _str(credential['rpName']);
    final displayName = _str(credential['userDisplayName']);
    return Passkey(
      id: '',
      credentialId: b64url(id),
      rpId: rpId,
      rpName: rpName.isEmpty ? null : rpName,
      userHandle: b64url(userHandle),
      userName: _str(credential['userName']),
      userDisplayName: displayName.isEmpty ? null : displayName,
      privateKey: b64(key),
      addedAt: DateTime.tryParse(_str(credential['creationDate']))?.millisecondsSinceEpoch ?? 0,
    );
  } on FormatException {
    return null;
  }
}

// ─── JavaScript's coercions ──────────────────────────────────────────────────

final _edgeSpace = RegExp(r'^\s+|\s+$');

/// JavaScript's `trim()`. Dart's also trims U+0085, which JavaScript keeps.
String _jsTrim(String text) => text.replaceAll(_edgeSpace, '');

/// JavaScript's `String(v)` for a JSON value. Numbers are written as Dart
/// writes them, which [_jsNumber] reads back as the same number.
String _jsString(Object? v) => switch (v) {
  null => 'null',
  final String text => text,
  final List<Object?> list => list.map((item) => item == null ? '' : _jsString(item)).join(','),
  Map<Object?, Object?>() => '[object Object]',
  _ => '$v',
};

/// JavaScript's `Number(v)` for a JSON value.
double _jsNumber(Object? v) => switch (v) {
  null => 0,
  final bool flag => flag ? 1 : 0,
  final num number => number.toDouble(),
  final String text => _stringToNumber(text),
  final List<Object?> list => _stringToNumber(_jsString(list)),
  _ => double.nan,
};

final _decimalNumber = RegExp(r'^[+-]?(?:Infinity|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)$');
final _radixNumber = RegExp(r'^0(?:[xX][0-9A-Fa-f]+|[oO][0-7]+|[bB][01]+)$');

/// JavaScript's `Number(text)`: trimmed, '' is 0, 0x, 0o and 0b prefixes without a sign, and NaN for anything else.
double _stringToNumber(String text) {
  final s = _jsTrim(text);
  if (s.isEmpty) return 0;
  if (_radixNumber.hasMatch(s)) {
    final radix = switch (s[1]) {
      'x' || 'X' => 16,
      'o' || 'O' => 8,
      _ => 2,
    };
    return BigInt.parse(s.substring(2), radix: radix).toDouble();
  }
  if (!_decimalNumber.hasMatch(s)) return double.nan;
  if (s.endsWith('Infinity')) return s.startsWith('-') ? double.negativeInfinity : double.infinity;
  return double.parse(s);
}

bool _isInteger(double value) => value.isFinite && value == value.truncateToDouble();

/// JavaScript's `Number.MAX_SAFE_INTEGER`, 2^53 - 1.
const _maxSafeInteger = 9007199254740991;

bool _isSafeInteger(double value) => _isInteger(value) && value.abs() <= _maxSafeInteger;

/// A JavaScript sort comparator's result, where NaN counts as equal.
int _sign(double value) => value < 0
    ? -1
    : value > 0
    ? 1
    : 0;

int _hexValue(int unit) => switch (unit) {
  >= 0x30 && <= 0x39 => unit - 0x30,
  >= 0x41 && <= 0x46 => unit - 0x37,
  >= 0x61 && <= 0x66 => unit - 0x57,
  _ => -1,
};

// ─── The WHATWG URL parser, as far as `new URL(uri)` needs it here ───────────

final _urlEdges = RegExp(r'^[\x00-\x20]+|[\x00-\x20]+$');
final _tabOrNewline = RegExp('[\t\n\r]');
final _urlScheme = RegExp(r'^([A-Za-z][A-Za-z0-9+.\-]*):');
final _forbiddenHostCodePoint = RegExp(r'[\x00\t\n\r #/:<>?@\[\\\]^|]');
final _digits = RegExp(r'^\d*$');

/// The raw query of an otpauth-migration: URL, the way `new URL(uri)` splits
/// it. Null for another scheme, no query, or a URL the parser refuses: a bad
/// host or port in the authority is all that can fail for this scheme.
String? _migrationQuery(String uri) {
  final text = uri.replaceAll(_urlEdges, '').replaceAll(_tabOrNewline, '');
  final scheme = _urlScheme.firstMatch(text);
  if (scheme == null || scheme[1]!.toLowerCase() != 'otpauth-migration') return null;
  var rest = text.substring(scheme.end);
  final hash = rest.indexOf('#');
  if (hash >= 0) rest = rest.substring(0, hash);
  final question = rest.indexOf('?');
  final beforeQuery = question < 0 ? rest : rest.substring(0, question);
  if (beforeQuery.startsWith('//') && !_validAuthority(beforeQuery.substring(2).split('/').first)) return null;
  return question < 0 ? null : rest.substring(question + 1);
}

bool _validAuthority(String authority) {
  final at = authority.lastIndexOf('@');
  final hostAndPort = authority.substring(at + 1);
  if (at >= 0 && hostAndPort.isEmpty) return false;
  // The port starts at the first colon outside brackets
  var colon = -1;
  var insideBrackets = false;
  for (var i = 0; i < hostAndPort.length && colon < 0; i++) {
    switch (hostAndPort[i]) {
      case '[':
        insideBrackets = true;
      case ']':
        insideBrackets = false;
      case ':' when !insideBrackets:
        colon = i;
    }
  }
  if (colon < 0) return _validHost(hostAndPort);
  final port = hostAndPort.substring(colon + 1).replaceFirst(RegExp('^0+'), '');
  if (colon == 0 || !_digits.hasMatch(port) || port.length > 5 || (port.isNotEmpty && int.parse(port) > 65535)) return false;
  return _validHost(hostAndPort.substring(0, colon));
}

/// An opaque host, or an IPv6 address in brackets; an empty host is fine for this scheme.
bool _validHost(String host) {
  if (host.startsWith('[')) return host.endsWith(']') && _validIpv6(host.substring(1, host.length - 1));
  return !host.contains(_forbiddenHostCodePoint);
}

/// Whether the WHATWG IPv6 parser accepts [input].
bool _validIpv6(String input) {
  final units = input.codeUnits;
  int at(int i) => i < units.length ? units[i] : -1;
  bool isDigit(int unit) => unit >= 0x30 && unit <= 0x39;
  const colon = 0x3a;
  var pieceIndex = 0;
  var compressed = false;
  var p = 0;
  if (at(p) == colon) {
    if (at(p + 1) != colon) return false;
    p += 2;
    pieceIndex++;
    compressed = true;
  }
  while (at(p) != -1) {
    if (pieceIndex == 8) return false;
    if (at(p) == colon) {
      if (compressed) return false;
      p++;
      pieceIndex++;
      compressed = true;
      continue;
    }
    var length = 0;
    while (length < 4 && _hexValue(at(p)) >= 0) {
      p++;
      length++;
    }
    if (at(p) == 0x2e) {
      // An IPv4 address in the last 32 bits
      if (length == 0 || pieceIndex > 6) return false;
      p -= length;
      var numbersSeen = 0;
      while (at(p) != -1) {
        if (numbersSeen > 0) {
          if (at(p) != 0x2e || numbersSeen >= 4) return false;
          p++;
        }
        if (!isDigit(at(p))) return false;
        int? piece;
        while (isDigit(at(p))) {
          final number = at(p) - 0x30;
          if (piece == 0) return false;
          piece = (piece ?? 0) * 10 + number;
          if (piece > 255) return false;
          p++;
        }
        numbersSeen++;
        if (numbersSeen == 2 || numbersSeen == 4) pieceIndex++;
      }
      return numbersSeen == 4 && (compressed || pieceIndex == 8);
    }
    if (at(p) == colon) {
      p++;
      if (at(p) == -1) return false;
    } else if (at(p) != -1) {
      return false;
    }
    pieceIndex++;
  }
  return compressed || pieceIndex == 8;
}

/// The first value of [name] in a raw query, as `URLSearchParams.get` reads it.
String? _searchParam(String query, String name) {
  for (final pair in query.split('&')) {
    if (pair.isEmpty) continue;
    final equals = pair.indexOf('=');
    if (_formDecode(equals < 0 ? pair : pair.substring(0, equals)) == name) {
      return _formDecode(equals < 0 ? '' : pair.substring(equals + 1));
    }
  }
  return null;
}

/// application/x-www-form-urlencoded decoding, which never fails: '+' is a
/// space, a '%' that doesn't start an escape stays, and bytes that aren't
/// UTF-8 become U+FFFD.
String _formDecode(String text) {
  final bytes = utf8.encode(text);
  final out = <int>[];
  for (var i = 0; i < bytes.length; i++) {
    final byte = bytes[i];
    if (byte == 0x2b) {
      out.add(0x20);
    } else if (byte == 0x25 && i + 2 < bytes.length && _hexValue(bytes[i + 1]) >= 0 && _hexValue(bytes[i + 2]) >= 0) {
      out.add(_hexValue(bytes[i + 1]) << 4 | _hexValue(bytes[i + 2]));
      i += 2;
    } else {
      out.add(byte);
    }
  }
  // utf8.decode drops a leading byte order mark, which the URL parser keeps
  return utf8.decode([0x20, ...out], allowMalformed: true).substring(1);
}
