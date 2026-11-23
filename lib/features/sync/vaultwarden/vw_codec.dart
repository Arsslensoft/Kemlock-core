/// Reading Kemlock's entries out of Vaultwarden items, and writing them back.
///
/// [VwReader] goes through a vault's items as `/api/sync` gives them and
/// finds the homes, and one home's entries: sealed or plain, made by Kemlock
/// or linked to the user's own login, or (plain, if asked) picked up from a
/// login that has a code and no home. It decrypts as little as it can, and
/// keeps what it decrypted by item and revision, so the next sync only
/// decrypts what changed.
///
/// [VwWriter] makes new items and changes existing ones. A change never
/// rebuilds an item: it starts from the item exactly as the server gave it
/// and replaces only the values Kemlock owns, so passwords, websites,
/// password history, passkeys, attachments and other apps' fields go back as
/// they were, never decrypted.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';

import '../../../core/websites.dart';
import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../models/backup_service.dart';
import '../../../models/json.dart';
import '../../../models/otp_account.dart';
import '../../../models/passkey.dart';
import '../../../models/vault_key.dart';
import '../../../models/website_rule.dart';
import '../../accounts/otpauth.dart';
import 'vw_formats.dart';
import 'vw_items.dart';
import 'vw_models.dart';

/// Bitwarden's item types.
abstract final class CipherType {
  static const login = 1;
  static const secureNote = 2;
  static const sshKey = sshKeyCipherType;
}

/// An item as `/api/sync` gives it, still encrypted.
class VwCipher {
  VwCipher(this.json);

  final Map<String, Object?> json;

  String get id => json['id']! as String;
  int get type => (json['type'] as num?)?.toInt() ?? 0;
  String? get organizationId => json['organizationId'] as String?;
  String? get folderId => json['folderId'] as String?;

  /// As the server wrote it, to send back as `lastKnownRevisionDate`.
  String get revisionDate => json['revisionDate']! as String;
  int get revisionMs => _ms(json['revisionDate']) ?? 0;
  int get createdMs => _ms(json['creationDate']) ?? revisionMs;

  /// When it went to the trash, or null.
  int? get deletedMs => _ms(json['deletedDate']);
  bool get inTrash => json['deletedDate'] != null;

  /// The item's own key, encrypted with the user key, when it has one.
  String? get key => json['key'] as String?;
  int get reprompt => (json['reprompt'] as num?)?.toInt() ?? 0;

  List<Map<String, Object?>> get fields => [...?(json['fields'] as List<Object?>?)?.whereType<Map<String, Object?>>()];
  Map<String, Object?>? get login => json['login'] as Map<String, Object?>?;

  @override
  String toString() => 'VwCipher($id, type $type)';
}

int? _ms(Object? date) => date is String ? DateTime.tryParse(date)?.millisecondsSinceEpoch : null;

/// What one of Kemlock's items is.
sealed class Claim {
  const Claim(this.cipher);

  final VwCipher cipher;
}

/// A home note.
class HomeClaim extends Claim {
  const HomeClaim(super.cipher, this.home);

  final HomeNote home;
}

/// An entry of the home being synced.
class EntryClaim extends Claim {
  const EntryClaim(
    super.cipher, {
    required this.id,
    required this.kind,
    required this.form,
    required this.own,
    this.entry,
    this.removedAt,
    this.pickedUp = false,
    this.unreadable = false,
    this.fieldIndex,
  });

  /// The entry's id.
  final String id;
  final EntryKind kind;

  /// How the item keeps it.
  final VaultwardenMode form;

  /// Whether Kemlock made the item, and so may trash it. False for a linked
  /// or picked-up login, of which only the code is Kemlock's.
  final bool own;

  /// The entry, or null when the item no longer holds it ([removedAt]) or it
  /// can't be read ([unreadable]).
  final Object? entry;

  /// When its code was removed in Bitwarden: a deletion.
  final int? removedAt;

  /// A login with a code but no home, shown because the user asked to.
  final bool pickedUp;

  /// Kemlock can't read it: left alone, and out of the merge.
  final bool unreadable;

  /// Where the `Kemlock` field is in the item's fields; null for a picked-up login.
  final int? fieldIndex;

  @override
  String toString() => 'EntryClaim($id, ${cipher.id}, ${form.name}${own ? ', own' : ''}${unreadable ? ', unreadable' : ''})';
}

/// What a read found.
class VwRead {
  const VwRead({required this.homes, required this.entries, required this.counts, required this.foreign, this.fielded = const {}});

  /// Every home note in the vault.
  final List<HomeClaim> homes;

  /// The entries of the home read, in the vault's order.
  final List<EntryClaim> entries;

  /// How many items each home has, by home id, for setup's list.
  final Map<String, int> counts;

  /// Logins with a code that no home claims, for setup to offer picking up.
  final int foreign;

  /// The ids of every item with a `Kemlock` field, of any home.
  final Set<String> fielded;
}

/// The key a cipher's values are encrypted with: its own, or the user key.
Future<BwKey> cipherKey(VwCipher cipher, BwKey userKey) async {
  final own = cipher.key;
  return own == null ? userKey : bwOpenCipherKey(own, userKey);
}

Future<String?> _open(Object? value, BwKey key) async => value is String ? bwDecryptString(value, key) : null;

/// One of an item's `login.uris`: the entry as the server gave it, its address
/// decrypted (null when it doesn't open) and its rule number.
typedef _OpenUri = ({Object? raw, String? uri, int? match});

/// [list], an item's `login.uris`, with each address decrypted with [key].
Future<List<_OpenUri>> _openUris(Object? list, BwKey key) async {
  if (list is! List<Object?>) return [];
  return [
    for (final item in list)
      if (item is Map<String, Object?>)
        (raw: item, uri: await _open(item['uri'], key).catchError((Object _) => null), match: (item['match'] as num?)?.toInt())
      else
        (raw: item, uri: null, match: null),
  ];
}

/// The id a picked-up login's entry has, the same on every phone.
String pickedUpId(String cipherId) => 'vw-$cipherId';

class _Scan {
  const _Scan({this.field, this.fieldIndex, this.totp, this.name, this.username});

  /// The `Kemlock` field's value, decrypted.
  final String? field;
  final int? fieldIndex;

  /// A login's code, name and username, decrypted when it has no field.
  final String? totp;
  final String? name;
  final String? username;
}

/// Reads Kemlock's items out of a vault for one account, keeping what it
/// decrypted for the next read.
class VwReader {
  VwReader(this.userKey);

  final BwKey userKey;
  final _scans = <String, ({String revision, _Scan scan})>{};

  /// Finds the homes and, when [home] is given, its entries. Sealed entries
  /// open with [sealKey]; without it they read as unreadable. With [pickUp],
  /// logins with a code and no home are entries too.
  Future<VwRead> read(List<VwCipher> ciphers, {String? home, Uint8List? sealKey, bool pickUp = false}) async {
    final homes = <HomeClaim>[];
    final entries = <EntryClaim>[];
    final counts = <String, int>{};
    var foreign = 0;
    final seen = <String>{};
    final fielded = <String>{};
    for (final cipher in ciphers) {
      // Organizations' items need RSA, which sync doesn't do yet
      if (cipher.organizationId != null) continue;
      seen.add(cipher.id);
      final _Scan scan;
      try {
        scan = await _scan(cipher);
      } on BwCryptoError {
        continue;
      }
      final field = scan.field;
      if (field != null) fielded.add(cipher.id);
      if (field == null) {
        if (scan.totp == null || cipher.type != CipherType.login) continue;
        if (!cipher.inTrash) foreign++;
        if (!pickUp || home == null) continue;
        final account = parseBitwardenTotp(scan.totp!, name: scan.name ?? '', username: scan.username ?? '');
        if (account == null) continue;
        entries.add(
          EntryClaim(
            cipher,
            id: pickedUpId(cipher.id),
            kind: EntryKind.account,
            form: VaultwardenMode.plain,
            own: false,
            pickedUp: true,
            entry: account.copyWith(id: pickedUpId(cipher.id), addedAt: cipher.createdMs, updatedAt: cipher.revisionMs),
          ),
        );
        continue;
      }

      if (HomeNote.tryParse(field) case final note?) {
        homes.add(HomeClaim(cipher, note));
        continue;
      }
      if (sealedHeader(field) case final header?) {
        counts[header.home] = (counts[header.home] ?? 0) + 1;
        if (header.home != home) continue;
        entries.add(await _sealed(cipher, field, header.id, sealKey, scan.fieldIndex!));
        continue;
      }
      if (PlainField.tryParse(field) case final plain?) {
        counts[plain.home] = (counts[plain.home] ?? 0) + 1;
        if (plain.home != home) continue;
        entries.add(await _plain(cipher, plain, scan.fieldIndex!));
      } else if (plainHeader(field) case final header?) {
        // A kind or version this build doesn't know: left alone, never taken for a deletion
        counts[header.home] = (counts[header.home] ?? 0) + 1;
        if (header.home != home) continue;
        entries.add(
          EntryClaim(
            cipher,
            id: header.id,
            kind: EntryKind.account,
            form: VaultwardenMode.plain,
            own: false,
            unreadable: true,
            fieldIndex: scan.fieldIndex,
          ),
        );
      }
    }
    _scans.removeWhere((id, _) => !seen.contains(id));
    return VwRead(homes: homes, entries: entries, counts: counts, foreign: foreign, fielded: fielded);
  }

  Future<_Scan> _scan(VwCipher cipher) async {
    final cached = _scans[cipher.id];
    if (cached != null && cached.revision == cipher.revisionDate) return cached.scan;
    final key = await cipherKey(cipher, userKey);
    _Scan scan = const _Scan();
    final fields = cipher.fields;
    for (var i = 0; i < fields.length; i++) {
      if (fields[i]['type'] != 1) continue;
      String? name;
      try {
        name = await _open(fields[i]['name'], key);
      } on BwCryptoError {
        continue;
      }
      if (name == fieldName) {
        scan = _Scan(field: await _open(fields[i]['value'], key), fieldIndex: i);
        break;
      }
    }
    if (scan.field == null && cipher.type == CipherType.login) {
      final login = cipher.login ?? const {};
      final totp = await _open(login['totp'], key);
      if (totp != null && totp.trim().isNotEmpty) {
        scan = _Scan(totp: totp, name: await _open(cipher.json['name'], key), username: await _open(login['username'], key));
      }
    }
    _scans[cipher.id] = (revision: cipher.revisionDate, scan: scan);
    return scan;
  }

  Future<EntryClaim> _sealed(VwCipher cipher, String field, String id, Uint8List? sealKey, int fieldIndex) async {
    Object? entry;
    if (sealKey != null) {
      try {
        entry = await openSealedEntry(field, sealKey);
      } on SealedEntryError {
        entry = null;
      }
    }
    return EntryClaim(
      cipher,
      id: id,
      kind: entry == null ? EntryKind.account : EntryKind.of(entry),
      form: VaultwardenMode.sealed,
      own: true,
      entry: entry,
      unreadable: entry == null,
      fieldIndex: fieldIndex,
    );
  }

  Future<EntryClaim> _plain(VwCipher cipher, PlainField plain, int fieldIndex) async {
    EntryClaim claim({Object? entry, int? removedAt, bool unreadable = false}) => EntryClaim(
      cipher,
      id: plain.id,
      kind: plain.kind,
      form: VaultwardenMode.plain,
      own: plain.own,
      entry: entry,
      removedAt: removedAt,
      unreadable: unreadable,
      fieldIndex: fieldIndex,
    );

    final key = await cipherKey(cipher, userKey);
    final at = cipher.revisionMs;
    if (plain.kind.isLater) {
      // A key, a note or a passkey: only in the item types Kemlock writes them as
      final sshItem = cipher.type == CipherType.sshKey;
      final fits = switch (plain.kind) {
        EntryKind.note => cipher.type == CipherType.secureNote,
        EntryKind.key => cipher.type == CipherType.secureNote || sshItem,
        EntryKind.contact => cipher.type == CipherType.secureNote,
        _ => cipher.type == CipherType.login,
      };
      final values = fits ? await _laterValues(cipher, key, plain.kind) : null;
      if (values == null) return claim(unreadable: true);
      // A passkey taken off its login in Bitwarden is a deletion, as a code taken off is
      if (plain.kind == EntryKind.passkey && !holdsPasskey(cipher.login)) return claim(removedAt: at);
      if (valuesSum(values) == plain.sum) return claim(entry: plain.entry);
      return claim(
        entry: laterEdited(plain.entry, values, at: at, sshItem: sshItem),
      );
    }
    final values = await _plainValues(cipher, key, plain);
    if (values == null) return claim(unreadable: true);
    if (valuesSum(values) == plain.sum) return claim(entry: await _takeInUris(plain, cipher, key, plain.entry, at));

    // Changed in Bitwarden: its values win, as of the item's revision
    switch (plain.entry) {
      case final BackupService service:
        final name = values['name'] as String? ?? '';
        final read = readBackupCodesText(values['notes'] as String? ?? '', service, at: at);
        final serviceName = name.endsWith(backupCodesSuffix) ? name.substring(0, name.length - backupCodesSuffix.length) : name;
        return claim(
          entry: read.copyWith(serviceName: serviceName.trim().isEmpty ? service.serviceName : serviceName, updatedAt: at),
        );
      case final OtpAccount account:
        var next = account;
        final totp = values['totp'] as String?;
        if (account.kind != OtpType.hotp || totp != null) {
          if (totp == null || totp.trim().isEmpty) return claim(removedAt: at);
          final parsed = parseBitwardenTotp(totp, name: account.issuer, username: account.label);
          if (parsed == null || parsed.kind == OtpType.hotp) return claim(unreadable: true);
          next = next.copyWith(
            type: parsed.kind == OtpType.totp && account.type == null ? keep : parsed.kind,
            secret: parsed.secret,
            algorithm: parsed.algorithm,
            digits: parsed.digits,
            period: parsed.period,
            counter: unset,
          );
        }
        if (plain.own) {
          final notes = values['notes'] as String?;
          next = next.copyWith(
            issuer: values['name'] as String? ?? account.issuer,
            label: values['username'] as String? ?? '',
            note: notes == null || notes.isEmpty ? unset : notes,
            pinned: values['favorite'] == true ? true : unset,
          );
        }
        return claim(entry: await _takeInUris(plain, cipher, key, next.copyWith(updatedAt: at), at));
    }
    return claim(unreadable: true);
  }

  /// [entry], the account of a plain item Kemlock made, with the websites a Bitwarden app
  /// gave its URIs (the add-cards-identities-and-websites plan, design decision 9). Only an
  /// item that carries the sum of its URIs ([PlainField.uriSum]) takes anything in: if the
  /// URIs after the first no longer add up to it, they were edited in another app, and they
  /// are the code's own websites now. An address that isn't a host stays only on Starts with,
  /// Exact and Regular expression. An item without the sum, or whose URIs don't open, takes
  /// nothing in.
  Future<Object> _takeInUris(PlainField plain, VwCipher cipher, BwKey key, Object entry, int at) async {
    final sum = plain.uriSum;
    if (sum == null || !plain.own || entry is! OtpAccount) return entry;
    final opened = (await _openUris((cipher.login ?? const {})['uris'], key)).skip(1).toList();
    if (opened.any((item) => item.uri == null)) return entry;
    final after = [
      for (final item in opened)
        if (item.uri case final uri?) (uri: uri, match: item.match),
    ];
    if (urisSum(after) == sum) return entry;
    final rules = <WebsiteRule>[];
    for (final (:uri, :match) in after) {
      final readable =
          normaliseWebsite(uri) != null ||
          match == WebsiteMatch.startsWith ||
          match == WebsiteMatch.exact ||
          match == WebsiteMatch.regularExpression;
      final rule = WebsiteRule(uri, match: match);
      if (readable && !rules.contains(rule)) rules.add(rule);
    }
    final made = websitesOf(rules);
    return entry.copyWith(websites: made.websites ?? unset, uris: made.uris ?? unset, updatedAt: at);
  }
}

/// The item's own values that a plain entry is shown with, decrypted, as
/// [VwWriter] wrote them and [valuesSum] hashes them; null when they don't open.
Future<Map<String, Object?>?> _plainValues(VwCipher cipher, BwKey key, PlainField plain) async {
  try {
    final login = cipher.login ?? const {};
    if (plain.kind == EntryKind.backupService) {
      return {'name': await _open(cipher.json['name'], key), 'notes': await _open(cipher.json['notes'], key)};
    }
    if (!plain.own) return {'totp': await _open(login['totp'], key)};
    return {
      'name': await _open(cipher.json['name'], key),
      'username': await _open(login['username'], key),
      'totp': await _open(login['totp'], key),
      'notes': await _open(cipher.json['notes'], key),
      'favorite': cipher.json['favorite'] == true,
    };
  } on BwCryptoError {
    return null;
  }
}

/// A key's, a note's or a passkey's item values, decrypted, as
/// [laterValues] gives them; null when they don't open.
Future<Map<String, Object?>?> _laterValues(VwCipher cipher, BwKey key, EntryKind kind) async {
  try {
    return {
      'name': await _open(cipher.json['name'], key),
      if (kind == EntryKind.passkey) 'username': await _open((cipher.login ?? const {})['username'], key),
      'notes': await _open(cipher.json['notes'], key),
      'favorite': kind == EntryKind.passkey || kind == EntryKind.contact ? false : cipher.json['favorite'] == true,
    };
  } on BwCryptoError {
    return null;
  }
}

/// Makes and changes Kemlock's items, as the request bodies the API takes.
class VwWriter {
  VwWriter({required this.userKey, required this.userId});

  final BwKey userKey;

  /// Sent as `encryptedFor`, which Vaultwarden checks.
  final String userId;

  Future<String> _enc(String value, BwKey key) => bwEncryptString(value, key);

  Future<String?> _encOrNull(String? value, BwKey key) async => value == null ? null : _enc(value, key);

  Future<Map<String, Object?>> _field(String value, BwKey key) async => {
    'type': 1,
    'name': await _enc(fieldName, key),
    'value': await _enc(value, key),
    'linkedId': null,
  };

  /// A new item holding [entry], in [form], in the home's folder. [website]
  /// is a new plain login's address, when the 2FA directory knows one.
  /// [sshKeyItems]: the server keeps SSH key items, so a plain SSH key goes
  /// in one.
  Future<Map<String, Object?>> create(
    Object entry, {
    required VaultwardenMode form,
    required String home,
    required String folderId,
    Uint8List? sealKey,
    String? website,
    bool sshKeyItems = false,
  }) async {
    final key = userKey;
    final base = <String, Object?>{
      'organizationId': null,
      'folderId': folderId,
      'favorite': false,
      'reprompt': 0,
      'key': null,
      'passwordHistory': null,
      'encryptedFor': userId,
    };
    if (form == VaultwardenMode.sealed) {
      return {
        ...base,
        'type': CipherType.secureNote,
        'name': await _enc(sealedEntryName, key),
        'notes': await _enc(sealedEntryText, key),
        'secureNote': {'type': 0},
        'fields': [await _field(await sealEntry(entry, home, sealKey!), key)],
      };
    }
    if (EntryKind.of(entry).isLater) return _createLater(entry, base, home: home, key: key, sshKeyItems: sshKeyItems);
    final values = plainValues(entry, own: true);
    // The code's own websites follow the directory's, which stays first; one that is the directory's
    // on the default rule is not listed twice
    final own = entry is OtpAccount ? entry.rules : const <WebsiteRule>[];
    final listed = [
      for (final rule in own)
        if (rule.uri != website || rule.match != null) rule,
    ];
    // Only a code with websites of its own carries the sum of its URIs after the first
    final uris = <({String uri, int? match})>[
      if (website != null) (uri: website, match: null),
      for (final rule in listed) (uri: rule.uri, match: rule.match),
    ];
    final field = PlainField(
      home: home,
      own: true,
      sum: valuesSum(values),
      entry: entry,
      extra: {if (own.isNotEmpty) 'uriSum': urisSum(uris.skip(1))},
    );
    if (entry is BackupService) {
      return {
        ...base,
        'type': CipherType.secureNote,
        'name': await _enc(values['name']! as String, key),
        'notes': await _encOrNull(values['notes'] as String?, key),
        'secureNote': {'type': 0},
        'fields': [await _field(field.toText(), key)],
      };
    }
    return {
      ...base,
      'type': CipherType.login,
      'name': await _enc(values['name']! as String, key),
      'notes': await _encOrNull(values['notes'] as String?, key),
      'favorite': values['favorite'],
      'fields': [await _field(field.toText(), key)],
      'login': {
        'username': await _encOrNull(values['username'] as String?, key),
        'password': null,
        'totp': await _encOrNull(values['totp'] as String?, key),
        'uris': [
          if (website != null)
            {
              'uri': await _enc(website, key),
              'uriChecksum': await _enc(b64(sha256.convert(utf8.encode(website)).bytes), key),
              'match': null,
            },
          for (final rule in listed) await _uriEntry(rule, key),
        ],
      },
    };
  }

  /// One of a login's `uris` for [rule]: its address and checksum encrypted, and its rule as
  /// Bitwarden's number, as the directory's website is written.
  Future<Map<String, Object?>> _uriEntry(WebsiteRule rule, BwKey key) async => {
    'uri': await _enc(rule.uri, key),
    'uriChecksum': await _enc(b64(sha256.convert(utf8.encode(rule.uri)).bytes), key),
    'match': rule.match,
  };

  /// [login]'s `uris` after the websites the phone changed from [before] to [after]
  /// (the add-cards-identities-and-websites plan, design decision 9), and nothing else:
  /// a website added is appended, one removed takes the URI of that address with it, and
  /// one whose rule changed gets that URI's `match`. Every other URI, one a Bitwarden app
  /// added included, goes back exactly as it was read, in place, and the first stays first.
  Future<List<Object?>> _patchedUris(Map<String, Object?> login, BwKey key, List<WebsiteRule> before, List<WebsiteRule> after) async {
    final next = await _openUris(login['uris'], key);
    final was = {for (final rule in before) rule.uri: rule};
    final now = {for (final rule in after) rule.uri: rule};
    for (final uri in was.keys) {
      if (now.containsKey(uri)) continue;
      final at = next.indexWhere((item) => item.uri == uri);
      if (at > 0) next.removeAt(at);
    }
    for (final MapEntry(key: uri, value: rule) in now.entries) {
      final at = next.indexWhere((item) => item.uri == uri);
      final old = was[uri];
      if (old == null) {
        if (at < 0) next.add((raw: await _uriEntry(rule, key), uri: rule.uri, match: rule.match));
      } else if (old.match != rule.match && at > 0 && next[at].raw is Map<String, Object?>) {
        next[at] = (raw: {...next[at].raw! as Map<String, Object?>, 'match': rule.match}, uri: uri, match: rule.match);
      }
    }
    return [for (final item in next) item.raw];
  }

  /// A plain key, note or passkey: a secure note, an SSH key item or a login,
  /// with the `Kemlock` field and, for a key kept as a note, its private half
  /// in a hidden field.
  Future<Map<String, Object?>> _createLater(
    Object entry,
    Map<String, Object?> base, {
    required String home,
    required BwKey key,
    required bool sshKeyItems,
  }) async {
    final ssh = entry is VaultKey && sshKeyItems ? await sshKeyValues(entry) : null;
    final values = laterValues(entry, sshItem: ssh != null);
    final field = await _field(PlainField(home: home, own: true, sum: valuesSum(values), entry: entry).toText(), key);
    final item = {
      ...base,
      'name': await _enc(values['name']! as String, key),
      'notes': await _encOrNull(values['notes'] as String?, key),
      'favorite': values['favorite'],
    };
    switch (entry) {
      case Passkey():
        final website = passkeyWebsite(entry);
        return {
          ...item,
          'type': CipherType.login,
          'fields': [field],
          'login': {
            'username': await _encOrNull(values['username'] as String?, key),
            'password': null,
            'totp': null,
            'uris': [
              {
                'uri': await _enc(website, key),
                'uriChecksum': await _enc(b64(sha256.convert(utf8.encode(website)).bytes), key),
                'match': null,
              },
            ],
            'fido2Credentials': [await fido2Credential(entry, key)],
          },
        };
      case VaultKey() when ssh != null:
        return {
          ...item,
          'type': CipherType.sshKey,
          'fields': [field],
          'sshKey': {
            'privateKey': await _enc(ssh.privateKey, key),
            'publicKey': await _enc(ssh.publicKey, key),
            'keyFingerprint': await _enc(ssh.fingerprint, key),
          },
        };
      case VaultKey():
        return {
          ...item,
          'type': CipherType.secureNote,
          'secureNote': {'type': 0},
          'fields': [
            {
              'type': 1,
              'name': await _enc(privateKeyFieldName, key),
              'value': await _enc(await privateKeyText(entry), key),
              'linkedId': null,
            },
            field,
          ],
        };
      default:
        return {
          ...item,
          'type': CipherType.secureNote,
          'secureNote': {'type': 0},
          'fields': [field],
        };
    }
  }

  /// [claim]'s item holding [entry] instead, in the same form, as an update
  /// that only goes through if the item hasn't changed since it was read. A
  /// picked-up login becomes linked: it gets the `Kemlock` field.
  Future<Map<String, Object?>> update(EntryClaim claim, Object entry, {required String home, Uint8List? sealKey}) async {
    final cipher = claim.cipher;
    final key = await cipherKey(cipher, userKey);
    final next = _copy(cipher);
    if (claim.form == VaultwardenMode.sealed) {
      _setField(next, claim.fieldIndex, await _field(await sealEntry(entry, home, sealKey!), key));
      return next;
    }
    if (EntryKind.of(entry).isLater) {
      // The name, notes and favourite; a passkey's credential never changes, and an SSH key's halves
      // never do. A PGP key's halves grow when it is changed, and its hidden private half follows the
      // public one in the notes (openspec: add-pgp-key-editing)
      final values = laterValues(entry, sshItem: cipher.type == CipherType.sshKey);
      _setField(
        next,
        claim.fieldIndex,
        await _field(PlainField(home: home, own: true, sum: valuesSum(values), entry: entry).toText(), key),
      );
      next['name'] = await _enc(values['name']! as String, key);
      next['notes'] = await _encOrNull(values['notes'] as String?, key);
      next['favorite'] = values['favorite'];
      final previous = claim.entry;
      if (entry is VaultKey && cipher.type != CipherType.sshKey && previous is VaultKey && previous.privateKey != entry.privateKey) {
        await _setPrivateKey(next, key, entry);
      }
      if (entry is Passkey) {
        final username = await _encOrNull(values['username'] as String?, key);
        next['login'] = {...?(next['login'] as Map<String, Object?>?), 'username': username};
      }
      return next;
    }
    final values = plainValues(entry, own: claim.own);
    // What the field says beyond the entry stays: keys of later versions, and the sum of the URIs
    final extra = {...?(await _previousField(claim, key))?.extra};
    PlainField fieldOf() => PlainField(home: home, own: claim.own, sum: valuesSum(values), entry: entry, extra: extra);
    if (entry is BackupService) {
      _setField(next, claim.fieldIndex, await _field(fieldOf().toText(), key));
      next['name'] = await _enc(values['name']! as String, key);
      next['notes'] = await _encOrNull(values['notes'] as String?, key);
      return next;
    }
    final login = {...?(next['login'] as Map<String, Object?>?)};
    if (claim.own) {
      next['name'] = await _enc(values['name']! as String, key);
      next['notes'] = await _encOrNull(values['notes'] as String?, key);
      next['favorite'] = values['favorite'];
      login['username'] = await _encOrNull(values['username'] as String?, key);
      login['totp'] = await _encOrNull(values['totp'] as String?, key);
      // The URIs after the first change only when the code's own websites did on the phone, or
      // when the item carries the sum of them, which then follows what Kemlock writes
      final before = claim.entry is OtpAccount ? (claim.entry! as OtpAccount).rules : const <WebsiteRule>[];
      final after = (entry as OtpAccount).rules;
      final changed = !const ListEquality<WebsiteRule>().equals(before, after);
      final held = extra['uriSum'] != null;
      if (changed || held) {
        if (changed) login['uris'] = await _patchedUris(login, key, before, after);
        // A code that has no website of its own carries no sum
        final written = [
          for (final item in (await _openUris(login['uris'], key)).skip(1))
            if (item.uri case final uri?) (uri: uri, match: item.match),
        ];
        if (after.isEmpty) {
          extra.remove('uriSum');
        } else {
          extra['uriSum'] = urisSum(written);
        }
      }
    } else if ((entry as OtpAccount).kind != OtpType.hotp) {
      login['totp'] = await _encOrNull(values['totp'] as String?, key);
    }
    _setField(next, claim.fieldIndex, await _field(fieldOf().toText(), key));
    next['login'] = login;
    return next;
  }

  /// The `Kemlock` field [claim]'s item holds now, or null when it holds none or it doesn't open.
  Future<PlainField?> _previousField(EntryClaim claim, BwKey key) async {
    final index = claim.fieldIndex;
    final fields = claim.cipher.fields;
    if (index == null || index >= fields.length) return null;
    try {
      final text = await _open(fields[index]['value'], key);
      return text == null ? null : PlainField.tryParse(text);
    } on BwCryptoError {
      return null;
    }
  }

  /// [claim]'s linked login without Kemlock: its code and the `Kemlock`
  /// field removed, everything else as it was.
  Future<Map<String, Object?>> unlink(EntryClaim claim) async {
    final next = _copy(claim.cipher);
    final fields = [...?(next['fields'] as List<Object?>?)];
    if (claim.fieldIndex case final index? when index < fields.length) fields.removeAt(index);
    next['fields'] = fields;
    next['login'] = {...?(next['login'] as Map<String, Object?>?), 'totp': null};
    return next;
  }

  /// A new home note in [folderId].
  Future<Map<String, Object?>> createHome(HomeNote home, {required String folderId}) async => {
    'type': CipherType.secureNote,
    'organizationId': null,
    'folderId': folderId,
    'name': await _enc(homeNoteName, userKey),
    'notes': await _enc(homeNoteText, userKey),
    'favorite': false,
    'reprompt': 0,
    'key': null,
    'passwordHistory': null,
    'secureNote': {'type': 0},
    'fields': [await _field(home.toText(), userKey)],
    'encryptedFor': userId,
  };

  /// [claim]'s home note holding [home] instead.
  Future<Map<String, Object?>> updateHome(HomeClaim claim, HomeNote home) async {
    final cipher = claim.cipher;
    final key = await cipherKey(cipher, userKey);
    final next = _copy(cipher);
    final fields = cipher.fields;
    var index = -1;
    for (var i = 0; i < fields.length; i++) {
      if (fields[i]['type'] == 1 && await _open(fields[i]['name'], key).catchError((Object _) => null) == fieldName) index = i;
    }
    _setField(next, index < 0 ? null : index, await _field(home.toText(), key));
    return next;
  }

  /// [cipher]'s hidden "Private key" field holding [entry]'s private half
  /// instead, encrypted with [key]; the field is added again when it was
  /// taken off in Bitwarden. Every other field stays as it was.
  Future<void> _setPrivateKey(Map<String, Object?> cipher, BwKey key, VaultKey entry) async {
    final fields = [...?(cipher['fields'] as List<Object?>?)];
    final value = await _enc(await privateKeyText(entry), key);
    for (final (i, field) in fields.indexed) {
      if (field is! Map<String, Object?> || field['type'] != 1) continue;
      if (await _open(field['name'], key).catchError((Object _) => null) != privateKeyFieldName) continue;
      fields[i] = {...field, 'value': value};
      cipher['fields'] = fields;
      return;
    }
    cipher['fields'] = [
      ...fields,
      {'type': 1, 'name': await _enc(privateKeyFieldName, key), 'value': value, 'linkedId': null},
    ];
  }

  Map<String, Object?> _copy(VwCipher cipher) => {
    ...jsonDecode(jsonEncode(cipher.json)) as Map<String, Object?>,
    'encryptedFor': userId,
    'lastKnownRevisionDate': cipher.revisionDate,
  };

  void _setField(Map<String, Object?> cipher, int? index, Map<String, Object?> field) {
    final fields = [...?(cipher['fields'] as List<Object?>?)];
    if (index != null && index < fields.length) {
      fields[index] = field;
    } else {
      fields.add(field);
    }
    cipher['fields'] = fields;
  }
}

/// The item's own values a plain entry is shown with: for a login Kemlock
/// made, its name, username, code, notes and favourite; for a linked one,
/// the code; for backup codes, the note's name and text.
Map<String, Object?> plainValues(Object entry, {required bool own}) => switch (entry) {
  BackupService() => {'name': '${entry.serviceName}$backupCodesSuffix', 'notes': backupCodesText(entry)},
  OtpAccount() when !own => {'totp': buildBitwardenTotp(entry)},
  OtpAccount() => {
    'name': entry.issuer.isNotEmpty ? entry.issuer : (entry.label.isNotEmpty ? entry.label : 'Kemlock'),
    'username': entry.label.isEmpty ? null : entry.label,
    'totp': buildBitwardenTotp(entry),
    'notes': entry.note == null || entry.note!.isEmpty ? null : entry.note,
    'favorite': entry.pinned == true,
  },
  _ => throw ArgumentError.value(entry, 'entry', 'Not an account or a backup service'),
};
