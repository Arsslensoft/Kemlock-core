/// The files sync keeps on a WebDAV server, and the invites that let someone
/// join a shared space, ported from `syncCrypto.ts`. Both are AES-256-GCM;
/// the server only ever sees ciphertext.
///
/// A vault's own sync file is keyed by scrypt(sync passphrase), with the salt
/// in the file so every device derives the same key. A shared space's file
/// uses a random key that travels inside an invite, itself sealed with a
/// one-time invite code the inviter passes on separately (out loud, or in
/// another app). Files and invites made by either app open in the other.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';

import '../../crypto/aes_gcm.dart';
import '../../crypto/bytes.dart';
import '../../models/json.dart';
import '../../vault/vault_export.dart' show formatAppName;
import '../../vault/vault_store.dart' show DeriveKey, deriveVaultKey, scryptN, scryptP, scryptR;
import '../accounts/service_names.dart' show jsTrim;
import 'sync_merge.dart';

/// [length] random bytes. The default is [randomBytes]; tests pass a fixed
/// source to replay what the TypeScript app drew.
typedef RandomSource = Uint8List Function(int length);

/// The scrypt salt and parameters of a passphrase-keyed sync file, matching
/// the vault's. Keys it doesn't know are kept in [extra] and written back.
class Kdf {
  const Kdf({required this.salt, this.n = scryptN, this.r = scryptR, this.p = scryptP, this.extra = const {}});

  /// Reads the `kdf` of a sync file or of the stored settings. A parameter
  /// that isn't a whole number reads as 0, which [deriveSyncKey] refuses.
  factory Kdf.fromJson(Map<String, Object?> json) => Kdf(
    salt: asString(json['salt']),
    n: _whole(json['N']),
    r: _whole(json['r']),
    p: _whole(json['p']),
    extra: extraKeys(json, const {'salt', 'N', 'r', 'p'}),
  );

  /// base64
  final String salt;
  final int n;
  final int r;
  final int p;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'salt': salt, 'N': n, 'r': r, 'p': p, ...extra};

  @override
  bool operator ==(Object other) => other is Kdf && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(salt, n, r, p);

  @override
  String toString() => 'Kdf(${toJson()})';
}

int _whole(Object? value) => value is num && value.isFinite && value == value.truncate() ? value.toInt() : 0;

/// What is wrong with a sync file. The names are the ends of the
/// `sync.problem.*` message ids.
enum SyncFileProblem {
  /// Not a Kemlock sync file, or a salt made with other scrypt parameters.
  format,

  /// The passphrase or key doesn't open it.
  key,

  /// It opens, and is older than a file this device already saw in the
  /// scope (`SyncDoc.seq`).
  older,
}

/// A sync file that can't be read, and why.
class SyncFileError implements Exception {
  const SyncFileError(this.problem);

  final SyncFileProblem problem;

  String get message => switch (problem) {
    SyncFileProblem.format => 'Not a Kemlock sync file.',
    SyncFileProblem.key => 'Wrong sync passphrase or key.',
    SyncFileProblem.older => 'The sync file is older than one this device already synced.',
  };

  @override
  String toString() => 'SyncFileError: $message';
}

/// A new random salt with the vault's scrypt parameters, for a folder that
/// has no sync file yet.
Kdf newKdf({RandomSource random = randomBytes}) => Kdf(salt: b64(random(32)));

/// The key a sync passphrase gives with this salt, derived off the UI
/// isolate. Fails with a `format` [SyncFileError] for other scrypt
/// parameters, before any work is done. [derive] is the vault's scrypt;
/// tests pass a cheaper one.
Future<Uint8List> deriveSyncKey(String passphrase, Kdf kdf, {DeriveKey derive = deriveVaultKey}) async {
  if (kdf.n != scryptN || kdf.r != scryptR || kdf.p != scryptP) throw const SyncFileError(SyncFileProblem.format);
  return derive(passphrase, unb64(kdf.salt));
}

/// The outer JSON of a sync file, checked as `parseFile` checks it.
Map<String, Object?> _parseFile(String text) {
  try {
    final file = jsonDecode(text);
    if (file is Map<String, Object?> &&
        file['app'] == formatAppName &&
        file['kind'] == 'sync' &&
        file['version'] == 1 &&
        file['nonce'] is String &&
        file['ct'] is String) {
      return file;
    }
  } on FormatException {
    // Falls through to the format error
  }
  throw const SyncFileError(SyncFileProblem.format);
}

/// The salt a passphrase-keyed file was made with, or null for a space's
/// file. Throws a `format` [SyncFileError] for text that isn't a sync file,
/// and for a `kdf` that isn't an object, which the TypeScript app refuses
/// when it comes to derive the key.
Kdf? readKdf(String text) => switch (_parseFile(text)['kdf']) {
  null => null,
  final Map<String, Object?> kdf => Kdf.fromJson(kdf),
  _ => throw const SyncFileError(SyncFileProblem.format),
};

/// Encrypts one scope's document with its 32-byte [key]. A vault's own file
/// carries the passphrase's [kdf], so another device can derive the key.
Future<String> encryptSyncFile(SyncDoc doc, Uint8List key, {Kdf? kdf, RandomSource random = randomBytes}) async {
  final sealed = await aesGcmEncrypt(key, utf8.encode(jsonEncode(doc.toJson())), nonce: random(12));
  return jsonEncode({
    'app': formatAppName,
    'kind': 'sync',
    'version': 1,
    'kdf': ?kdf?.toJson(),
    'nonce': b64(sealed.nonce),
    'ct': b64(sealed.ct),
  });
}

/// Opens a sync file. Throws a [SyncFileError]: `format` for text that isn't
/// a sync file, `key` when [key] doesn't open it. Lists that are missing or
/// aren't lists read as empty.
Future<SyncDoc> decryptSyncFile(String text, Uint8List key) async {
  final file = _parseFile(text);
  Uint8List plain;
  try {
    plain = await aesGcmDecrypt(key, unb64(file['nonce']! as String), unb64(file['ct']! as String));
  } catch (_) {
    throw const SyncFileError(SyncFileProblem.key);
  }
  final doc = jsonDecode(utf8.decode(plain, allowMalformed: true));
  // Every app writes an object here; anything else is no document to merge into
  if (doc is! Map<String, Object?>) throw const SyncFileError(SyncFileProblem.format);
  return SyncDoc.fromJson(doc);
}

// ─── Shared-space invites ─────────────────────────────────────────────────────

/// What an invite carries: the space, its file and the key to it.
class SpaceInvite {
  const SpaceInvite({required this.id, required this.name, required this.file, required this.key});

  final String id;
  final String name;

  /// File name inside the shared folder.
  final String file;

  /// The space's 32-byte AES key.
  final Uint8List key;

  @override
  bool operator ==(Object other) =>
      other is SpaceInvite &&
      other.id == id &&
      other.name == name &&
      other.file == file &&
      const ListEquality<int>().equals(other.key, key);

  @override
  int get hashCode => Object.hash(id, name, file);

  /// Leaves the key out, so it never ends up in a log.
  @override
  String toString() => 'SpaceInvite($id, $name, $file)';
}

const _invitePrefix = 'bmc-space:';

/// The letters invite codes are made of: no 0/O, 1/I/L or U.
const inviteCodeAlphabet = 'ABCDEFGHJKMNPQRSTVWXYZ23456789';

/// A one-time code for an invite, e.g. "K7PQ-2M9X-DARF" (about 59 bits).
String newInviteCode({RandomSource random = randomBytes}) {
  final chars = <String>[];
  // Bytes past the last whole multiple of the alphabet would favour its first letters
  const limit = 256 - (256 % inviteCodeAlphabet.length);
  while (chars.length < 12) {
    for (final b in random(16)) {
      if (b < limit && chars.length < 12) chars.add(inviteCodeAlphabet[b % inviteCodeAlphabet.length]);
    }
  }
  return [
    for (final i in const [0, 4, 8]) chars.sublist(i, i + 4).join(),
  ].join('-');
}

/// An invite code as it's keyed: upper case, letters and digits only, so it
/// works however it was typed. Like JavaScript's `toUpperCase()`, which
/// `syncCrypto.ts` calls, it turns ß, the Latin ligatures and a few other
/// letters into ASCII ones.
String normalizeInviteCode(String code) {
  final out = StringBuffer();
  for (final rune in code.runes) {
    if (rune >= 0x61 && rune <= 0x7a) {
      out.writeCharCode(rune - 0x20);
    } else if ((rune >= 0x41 && rune <= 0x5a) || (rune >= 0x30 && rune <= 0x39)) {
      out.writeCharCode(rune);
    } else if (_upperAscii[rune] case final letters?) {
      out.write(letters);
    }
  }
  return out.toString();
}

// Every character outside a-z whose upper case in JavaScript has letters
// A to Z in it, and those letters (marks and the like are dropped after).
const _upperAscii = {
  0xdf: 'SS', // ß
  0x131: 'I', // dotless ı
  0x149: 'N', // ŉ → ʼN
  0x17f: 'S', // long ſ
  0x1f0: 'J', // ǰ → J̌
  0x1e96: 'H', // ẖ → H̱
  0x1e97: 'T', // ẗ → T̈
  0x1e98: 'W', // ẘ → W̊
  0x1e99: 'Y', // ẙ → Y̊
  0x1e9a: 'A', // ẚ → Aʾ
  0xfb00: 'FF',
  0xfb01: 'FI',
  0xfb02: 'FL',
  0xfb03: 'FFI',
  0xfb04: 'FFL',
  0xfb05: 'ST',
  0xfb06: 'ST',
};

/// Base64url back to the standard alphabet, padded by the length of the
/// text as it came, as `fromB64url` does before `atob`.
String _fromB64url(String s) => s.replaceAll('-', '+').replaceAll('_', '/').padRight(s.length + (4 - s.length % 4) % 4, '=');

/// What an invite can't be opened for.
enum InviteProblem {
  /// Not a Kemlock invite.
  format,

  /// The invite code is wrong.
  code,
}

/// An invite that can't be opened, and why. The dialog's message ids end in
/// the problem's name (`spaces.error.invite.format`, `….code`).
class InviteError implements Exception {
  const InviteError(this.problem);

  final InviteProblem problem;

  String get message => problem == InviteProblem.code ? 'Wrong invite code.' : 'Not a Kemlock invite.';

  @override
  String toString() => 'InviteError: $message';
}

/// The invite as one line of text (also what its QR code holds), sealed
/// with a key scrypt derives from [code].
Future<String> sealInvite(SpaceInvite invite, String code, {DeriveKey derive = deriveVaultKey, RandomSource random = randomBytes}) async {
  final salt = random(16);
  final key = await derive(normalizeInviteCode(code), salt);
  final body = jsonEncode({'id': invite.id, 'name': invite.name, 'file': invite.file, 'key': b64(invite.key)});
  final sealed = await aesGcmEncrypt(key, utf8.encode(body), nonce: random(12));
  final text = jsonEncode({'v': 1, 'salt': b64(salt), 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)});
  return _invitePrefix + b64url(latin1.encode(text));
}

/// Whether [text] looks like an invite, before asking for its code.
bool isInvite(String text) => jsTrim(text).startsWith(_invitePrefix);

/// Whether [id] can be a shared space's id: letters, digits, `-` and `_`, 64
/// at most, and neither of the names the vault's own entries sync under
/// (`personalScope` and `vaultwardenScope`).
///
/// What each scope last saw is kept by scope id, the vault's own and the
/// spaces' in one map. A space called `personal` would read the vault's own
/// list as its own, write every id in it into the space's file as deleted,
/// and make the vault forget what it had synced.
bool isSpaceId(String id) => _spaceId.hasMatch(id) && id != 'personal' && id != 'vaultwarden';

final _spaceId = RegExp(r'^[A-Za-z0-9_-]{1,64}$');

/// Opens an invite with its code, however the code is typed. Throws an
/// [InviteError]: `format` for text that isn't an invite or that names a
/// space no space can be ([isSpaceId]), `code` when the code doesn't open it.
Future<SpaceInvite> openInvite(String text, String code, {DeriveKey derive = deriveVaultKey}) async {
  Map<String, Object?> sealed;
  try {
    final trimmed = jsTrim(text);
    if (!trimmed.startsWith(_invitePrefix)) throw const InviteError(InviteProblem.format);
    final json = jsonDecode(latin1.decode(unb64(_fromB64url(trimmed.substring(_invitePrefix.length)))));
    if (json is! Map<String, Object?> || json['v'] != 1) throw const InviteError(InviteProblem.format);
    sealed = json;
  } catch (_) {
    throw const InviteError(InviteProblem.format);
  }
  Uint8List plain;
  try {
    final key = await derive(normalizeInviteCode(code), unb64(sealed['salt']! as String));
    plain = await aesGcmDecrypt(key, unb64(sealed['nonce']! as String), unb64(sealed['ct']! as String));
  } catch (_) {
    throw const InviteError(InviteProblem.code);
  }
  final SpaceInvite invite;
  try {
    final body = jsonDecode(utf8.decode(plain, allowMalformed: true)) as Map<String, Object?>;
    invite = SpaceInvite(
      id: body['id']! as String,
      name: body['name']! as String,
      file: body['file']! as String,
      key: unb64(body['key']! as String),
    );
  } catch (_) {
    throw const InviteError(InviteProblem.format);
  }
  // The inviter chose every field: a name the vault keeps for itself is refused
  if (!isSpaceId(invite.id) || invite.key.length != 32) throw const InviteError(InviteProblem.format);
  return invite;
}
