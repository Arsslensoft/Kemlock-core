/// The vault's side of opening with a security key (openspec:
/// add-security-key-unlock, decisions 1 to 3): what a vault's config keeps
/// under `keyUnlock`, and the keys derived from a security key's secret and
/// the password's key. Pure functions; nothing here talks to a key.
///
/// A vault with key unlock has a random 32-byte key secret, K. The config
/// holds K once per enrolled key, wrapped under that key's `hmac-secret`
/// output, and the vault's private key (`skNonce`, `skEnc`) is wrapped
/// under a key that depends on the mode:
///
/// ```
/// password : scrypt(password, config.salt)                       as ever
/// key      : HKDF(K,          salt, "Kemlock key unlock v1: key")
/// both     : HKDF(pwKey ‖ K,  salt, "Kemlock key unlock v1: both")
/// ```
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/aes_gcm.dart';
import '../crypto/bytes.dart';
import '../crypto/hkdf.dart';
import '../models/json.dart';

/// How a vault opens.
enum UnlockMode {
  /// With its master password, as every vault did before security keys.
  password,

  /// With an enrolled security key and its PIN; no password opens it.
  key,

  /// With its master password and an enrolled security key together.
  both;

  /// Whether the vault does not open without an enrolled key.
  bool get needsKey => this != password;

  /// Whether the vault has a master password.
  bool get hasPassword => this != key;

  static UnlockMode? fromName(Object? name) {
    for (final mode in values) {
      if (mode.name == name) return mode;
    }
    return null;
  }
}

const _labelWrap = 'Kemlock key unlock v1: key wrap';
const _labelKey = 'Kemlock key unlock v1: key';
const _labelBoth = 'Kemlock key unlock v1: both';
const _labelCheck = 'Kemlock key unlock v1: password check';

/// The length of a key's output, of the key secret, and of every key here.
const keySecretLength = 32;

Uint8List _derive(List<int> ikm, Uint8List salt, String label) => hkdfSha256(ikm, salt: salt, info: utf8.encode(label));

/// The key that wraps the key secret for one enrolled key, from that key's
/// `hmac-secret` [output].
Uint8List keyWrapKey(Uint8List output, Uint8List salt) => _derive(output, salt, _labelWrap);

/// The key that wraps the private key of a vault that opens with a key alone.
Uint8List keyModeWrapKey(Uint8List keySecret, Uint8List salt) => _derive(keySecret, salt, _labelKey);

/// The key that wraps the private key of a vault that needs both: neither
/// the password's key nor the key secret gives it without the other.
Uint8List bothModeWrapKey(Uint8List passwordKey, Uint8List keySecret, Uint8List salt) =>
    _derive([...passwordKey, ...keySecret], salt, _labelBoth);

/// What tells the right password of a vault that needs both before its key
/// is asked for (decision 3). It opens nothing.
Uint8List passwordCheck(Uint8List passwordKey, Uint8List salt) => _derive(passwordKey, salt, _labelCheck);

/// Whether [a] and [b] are the same bytes, in a time that does not depend
/// on where they differ.
bool sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

/// One enrolled security key: the credential it holds for this vault, and
/// the key secret wrapped under its output.
class EnrolledKey {
  EnrolledKey({
    required this.id,
    required this.credential,
    required this.nonce,
    required this.ct,
    required this.name,
    required this.addedAt,
    required this.pinBound,
    this._extra = const {},
  });

  /// Eight random bytes in hex, the entry's own name for itself.
  final String id;

  /// The credential id, sent to the key at every unlock.
  final Uint8List credential;
  final Uint8List nonce;
  final Uint8List ct;

  /// The name the person gave the key.
  final String name;

  /// When it was enrolled, in epoch ms.
  final int addedAt;

  /// The key ties its secret to its PIN or fingerprint (decision 6), so it
  /// can be the only lock of a vault.
  final bool pinBound;

  /// Members a newer version wrote, kept as they are.
  final Map<String, Object?> _extra;

  static const _known = {'id', 'credential', 'nonce', 'ct', 'name', 'addedAt', 'pinBound'};

  static EnrolledKey? parse(Object? json) {
    if (json is! Map<String, Object?>) return null;
    final id = json['id'];
    final credential = _bytes(json['credential']);
    final nonce = _bytes(json['nonce']);
    final ct = _bytes(json['ct']);
    if (id is! String || id.isEmpty || credential == null || credential.isEmpty || nonce == null || nonce.isEmpty || ct == null) {
      return null;
    }
    return EnrolledKey(
      id: id,
      credential: credential,
      nonce: nonce,
      ct: ct,
      name: asString(json['name']),
      addedAt: asInt(json['addedAt']) ?? 0,
      pinBound: json['pinBound'] == true,
      extra: extraKeys(json, _known),
    );
  }

  Map<String, Object?> toJson() => {
    'id': id,
    'credential': b64(credential),
    'nonce': b64(nonce),
    'ct': b64(ct),
    'name': name,
    'addedAt': addedAt,
    'pinBound': pinBound,
    ..._extra,
  };

  EnrolledKey renamed(String name) =>
      EnrolledKey(id: id, credential: credential, nonce: nonce, ct: ct, name: name, addedAt: addedAt, pinBound: pinBound, extra: _extra);
}

Uint8List? _bytes(Object? value) {
  if (value is! String) return null;
  try {
    return unb64(value);
  } on FormatException {
    return null;
  }
}

/// A vault config's `keyUnlock` (decision 2). It is written when the first
/// key is enrolled and removed with the last.
class KeyUnlock {
  KeyUnlock({required this.mode, required this.salt, this.check, required this.keys, this._extra = const {}});

  /// The version this code writes and reads.
  static const version = 1;

  final UnlockMode mode;

  /// 32 bytes, one per vault: the salt sent to whichever key answers, and
  /// the salt of every derivation here.
  final Uint8List salt;

  /// [passwordCheck] of the password's key, in mode both only.
  final Uint8List? check;

  final List<EnrolledKey> keys;
  final Map<String, Object?> _extra;

  static const _known = {'v', 'mode', 'salt', 'check', 'keys'};

  /// What a config's `keyUnlock` holds, or null when there is none or it is
  /// not one this version can read: the vault is then a password vault to
  /// this code, as it is to a version from before security keys.
  static KeyUnlock? parse(Object? json) {
    if (json is! Map<String, Object?>) return null;
    if (json['v'] != version) return null;
    final mode = UnlockMode.fromName(json['mode']);
    final salt = _bytes(json['salt']);
    final list = json['keys'];
    if (mode == null || salt == null || salt.length != keySecretLength || list is! List<Object?> || list.isEmpty) return null;
    final keys = <EnrolledKey>[];
    for (final item in list) {
      final key = EnrolledKey.parse(item);
      if (key == null) return null;
      keys.add(key);
    }
    final check = json['check'] == null ? null : _bytes(json['check']);
    if (mode == UnlockMode.both && (check == null || check.length != keySecretLength)) return null;
    return KeyUnlock(mode: mode, salt: salt, check: mode == UnlockMode.both ? check : null, keys: keys, extra: extraKeys(json, _known));
  }

  /// The `keyUnlock` of [config], or null.
  static KeyUnlock? of(Map<String, Object?>? config) => parse(config?['keyUnlock']);

  Map<String, Object?> toJson() => {
    'v': version,
    'mode': mode.name,
    'salt': b64(salt),
    if (check case final check?) 'check': b64(check),
    'keys': [for (final key in keys) key.toJson()],
    ..._extra,
  };

  /// The entry of the credential [credential], or null.
  EnrolledKey? keyFor(List<int> credential) {
    for (final key in keys) {
      if (sameBytes(key.credential, credential)) return key;
    }
    return null;
  }

  /// The same with another mode, password check or list of keys.
  KeyUnlock copyWith({UnlockMode? mode, Uint8List? check, List<EnrolledKey>? keys}) {
    final next = mode ?? this.mode;
    return KeyUnlock(
      mode: next,
      salt: salt,
      check: next == UnlockMode.both ? (check ?? this.check) : null,
      keys: keys ?? this.keys,
      extra: _extra,
    );
  }
}

/// The key secret wrapped for the key that gave [output].
Future<({Uint8List nonce, Uint8List ct})> wrapKeySecret(Uint8List keySecret, Uint8List output, Uint8List salt) =>
    aesGcmEncrypt(keyWrapKey(output, salt), keySecret);

/// The key secret an enrolled key's entry wraps, opened with that key's
/// [output]. Throws [AesGcmAuthError] for any other output.
Future<Uint8List> unwrapKeySecret(EnrolledKey key, Uint8List output, Uint8List salt) =>
    aesGcmDecrypt(keyWrapKey(output, salt), key.nonce, key.ct);
