// Bitwarden's client-side crypto, as Vaultwarden accounts use it: the
// master key from the master password, the hash sent to the server, the
// stretched key that opens the user key, and the encrypted strings every
// item is made of. Only what Vaultwarden sync needs is here; organization
// keys (RSA) are not.
//
// The master key is derived off the UI isolate, like the vault's scrypt.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import 'background.dart';
import 'bytes.dart';
import 'hkdf.dart' as hkdf;
import 'kdf.dart';

/// How an account turns its master password into a key, as prelogin says.
enum BwKdfType {
  /// PBKDF2-SHA256 (kdf 0).
  pbkdf2,

  /// Argon2id (kdf 1).
  argon2id,
}

/// An account's KDF and its cost, from prelogin or a token answer.
class BwKdf {
  const BwKdf({required this.type, required this.iterations, this.memory, this.parallelism});

  /// Reads `kdf`, `kdfIterations`, `kdfMemory` and `kdfParallelism`,
  /// whatever the case of their names. Throws a [FormatException] for a KDF
  /// type other than 0 and 1, or a cost that isn't a whole number within the
  /// bounds Bitwarden's own apps hold a server's answer to.
  ///
  /// The server names the cost, and the master password's hash is sent to it
  /// at that cost. Without a floor, a server that answers "1 iteration" is
  /// sent a hash that is guessed about as fast as an unsalted one; without a
  /// ceiling, it can ask for more memory or time than a phone has.
  factory BwKdf.fromJson(Map<String, Object?> json) {
    final values = {for (final MapEntry(:key, :value) in json.entries) key.toLowerCase(): value};
    final type = switch (values['kdf']) {
      0 => BwKdfType.pbkdf2,
      1 => BwKdfType.argon2id,
      final other => throw FormatException('Unknown KDF', '$other'),
    };
    int within(String name, int least, int most) => switch (values[name]) {
      final int value when value >= least && value <= most => value,
      final other => throw FormatException('KDF cost out of range', '$name: $other'),
    };
    if (type == BwKdfType.pbkdf2) {
      return BwKdf(type: type, iterations: within('kdfiterations', minPbkdf2Iterations, maxPbkdf2Iterations));
    }
    return BwKdf(
      type: type,
      iterations: within('kdfiterations', minArgon2Iterations, maxArgon2Iterations),
      memory: within('kdfmemory', minArgon2Memory, maxArgon2Memory),
      parallelism: within('kdfparallelism', minArgon2Parallelism, maxArgon2Parallelism),
    );
  }

  /// The least and most a server may ask for, as in Bitwarden's apps.
  static const minPbkdf2Iterations = 5000;
  static const maxPbkdf2Iterations = 2000000;
  static const minArgon2Iterations = 2;
  static const maxArgon2Iterations = 10;

  /// MiB.
  static const minArgon2Memory = 16;
  static const maxArgon2Memory = 1024;
  static const minArgon2Parallelism = 1;
  static const maxArgon2Parallelism = 16;

  final BwKdfType type;
  final int iterations;

  /// Argon2id only: MiB.
  final int? memory;

  /// Argon2id only.
  final int? parallelism;

  Map<String, Object?> toJson() => {'kdf': type.index, 'kdfIterations': iterations, 'kdfMemory': ?memory, 'kdfParallelism': ?parallelism};

  @override
  bool operator ==(Object other) =>
      other is BwKdf && other.type == type && other.iterations == iterations && other.memory == memory && other.parallelism == parallelism;

  @override
  int get hashCode => Object.hash(type, iterations, memory, parallelism);

  @override
  String toString() => 'BwKdf(${toJson()})';
}

/// The email as Bitwarden salts with it: trimmed and lower-cased.
String bwSaltEmail(String email) => email.trim().toLowerCase();

/// The master key: PBKDF2-SHA256 of the password with the email as salt, or
/// Argon2id with the email's SHA-256 as salt. Runs in a background isolate.
Future<Uint8List> bwMasterKey(String password, String email, BwKdf kdf) {
  final salt = utf8.encode(bwSaltEmail(email));
  final secret = utf8.encode(password);
  switch (kdf.type) {
    case BwKdfType.pbkdf2:
      return pbkdf2Sha256InBackground(secret, salt, kdf.iterations, 32);
    case BwKdfType.argon2id:
      final memory = kdf.memory!;
      final parallelism = kdf.parallelism!;
      final iterations = kdf.iterations;
      final saltHash = Uint8List.fromList(hash.sha256.convert(salt).bytes);
      return runInBackground(() async {
        final argon = DartArgon2id(parallelism: parallelism, memory: memory * 1024, iterations: iterations, hashLength: 32);
        final key = await argon.deriveKey(secretKey: SecretKeyData(secret), nonce: saltHash);
        return Uint8List.fromList(await key.extractBytes());
      }, debugName: 'argon2id');
  }
}

/// What the server checks the password against: base64 of
/// PBKDF2-SHA256(master key, salt = password, 1 round).
Future<String> bwMasterPasswordHash(Uint8List masterKey, String password) async =>
    b64(await pbkdf2Sha256InBackground(masterKey, utf8.encode(password), 1, 32));

/// HKDF-Expand with SHA-256 (RFC 5869, section 2.3), no extract step, as
/// Bitwarden stretches the master key. It is `hkdf.dart`'s.
Uint8List hkdfExpandSha256(List<int> prk, List<int> info, int length) => hkdf.hkdfExpandSha256(prk, info, length);

/// A key that encrypts Bitwarden values: 32 bytes for AES-256-CBC and, but
/// for type 0 values, 32 for HMAC-SHA256.
class BwKey {
  BwKey(this.enc, [this.mac]) {
    if (enc.length != 32 || (mac != null && mac!.length != 32)) throw ArgumentError('A Bitwarden key is 32 + 32 bytes');
  }

  /// A 64-byte key (encryption then MAC), or a 32-byte one without a MAC.
  factory BwKey.fromBytes(List<int> bytes) => switch (bytes.length) {
    64 => BwKey(Uint8List.fromList(bytes.sublist(0, 32)), Uint8List.fromList(bytes.sublist(32))),
    32 => BwKey(Uint8List.fromList(bytes)),
    _ => throw ArgumentError.value(bytes.length, 'bytes', 'A Bitwarden key is 32 or 64 bytes'),
  };

  /// A new random 64-byte key, as for a cipher's own key.
  factory BwKey.random() => BwKey.fromBytes(randomBytes(64));

  final Uint8List enc;
  final Uint8List? mac;

  /// The key's bytes, encryption key first.
  Uint8List get bytes => concatBytes([enc, ?mac]);

  /// Leaves the key out, so it never ends up in a log.
  @override
  String toString() => 'BwKey(${mac == null ? 32 : 64} bytes)';
}

/// The key that opens the user key: HKDF-Expand of the master key with
/// "enc" and "mac".
BwKey bwStretch(Uint8List masterKey) =>
    BwKey(hkdfExpandSha256(masterKey, utf8.encode('enc'), 32), hkdfExpandSha256(masterKey, utf8.encode('mac'), 32));

/// A value that isn't a Bitwarden encrypted string, or that a key doesn't
/// open (its MAC doesn't verify, or it doesn't decrypt).
class BwCryptoError implements Exception {
  const BwCryptoError(this.message);

  final String message;

  @override
  String toString() => 'BwCryptoError: $message';
}

/// An encrypted string: `<type>.<iv>|<data>|<mac>`, all base64. Only types 0
/// (AES-256-CBC) and 2 (AES-256-CBC with HMAC-SHA256) are read.
class EncString {
  EncString({required this.type, required this.iv, required this.data, this.mac});

  /// Reads [text]. Throws a [BwCryptoError] for anything that isn't a type 0
  /// or 2 value.
  factory EncString.parse(String text) {
    final dot = text.indexOf('.');
    if (dot < 1) throw const BwCryptoError('Not an encrypted string');
    final type = int.tryParse(text.substring(0, dot));
    final parts = text.substring(dot + 1).split('|');
    try {
      switch ((type, parts.length)) {
        case (0, 2):
          return EncString(type: 0, iv: unb64(parts[0]), data: unb64(parts[1]));
        case (2, 3):
          return EncString(type: 2, iv: unb64(parts[0]), data: unb64(parts[1]), mac: unb64(parts[2]));
      }
    } on FormatException {
      throw const BwCryptoError('Not an encrypted string');
    }
    throw BwCryptoError('Unsupported encrypted string type ${text.substring(0, dot)}');
  }

  final int type;
  final Uint8List iv;
  final Uint8List data;
  final Uint8List? mac;

  @override
  String toString() => mac == null ? '$type.${b64(iv)}|${b64(data)}' : '$type.${b64(iv)}|${b64(data)}|${b64(mac!)}';
}

/// Whether [text] is an encrypted string this code can open.
bool isEncString(String text) {
  try {
    EncString.parse(text);
    return true;
  } on BwCryptoError {
    return false;
  }
}

final _aesCbc = DartAesCbc.with256bits(macAlgorithm: MacAlgorithm.empty);

Uint8List _hmac(List<int> key, List<int> iv, List<int> data) =>
    Uint8List.fromList(hash.Hmac(hash.sha256, key).convert([...iv, ...data]).bytes);

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Encrypts [plain] with [key] as a type 2 value (type 0 for a key without a
/// MAC key), under [iv] or a fresh random 16-byte one.
Future<EncString> bwEncrypt(List<int> plain, BwKey key, {List<int>? iv}) async {
  final nonce = iv == null ? randomBytes(16) : Uint8List.fromList(iv);
  final box = await _aesCbc.encrypt(plain, secretKey: SecretKeyData(List<int>.of(key.enc)), nonce: nonce);
  final data = Uint8List.fromList(box.cipherText);
  final macKey = key.mac;
  if (macKey == null) return EncString(type: 0, iv: nonce, data: data);
  return EncString(type: 2, iv: nonce, data: data, mac: _hmac(macKey, nonce, data));
}

/// Opens [value] with [key]. Throws a [BwCryptoError] when the MAC doesn't
/// verify, the value doesn't decrypt, it needs a MAC key [key] lacks, or it
/// has no MAC while [key] has a MAC key: a server could otherwise swap any
/// value for a type 0 one of its own making, which nothing checks.
Future<Uint8List> bwDecrypt(EncString value, BwKey key) async {
  final macKey = key.mac;
  if (value.type == 2) {
    if (macKey == null || !_sameBytes(_hmac(macKey, value.iv, value.data), value.mac!)) {
      throw const BwCryptoError('Wrong key or changed data');
    }
  } else if (macKey != null) {
    throw const BwCryptoError('Wrong key or changed data');
  }
  try {
    final plain = await _aesCbc.decrypt(
      SecretBox(value.data, nonce: value.iv, mac: Mac.empty),
      secretKey: SecretKeyData(List<int>.of(key.enc)),
    );
    return Uint8List.fromList(plain);
  } catch (_) {
    throw const BwCryptoError('Wrong key or changed data');
  }
}

/// Encrypts a UTF-8 string.
Future<String> bwEncryptString(String plain, BwKey key) async => (await bwEncrypt(utf8.encode(plain), key)).toString();

/// Opens an encrypted UTF-8 string. Throws a [BwCryptoError].
Future<String> bwDecryptString(String value, BwKey key) async {
  final bytes = await bwDecrypt(EncString.parse(value), key);
  try {
    return utf8.decode(bytes);
  } on FormatException {
    throw const BwCryptoError('Not UTF-8');
  }
}

/// Opens the account's user key (the token answer's `Key`) with the master
/// key: a type 2 value with the stretched key, or, on old accounts, a type 0
/// value with the master key itself. Throws a [BwCryptoError] for a wrong
/// master key or a key that isn't 64 bytes.
Future<BwKey> bwOpenUserKey(String encrypted, Uint8List masterKey) async {
  final value = EncString.parse(encrypted);
  final key = value.type == 0 ? BwKey(masterKey) : bwStretch(masterKey);
  final bytes = await bwDecrypt(value, key);
  if (bytes.length != 64) throw const BwCryptoError('The user key is not 64 bytes');
  return BwKey.fromBytes(bytes);
}

/// Opens a cipher's own key (its `key`) with the user key.
Future<BwKey> bwOpenCipherKey(String encrypted, BwKey userKey) async {
  final bytes = await bwDecrypt(EncString.parse(encrypted), userKey);
  if (bytes.length != 64) throw const BwCryptoError('The cipher key is not 64 bytes');
  return BwKey.fromBytes(bytes);
}
