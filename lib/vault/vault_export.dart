import 'dart:convert';
import 'dart:typed_data';

import '../core/time.dart';
import '../crypto/aes_gcm.dart';
import '../crypto/bytes.dart';
import '../crypto/ml_kem.dart';
import '../models/backup_service.dart';
import '../models/contact.dart';
import '../models/identity.dart';
import '../models/key_account.dart';
import '../models/login.dart';
import '../models/otp_account.dart';
import '../models/passkey.dart';
import '../models/payment_card.dart';
import '../models/secure_note.dart';
import '../models/vault_key.dart';
import 'sealed_value.dart';
import 'vault_store.dart';

/// The version of the `.json` export this app writes; files up to it can be read.
const exportVersion = 2;

/// What an export's payload is sealed for (sealed_value.dart), in place of
/// the storage key a vault's value is sealed for: a file has one payload.
const exportSealKey = 'export';

/// The `app` field of every export and sync file. It is the app's name from
/// before it became Kemlock, and it stays: every version checks for it, so a
/// file that said anything else wouldn't open in the versions people have.
const formatAppName = 'BackMyCodes';

/// What an export holds. Keys, notes, passkeys, contacts, logins, cards and identities sit
/// beside the codes in the same version 2 payload, so older versions still
/// read the codes and pass the rest over.
class VaultExportPayload {
  const VaultExportPayload({
    required this.accounts,
    required this.backupServices,
    this.keys = const [],
    this.notes = const [],
    this.passkeys = const [],
    this.keyAccounts = const [],
    this.contacts = const [],
    this.logins = const [],
    this.cards = const [],
    this.identities = const [],
  });

  final List<OtpAccount> accounts;
  final List<BackupService> backupServices;
  final List<VaultKey> keys;
  final List<SecureNote> notes;
  final List<Passkey> passkeys;

  /// The accounts kept on a security key, by name: "on your key, not in
  /// this file" (openspec: add-security-key-codes, decision 10).
  final List<KeyAccount> keyAccounts;

  /// Other people's public keys, with their checks.
  final List<Contact> contacts;

  /// The vault's logins, passwords and all (openspec: add-passwords).
  final List<Login> logins;

  /// The vault's cards, numbers and codes and all.
  final List<PaymentCard> cards;

  /// The vault's identities, document numbers and all.
  final List<Identity> identities;

  /// How many attached files its notes name.
  int get fileCount => notes.fold(0, (count, note) => count + note.files.length);
}

/// The vault items of an export, written only when there are some, so a
/// vault of codes alone exports as it always did.
Map<String, Object?> _items(
  List<VaultKey> keys,
  List<SecureNote> notes,
  List<Passkey> passkeys,
  List<KeyAccount> keyAccounts,
  List<Contact> contacts,
  List<Login> logins,
  List<PaymentCard> cards,
  List<Identity> identities,
) => {
  if (keys.isNotEmpty) 'keys': [for (final key in keys) key.toJson()],
  if (notes.isNotEmpty) 'notes': [for (final note in notes) note.toJson()],
  if (passkeys.isNotEmpty) 'passkeys': [for (final passkey in passkeys) passkey.toJson()],
  if (keyAccounts.isNotEmpty) 'keyAccounts': [for (final account in keyAccounts) account.toJson()],
  if (contacts.isNotEmpty) 'contacts': [for (final contact in contacts) contact.toJson()],
  if (logins.isNotEmpty) 'logins': [for (final login in logins) login.toJson()],
  if (cards.isNotEmpty) 'cards': [for (final card in cards) card.toJson()],
  if (identities.isNotEmpty) 'identities': [for (final identity in identities) identity.toJson()],
};

List<T> _read<T>(Object? list, T Function(Map<String, Object?> json) from) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) from(json),
];

VaultExportPayload _payload(Map<String, Object?> json) => VaultExportPayload(
  accounts: _accounts(json['accounts']),
  backupServices: _services(json['backupServices']),
  keys: _read(json['keys'], VaultKey.fromJson),
  notes: _read(json['notes'], SecureNote.fromJson),
  passkeys: _read(json['passkeys'], Passkey.fromJson),
  keyAccounts: _read(json['keyAccounts'], KeyAccount.fromJson),
  contacts: _read(json['contacts'], Contact.fromJson),
  logins: _read(json['logins'], Login.fromJson),
  cards: _read(json['cards'], PaymentCard.fromJson),
  identities: _read(json['identities'], Identity.fromJson),
);

/// The file isn't an export this app can read. [message] is the text the
/// import dialog shows, as `crypto.ts` worded it.
class ExportFileError implements Exception {
  const ExportFileError(this.message);

  static const notJson = ExportFileError('Invalid file — not valid JSON.');
  static const notKemlock = ExportFileError('Invalid file — not a Kemlock export.');
  static const encrypted = ExportFileError('File is encrypted — use the encrypted import path.');
  static const noKit = ExportFileError('This export was made without a Recovery Kit.');

  final String message;

  @override
  String toString() => message;
}

const _indent = JsonEncoder.withIndent('  ');

Map<String, Object?> _parse(String text) {
  final Object? parsed;
  try {
    parsed = jsonDecode(text);
  } on FormatException {
    throw ExportFileError.notJson;
  }
  if (parsed is! Map<String, Object?>) throw ExportFileError.notKemlock;
  return parsed;
}

Map<String, Object?> _parseEncrypted(String text) {
  final exported = _parse(text);
  final version = exported['version'];
  if (exported['app'] != formatAppName || version is! num) throw ExportFileError.notKemlock;
  if (version > exportVersion) {
    throw ExportFileError('Unsupported export version ${_jsNumber(version)}. Please update the app.');
  }
  return exported;
}

String _jsNumber(num value) => value == value.roundToDouble() ? value.toInt().toString() : value.toString();

List<OtpAccount> _accounts(Object? list) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) OtpAccount.fromJson(json),
];

List<BackupService> _services(Object? list) => [
  if (list is List)
    for (final json in list)
      if (json is Map<String, Object?>) BackupService.fromJson(json),
];

/// A self-contained encrypted export of the given accounts and services,
/// and the vault's [keys], [notes], [passkeys], [contacts], [logins], [cards] and [identities], and
/// the names of its [keyAccounts], whose secrets stay on their key.
///
/// Each export gets its own ML-KEM-1024 key pair, whose private key is
/// wrapped under [password] (scrypt, then AES-256-GCM); the data is
/// encrypted with a fresh encapsulation of its public key. The file doesn't
/// depend on the vault's password. With the vault's [recoveryKey], the
/// private key gets a second wrap, so the file also opens with the kit.
///
/// The public key is in the file for anyone to read, so the payload is
/// sealed authenticated by the private key, and both wraps say so
/// ([authenticatedWrapNonce]): whoever can change a stored export without
/// its password or kit can't swap what it holds. The file has the shape
/// it always had, so older versions and the TypeScript app read it. That
/// doesn't stop an older export, whose wraps say nothing, being put in
/// its place.
Future<String> exportVault(
  List<OtpAccount> accounts,
  List<BackupService> backupServices,
  String password, {
  List<VaultKey> keys = const [],
  List<SecureNote> notes = const [],
  List<Passkey> passkeys = const [],
  List<KeyAccount> keyAccounts = const [],
  List<Contact> contacts = const [],
  List<Login> logins = const [],
  List<PaymentCard> cards = const [],
  List<Identity> identities = const [],
  RecoveryKey? recoveryKey,
  DeriveKey deriveKey = deriveVaultKey,
  DateTime? now,
}) async {
  final salt = randomBytes(32);
  final kek = await deriveKey(password, salt);
  final pair = MlKem1024.keygen();
  try {
    final wrapped = await aesGcmEncrypt(kek, pair.secretKey, nonce: authenticatedWrapNonce());
    final payload = {
      'accounts': [for (final a in accounts) a.toJson()],
      'backupServices': [for (final s in backupServices) s.toJson()],
      ..._items(keys, notes, passkeys, keyAccounts, contacts, logins, cards, identities),
    };
    final sealed = await sealValue(
      utf8.encode(jsonEncode(payload)),
      pair.publicKey,
      storageKey: exportSealKey,
      authKey: sealAuthKey(pair.secretKey),
    );
    return _indent.convert({
      'version': exportVersion,
      'app': formatAppName,
      'exportedAt': isoString(now ?? DateTime.now()),
      'scheme': 'ML-KEM-1024 + AES-256-GCM + scrypt(N=$scryptN,r=$scryptR,p=$scryptP)',
      'config': {
        'salt': b64(salt),
        'skNonce': b64(wrapped.nonce),
        'skEnc': b64(wrapped.ct),
        'publicKey': b64(pair.publicKey),
        'scrypt': {'N': scryptN, 'r': scryptR, 'p': scryptP},
      },
      'vault': sealed,
      if (recoveryKey != null) 'recovery': await wrapForKit(recoveryKey, pair.secretKey, authenticated: true),
    });
  } finally {
    // The password's key and the file's private key are in the file, wrapped, and nowhere else
    _wipe(kek);
    _wipe(pair.secretKey);
  }
}

void _wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

/// Decrypts an encrypted export with its password. Throws [ExportFileError]
/// for a file this app can't read and [AesGcmAuthError] for a wrong password
/// or tampered data, a payload that isn't authenticated in a file whose
/// wrap says it is included.
Future<VaultExportPayload> importVault(String text, String password, {DeriveKey deriveKey = deriveVaultKey}) async {
  final exported = _parseEncrypted(text);
  final config = exported['config']! as Map<String, Object?>;
  final kek = await deriveKey(password, unb64(config['salt']! as String));
  final Uint8List secretKey;
  try {
    secretKey = await aesGcmDecrypt(kek, unb64(config['skNonce']! as String), unb64(config['skEnc']! as String));
  } finally {
    _wipe(kek);
  }
  try {
    return await _decrypt(exported, secretKey, demand: isAuthenticatedWrapNonce(config['skNonce']));
  } finally {
    _wipe(secretKey);
  }
}

/// The kit an encrypted export can also be opened with, or null.
({String kitId, int threshold})? exportRecoveryKit(String text) {
  try {
    final wrap = (jsonDecode(text) as Map<String, Object?>)['recovery'] as Map<String, Object?>?;
    if (wrap == null) return null;
    return (kitId: wrap['kitId']! as String, threshold: (wrap['threshold']! as num).toInt());
  } catch (_) {
    return null;
  }
}

/// Decrypts an export with its vault's Recovery Kit instead of the export password.
///
/// The payload has to be authenticated when the kit's wrap says so, or the
/// password's does: a kit wrap from an older export doesn't lower what the
/// file demands.
Future<VaultExportPayload> importVaultWithRecoveryKey(String text, Uint8List key) async {
  final exported = _parseEncrypted(text);
  final wrap = exported['recovery'] as Map<String, Object?>?;
  if (wrap == null) throw ExportFileError.noKit;
  final config = exported['config'];
  final demand = isAuthenticatedWrapNonce(wrap['nonce']) || (config is Map<String, Object?> && isAuthenticatedWrapNonce(config['skNonce']));
  final secretKey = await unwrapForKit(wrap, key);
  try {
    return await _decrypt(exported, secretKey, demand: demand);
  } finally {
    _wipe(secretKey);
  }
}

/// The payload of [exported], opened with its [secretKey]. With [demand],
/// one that isn't authenticated by that key is refused as a changed one is.
Future<VaultExportPayload> _decrypt(Map<String, Object?> exported, Uint8List secretKey, {required bool demand}) async {
  final vault = exported['vault']! as Map<String, Object?>;
  final opened = await openSealedValue(vault, secretKey, storageKey: exportSealKey);
  if (demand && !opened.verified) throw const AesGcmAuthError();
  final parsed = jsonDecode(utf8.decode(opened.plain));
  // A version 1 export holds the accounts alone
  if (parsed is List) return VaultExportPayload(accounts: _accounts(parsed), backupServices: const []);
  return _payload(parsed as Map<String, Object?>);
}

/// A plain JSON export, readable by anyone: private keys, passkeys and passwords too.
String exportVaultPlaintext(
  List<OtpAccount> accounts,
  List<BackupService> backupServices, {
  List<VaultKey> keys = const [],
  List<SecureNote> notes = const [],
  List<Passkey> passkeys = const [],
  List<KeyAccount> keyAccounts = const [],
  List<Contact> contacts = const [],
  List<Login> logins = const [],
  List<PaymentCard> cards = const [],
  List<Identity> identities = const [],
  DateTime? now,
}) => _indent.convert({
  'version': exportVersion,
  'app': formatAppName,
  'exportedAt': isoString(now ?? DateTime.now()),
  'scheme': 'plaintext',
  'accounts': [for (final a in accounts) a.toJson()],
  'backupServices': [for (final s in backupServices) s.toJson()],
  ..._items(keys, notes, passkeys, keyAccounts, contacts, logins, cards, identities),
});

/// True for an encrypted export, false for a plain one; throws [ExportFileError] for anything else.
bool isEncryptedExport(String text) {
  final parsed = _parse(text);
  if (parsed['app'] != formatAppName) throw ExportFileError.notKemlock;
  return parsed['scheme'] != 'plaintext';
}

/// Reads a plain export; throws [ExportFileError] for an encrypted or foreign file.
VaultExportPayload importVaultPlaintext(String text) {
  final parsed = _parse(text);
  if (parsed['app'] != formatAppName) throw ExportFileError.notKemlock;
  if (parsed['scheme'] != 'plaintext') throw ExportFileError.encrypted;
  return _payload(parsed);
}
