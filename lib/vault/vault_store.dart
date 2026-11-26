import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import '../core/storage/key_value_store.dart';
import '../crypto/aes_gcm.dart';
import '../crypto/bytes.dart';
import '../crypto/kdf.dart';
import '../crypto/ml_kem.dart';
import '../crypto/p256.dart';
import '../models/backup_service.dart';
import '../models/contact.dart';
import '../models/generated_password.dart';
import '../models/identity.dart';
import '../models/key_account.dart';
import '../models/login.dart';
import '../models/otp_account.dart';
import '../models/passkey.dart';
import '../models/payment_card.dart';
import '../models/secure_note.dart';
import '../models/vault_file.dart';
import '../models/vault_key.dart';
import '../platform/unlock_keys_interface.dart';
import 'biometrics_interface.dart';
import 'key_unlock.dart';
import 'sealed_value.dart';
import 'vault_registry.dart';

// Every vault has its own copy of each key (see VaultRegistry).
const _keyData = 'backmycodes_vault_data';
const _keyBackupData = 'backmycodes_backup_data';

/// The vault's notes. Versions from before notes never read this key, and
/// delete it with the vault, as they do every key of a vault.
const _keyNoteData = 'backmycodes_note_data';

/// The vault's passkeys, kept the same way.
const _keyPasskeyData = 'backmycodes_passkey_data';

/// The vault's key pairs, kept the same way.
const _keyKeyData = 'backmycodes_key_data';

/// The vault's logins, kept the same way (openspec: add-passwords).
const _keyLoginData = 'backmycodes_login_data';

/// The vault's cards, kept the same way. It is written the first time a card
/// is saved, so a vault that never held one has no such key.
const _keyCardData = 'backmycodes_card_data';

/// The vault's identities, kept the same way and only once there is one.
const _keyIdentityData = 'backmycodes_identity_data';

/// The vault's File items (each holds one attached file), kept the same way and only once there is one.
const _keyFileData = 'backmycodes_file_data';

/// The passwords AutoFill generated that no saved login holds, kept the same
/// way for 30 days; never synced or exported.
const _keyGeneratedData = 'backmycodes_generated_data';

/// What the vault remembers of the accounts on a security key: names, never
/// secrets (openspec: add-security-key-codes, decision 3). Kept the same
/// way, and only once there is something to keep.
const _keyKeyAccountData = 'backmycodes_key_account_data';

/// What proves a security key's code password to that key, by the key's
/// id: `{"<device>": "<16 bytes, base64>"}`, sealed like the accounts
/// (decision 8). Never the password. It stays on this phone: it is in no
/// list, so no export, sync file or QR transfer can carry it.
const _keyKeyAccess = 'backmycodes_key_access';

/// Other people's public keys, kept the same way. It is written the first
/// time a contact is saved, so a vault that never held one has no such key.
const _keyContactData = 'backmycodes_contact_data';

/// The private half of the vault's passkey inbox key, made when passkeys
/// are first turned on: new passkeys wait sealed to its public half.
const _keyPasskeyInbox = 'backmycodes_passkey_inbox';

/// The vault's biometric entry as versions before the hardware key wrote it,
/// and as the Capacitor plugin did: the seal key beside the private key it
/// seals, which anything that reads the app's storage can open.
const keyNativeBio = 'backmycodes_native_bio';

/// The vault's biometric entry since its seal key went into the phone's
/// hardware (openspec: harden-unlock-and-clipboard): `{"v": 1, "nonce",
/// "ct", "wrap"}`, the private key sealed under the seal key, and on Android
/// the seal key wrapped by the vault's Keystore key. Nothing in it opens
/// anything without the hardware. It stays on the phone: no export, sync
/// file or Vaultwarden item holds it.
const keyHardwareBio = 'backmycodes_hardware_bio';

/// The Recovery Kit's key, encrypted with the vault, so new exports can carry a copy for it.
const _keyRecovery = 'backmycodes_recovery';

/// A replacement of the vault's key pair under way (openspec:
/// replace-vault-key-pair, decision 1), sealed to the new key pair:
/// `{"v": 1, "previous", "recovery", "inbox", "startedAt"}`, with the old
/// private key, the new kit's record (null without a kit), the new passkey
/// inbox key (only when there is an inbox) and when it started, in ms. It is
/// written before the config changes, so until then no stored key opens it,
/// and deleted once every value is sealed to the new key pair. Older versions
/// never read it, and delete it with the vault.
const keyKeyRotation = 'backmycodes_key_rotation';

/// When the vault's key pair was made, and whether a copy of its private
/// key is known to have been in the app's storage beside the key that opens
/// it, as an old biometric entry kept it (openspec: replace-vault-key-pair,
/// decision 8): `{"madeAt": ms, "exposed": bool, "asked": bool}`, sealed like
/// the accounts, so it is read only once the vault is open. `madeAt` is
/// missing for a key pair made before this was written. Older versions never
/// read it, and delete it with the vault.
const keyKeyInfo = 'backmycodes_key_info';

/// scrypt parameters of every vault, export and sync file (about a quarter of a second on a phone).
const scryptN = 131072;
const scryptR = 8;
const scryptP = 1;

/// The key a password gives with a salt: scrypt with the vault's parameters.
typedef DeriveKey = Future<Uint8List> Function(String password, Uint8List salt);

/// scrypt(password, salt) as raw key bytes, off the UI isolate.
Future<Uint8List> deriveVaultKey(String password, Uint8List salt) =>
    scryptInBackground(utf8.encode(password), salt, n: scryptN, r: scryptR, p: scryptP);

/// An unlocked vault's keys, kept in memory only.
class VaultSession {
  VaultSession({required this.publicKey, required this.secretKey, this._authenticated = false});

  /// The session of a private key just opened, with the public key it holds.
  ///
  /// The public key is never read from the vault's config, which is stored in
  /// the clear: whoever could write that file would put a key of their own
  /// there, and everything saved from then on would be sealed to them.
  factory VaultSession.holding(Uint8List secretKey, {bool authenticated = false}) =>
      VaultSession(publicKey: MlKem1024.publicKeyOf(secretKey), secretKey: secretKey, authenticated: authenticated);

  /// ML-KEM-1024 public key, needed to encrypt on save.
  final Uint8List publicKey;

  /// The decrypted ML-KEM-1024 private key. Never written to storage.
  final Uint8List secretKey;

  /// The vault's values are authenticated (sealed_value.dart): one that was
  /// not sealed by a holder of the private key, for the key it is stored
  /// under, is refused as a changed one is. True when the wrap of the
  /// private key this session was opened through says so, or the config's
  /// own wrap does; a vault from before values were authenticated is read
  /// as it always was until it moves over ([VaultStore._moveOver]), and
  /// from then on in this session too. It is never lowered.
  ///
  /// Values are sealed authenticated whatever this says: it decides what is
  /// demanded of a value read, not what is written.
  bool get authenticated => _authenticated;
  bool _authenticated;
}

/// A Recovery Kit's key and how it was split.
class RecoveryKey {
  const RecoveryKey({required this.kitId, required this.key, required this.threshold, required this.shares, required this.createdAt});

  final String kitId;
  final Uint8List key;

  /// Pieces needed to rebuild the key.
  final int threshold;

  /// Pieces made.
  final int shares;

  /// ISO 8601, as `Date.toISOString()` writes it.
  final String createdAt;
}

/// When and how a vault's kit was made.
class RecoveryKitInfo {
  const RecoveryKitInfo({required this.kitId, required this.threshold, required this.shares, required this.createdAt});

  final String kitId;
  final int threshold;
  final int shares;
  final String createdAt;

  @override
  bool operator ==(Object other) =>
      other is RecoveryKitInfo &&
      other.kitId == kitId &&
      other.threshold == threshold &&
      other.shares == shares &&
      other.createdAt == createdAt;

  @override
  int get hashCode => Object.hash(kitId, threshold, shares, createdAt);
}

/// No vault, or no vault config, where one was needed.
class VaultMissingError implements Exception {
  const VaultMissingError([this.message = 'No vault found. Please set up a master password first.']);

  final String message;

  @override
  String toString() => message;
}

/// The password opens no vault the lock screen may open with it.
class IncorrectPasswordError implements Exception {
  const IncorrectPasswordError();

  @override
  String toString() => 'Incorrect password.';
}

/// Another vault on the device already opens with this password.
class PasswordInUseError implements Exception {
  const PasswordInUseError();

  @override
  String toString() => 'Another vault already uses this password.';
}

/// No vault on this device has the kit these pieces belong to.
class KitNotFoundError implements Exception {
  const KitNotFoundError();

  @override
  String toString() => 'This Recovery Kit doesn’t belong to a vault on this device.';
}

/// What a security key gave: the credential that answered and its secret
/// for the vault's salt (openspec: add-security-key-unlock).
typedef KeyReading = ({Uint8List credential, Uint8List output});

/// What to send a key to get its secret for a vault: the vault's salt and
/// its credentials, one of which an enrolled key holds.
typedef KeyChallenge = ({Uint8List salt, List<Uint8List> credentials});

/// That whoever is at the phone gave what opens a vault now (openspec:
/// add-security-key-unlock, decision 9): the pieces [VaultStore.proveOwner]
/// checked against the vault's config, kept in memory for the action they
/// allow and cleared with [wipe] when it is over.
class OwnerProof {
  OwnerProof._(this.vault, this.passwordKey, this.keySecret);

  /// The vault it was given for.
  final String vault;

  /// The password's key, when the vault has a password.
  final Uint8List? passwordKey;

  /// The key secret, when an enrolled key was presented.
  final Uint8List? keySecret;

  /// Clears the secrets. The proof allows nothing afterwards.
  void wipe() {
    passwordKey?.fillRange(0, passwordKey!.length, 0);
    keySecret?.fillRange(0, keySecret!.length, 0);
  }
}

/// The right password of a vault that needs both was typed: the vault it
/// belongs to and the password's key, in memory only, until an enrolled key
/// finishes the unlock or the lock screen drops the step (decision 7).
class PendingKeyStep {
  PendingKeyStep._(this.vault, this.passwordKey);

  final String vault;
  final Uint8List passwordKey;

  /// Clears the password's key. The step opens nothing afterwards.
  void wipe() => passwordKey.fillRange(0, passwordKey.length, 0);
}

/// What a password typed on the lock screen did.
sealed class UnlockStep {
  const UnlockStep();
}

/// It opened a vault.
class UnlockOpened extends UnlockStep {
  const UnlockOpened(this.session);

  final VaultSession session;
}

/// It is the password of a vault that needs both; the key is asked next.
class UnlockNeedsKey extends UnlockStep {
  const UnlockNeedsKey(this.pending);

  final PendingKeyStep pending;
}

/// The password is right, and the vault it belongs to also needs a security key.
class SecurityKeyNeededError implements Exception {
  const SecurityKeyNeededError(this.pending);

  final PendingKeyStep pending;

  @override
  String toString() => 'This vault also needs its security key.';
}

/// The key presented is not one of the vault's enrolled keys, or what it
/// gave does not open the vault.
class KeyNotEnrolledError implements Exception {
  const KeyNotEnrolledError();

  @override
  String toString() => 'This security key does not open this vault.';
}

/// The key presented already opens the vault.
class KeyAlreadyEnrolledError implements Exception {
  const KeyAlreadyEnrolledError();

  @override
  String toString() => 'This security key already opens this vault.';
}

/// What was given does not hold what the vault's way of opening needs: the
/// password, an enrolled key, or both.
class ProofIncompleteError implements Exception {
  const ProofIncompleteError();

  @override
  String toString() => 'What opens this vault now is needed first.';
}

/// The change would leave a vault that needs a key with one key and no
/// Recovery Kit, or with neither a kit nor two keys (decision 8): a lost
/// key would then lock it for good.
class SafetyNetError implements Exception {
  const SafetyNetError();

  @override
  String toString() => 'A vault that needs a key keeps a Recovery Kit or a second key.';
}

/// The last key of a vault that needs one cannot be removed.
class LastKeyError implements Exception {
  const LastKeyError();

  @override
  String toString() => 'This vault needs a key: its last one cannot be removed.';
}

/// A vault cannot open with a key alone while one of its keys gives its
/// secret on a touch, without its PIN (decision 6).
class KeyNotPinBoundError implements Exception {
  const KeyNotPinBoundError();

  @override
  String toString() => 'A key of this vault does not tie its secret to its PIN.';
}

/// A hidden vault opens with its password or with both, never with a key
/// alone: its password is the only way it is ever found.
class HiddenVaultKeyOnlyError implements Exception {
  const HiddenVaultKeyOnlyError();

  @override
  String toString() => 'A hidden vault cannot open with a key alone.';
}

/// What a vault knows about its key pair (decision 8 of
/// replace-vault-key-pair).
class KeyInfo {
  const KeyInfo({this.madeAt, required this.exposed, required this.asked});

  /// When the key pair was made; null when it was made before this was kept.
  final DateTime? madeAt;

  /// A copy of the private key was in the app's storage beside the key that
  /// opens it, so phone backups made meanwhile hold it.
  final bool exposed;

  /// The person was offered, once, to replace an exposed key pair.
  final bool asked;

  Map<String, Object?> toJson() => {if (madeAt case final at?) 'madeAt': at.millisecondsSinceEpoch, 'exposed': exposed, 'asked': asked};

  static KeyInfo fromJson(Map<String, Object?> json) => KeyInfo(
    madeAt: json['madeAt'] is num ? DateTime.fromMillisecondsSinceEpoch((json['madeAt']! as num).toInt()) : null,
    exposed: json['exposed'] == true,
    asked: json['asked'] == true,
  );

  /// The same moment, in whatever time zone.
  @override
  bool operator ==(Object other) =>
      other is KeyInfo &&
      other.madeAt?.millisecondsSinceEpoch == madeAt?.millisecondsSinceEpoch &&
      other.exposed == exposed &&
      other.asked == asked;

  @override
  int get hashCode => Object.hash(madeAt?.millisecondsSinceEpoch, exposed, asked);

  @override
  String toString() => 'KeyInfo(madeAt: $madeAt, exposed: $exposed, asked: $asked)';
}

/// A replacement of the vault's key pair got past its commit, but some
/// values open with neither the new key nor the previous one, so they were
/// unreadable already (openspec: replace-vault-key-pair, decision 2). They are
/// left as they are, and so is the previous key, which a later version can
/// try them with again; everything else is sealed to the new pair.
class KeyReplacementIncomplete implements Exception {
  const KeyReplacementIncomplete(this.session, this.unreadable);

  /// The vault's new key pair, which the vault now opens with.
  final VaultSession session;

  /// The storage keys of the values neither key opens.
  final List<String> unreadable;

  @override
  String toString() => 'The vault’s key was replaced, but ${unreadable.length} values open with neither key.';
}

/// What a biometric unlock did (openspec: harden-unlock-and-clipboard,
/// decision 5).
enum BiometricOutcome {
  /// The hardware entry opened the vault.
  opened,

  /// The old entry opened the vault, and a hardware entry was written beside
  /// it: the vault's seal key had been in the app's storage until now.
  moved,

  /// The hardware entry failed for a reason of its own, and the old entry
  /// opened the vault after `local_auth`'s prompt.
  fellBack,

  /// Biometrics changed or the passcode went: both entries and the key were
  /// deleted, and the password is needed.
  invalidated,

  /// The phone has no biometrics the key can be bound to, so the old entry,
  /// which can't move, was deleted.
  unsupported,

  /// The prompt was cancelled; nothing changed.
  cancelled,
}

/// A biometric unlock's session, when it opened the vault, and what it did.
typedef BiometricUnlock = ({VaultSession? session, BiometricOutcome outcome});

/// The post-quantum vault, as `crypto.ts` keeps it.
///
/// The master password goes through scrypt to a 32-byte key that wraps the
/// vault's ML-KEM-1024 private key with AES-256-GCM. Each save encapsulates
/// a fresh shared secret against the public key and encrypts the JSON with
/// it, so every save has its own data key. Storage reads and writes go to
/// the registry's active vault unless another id is given.
class VaultStore {
  VaultStore(
    this._store,
    this._vaults, {
    this._deriveKey = deriveVaultKey,
    this._unlockKeys = const NoUnlockKeys(),
    this._clock = DateTime.now,
  });

  final KeyValueStore _store;
  final VaultRegistry _vaults;
  final DeriveKey _deriveKey;

  /// The phone's hardware keys behind biometric unlock.
  final UnlockKeys _unlockKeys;

  /// Now, for when a key pair was made.
  final DateTime Function() _clock;

  /// A replacement of a key pair under way, which every other load and save
  /// waits for (openspec: replace-vault-key-pair, decision 6).
  Completer<void>? _replacing;

  /// Saves under way, which a replacement lets land before it starts.
  var _saving = 0;
  Completer<void>? _saved;

  /// The public key each key pair replaced while the app ran was replaced
  /// with, so a save given the old session, by something that held it
  /// across the replacement, seals to the new pair instead; and the new
  /// pair's seal key ([sealAuthKey]), so that save is authenticated like any
  /// other. No private key outlives its session here: the seal key opens
  /// nothing, though it vouches for what it seals, so it stays in memory.
  final Map<String, ({Uint8List publicKey, Uint8List authKey})> _successors = {};

  /// Waits while a key pair is being replaced.
  Future<void> _whileReplacing() async {
    for (var running = _replacing; running != null; running = _replacing) {
      await running.future;
    }
  }

  Map<String, Object?>? _readConfig([String? id]) {
    final raw = _store.getItem(_vaults.vaultKey(keyConfig, id));
    return raw == null ? null : jsonDecode(raw) as Map<String, Object?>;
  }

  void _writeConfig(Map<String, Object?> config, [String? id]) => _store.setItem(_vaults.vaultKey(keyConfig, id), jsonEncode(config));

  /// Whether [config]'s wrap of the private key says the vault's values are
  /// authenticated ([authenticatedWrapNonce]).
  static bool _authenticated(Map<String, Object?>? config) => isAuthenticatedWrapNonce(config?['skNonce']);

  /// The nonce of a new wrap of the private key of the vault [config] is
  /// of: one that says its values are authenticated when they are, and
  /// none, so a random one, for a vault from before they were. A wrap that
  /// said so of a vault whose values are not would shut it.
  static Uint8List? _wrapNonce(Map<String, Object?>? config) => _authenticated(config) ? authenticatedWrapNonce() : null;

  /// The scrypt salt of the vault [config] is of, as stored, which a new
  /// password keeps; a fresh one only for a config without any. Vaults
  /// share the first one's salt, so the lock screen tries a password on
  /// every hidden vault with one derivation ([_openFirst]): a salt of its
  /// own would make a wrong password take one more, about a quarter of a
  /// second, only on a phone with a hidden vault, which anyone holding it
  /// could time.
  static String _keptSalt(Map<String, Object?> config) => switch (config['salt']) {
    final String salt => salt,
    _ => b64(randomBytes(32)),
  };

  /// The session of [secretKey], opened through a wrap whose nonce is
  /// [wrapNonce] in the vault [config] is of. Its values are authenticated
  /// when that wrap says so or the config's own does: a wrap of another
  /// kind made earlier, a Recovery Kit's or a biometric entry's, doesn't
  /// lower what the vault demands.
  static VaultSession _sessionThrough(Object? wrapNonce, Map<String, Object?>? config, Uint8List secretKey) =>
      VaultSession.holding(secretKey, authenticated: isAuthenticatedWrapNonce(wrapNonce) || _authenticated(config));

  /// True when any vault exists on this device.
  bool isVaultSetup() => _vaults.allVaultIds().isNotEmpty;

  /// Creates an ML-KEM-1024 key pair, wraps the private key under the
  /// password, and saves the config, in the active vault unless another id
  /// is given. A new vault's values are authenticated from the start.
  Future<VaultSession> setupVault(String password, {String? id, String? name, Uint8List? salt}) async {
    final keySalt = salt ?? randomBytes(32);
    final kek = await _deriveKey(password, keySalt);
    final pair = MlKem1024.keygen();
    final ({Uint8List nonce, Uint8List ct}) wrapped;
    try {
      wrapped = await aesGcmEncrypt(kek, pair.secretKey, nonce: authenticatedWrapNonce());
    } finally {
      _wipe(kek);
    }
    _writeConfig({
      'salt': b64(keySalt),
      'skNonce': b64(wrapped.nonce),
      'skEnc': b64(wrapped.ct),
      'publicKey': b64(pair.publicKey),
      'scrypt': {'N': scryptN, 'r': scryptR, 'p': scryptP},
      if (name != null && name.isNotEmpty) 'name': name,
    }, id);
    final session = VaultSession(publicKey: pair.publicKey, secretKey: pair.secretKey, authenticated: true);
    // A new key pair, whose private key has never been anywhere but here
    await _writeKeyInfo(id ?? _vaults.active, session, KeyInfo(madeAt: _clock(), exposed: false, asked: false));
    return session;
  }

  /// Opens the active vault with its password; throws [AesGcmAuthError] on a wrong one.
  Future<VaultSession> unlockVault(String password) async {
    final config = _readConfig();
    if (config == null) throw const VaultMissingError();
    final kek = await _deriveKey(password, unb64(config['salt']! as String));
    try {
      return await _open(config, kek);
    } finally {
      _wipe(kek);
    }
  }

  Future<VaultSession> _open(Map<String, Object?> config, Uint8List kek) async {
    final secretKey = await aesGcmDecrypt(kek, unb64(config['skNonce']! as String), unb64(config['skEnc']! as String));
    return VaultSession.holding(secretKey, authenticated: _authenticated(config));
  }

  /// Tries the password on each vault in [ids] and returns the first that
  /// opens. Vaults sharing a salt share one scrypt run, so checking hidden
  /// vaults stays cheap.
  ///
  /// The plain wrap is tried on every vault, whatever its mode says, so a
  /// password takes the same work whether the vault opens with a password,
  /// a key or both (openspec: add-security-key-unlock, decision 7). For a
  /// vault that needs both, the password is then compared with the vault's
  /// check: the first that passes is returned with the password's key and
  /// no session, since the key is still to come.
  ///
  /// The password's key comes back as a copy, which the caller clears once
  /// it is done with it; every key derived here is cleared before it returns.
  Future<({String id, VaultSession? session, Uint8List passwordKey})?> _openFirst(String password, Iterable<String> ids) async {
    final keks = <String, Uint8List>{};
    try {
      for (final id in ids) {
        final config = _readConfig(id);
        if (config == null) continue;
        final salt = config['salt']! as String;
        final kek = keks[salt] ??= await _deriveKey(password, unb64(salt));
        try {
          return (id: id, session: await _open(config, kek), passwordKey: Uint8List.fromList(kek));
        } on AesGcmAuthError {
          // Not this vault's password, or not all that opens it
        }
        final unlock = KeyUnlock.of(config);
        if (unlock != null && unlock.mode == UnlockMode.both && sameBytes(passwordCheck(kek, unlock.salt), unlock.check!)) {
          return (id: id, session: null, passwordKey: Uint8List.fromList(kek));
        }
      }
      return null;
    } finally {
      keks.values.forEach(_wipe);
    }
  }

  /// Takes the password typed on the lock screen for the vault chosen
  /// there or for a hidden vault. A vault it opens becomes the active
  /// vault. When it is the password of a vault that also needs a security
  /// key, nothing opens and nothing is written: the pending step it
  /// returns goes to [unlockWithSecurityKey] with what an enrolled key
  /// gave. Throws [IncorrectPasswordError] for a password that is neither.
  Future<UnlockStep> beginUnlock(String password, String? chosen) async {
    final order = {?chosen, ..._vaults.hiddenVaultIds()};
    final found = await _openFirst(password, order);
    if (found == null) throw const IncorrectPasswordError();
    final session = found.session;
    // The step keeps the password's key until the lock screen wipes it
    if (session == null) return UnlockNeedsKey(PendingKeyStep._(found.id, found.passwordKey));
    try {
      _repairPlainWrap(found.id);
      _vaults.active = found.id;
      await _afterUnlock(found.id, session, wrapKey: found.passwordKey);
    } finally {
      _wipe(found.passwordKey);
    }
    return UnlockOpened(session);
  }

  /// Whether [password] is the password of [vault], checked and nothing more: no hidden vault is
  /// tried, nothing is opened or written, and the active vault stays as it is. A vault that needs a
  /// security key as well counts when the password is its own. For a caller that already holds the
  /// open vault and wants to be sure it is the person at it (an export asks it again).
  Future<bool> passwordOpens(String password, String vault) async {
    final found = await _openFirst(password, [vault]);
    if (found == null) return false;
    found.session?.secretKey.fillRange(0, found.session!.secretKey.length, 0);
    _wipe(found.passwordKey);
    return true;
  }

  /// Unlocks the vault chosen on the lock screen, or a hidden vault whose
  /// password this is, and makes it the active vault. Throws
  /// [SecurityKeyNeededError], with the pending step, for the password of a
  /// vault that also needs its security key: see [beginUnlock].
  Future<VaultSession> unlockAnyVault(String password, String? chosen) async => switch (await beginUnlock(password, chosen)) {
    UnlockOpened(:final session) => session,
    UnlockNeedsKey(:final pending) => throw SecurityKeyNeededError(pending),
  };

  /// A vault whose config says it needs a key, but whose private key the
  /// password alone just opened: a version from before security keys
  /// opened it with its Recovery Kit and set a password, writing the plain
  /// wrap and keeping a `keyUnlock` it does not read (decision 13). The
  /// kit's reset removes the keys here too, so `keyUnlock` goes.
  void _repairPlainWrap(String vault) {
    final config = _readConfig(vault);
    final unlock = KeyUnlock.of(config);
    if (config == null || unlock == null || !unlock.mode.needsKey) return;
    _writeConfig({...config}..remove('keyUnlock'), vault);
  }

  /// Opens [vault] with what one of its enrolled keys gave, and makes it
  /// the active vault: a vault that opens with a key alone, or, with the
  /// [pending] step its password gave, a vault that needs both. It ends as
  /// every unlock does, so a key-pair replacement cut short is finished.
  ///
  /// Throws [KeyNotEnrolledError] when the key is not one of the vault's or
  /// what it gave opens nothing, and [ProofIncompleteError] for a vault
  /// that needs both without its pending step. Nothing is written for a
  /// key that does not open the vault.
  Future<VaultSession> unlockWithSecurityKey(String vault, KeyReading key, {PendingKeyStep? pending}) async {
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    final entry = unlock?.keyFor(key.credential);
    if (unlock == null || entry == null) throw const KeyNotEnrolledError();
    // A vault that opens with its password has no key step
    if (!unlock.mode.needsKey) throw const ProofIncompleteError();
    if (unlock.mode == UnlockMode.both && (pending == null || pending.vault != vault)) throw const ProofIncompleteError();
    final Uint8List keySecret;
    try {
      keySecret = await unwrapKeySecret(entry, key.output, unlock.salt);
    } on AesGcmAuthError {
      throw const KeyNotEnrolledError();
    }
    // Derived for this unlock in mode "key" or "both", never the password's key itself
    final Uint8List wrapKey;
    try {
      wrapKey = _wrapKey(unlock.mode, unlock, pending?.passwordKey, keySecret);
    } finally {
      _wipe(keySecret);
    }
    final VaultSession session;
    try {
      session = await _open(config, wrapKey);
    } on AesGcmAuthError {
      _wipe(wrapKey);
      throw const KeyNotEnrolledError();
    }
    _vaults.active = vault;
    try {
      // What opened the vault's wrap, so a vault from before authenticated values moves over here,
      // a vault that opens with a key alone included
      await _afterUnlock(vault, session, wrapKey: wrapKey);
    } finally {
      _wipe(wrapKey);
    }
    return session;
  }

  /// True when the password already opens a vault on this device, or is
  /// the password of one that also needs a security key.
  Future<bool> passwordOpensAVault(String password) async {
    final found = await _openFirst(password, _vaults.allVaultIds());
    if (found == null) return false;
    // Opened only to tell: the key and the private key it gave go at once
    _wipe(found.passwordKey);
    if (found.session case final session?) _wipe(session.secretKey);
    return true;
  }

  /// Adds a vault next to the current one and returns its id. It shares the
  /// first vault's scrypt salt, so the lock screen can test a password
  /// against every hidden vault with a single derivation.
  Future<String> createVault(String name, String password, {required bool listed}) async {
    // One password must open one vault, or the lock screen couldn't tell which was meant
    if (await passwordOpensAVault(password)) throw const PasswordInUseError();
    final id = VaultRegistry.newVaultId();
    final existing = _readConfig(mainVault) ?? (_vaults.allVaultIds().isEmpty ? null : _readConfig(_vaults.allVaultIds().first));
    await setupVault(password, id: id, name: name.trim(), salt: existing == null ? null : unb64(existing['salt']! as String));
    _vaults.setListed(id, listed);
    return id;
  }

  /// Renames a vault; an empty name gives the first vault back its default label.
  void renameVault(String id, String name) {
    final config = _readConfig(id);
    if (config == null) return;
    final trimmed = name.trim();
    final next = {...config}..remove('name');
    _writeConfig({...next, if (trimmed.isNotEmpty) 'name': trimmed}, id);
  }

  /// Re-wraps the private key under a new password, keeping the key pair, the
  /// scrypt salt and everything else in the config, such as passkeys the web
  /// build registered.
  ///
  /// With security keys enrolled (openspec: add-security-key-unlock,
  /// decision 9), it takes [proof], what opens the vault now, and the keys
  /// stay: a vault that needs both gets a new password check and its
  /// private key under the new password's key and the same key secret, so
  /// every enrolled key works with the new password and the old password
  /// opens nothing. Without a proof such a vault throws
  /// [ProofIncompleteError] and changes nothing; the Recovery Kit's way
  /// back to a password is [resetToPassword]. A vault that opens with a
  /// key alone has no password to change: its mode is changed with
  /// [setUnlockMode].
  Future<VaultSession> changePassword(VaultSession session, String newPassword, {OwnerProof? proof}) async {
    final config = _readConfig();
    if (config == null) throw const VaultMissingError('No vault config found.');
    final unlock = KeyUnlock.of(config);
    if (proof != null) {
      await _check(_vaults.active, config, proof, session);
      if (unlock != null && !unlock.mode.hasPassword) throw StateError('A vault that opens with a key alone has no password to change.');
    } else if (unlock != null) {
      throw const ProofIncompleteError();
    }
    return _writePassword(config, unlock, session, newPassword, proof);
  }

  /// Gives the active vault, opened in [session] by its Recovery Kit, a new
  /// password that opens it alone (openspec: add-security-key-unlock,
  /// decision 11). The kit gives no key secret, so a vault with security
  /// keys goes back to opening with its password, and its `keyUnlock`,
  /// with every enrolled key, is removed. A vault without keys gets what
  /// [changePassword] writes, byte for byte.
  Future<VaultSession> resetToPassword(VaultSession session, String newPassword) async {
    final config = _readConfig();
    if (config == null) throw const VaultMissingError('No vault config found.');
    return _writePassword(config, KeyUnlock.of(config), session, newPassword, null);
  }

  /// The private key under [newPassword], with the vault's own salt
  /// ([_keptSalt]): with [proof], in the vault's mode, and without one,
  /// alone, `keyUnlock` going with the keys. A vault from before
  /// authenticated values moves over on the way, the new wrap being its
  /// commit.
  Future<VaultSession> _writePassword(
    Map<String, Object?> config,
    KeyUnlock? unlock,
    VaultSession session,
    String newPassword,
    OwnerProof? proof,
  ) async {
    final salt = _keptSalt(config);
    final kek = await _deriveKey(newPassword, unb64(salt));
    var wrapKey = kek;
    KeyUnlock? changed;
    final moving = !_authenticated(config);
    final ({Uint8List nonce, Uint8List ct}) wrapped;
    try {
      if (unlock != null && proof != null && unlock.mode == UnlockMode.both) {
        final keySecret = proof.keySecret ?? (throw const ProofIncompleteError());
        changed = unlock.copyWith(check: passwordCheck(kek, unlock.salt));
        wrapKey = bothModeWrapKey(kek, keySecret, unlock.salt);
      }
      if (moving) await _moveValues(_vaults.active, session);
      wrapped = await aesGcmEncrypt(wrapKey, session.secretKey, nonce: authenticatedWrapNonce());
    } finally {
      _wipe(kek);
      if (!identical(wrapKey, kek)) _wipe(wrapKey);
    }
    final next = {
      ...config,
      'salt': salt,
      'skNonce': b64(wrapped.nonce),
      'skEnc': b64(wrapped.ct),
      'scrypt': {'N': scryptN, 'r': scryptR, 'p': scryptP},
    };
    if (changed != null) {
      next['keyUnlock'] = changed.toJson();
    } else if (unlock != null && proof == null) {
      // The Recovery Kit's reset: the plain wrap, and no key left enrolled
      next.remove('keyUnlock');
    }
    if (moving) await _authenticateKitWrap(_vaults.active, next, session);
    _writeConfig(next);
    if (moving) session._authenticated = true;
    return session;
  }

  // ─── Replacing the key pair ────────────────────────────────────────────────
  //
  // openspec: replace-vault-key-pair, decision 1. A copy of the private key,
  // such as the one an old phone backup holds, keeps opening every value
  // sealed to its pair, so the vault gets a new pair and every value is
  // sealed to it again, in place. The old private key is written down first,
  // sealed to the new pair only; one write of the config is the commit.
  // Cut short before it, the vault is as it was; after it, the new key opens
  // the config and so the old key, and the next unlock finishes the work.

  /// Gives the active vault, open in [session], a new key pair, once
  /// [password] opens the vault as it is now; returns the new session.
  ///
  /// A vault with a Recovery Kit needs a new [kit], made and saved by the
  /// person beforehand, or [dropKit]: the old kit's key was sealed to the old
  /// pair, so it can't open the new one (decision 4). The password, its salt
  /// and everything that travels stay as they are. Throws
  /// [IncorrectPasswordError] and changes nothing when the password doesn't
  /// open the vault, and [KeyReplacementIncomplete], with the new session,
  /// when the vault holds values neither key opens. Until it returns, nothing
  /// else may write to the vault (decision 6): the caller holds the other
  /// writes.
  ///
  /// A vault that needs a security key takes [proof] in place of the
  /// password, which alone opens nothing there (openspec:
  /// add-security-key-unlock, decision 10). The new private key is wrapped
  /// under the same wrap key, whatever the mode, and `keyUnlock` stays as it
  /// is: the key secret never sat where the old private key could open it,
  /// so every enrolled key keeps working.
  Future<VaultSession> replaceKeyPair(
    VaultSession session,
    String password, {
    RecoveryKey? kit,
    bool dropKit = false,
    OwnerProof? proof,
  }) async {
    if (_replacing != null) throw StateError('A key pair is being replaced already.');
    final running = _replacing = Completer<void>();
    try {
      return await _replaceKeyPair(session, password, kit: kit, dropKit: dropKit, proof: proof);
    } finally {
      _replacing = null;
      running.complete();
    }
  }

  Future<VaultSession> _replaceKeyPair(
    VaultSession session,
    String password, {
    RecoveryKey? kit,
    required bool dropKit,
    OwnerProof? proof,
  }) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final hadKit = config['recovery'] != null;
    if (kit != null && (!hadKit || dropKit)) throw ArgumentError.value(kit, 'kit', 'Only a vault with a kit gets a new one');
    if (hadKit && kit == null && !dropKit) throw ArgumentError.value(kit, 'kit', 'The vault has a kit: give the new one, or drop it');
    // A vault that needs a key keeps its kit unless a second key is there (add-security-key-unlock, decision 8)
    if (dropKit && recoveryKitIsLastWayBack()) throw const SafetyNetError();
    // 1. The password, or the proof of a vault that needs a key, against the vault as it is now
    final kek = proof != null
        ? await _checkProof(vault, config, proof, session)
        : await _deriveKey(password, unb64(config['salt']! as String));
    try {
      final Uint8List previous;
      try {
        previous = (await _open(config, kek)).secretKey;
      } on AesGcmAuthError {
        throw const IncorrectPasswordError();
      }
      if (b64(previous) != b64(session.secretKey)) throw StateError('The session isn’t the vault’s own key pair.');
      // 2. Saves already under way land before any of this, sealed to the old pair, so the walk finds
      // them; saves started from now on wait for the replacement (decision 6)
      while (_saving > 0) {
        await (_saved ??= Completer<void>()).future;
      }
      await _store.flush();
      // 3. The new pair, whose values are authenticated when the old pair's are
      final pair = MlKem1024.keygen();
      final next = VaultSession(publicKey: pair.publicKey, secretKey: pair.secretKey, authenticated: _authenticated(config));
      // 4. Both biometric entries hold the old private key, and would pair it with the new public key
      // after the commit (decision 5). Cut short here, the vault loses only biometric unlock, which the
      // next password unlock offers again.
      _store.removeItem(_vaults.vaultKey(keyNativeBio, vault));
      _store.removeItem(_vaults.vaultKey(keyHardwareBio, vault));
      try {
        await _unlockKeys.delete(vault);
      } on Exception {
        // Without its entry the key opens nothing; turning biometric unlock on again replaces it
      }
      // 5. The old key, under the new pair only
      final rotation = {
        'v': 1,
        'previous': b64(previous),
        'recovery': kit == null ? null : _kitRecord(kit),
        // Made now, so a run cut short and finished later hands the inbox this key, not a second one
        if (_store.getItem(_vaults.vaultKey(_keyPasskeyInbox, vault)) != null) 'inbox': b64(newP256KeyPair().toPkcs8()),
        'startedAt': _clock().millisecondsSinceEpoch,
      };
      final rotationKey = _vaults.vaultKey(keyKeyRotation, vault);
      _store.setItem(rotationKey, await _seal(rotationKey, utf8.encode(jsonEncode(rotation)), next));
      // 6. The commit: the new private key under the same wrap key and salt, the new kit's wrap
      // or none, every other key kept where it was
      final wrapped = await aesGcmEncrypt(kek, next.secretKey, nonce: _wrapNonce(config));
      final committed = {...config, 'skNonce': b64(wrapped.nonce), 'skEnc': b64(wrapped.ct), 'publicKey': b64(next.publicKey)};
      if (kit != null) {
        committed['recovery'] = await wrapForKit(kit, next.secretKey, authenticated: next.authenticated);
      } else {
        committed.remove('recovery');
      }
      _writeConfig(committed, vault);
      // A save that waited, given the old session, seals to the new pair
      _successors[b64(session.publicKey)] = (publicKey: next.publicKey, authKey: sealAuthKey(next.secretKey));
      // 7 and 8
      await _finishReplacement(vault, next, rotation);
      return next;
    } finally {
      // The password's key derived here; a proof's own key is its holder's to clear
      if (!identical(kek, proof?.passwordKey)) _wipe(kek);
    }
  }

  /// Run at every unlock of [vault], before anything is loaded: settles a
  /// replacement of its key pair cut short, then learns what it can about a
  /// key pair made before this version kept track.
  ///
  /// An unlock that needed no biometric entry (the password, a security
  /// key, the Recovery Kit) also deletes the old entry, which keeps the
  /// private key beside the key that opens it: it would otherwise stay in
  /// storage, and in every phone backup, until biometrics had opened the
  /// vault twice, and for good in a vault that is hidden or always opened
  /// with its password. With [byBiometrics] it stays, for the biometric
  /// unlock's own steps to move and delete.
  ///
  /// Given the [wrapKey] that opened the config's wrap, as an unlock by
  /// password or security key has it, a vault from before authenticated
  /// values then moves over.
  Future<void> _afterUnlock(String vault, VaultSession session, {Uint8List? wrapKey, bool byBiometrics = false}) async {
    await _resumeReplacement(vault, session);
    await _classifyKey(vault, session);
    if (!byBiometrics) await _dropOldEntry(vault, session);
    if (wrapKey != null) await _moveOver(vault, session, wrapKey);
  }

  // ─── Moving a vault over to authenticated values ───────────────────────────
  //
  // A vault from before values were authenticated (sealed_value.dart) has
  // no wrap that says so, and its values are sealed with the public key
  // alone. It moves over where the key that wraps its private key is at
  // hand: at an unlock by password or security key, and wherever a new
  // password wrap is written. Every value is sealed again, under its own
  // key; both biometric entries go, as the hardware one can't be wrapped
  // again without its prompt; then one write of the config, its wraps
  // saying the values are authenticated, is the commit. Cut short before
  // it, the vault opens as before, since an authenticated seal reads in a
  // session that demands nothing, and the next time finishes the work.
  // A vault opened by biometrics alone stays as it is until then.
  //
  // What was in the vault before the move is taken for its own: nothing
  // can tell a value someone else sealed then from one the vault did.

  /// Moves [vault], open in [session] through [wrapKey], over at an unlock.
  Future<void> _moveOver(String vault, VaultSession session, Uint8List wrapKey) async {
    final before = _readConfig(vault);
    if (before == null || _authenticated(before)) return;
    // The wrap is made again under the key that opens it as it is now, or not at all
    try {
      final opened = await aesGcmDecrypt(wrapKey, unb64(before['skNonce']! as String), unb64(before['skEnc']! as String));
      final same = sameBytes(opened, session.secretKey);
      _wipe(opened);
      if (!same) return;
    } on AesGcmAuthError {
      return;
    }
    await _moveValues(vault, session);
    final config = _readConfig(vault);
    if (config == null || config['skNonce'] != before['skNonce'] || config['skEnc'] != before['skEnc']) return;
    final wrapped = await aesGcmEncrypt(wrapKey, session.secretKey, nonce: authenticatedWrapNonce());
    final next = {...config, 'skNonce': b64(wrapped.nonce), 'skEnc': b64(wrapped.ct)};
    await _authenticateKitWrap(vault, next, session);
    // The commit
    _writeConfig(next, vault);
    await _store.flush();
    session._authenticated = true;
  }

  /// What moving [vault] over does before its commit: every value
  /// [session]'s private key opens, those of newer versions included, is
  /// sealed again, byte for byte the same plaintext, authenticated for the
  /// key it sits under; then both biometric entries and the hardware key go.
  /// A value that doesn't open is left as it is, as a key replacement
  /// leaves it. Run again, it seals nothing twice.
  Future<void> _moveValues(String vault, VaultSession session) async {
    for (final key in sealedValueKeys(vault)) {
      final raw = _store.getItem(key);
      if (raw == null) continue;
      final ({Uint8List plain, bool verified}) opened;
      try {
        opened = await openSealedValue(jsonDecode(raw) as Map<String, Object?>, session.secretKey, storageKey: key);
      } catch (_) {
        // Sealed to another key, or damaged
        continue;
      }
      if (opened.verified) continue;
      final sealed = await _seal(key, opened.plain, session);
      // A save that landed meanwhile is newer, and authenticated already
      if (_store.getItem(key) == raw) _store.setItem(key, sealed);
    }
    final native = _vaults.vaultKey(keyNativeBio, vault);
    final hardware = _vaults.vaultKey(keyHardwareBio, vault);
    final hadEntry = _store.getItem(native) != null || _store.getItem(hardware) != null;
    // The old entry kept the private key beside its seal key: the key info says so before it goes
    if (_store.getItem(native) != null) await _markExposed(vault, session.publicKey, secretKey: session.secretKey);
    _store.removeItem(native);
    _store.removeItem(hardware);
    if (hadEntry) {
      try {
        await _unlockKeys.delete(vault);
      } on Exception {
        // Without its entry the key opens nothing; turning biometric unlock on again replaces it
      }
    }
    await _store.flush();
  }

  /// Makes [config]'s Recovery Kit wrap again with a nonce that says the
  /// vault's values are authenticated, when the kit's key the vault keeps
  /// opens it to [session]'s private key. Otherwise the wrap stays as it
  /// is, and a kit unlock through it is authenticated all the same, the
  /// password's wrap saying so.
  Future<void> _authenticateKitWrap(String vault, Map<String, Object?> config, VaultSession session) async {
    final wrap = config['recovery'];
    if (wrap is! Map<String, Object?> || isAuthenticatedWrapNonce(wrap['nonce'])) return;
    final RecoveryKey? kit;
    try {
      kit = await _kitOf(vault, wrap, session);
    } catch (_) {
      // A kit record that doesn't open: the wrap stays
      return;
    }
    if (kit == null) return;
    final sealed = await aesGcmEncrypt(kit.key, session.secretKey, nonce: authenticatedWrapNonce());
    config['recovery'] = {...wrap, 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)};
  }

  /// Deletes [vault]'s old biometric entry, the key info saying first that
  /// the key pair was exposed. A hardware entry beside it stays; without
  /// one the vault has no biometric unlock left, and the app offers it
  /// again once the vault is open.
  Future<void> _dropOldEntry(String vault, VaultSession session) async {
    final key = _vaults.vaultKey(keyNativeBio, vault);
    if (_store.getItem(key) == null) return;
    await _markExposed(vault, session.publicKey, secretKey: session.secretKey);
    _store.removeItem(key);
  }

  /// A vault first opened by this version has no key info: its key pair was
  /// made before (decision 8). It is exposed when either biometric entry is
  /// there: the old one keeps the private key beside its seal key, and a
  /// hardware entry may have been the old one until the update moved it. A
  /// vault without either may still have had one, turned off since; the
  /// Settings row's hint covers that.
  ///
  /// Key info that says the key is fine without being authenticated, in a
  /// vault whose values are, is no key info: the vault is classified again.
  Future<void> _classifyKey(String vault, VaultSession session) async {
    if (_store.getItem(_vaults.vaultKey(keyKeyInfo, vault)) != null) {
      final held = await _openKeyInfo(vault, session);
      // Left alone unless it reads and can't be believed: one that doesn't read was left alone before
      if (held == null || held.verified || !session.authenticated || held.info.exposed) return;
    }
    final exposed =
        _store.getItem(_vaults.vaultKey(keyNativeBio, vault)) != null || _store.getItem(_vaults.vaultKey(keyHardwareBio, vault)) != null;
    await _writeKeyInfo(vault, session, KeyInfo(exposed: exposed, asked: false));
  }

  /// Finishes a replacement of [vault]'s key pair cut short after its commit, which needs no
  /// password, so a Recovery Kit unlock finishes it too; or deletes what one
  /// cut short before its commit left, sealed to a key that never became the
  /// vault's. Without either, it reads one key and writes nothing.
  Future<void> _resumeReplacement(String vault, VaultSession session) async {
    final key = _vaults.vaultKey(keyKeyRotation, vault);
    if (_store.getItem(key) == null) return;
    final rotation = await _readRotation(vault, session);
    if (rotation == null) {
      _store.removeItem(key);
      await _store.flush();
      return;
    }
    try {
      await _finishReplacement(vault, session, rotation);
    } on KeyReplacementIncomplete {
      // The vault opens all the same; the previous key stays for a later try
    }
  }

  /// Steps 7 and 8 of a replacement whose config names [session]'s key
  /// pair: every value still sealed to the previous key is sealed to the new
  /// one, byte for byte the same plaintext, and the replacement's own value
  /// goes last, so the previous key stays at hand until nothing needs it.
  /// Throws [KeyReplacementIncomplete], keeping the replacement's value,
  /// when a value opens with neither key.
  ///
  /// In a vault whose values are authenticated, a value counts as opening
  /// only when it is authenticated too, under whichever key opens it: a
  /// value anyone could have sealed is not sealed again as the vault's own.
  Future<void> _finishReplacement(String vault, VaultSession session, Map<String, Object?> rotation) async {
    final previous = unb64(rotation['previous']! as String);
    await _replaceKitRecord(vault, session, rotation['recovery']);
    final keyInfo = _vaults.vaultKey(keyKeyInfo, vault);
    final unreadable = <String>[];
    for (final key in sealedValueKeys(vault)) {
      // Written anew below, whatever it says: it may be the one value sealed with the public key alone
      if (key == keyInfo) continue;
      final stored = jsonDecode(_store.getItem(key)!) as Map<String, Object?>;
      // Sealed again already, by a run cut short or a save since
      if (await _tryOpen(key, stored, session.secretKey, demand: session.authenticated) != null) continue;
      final plain = await _tryOpen(key, stored, previous, demand: session.authenticated);
      if (plain == null) {
        unreadable.add(key);
        continue;
      }
      _store.setItem(key, await _seal(key, plain, session));
    }
    await _replaceInboxKey(vault, session, rotation['inbox']);
    final made = KeyInfo(
      madeAt: DateTime.fromMillisecondsSinceEpoch((rotation['startedAt']! as num).toInt()),
      exposed: false,
      asked: false,
    );
    final held = await _openKeyInfo(vault, session);
    if (held == null || held.info != made || (session.authenticated && !held.verified)) await _writeKeyInfo(vault, session, made);
    if (unreadable.isNotEmpty) throw KeyReplacementIncomplete(session, unreadable);
    _store.removeItem(_vaults.vaultKey(keyKeyRotation, vault));
    await _store.flush();
  }

  /// The kit key new exports are wrapped for, as the replacement left it:
  /// the new kit's [record], which the person saved before the commit, or
  /// none when they went on without a kit (decision 4). It goes before the
  /// other values, so nothing reads the old kit's key as the vault's.
  Future<void> _replaceKitRecord(String vault, VaultSession session, Object? record) async {
    final key = _vaults.vaultKey(_keyRecovery, vault);
    if (record is! Map<String, Object?>) return _store.removeItem(key);
    final raw = _store.getItem(key);
    final held = raw == null
        ? null
        : await _tryOpen(key, jsonDecode(raw) as Map<String, Object?>, session.secretKey, demand: session.authenticated);
    // Written already by a run cut short after this point
    if (held != null && (jsonDecode(utf8.decode(held)) as Map<String, Object?>)['kitId'] == record['kitId']) return;
    _store.setItem(key, await _seal(key, utf8.encode(jsonEncode(record)), session));
  }

  /// The passkey inbox key sits in the vault, so an old backup gives it away
  /// too, and the inbox files sit where phone backups reach them: the inbox
  /// gets the [fresh] key the replacement made, and keeps the old one as
  /// `previous` while passkeys may still wait under it (decision 7). Older
  /// versions read only `privateKey`, and keep the rest as it is.
  Future<void> _replaceInboxKey(String vault, VaultSession session, Object? fresh) async {
    if (fresh is! String) return;
    final key = _vaults.vaultKey(_keyPasskeyInbox, vault);
    final raw = _store.getItem(key);
    // Unreadable, the walk reports it
    final plain = raw == null
        ? null
        : await _tryOpen(key, jsonDecode(raw) as Map<String, Object?>, session.secretKey, demand: session.authenticated);
    if (plain == null) return;
    final stored = jsonDecode(utf8.decode(plain)) as Map<String, Object?>;
    // Handed over already, by a run cut short after this point
    if (stored['privateKey'] == fresh) return;
    final next = {...stored, 'privateKey': fresh, if (stored['privateKey'] case final String old) 'previous': old};
    _store.setItem(key, await _seal(key, utf8.encode(jsonEncode(next)), session));
  }

  /// [vault]'s key info as stored, and whether it is authenticated; null
  /// when there is none or [session]'s private key doesn't open it.
  Future<({KeyInfo info, bool verified})?> _openKeyInfo(String vault, VaultSession session) async {
    final key = _vaults.vaultKey(keyKeyInfo, vault);
    final raw = _store.getItem(key);
    if (raw == null) return null;
    try {
      final opened = await openSealedValue(jsonDecode(raw) as Map<String, Object?>, session.secretKey, storageKey: key);
      return (info: KeyInfo.fromJson(jsonDecode(utf8.decode(opened.plain)) as Map<String, Object?>), verified: opened.verified);
    } catch (_) {
      // Sealed to another key, or damaged
      return null;
    }
  }

  /// [vault]'s key info as [session] may believe it, or null when there is
  /// none or its private key doesn't open it.
  ///
  /// Key info is the one value the app itself seals with the public key
  /// alone: when an old biometric entry goes while the vault is shut, the
  /// private key isn't there to say so with ([_markExposed]). Such a record
  /// can't be authenticated, and anyone could have written it. So in a
  /// vault whose values are authenticated it counts only for what is
  /// harmless to believe: it may say the key pair is exposed, which at
  /// worst offers a replacement nobody needed, never that it is fine.
  Future<KeyInfo?> _readKeyInfo(String vault, VaultSession session) async {
    final held = await _openKeyInfo(vault, session);
    return held == null ? null : _believed(held, session);
  }

  static KeyInfo? _believed(({KeyInfo info, bool verified}) held, VaultSession session) {
    if (held.verified || !session.authenticated) return held.info;
    return held.info.exposed ? const KeyInfo(exposed: true, asked: false) : null;
  }

  /// Keeps [info] as [vault]'s key info, sealed by [session]'s private key.
  Future<void> _writeKeyInfo(String vault, VaultSession session, KeyInfo info) async {
    final key = _vaults.vaultKey(keyKeyInfo, vault);
    _store.setItem(key, await _seal(key, utf8.encode(jsonEncode(info.toJson())), session));
  }

  /// What the active vault knows about its key pair; null before the vault
  /// was first opened by this version. Throws [AesGcmAuthError] for key
  /// info [session] doesn't open. See [_readKeyInfo] for what is believed
  /// of key info sealed with the public key alone.
  Future<KeyInfo?> loadKeyInfo(VaultSession session) async {
    if (_replacing != null) await _whileReplacing();
    final vault = _vaults.active;
    final raw = _store.getItem(_vaults.vaultKey(keyKeyInfo, vault));
    if (raw == null || raw.isEmpty) return null;
    final held = await _openKeyInfo(vault, session);
    if (held == null) throw const AesGcmAuthError();
    return _believed(held, session);
  }

  /// The person was offered to replace the active vault's exposed key pair,
  /// and isn't asked again.
  Future<void> markKeyAsked(VaultSession session) async {
    final info = await loadKeyInfo(session);
    if (info == null || info.asked) return;
    await saveEncryptedValue(keyKeyInfo, KeyInfo(madeAt: info.madeAt, exposed: info.exposed, asked: true).toJson(), session);
  }

  /// What the value [stored] under [storageKey] holds when [secretKey]
  /// opens it, or null. With [demand], also null for a value that isn't
  /// authenticated.
  Future<Uint8List?> _tryOpen(String storageKey, Map<String, Object?> stored, Uint8List secretKey, {required bool demand}) async {
    try {
      return await _openSealed(storageKey, stored, secretKey, demand: demand);
    } catch (_) {
      // Sealed to another key, or damaged: either way this key doesn't open it. Nothing is written here.
      return null;
    }
  }

  // ─── Encrypted values ──────────────────────────────────────────────────────
  //
  // Each value is sealed to the vault's public key, with its own
  // encapsulation and so its own data key, and authenticated by the private
  // key for the storage key it is kept under (sealed_value.dart): the full
  // key, vault suffix and all, so a value moved to another slot or another
  // vault isn't taken for that one's.

  /// [plain] sealed for [storageKey] by [session], as every value of a vault is stored.
  Future<String> _seal(String storageKey, Uint8List plain, VaultSession session) async =>
      jsonEncode(await sealValue(plain, session.publicKey, storageKey: storageKey, authKey: sealAuthKey(session.secretKey)));

  /// What the value [stored] under [storageKey] holds. Throws
  /// [AesGcmAuthError] when it was sealed to another key pair than
  /// [secretKey]'s, since ML-KEM then gives a wrong secret rather than
  /// failing; and, with [demand], when its seal isn't authenticated for
  /// this storage key, as anyone could have made it or it was sealed for
  /// another slot.
  Future<Uint8List> _openSealed(String storageKey, Map<String, Object?> stored, Uint8List secretKey, {required bool demand}) async {
    final opened = await openSealedValue(stored, secretKey, storageKey: storageKey);
    if (demand && !opened.verified) throw const AesGcmAuthError();
    return opened.plain;
  }

  Future<void> _saveTo(String storageKey, Object? value, VaultSession session) async {
    if (_replacing != null) await _whileReplacing();
    var publicKey = session.publicKey;
    Uint8List? authKey;
    if (_successors.isNotEmpty) {
      for (var next = _successors[b64(publicKey)]; next != null; next = _successors[b64(publicKey)]) {
        publicKey = next.publicKey;
        authKey = next.authKey;
      }
    }
    _saving++;
    try {
      final sealed = await sealValue(
        utf8.encode(jsonEncode(value)),
        publicKey,
        storageKey: storageKey,
        authKey: authKey ?? sealAuthKey(session.secretKey),
      );
      _store.setItem(storageKey, jsonEncode(sealed));
    } finally {
      if (--_saving == 0) {
        final saved = _saved;
        _saved = null;
        saved?.complete();
      }
    }
  }

  Future<Object?> _loadFrom(String storageKey, VaultSession session, String vault) async {
    if (_replacing != null) await _whileReplacing();
    final raw = _store.getItem(storageKey);
    if (raw == null || raw.isEmpty) return null;
    final stored = jsonDecode(raw) as Map<String, Object?>;
    final Uint8List plain;
    try {
      plain = await _openSealed(storageKey, stored, session.secretKey, demand: session.authenticated);
    } on AesGcmAuthError {
      // Mid-replacement, a value not sealed again yet is still the previous key's
      final previous = await _previousKey(vault, session);
      if (previous == null) rethrow;
      return jsonDecode(utf8.decode(await _openSealed(storageKey, stored, previous, demand: session.authenticated)));
    }
    return jsonDecode(utf8.decode(plain));
  }

  /// The replacement under way in [vault], when there is one and
  /// [session], the new key pair's, opens it; null otherwise, as before the
  /// replacement's commit, when no stored key opens it. It holds the
  /// previous private key, which then opens values in the vault's name: in
  /// a vault whose values are authenticated, one that isn't is not read.
  Future<Map<String, Object?>?> _readRotation(String vault, VaultSession session) async {
    final key = _vaults.vaultKey(keyKeyRotation, vault);
    final raw = _store.getItem(key);
    if (raw == null) return null;
    try {
      final plain = await _openSealed(key, jsonDecode(raw) as Map<String, Object?>, session.secretKey, demand: session.authenticated);
      return jsonDecode(utf8.decode(plain)) as Map<String, Object?>;
    } on AesGcmAuthError {
      return null;
    }
  }

  /// The private key [vault] had before the replacement under way.
  Future<Uint8List?> _previousKey(String vault, VaultSession session) async {
    final previous = (await _readRotation(vault, session))?['previous'];
    return previous is String ? unb64(previous) : null;
  }

  /// The storage keys of [vault]'s values sealed to its key pair, as a
  /// replacement of the key pair finds them (decision 2): every key of the
  /// vault holding a JSON object of exactly `kemCT`, `nonce` and `ct` as
  /// strings, those a newer version wrote included, so none stays sealed to
  /// the old key. The config, the replacement's own value and the biometric
  /// entries are never listed; anything else is left alone.
  List<String> sealedValueKeys(String vault) {
    final skipped = {
      for (final base in [keyConfig, keyKeyRotation, keyNativeBio, keyHardwareBio]) _vaults.vaultKey(base, vault),
    };
    return [
      for (final key in _vaults.keysOf(vault))
        if (!skipped.contains(key) && _looksSealed(_store.getItem(key))) key,
    ];
  }

  static bool _looksSealed(String? raw) {
    if (raw == null) return false;
    try {
      final value = jsonDecode(raw);
      return value is Map && value.length == 3 && value['kemCT'] is String && value['nonce'] is String && value['ct'] is String;
    } on FormatException {
      return false;
    }
  }

  /// Saves any JSON value under [base] in the active vault, encrypted like
  /// the accounts. Used for settings that hold secrets, such as sync credentials.
  Future<void> saveEncryptedValue(String base, Object? value, VaultSession session) => _saveTo(_vaults.vaultKey(base), value, session);

  /// Reads a value saved with [saveEncryptedValue], or null when there is
  /// none. While the vault's key pair is being replaced, a value still sealed
  /// to the previous one opens too.
  Future<Object?> loadEncryptedValue(String base, VaultSession session) => _loadFrom(_vaults.vaultKey(base), session, _vaults.active);

  void removeEncryptedValue(String base) => _store.removeItem(_vaults.vaultKey(base));

  Future<List<Object?>> _loadList(String base, VaultSession session) async =>
      (await loadEncryptedValue(base, session) as List<Object?>?) ?? [];

  /// The active vault's accounts, an empty list when none are saved yet.
  Future<List<OtpAccount>> loadAccounts(VaultSession session) async => [
    for (final json in await _loadList(_keyData, session)) OtpAccount.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveAccounts(List<OtpAccount> accounts, VaultSession session) =>
      saveEncryptedValue(_keyData, [for (final account in accounts) account.toJson()], session);

  /// The active vault's backup services, an empty list when none are saved yet.
  Future<List<BackupService>> loadBackupServices(VaultSession session) async => [
    for (final json in await _loadList(_keyBackupData, session)) BackupService.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveBackupServices(List<BackupService> services, VaultSession session) =>
      saveEncryptedValue(_keyBackupData, [for (final service in services) service.toJson()], session);

  /// The active vault's notes, an empty list when none are saved yet.
  Future<List<SecureNote>> loadNotes(VaultSession session) async => [
    for (final json in await _loadList(_keyNoteData, session)) SecureNote.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveNotes(List<SecureNote> notes, VaultSession session) =>
      saveEncryptedValue(_keyNoteData, [for (final note in notes) note.toJson()], session);

  /// The active vault's key pairs, an empty list when none are saved yet.
  Future<List<VaultKey>> loadKeys(VaultSession session) async => [
    for (final json in await _loadList(_keyKeyData, session)) VaultKey.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveKeys(List<VaultKey> keys, VaultSession session) =>
      saveEncryptedValue(_keyKeyData, [for (final key in keys) key.toJson()], session);

  /// The active vault's logins, an empty list when none are saved yet.
  Future<List<Login>> loadLogins(VaultSession session) async => [
    for (final json in await _loadList(_keyLoginData, session)) Login.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveLogins(List<Login> logins, VaultSession session) =>
      saveEncryptedValue(_keyLoginData, [for (final login in logins) login.toJson()], session);

  /// The active vault's cards, an empty list when none are saved yet.
  Future<List<PaymentCard>> loadCards(VaultSession session) async => [
    for (final json in await _loadList(_keyCardData, session)) PaymentCard.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveCards(List<PaymentCard> cards, VaultSession session) =>
      saveEncryptedValue(_keyCardData, [for (final card in cards) card.toJson()], session);

  /// The active vault's identities, an empty list when none are saved yet.
  Future<List<Identity>> loadIdentities(VaultSession session) async => [
    for (final json in await _loadList(_keyIdentityData, session)) Identity.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveIdentities(List<Identity> identities, VaultSession session) =>
      saveEncryptedValue(_keyIdentityData, [for (final identity in identities) identity.toJson()], session);

  /// The active vault's File items, an empty list when none are saved yet.
  Future<List<VaultFile>> loadFiles(VaultSession session) async => [
    for (final json in await _loadList(_keyFileData, session)) VaultFile.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveFiles(List<VaultFile> files, VaultSession session) =>
      saveEncryptedValue(_keyFileData, [for (final file in files) file.toJson()], session);

  /// The passwords AutoFill generated that no saved login holds, an empty list when none.
  Future<List<GeneratedPassword>> loadGenerated(VaultSession session) async => [
    for (final json in await _loadList(_keyGeneratedData, session)) GeneratedPassword.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveGenerated(List<GeneratedPassword> generated, VaultSession session) =>
      saveEncryptedValue(_keyGeneratedData, [for (final item in generated) item.toJson()], session);

  /// The active vault's contacts, other people's public keys; an empty list
  /// when none were ever saved.
  Future<List<Contact>> loadContacts(VaultSession session) async => [
    for (final json in await _loadList(_keyContactData, session)) Contact.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> saveContacts(List<Contact> contacts, VaultSession session) =>
      saveEncryptedValue(_keyContactData, [for (final contact in contacts) contact.toJson()], session);

  /// The active vault's passkey inbox key, as PKCS#8 DER, or null when
  /// passkeys were never turned on.
  Future<Uint8List?> loadPasskeyInboxKey(VaultSession session) async {
    final stored = await loadEncryptedValue(_keyPasskeyInbox, session) as Map<String, Object?>?;
    final key = stored?['privateKey'];
    return key is String ? unb64(key) : null;
  }

  /// Keeps [pkcs8] as the active vault's passkey inbox key, encrypted like the accounts.
  /// The inbox key a key replacement left behind, as PKCS#8 DER, under which
  /// passkeys made before it may still wait; null without one (openspec:
  /// replace-vault-key-pair, decision 7).
  Future<Uint8List?> loadPreviousPasskeyInboxKey(VaultSession session) async {
    final stored = await loadEncryptedValue(_keyPasskeyInbox, session) as Map<String, Object?>?;
    final key = stored?['previous'];
    return key is String ? unb64(key) : null;
  }

  /// Forgets the inbox key a key replacement left behind, once no passkey
  /// waits under it.
  Future<void> dropPreviousPasskeyInboxKey(VaultSession session) async {
    final stored = await loadEncryptedValue(_keyPasskeyInbox, session) as Map<String, Object?>?;
    if (stored == null || !stored.containsKey('previous')) return;
    await saveEncryptedValue(_keyPasskeyInbox, {...stored}..remove('previous'), session);
  }

  Future<void> savePasskeyInboxKey(Uint8List pkcs8, VaultSession session) =>
      saveEncryptedValue(_keyPasskeyInbox, {'privateKey': b64(pkcs8)}, session);

  /// The active vault's passkeys, an empty list when none are saved yet.
  Future<List<Passkey>> loadPasskeys(VaultSession session) async => [
    for (final json in await _loadList(_keyPasskeyData, session)) Passkey.fromJson(json! as Map<String, Object?>),
  ];

  Future<void> savePasskeys(List<Passkey> passkeys, VaultSession session) =>
      saveEncryptedValue(_keyPasskeyData, [for (final passkey in passkeys) passkey.toJson()], session);

  /// What the active vault remembers of the accounts on security keys, an
  /// empty list when it never read a key.
  Future<List<KeyAccount>> loadKeyAccounts(VaultSession session) async => [
    for (final json in await _loadList(_keyKeyAccountData, session)) KeyAccount.fromJson(json! as Map<String, Object?>),
  ];

  /// Keeps [accounts]. An empty list is not stored: a vault that knows no
  /// key holds nothing that says keys exist.
  Future<void> saveKeyAccounts(List<KeyAccount> accounts, VaultSession session) async {
    if (accounts.isEmpty) return removeEncryptedValue(_keyKeyAccountData);
    await saveEncryptedValue(_keyKeyAccountData, [for (final account in accounts) account.toJson()], session);
  }

  /// The access keys the active vault remembers, by the id of the key's
  /// code application; empty when none was ever remembered.
  Future<Map<String, Uint8List>> loadKeyAccess(VaultSession session) async {
    final stored = await loadEncryptedValue(_keyKeyAccess, session);
    return {
      if (stored is Map<String, Object?>)
        for (final MapEntry(key: device, :value) in stored.entries)
          if (value is String) device: unb64(value),
    };
  }

  /// Keeps [access] in place of what was remembered; nothing is stored for an empty map.
  Future<void> saveKeyAccess(Map<String, Uint8List> access, VaultSession session) async {
    if (access.isEmpty) return removeEncryptedValue(_keyKeyAccess);
    await saveEncryptedValue(_keyKeyAccess, {for (final MapEntry(key: device, :value) in access.entries) device: b64(value)}, session);
  }

  /// Wipes every vault on the device and all stored data but the language.
  /// The lock screen's reset can't know which vault was meant, and must not
  /// reveal hidden ones by sparing them. [erasedNote] is left for setup to
  /// show, even when the erase is only finished at the next launch.
  void wipeVault({String? erasedNote}) => _vaults.removeAllVaults(erasedNote: erasedNote);

  // ─── Biometric unlock ──────────────────────────────────────────────────────
  //
  // A random seal key wraps the private key. The seal key is in the phone's
  // hardware ([UnlockKeys]), given out only after the system's biometric
  // prompt, and the entry in storage keeps the sealed private key. Entries
  // the Capacitor plugin and earlier versions wrote keep the seal key beside
  // it; they keep opening until they move over.

  Map<String, Object?>? _readEntry(String base, String vault) {
    final raw = _store.getItem(_vaults.vaultKey(base, vault));
    return raw == null ? null : jsonDecode(raw) as Map<String, Object?>;
  }

  /// True when biometric unlock is set up for the active vault, in either
  /// entry. Never for a vault that needs a security key: an entry holds the
  /// private key, and would open the vault without the key (openspec:
  /// add-security-key-unlock, decision 11).
  bool hasBiometricUnlock() =>
      !unlockMode().needsKey &&
      (_store.getItem(_vaults.vaultKey(keyHardwareBio)) != null || _store.getItem(_vaults.vaultKey(keyNativeBio)) != null);

  /// Turns biometric unlock on for the active vault: a fresh seal key goes
  /// into the hardware, which shows the prompt with [reason], and the entry
  /// keeps the private key sealed under it. Throws an [UnlockKeyError],
  /// [UnlockKeyCancelled] when the prompt was cancelled.
  /// A vault that needs a security key has no biometric unlock, and
  /// asking for it is a [StateError].
  Future<void> enableBiometricUnlock(VaultSession session, String reason) {
    if (unlockMode().needsKey) throw StateError('A vault that needs a security key has no biometric unlock.');
    return _writeHardwareEntry(_vaults.active, session.secretKey, reason);
  }

  Future<void> _writeHardwareEntry(String vault, Uint8List secretKey, String reason) async {
    final sealKey = randomBytes(32);
    await _writeSealed(vault, sealKey, await _unlockKeys.seal(vault, sealKey, reason), secretKey);
  }

  Future<void> _writeSealed(String vault, Uint8List sealKey, String wrap, Uint8List secretKey) async {
    // A wrap of the private key, so it says whether the vault's values are authenticated
    final sealed = await aesGcmEncrypt(sealKey, secretKey, nonce: _wrapNonce(_readConfig(vault)));
    _store.setItem(
      _vaults.vaultKey(keyHardwareBio, vault),
      jsonEncode({'v': 1, 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct), if (wrap.isNotEmpty) 'wrap': wrap}),
    );
  }

  /// Opens the active vault by biometrics, with one prompt showing [reason],
  /// as decision 5 of the change has it:
  ///
  /// - the hardware entry alone: it opens the vault;
  /// - the old entry alone: it moves over ([_moveOldEntry]);
  /// - both: the hardware entry opens the vault and the old one is deleted;
  ///   if the hardware entry fails for a reason of its own (the Keystore, or
  ///   a key that doesn't open it), the old one opens the vault after
  ///   [fallback]'s prompt ([_fallBack]); a failed prompt, such as a lockout
  ///   or a timeout, is thrown as it is, never fallen back from;
  /// - biometrics changed: both entries and the key go, and nothing opens;
  /// - the prompt cancelled: nothing changes.
  ///
  /// On a phone with no biometrics the key can use, an old entry is deleted.
  /// Throws [VaultMissingError] when the vault has no entry, and an
  /// [UnlockKeyError] the lock screen shows, such as a lockout.
  Future<BiometricUnlock> unlockWithBiometrics(String reason, Biometrics fallback) async {
    final vault = _vaults.active;
    // A vault that needs a security key never opens by biometrics: an entry found beside it is
    // deleted and opens nothing
    if (unlockMode(vault).needsKey) {
      await _forgetBiometrics(vault, keyMayStay: true);
      throw const VaultMissingError('No biometric unlock registered.');
    }
    final unlock = await _unlockWithBiometrics(vault, reason, fallback);
    if (unlock.session case final session?) await _afterUnlock(vault, session, byBiometrics: true);
    return unlock;
  }

  Future<BiometricUnlock> _unlockWithBiometrics(String vault, String reason, Biometrics fallback) async {
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final publicKey = unb64(config['publicKey']! as String);
    final hardware = _readEntry(keyHardwareBio, vault);
    var old = _readEntry(keyNativeBio, vault);
    if (hardware == null && old == null) throw const VaultMissingError('No biometric unlock registered.');
    // An old entry can't move to a phone without strong biometrics, and mustn't stay in storage
    if (old != null && !await _unlockKeys.status()) {
      await _markExposed(vault, publicKey);
      _store.removeItem(_vaults.vaultKey(keyNativeBio, vault));
      old = null;
      if (hardware == null) return (session: null, outcome: BiometricOutcome.unsupported);
    }
    if (hardware == null) return _moveOldEntry(vault, old!, publicKey, reason);
    try {
      final sealKey = await _unlockKeys.open(vault, hardware['wrap'] as String? ?? '', reason);
      final Uint8List secretKey;
      try {
        secretKey = await aesGcmDecrypt(sealKey, unb64(hardware['nonce']! as String), unb64(hardware['ct']! as String));
      } on AesGcmAuthError {
        throw const UnlockKeyFailed('The key the phone gave back doesn’t open the entry.');
      }
      // The hardware entry has opened the vault once: the old one has done its part
      if (old != null) {
        await _markExposed(vault, publicKey, secretKey: secretKey);
        _store.removeItem(_vaults.vaultKey(keyNativeBio, vault));
      }
      return (session: _sessionThrough(hardware['nonce'], config, secretKey), outcome: BiometricOutcome.opened);
    } on UnlockKeyCancelled {
      return (session: null, outcome: BiometricOutcome.cancelled);
    } on UnlockKeyInvalidated {
      // Never the old entry instead: that would undo what invalidation is for
      await _forgetBiometrics(vault);
      return (session: null, outcome: BiometricOutcome.invalidated);
    } on UnlockKeyFailed {
      // Only the Keystore, the Keychain or the entry failing: a failed prompt (UnlockKeyPromptFailed) goes up
      // as it is, since the fallback's weaker prompt would get round a lockout
      if (old == null) rethrow;
      return _fallBack(vault, old, publicKey, reason, fallback);
    }
  }

  /// The private key an old entry seals under the seal key beside it.
  Future<Uint8List> _openOldEntry(Map<String, Object?> entry) =>
      aesGcmDecrypt(unb64(entry['sealKey']! as String), unb64(entry['nativeSkNonce']! as String), unb64(entry['nativeSkEnc']! as String));

  /// Moves [vault]'s old entry into the hardware: a fresh seal key goes in,
  /// which shows the one prompt this unlock has, in place of the prompt the
  /// old entry was opened behind; the old entry opens the vault; and the new
  /// entry is written beside it. The old entry stays until the new one has
  /// opened the vault once, so a Keystore that encrypts and then can't
  /// decrypt costs one fallback, not biometric unlock.
  Future<BiometricUnlock> _moveOldEntry(String vault, Map<String, Object?> old, Uint8List publicKey, String reason) async {
    final sealKey = randomBytes(32);
    final String wrap;
    try {
      wrap = await _unlockKeys.seal(vault, sealKey, reason);
    } on UnlockKeyCancelled {
      return (session: null, outcome: BiometricOutcome.cancelled);
    }
    final Uint8List secretKey;
    try {
      secretKey = await _openOldEntry(old);
    } catch (_) {
      await _unlockKeys.delete(vault);
      rethrow;
    }
    await _writeSealed(vault, sealKey, wrap, secretKey);
    await _markExposed(vault, publicKey, secretKey: secretKey);
    return (session: _sessionThrough(old['nativeSkNonce'], _readConfig(vault), secretKey), outcome: BiometricOutcome.moved);
  }

  /// The hardware entry failed for a reason of its own: the old entry opens
  /// the vault after [fallback]'s prompt, and the hardware entry and its key
  /// are deleted, so the next unlock moves the old entry over again.
  Future<BiometricUnlock> _fallBack(String vault, Map<String, Object?> old, Uint8List publicKey, String reason, Biometrics fallback) async {
    if (!await fallback.authenticate(reason)) return (session: null, outcome: BiometricOutcome.cancelled);
    final secretKey = await _openOldEntry(old);
    _store.removeItem(_vaults.vaultKey(keyHardwareBio, vault));
    await _unlockKeys.delete(vault);
    return (session: _sessionThrough(old['nativeSkNonce'], _readConfig(vault), secretKey), outcome: BiometricOutcome.fellBack);
  }

  /// [vault]'s old biometric entry kept the private key beside its seal
  /// key, so phone backups made while it was there hold the key pair: the
  /// key info says so before the entry moves or goes (openspec:
  /// replace-vault-key-pair, decision 8). With the private key at hand the
  /// rest of the key info is kept. Without it, key info that is there
  /// already stays as it is: a vault can have both only once it was
  /// classified with the old entry there, and so exposed, and the person
  /// may have been asked since.
  ///
  /// Without the private key the record is sealed with the public key
  /// alone, which nothing can authenticate: [_readKeyInfo] says what such a
  /// record is believed for.
  Future<void> _markExposed(String vault, Uint8List publicKey, {Uint8List? secretKey}) async {
    if (secretKey == null) {
      final key = _vaults.vaultKey(keyKeyInfo, vault);
      if (_store.getItem(key) != null) return;
      const info = KeyInfo(exposed: true, asked: false);
      return _store.setItem(key, jsonEncode(await sealValue(utf8.encode(jsonEncode(info.toJson())), publicKey, storageKey: key)));
    }
    final session = VaultSession.holding(secretKey, authenticated: _authenticated(_readConfig(vault)));
    final info = await _readKeyInfo(vault, session);
    if (info != null && info.exposed) return;
    await _writeKeyInfo(vault, session, KeyInfo(madeAt: info?.madeAt, exposed: true, asked: info?.asked ?? false));
  }

  /// Turns biometric unlock off for the active vault: both entries go at
  /// once, and the hardware key after them.
  Future<void> removeBiometricUnlock() => _forgetBiometrics(_vaults.active);

  /// With [keyMayStay], a hardware key that will not go is let be: the
  /// entries are gone before it, and it opens nothing without them.
  Future<void> _forgetBiometrics(String vault, {bool keyMayStay = false}) async {
    final config = _readConfig(vault);
    if (config != null && _store.getItem(_vaults.vaultKey(keyNativeBio, vault)) != null) {
      await _markExposed(vault, unb64(config['publicKey']! as String));
    }
    _store.removeItem(_vaults.vaultKey(keyHardwareBio, vault));
    _store.removeItem(_vaults.vaultKey(keyNativeBio, vault));
    try {
      await _unlockKeys.delete(vault);
    } on Exception {
      if (!keyMayStay) rethrow;
    }
  }

  // ─── Security key unlock ───────────────────────────────────────────────────
  //
  // openspec: add-security-key-unlock. A vault's config may hold `keyUnlock`
  // (key_unlock.dart): a mode, a salt and the key secret wrapped once per
  // enrolled key. In mode "key" or "both" the private key's wrap, still
  // `skNonce` and `skEnc`, is under a key the password alone does not give.
  // Nothing here talks to a key: each call takes what a key gave.

  /// How a vault opens, the active one unless another id is given. A vault
  /// without a `keyUnlock` this version reads opens with its password.
  UnlockMode unlockMode([String? id]) => KeyUnlock.of(_readConfig(id))?.mode ?? UnlockMode.password;

  /// The keys enrolled for a vault, the active one unless another id is given.
  List<EnrolledKey> enrolledKeys([String? id]) => List.unmodifiable(KeyUnlock.of(_readConfig(id))?.keys ?? const <EnrolledKey>[]);

  /// What to send a key for a vault, the active one unless another id is
  /// given: its salt and its credentials. A vault with no key yet gets a
  /// fresh salt, which [enrolKey] stores with the first key.
  KeyChallenge keyChallenge([String? id]) {
    final unlock = KeyUnlock.of(_readConfig(id));
    if (unlock == null) return (salt: randomBytes(keySecretLength), credentials: const []);
    return (salt: Uint8List.fromList(unlock.salt), credentials: [for (final key in unlock.keys) Uint8List.fromList(key.credential)]);
  }

  /// The key that wraps the private key in [mode], from the pieces at hand.
  /// Throws [ProofIncompleteError] when one the mode needs is missing.
  static Uint8List _wrapKey(UnlockMode mode, KeyUnlock? unlock, Uint8List? passwordKey, Uint8List? keySecret) {
    switch (mode) {
      case UnlockMode.password:
        return passwordKey ?? (throw const ProofIncompleteError());
      case UnlockMode.key:
        if (unlock == null || keySecret == null) throw const ProofIncompleteError();
        return keyModeWrapKey(keySecret, unlock.salt);
      case UnlockMode.both:
        if (unlock == null || keySecret == null || passwordKey == null) throw const ProofIncompleteError();
        return bothModeWrapKey(passwordKey, keySecret, unlock.salt);
    }
  }

  /// Checks what opens the active vault now, and returns the pieces
  /// (decision 9): the [password] for a vault that has one, and what an
  /// enrolled [key] gave for a vault that needs one. A key may also be
  /// given for a vault that opens with its password and has keys enrolled,
  /// to get the key secret a further key or a change of mode needs.
  ///
  /// Throws [ProofIncompleteError] when a piece the vault needs was not
  /// given, [KeyNotEnrolledError] for a key that is not the vault's, and
  /// [IncorrectPasswordError] when the pieces do not open the vault.
  Future<OwnerProof> proveOwner({String? password, KeyReading? key}) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    final mode = unlock?.mode ?? UnlockMode.password;
    if (mode.hasPassword && password == null) throw const ProofIncompleteError();
    if (mode.needsKey && key == null) throw const ProofIncompleteError();
    Uint8List? keySecret;
    if (key != null) {
      final entry = unlock?.keyFor(key.credential);
      if (unlock == null || entry == null) throw const KeyNotEnrolledError();
      try {
        keySecret = await unwrapKeySecret(entry, key.output, unlock.salt);
      } on AesGcmAuthError {
        throw const KeyNotEnrolledError();
      }
    }
    final passwordKey = mode.hasPassword ? await _deriveKey(password!, unb64(config['salt']! as String)) : null;
    final wrapKey = _wrapKey(mode, unlock, passwordKey, keySecret);
    try {
      // Opened only to check: the private key it gives goes at once
      _wipe((await _open(config, wrapKey)).secretKey);
    } on AesGcmAuthError {
      if (passwordKey != null) _wipe(passwordKey);
      if (keySecret != null) _wipe(keySecret);
      throw const IncorrectPasswordError();
    } finally {
      if (!identical(wrapKey, passwordKey)) _wipe(wrapKey);
    }
    return OwnerProof._(vault, passwordKey, keySecret);
  }

  /// Checks [proof] against [vault]'s [config] as stored and that
  /// [session] is that vault's own key pair, and returns the key that wraps
  /// the private key now. A proof is checked again at every use, so one
  /// kept past a change of the vault allows nothing.
  Future<Uint8List> _checkProof(String vault, Map<String, Object?> config, OwnerProof proof, VaultSession session) async {
    if (proof.vault != vault) throw const ProofIncompleteError();
    final unlock = KeyUnlock.of(config);
    final wrapKey = _wrapKey(unlock?.mode ?? UnlockMode.password, unlock, proof.passwordKey, proof.keySecret);
    final Uint8List secretKey;
    try {
      secretKey = (await _open(config, wrapKey)).secretKey;
    } on AesGcmAuthError {
      throw const IncorrectPasswordError();
    }
    final same = sameBytes(secretKey, session.secretKey);
    // A copy opened only to compare
    _wipe(secretKey);
    if (!same) throw StateError('The session isn’t the vault’s own key pair.');
    return wrapKey;
  }

  /// [_checkProof] where the wrap key isn't wanted: one derived for the
  /// check is cleared, the proof's own password key left to its holder.
  Future<void> _check(String vault, Map<String, Object?> config, OwnerProof proof, VaultSession session) async {
    final wrapKey = await _checkProof(vault, config, proof, session);
    if (!identical(wrapKey, proof.passwordKey)) _wipe(wrapKey);
  }

  static Uint8List? _copy(Uint8List? bytes) => bytes == null ? null : Uint8List.fromList(bytes);

  /// Clears key material once nothing needs it.
  static void _wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);

  /// A `keyUnlock` a newer version wrote is left alone: this version does
  /// not write over what it cannot read.
  static void _refuseUnreadable(Map<String, Object?> config, KeyUnlock? unlock) {
    if (unlock == null && config.containsKey('keyUnlock')) throw StateError('This vault’s key unlock was written by a newer version.');
  }

  /// Whether a vault with [keys] enrolled keys and maybe a kit has a way
  /// back in when a key is lost (decision 8).
  static bool _hasSafetyNet(Map<String, Object?> config, int keys) => config['recovery'] != null || keys >= 2;

  /// Enrols a key for the active vault, open in [session]: the key secret
  /// is wrapped under the key's [output] for [salt] and written with its
  /// [credential]. The first key makes the key secret and stores [salt],
  /// which is the one [keyChallenge] gave; a further key needs the key
  /// secret in [proof], and the vault's own salt. The vault opens as
  /// before: turning a mode on is [setUnlockMode].
  ///
  /// Returns the proof with the key secret in it, for the next step. Until
  /// the one write of the config, nothing is stored.
  Future<OwnerProof> enrolKey(
    VaultSession session,
    OwnerProof proof, {
    required Uint8List salt,
    required Uint8List credential,
    required Uint8List output,
    required String name,
    required bool pinBound,
  }) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    _refuseUnreadable(config, unlock);
    await _check(vault, config, proof, session);
    if (salt.length != keySecretLength || output.length != keySecretLength || credential.isEmpty) {
      throw ArgumentError('A salt and a key’s output are 32 bytes, and a credential is not empty.');
    }
    final Uint8List keySecret;
    if (unlock == null) {
      keySecret = randomBytes(keySecretLength);
    } else {
      if (!sameBytes(salt, unlock.salt)) throw ArgumentError.value(salt, 'salt', 'Not the vault’s salt');
      if (unlock.keyFor(credential) != null) throw const KeyAlreadyEnrolledError();
      keySecret = proof.keySecret ?? (throw const ProofIncompleteError());
    }
    final wrap = await wrapKeySecret(keySecret, output, salt);
    final entry = EnrolledKey(
      id: [for (final byte in randomBytes(8)) byte.toRadixString(16).padLeft(2, '0')].join(),
      credential: Uint8List.fromList(credential),
      nonce: wrap.nonce,
      ct: wrap.ct,
      name: name.trim(),
      addedAt: _clock().millisecondsSinceEpoch,
      pinBound: pinBound,
    );
    // The wrap is opened once before it is trusted with anything
    if (!sameBytes(await unwrapKeySecret(entry, output, salt), keySecret)) throw StateError('The key secret’s wrap does not open.');
    final next = unlock == null
        ? KeyUnlock(mode: UnlockMode.password, salt: Uint8List.fromList(salt), keys: [entry])
        : unlock.copyWith(keys: [...unlock.keys, entry]);
    _writeConfig({...config, 'keyUnlock': next.toJson()}, vault);
    await _store.flush();
    return OwnerProof._(vault, _copy(proof.passwordKey), _copy(keySecret));
  }

  /// Whether what a key gave is the secret of one of the active vault's
  /// enrolled keys, for the sheet's "Check" (openspec:
  /// add-security-key-unlock, decision 8). It asks for nothing else, opens
  /// nothing and writes nothing.
  Future<bool> checkKey(KeyReading key) async {
    final unlock = KeyUnlock.of(_readConfig());
    final entry = unlock?.keyFor(key.credential);
    if (unlock == null || entry == null) return false;
    try {
      final keySecret = await unwrapKeySecret(entry, key.output, unlock.salt);
      keySecret.fillRange(0, keySecret.length, 0);
      return true;
    } on AesGcmAuthError {
      return false;
    }
  }

  /// Gives the enrolled key [id] of the active vault another name.
  Future<void> renameKey(VaultSession session, OwnerProof proof, String id, String name) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    await _check(vault, config, proof, session);
    if (unlock == null || !unlock.keys.any((key) => key.id == id)) throw const KeyNotEnrolledError();
    final keys = [for (final key in unlock.keys) key.id == id ? key.renamed(name.trim()) : key];
    _writeConfig({...config, 'keyUnlock': unlock.copyWith(keys: keys).toJson()}, vault);
  }

  /// Whether the enrolled key [id] of the active vault can be removed, or
  /// the error [removeKey] would throw, for a screen to say before asking
  /// for anything.
  Exception? removeKeyRefusal(String id) {
    final config = _readConfig();
    final unlock = KeyUnlock.of(config);
    if (config == null || unlock == null || !unlock.keys.any((key) => key.id == id)) return const KeyNotEnrolledError();
    if (!unlock.mode.needsKey) return null;
    if (unlock.keys.length == 1) return const LastKeyError();
    return _hasSafetyNet(config, unlock.keys.length - 1) ? null : const SafetyNetError();
  }

  /// Removes the enrolled key [id] from the active vault. The key itself
  /// is not needed, so a lost key can be removed. Its wrap of the key
  /// secret leaves the config: the vault, and every copy of it made from
  /// now on, holds nothing the key opens alone.
  ///
  /// The key secret itself stays, shared by the keys left, and the key
  /// pair's replacement keeps it too ([replaceKeyPair]). So a copy of the
  /// config made while the key was enrolled, such as one in an old phone
  /// backup, still gives that secret to the key and its PIN, and the
  /// secret opens the copies made later in mode "key" (in "both", with
  /// the password); in a key mode that old copy also gives the private key
  /// it holds, the vault's until its pair is replaced. Only a new secret
  /// ends the first: every key removed, the last taking `keyUnlock` with
  /// it, and the keys at hand enrolled again; a new key pair ends the
  /// second. The secret can't be changed here alone, as each key left
  /// would have to wrap the new one with what it gives when presented.
  ///
  /// Throws [LastKeyError] for the last key of a vault that needs one, and
  /// [SafetyNetError] when the vault needs a key and would be left with one
  /// key and no Recovery Kit. Neither changes anything.
  Future<void> removeKey(VaultSession session, OwnerProof proof, String id) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    await _check(vault, config, proof, session);
    if (removeKeyRefusal(id) case final refusal?) throw refusal;
    final keys = [
      for (final key in unlock!.keys)
        if (key.id != id) key,
    ];
    final next = {...config};
    if (keys.isEmpty) {
      next.remove('keyUnlock');
    } else {
      next['keyUnlock'] = unlock.copyWith(keys: keys).toJson();
    }
    _writeConfig(next, vault);
    await _store.flush();
  }

  /// Why the active vault cannot be set to [mode] as it is now, or null:
  /// what [setUnlockMode] would refuse before anything is asked of a key.
  Exception? unlockModeRefusal(UnlockMode mode) {
    final config = _readConfig();
    if (config == null) return const VaultMissingError();
    if (!mode.needsKey) return null;
    final unlock = KeyUnlock.of(config);
    if (mode == UnlockMode.key && !_vaults.isListed(_vaults.active)) return const HiddenVaultKeyOnlyError();
    if (unlock == null) return const KeyNotEnrolledError();
    if (mode == UnlockMode.key && unlock.keys.any((key) => !key.pinBound)) return const KeyNotPinBoundError();
    return _hasSafetyNet(config, unlock.keys.length) ? null : const SafetyNetError();
  }

  /// Changes how the active vault, open in [session], opens (decision 8).
  /// [proof] holds what opens it now, and the key secret when [mode] needs
  /// a key. Going to a mode with a password from "key" takes a
  /// [newPassword], which must not open another vault.
  ///
  /// The change is one write of the config: the mode, the password check,
  /// and the private key under the new wrap key, which is first opened
  /// once in memory and compared with the key in hand. A failure before
  /// that write leaves the vault opening as it did. A mode that needs a key
  /// turns biometric unlock off just before the write, as biometrics would
  /// open the vault without the key (decision 11). Returns the proof for
  /// the vault as it is now.
  ///
  /// Throws [SafetyNetError] without a Recovery Kit or two keys,
  /// [KeyNotPinBoundError] for "key" with a key that gives its secret on a
  /// touch, [HiddenVaultKeyOnlyError] for "key" on a hidden vault,
  /// [PasswordInUseError], and [ProofIncompleteError] when a piece is
  /// missing.
  Future<OwnerProof> setUnlockMode(VaultSession session, OwnerProof proof, UnlockMode mode, {String? newPassword}) async {
    final vault = _vaults.active;
    final config = _readConfig(vault);
    if (config == null) throw const VaultMissingError();
    final unlock = KeyUnlock.of(config);
    _refuseUnreadable(config, unlock);
    await _check(vault, config, proof, session);
    final current = unlock?.mode ?? UnlockMode.password;
    if (unlockModeRefusal(mode) case final refusal?) throw refusal;
    // A vault with no key enrolled has no keyUnlock, and "password" is what it is already
    if (unlock == null) return proof;
    final keySecret = proof.keySecret;
    if (mode.needsKey && keySecret == null) throw const ProofIncompleteError();
    // Key material made here, cleared once the change is made or given up; the proof's stays its holder's
    final made = <Uint8List>[];
    try {
      // The password's key: the one in hand, or a new password's for a vault that had none
      final next = {...config};
      Uint8List? passwordKey = proof.passwordKey;
      if (mode.hasPassword && !current.hasPassword) {
        if (newPassword == null || newPassword.isEmpty) throw const ProofIncompleteError();
        if (await passwordOpensAVault(newPassword)) throw const PasswordInUseError();
        final salt = _keptSalt(config);
        final fresh = await _deriveKey(newPassword, unb64(salt));
        made.add(fresh);
        passwordKey = fresh;
        next['salt'] = salt;
        next['scrypt'] = {'N': scryptN, 'r': scryptR, 'p': scryptP};
      }
      final changed = unlock.copyWith(mode: mode, check: mode == UnlockMode.both ? passwordCheck(passwordKey!, unlock.salt) : null);
      final wrapKey = _wrapKey(mode, changed, passwordKey, keySecret);
      if (!identical(wrapKey, passwordKey)) made.add(wrapKey);
      // A vault from before authenticated values moves over here, the new wrap being its commit
      final wrapped = await aesGcmEncrypt(wrapKey, session.secretKey, nonce: authenticatedWrapNonce());
      next['skNonce'] = b64(wrapped.nonce);
      next['skEnc'] = b64(wrapped.ct);
      next['keyUnlock'] = changed.toJson();
      // Before the write: the new config opens with the new wrap key, to the key in hand
      final reread = jsonDecode(jsonEncode(next)) as Map<String, Object?>;
      final reopenKey = _wrapKey(mode, KeyUnlock.of(reread), passwordKey, keySecret);
      if (!identical(reopenKey, passwordKey)) made.add(reopenKey);
      final reopened = await _open(reread, reopenKey);
      made.add(reopened.secretKey);
      if (!sameBytes(reopened.secretKey, session.secretKey)) throw StateError('The new wrap does not open to the vault’s key.');
      final moving = !_authenticated(config);
      if (moving) {
        await _moveValues(vault, session);
        await _authenticateKitWrap(vault, next, session);
      }
      // Biometric unlock goes before the commit, not after it: cut short in between, the vault opens
      // with its password as before and only offers biometrics again, where the other way round
      // would leave an entry that opens it without the key
      if (mode.needsKey) await _forgetBiometrics(vault, keyMayStay: true);
      // The commit
      _writeConfig(next, vault);
      await _store.flush();
      if (moving) session._authenticated = true;
      return OwnerProof._(vault, mode.hasPassword ? _copy(passwordKey) : null, _copy(keySecret));
    } finally {
      made.forEach(_wipe);
    }
  }

  // ─── Recovery Kit ──────────────────────────────────────────────────────────
  //
  // A random 256-bit key, split into pieces the user prints or hands to
  // people they trust. The vault's private key gets a second wrap under it,
  // so enough pieces open the vault without the master password, and
  // encrypted exports made while the kit exists carry the same kind of wrap.

  /// Makes [kit] the active vault's Recovery Kit, replacing any earlier one, whose pieces stop working.
  Future<void> setRecoveryKey(VaultSession session, RecoveryKey kit) async {
    final config = _readConfig();
    if (config == null) throw const VaultMissingError('No vault config found.');
    _writeConfig({...config, 'recovery': await wrapForKit(kit, session.secretKey, authenticated: _authenticated(config))});
    await saveEncryptedValue(_keyRecovery, _kitRecord(kit), session);
  }

  /// A kit's key as the vault keeps it, sealed, for new exports.
  static Map<String, Object?> _kitRecord(RecoveryKey kit) => {
    'kitId': kit.kitId,
    'key': b64(kit.key),
    'threshold': kit.threshold,
    'shares': kit.shares,
    'createdAt': kit.createdAt,
  };

  /// The active vault's kit key, for wrapping new exports; null when it has no kit.
  ///
  /// The stored key is used only if it opens the config's wrap of this
  /// vault's private key. A sealed value proves nothing about who wrote it,
  /// since anyone can seal to the public key: without this check, a kit
  /// record written into storage by someone else would wrap every later
  /// export under a key of theirs, and the export's password would no longer
  /// be needed to open it.
  Future<RecoveryKey?> loadRecoveryKey(VaultSession session) async {
    final wrap = _readConfig()?['recovery'] as Map<String, Object?>?;
    if (wrap == null) return null;
    return _kitOf(_vaults.active, wrap, session);
  }

  /// The kit key [vault] keeps, when it is the one that opens [wrap] to
  /// [session]'s private key; see [loadRecoveryKey].
  Future<RecoveryKey?> _kitOf(String vault, Map<String, Object?> wrap, VaultSession session) async {
    final stored = await _loadFrom(_vaults.vaultKey(_keyRecovery, vault), session, vault) as Map<String, Object?>?;
    // Another kit's key than the one the config names, as a key replacement cut short might leave
    if (stored == null || stored['kitId'] != wrap['kitId']) return null;
    final Uint8List key;
    try {
      key = unb64(stored['key']! as String);
      if (!sameBytes(await unwrapForKit(wrap, key), session.secretKey)) return null;
    } on Object {
      return null;
    }
    return RecoveryKey(
      kitId: stored['kitId']! as String,
      key: key,
      threshold: (stored['threshold']! as num).toInt(),
      shares: (stored['shares']! as num).toInt(),
      createdAt: stored['createdAt']! as String,
    );
  }

  /// When and how the active vault's kit was made, or null without one.
  RecoveryKitInfo? recoveryKitInfo() {
    final wrap = _readConfig()?['recovery'] as Map<String, Object?>?;
    if (wrap == null) return null;
    return RecoveryKitInfo(
      kitId: wrap['kitId']! as String,
      threshold: (wrap['threshold']! as num).toInt(),
      shares: (wrap['shares']! as num).toInt(),
      createdAt: wrap['createdAt']! as String,
    );
  }

  /// Whether the active vault's Recovery Kit is its only way back in: the
  /// vault needs a key and has fewer than two (openspec:
  /// add-security-key-unlock, decision 8). Such a kit is not deleted.
  bool recoveryKitIsLastWayBack() {
    final config = _readConfig();
    final unlock = KeyUnlock.of(config);
    return config != null && unlock != null && unlock.mode.needsKey && config['recovery'] != null && unlock.keys.length < 2;
  }

  /// Deletes the active vault's kit, so its pieces open nothing made from now on.
  /// Throws [SafetyNetError], and changes nothing, when the vault needs a
  /// key and the kit is its only way back in.
  void removeRecoveryKey() {
    if (recoveryKitIsLastWayBack()) throw const SafetyNetError();
    final config = _readConfig();
    if (config != null && config.containsKey('recovery')) _writeConfig({...config}..remove('recovery'));
    _store.removeItem(_vaults.vaultKey(_keyRecovery));
  }

  /// Opens whichever vault on this device the kit belongs to and makes it
  /// active. The session has no password key, so a new password is set next.
  Future<VaultSession> unlockWithRecoveryKey(String kitId, Uint8List key) async {
    for (final id in _vaults.allVaultIds()) {
      final config = _readConfig(id);
      final wrap = config?['recovery'] as Map<String, Object?>?;
      if (config == null || wrap == null || wrap['kitId'] != kitId) continue;
      final secretKey = await unwrapForKit(wrap, key);
      _vaults.active = id;
      final session = _sessionThrough(wrap['nonce'], config, secretKey);
      await _afterUnlock(id, session);
      return session;
    }
    throw const KitNotFoundError();
  }
}

/// A key wrapped with a Recovery Kit's key (AES-256-GCM), as the vault config and exports hold it.
///
/// [authenticated] is for the private key of a vault or an export whose
/// sealed values are authenticated: the wrap's nonce then says so
/// ([authenticatedWrapNonce]), and whatever the kit opens demands it.
Future<Map<String, Object?>> wrapForKit(RecoveryKey kit, Uint8List secret, {bool authenticated = false}) async {
  final sealed = await aesGcmEncrypt(kit.key, secret, nonce: authenticated ? authenticatedWrapNonce() : null);
  return {
    'kitId': kit.kitId,
    'threshold': kit.threshold,
    'shares': kit.shares,
    'createdAt': kit.createdAt,
    'nonce': b64(sealed.nonce),
    'ct': b64(sealed.ct),
  };
}

Future<Uint8List> unwrapForKit(Map<String, Object?> wrap, Uint8List key) =>
    aesGcmDecrypt(key, unb64(wrap['nonce']! as String), unb64(wrap['ct']! as String));
