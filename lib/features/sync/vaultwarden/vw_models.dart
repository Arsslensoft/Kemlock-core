/// What Vaultwarden sync keeps on the phone, encrypted with the vault:
/// where it syncs and how ([VaultwardenTarget], in the sync settings), and
/// the session that lets it in ([VwCredentials], stored apart because its
/// tokens change about every hour).
///
/// Both keep the keys they don't know and write them back, as the other
/// sync settings do.
library;

import '../../../crypto/bitwarden.dart';
import '../../../crypto/bytes.dart';
import '../../../models/json.dart';
import '../sync_crypto.dart' show Kdf;

/// How a home keeps its entries.
enum VaultwardenMode {
  /// Encrypted again under a key only Kemlock has.
  sealed,

  /// As ordinary Vaultwarden logins and notes.
  plain;

  static VaultwardenMode? parse(Object? value) => switch (value) {
    'sealed' => sealed,
    'plain' => plain,
    _ => null,
  };
}

/// The key sealed entries are encrypted with, and the passphrase's salt.
class VwSeal {
  const VwSeal({required this.key, required this.kdf, this.extra = const {}});

  factory VwSeal.fromJson(Map<String, Object?> json) => VwSeal(
    key: asString(json['key']),
    kdf: Kdf.fromJson(json['kdf'] is Map<String, Object?> ? json['kdf']! as Map<String, Object?> : const {}),
    extra: extraKeys(json, const {'key', 'kdf'}),
  );

  /// AES-256 key, base64.
  final String key;
  final Kdf kdf;
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'key': key, 'kdf': kdf.toJson(), ...extra};

  @override
  bool operator ==(Object other) => other is VwSeal && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => kdf.hashCode;

  /// Leaves the key out, so it never ends up in a log.
  @override
  String toString() => 'VwSeal($kdf)';
}

/// Where in a Vaultwarden account a vault's own entries sync, kept in the
/// sync settings under `vaultwarden`.
class VaultwardenTarget {
  const VaultwardenTarget({
    required this.server,
    required this.email,
    required this.home,
    required this.mode,
    required this.folderId,
    this.seal,
    this.pickUp = false,
    this.pin,
    this.plainKinds = const {},
    this.kemlockOfferDay,
    this.extra = const {},
  });

  factory VaultwardenTarget.fromJson(Map<String, Object?> json) => VaultwardenTarget(
    server: asString(json['server']),
    email: asString(json['email']),
    home: asString(json['home']),
    mode: VaultwardenMode.parse(json['mode']) ?? VaultwardenMode.sealed,
    folderId: asString(json['folderId']),
    seal: json['seal'] is Map<String, Object?> ? VwSeal.fromJson(json['seal']! as Map<String, Object?>) : null,
    pickUp: json['pickUp'] == true,
    pin: asOptionalString(json['pin']),
    plainKinds: {...?asStrings(json['plainKinds'])},
    kemlockOfferDay: asOptionalString(json['kemlockOfferDay']),
    extra: extraKeys(json, const {'server', 'email', 'home', 'mode', 'folderId', 'seal', 'pickUp', 'pin', 'plainKinds', 'kemlockOfferDay'}),
  );

  /// e.g. https://vault.example.com
  final String server;
  final String email;

  /// The id of the home this vault syncs with.
  final String home;
  final VaultwardenMode mode;

  /// The folder new items go in: the home's.
  final String folderId;

  /// Sealed only: the key entries are sealed with. Kept after a change to
  /// plain storage until every entry is moved.
  final VwSeal? seal;

  /// Plain only: also show logins with codes that no home claims.
  final bool pickUp;

  /// The SHA-256 fingerprint of a self-signed certificate the user pinned.
  final String? pin;

  /// The kinds of entries added after codes (`key`, `note`, `passkey`) the
  /// user agreed to have written in the clear in a plain home. Until a kind
  /// is agreed to, plain sync writes none of its entries. Saved only once
  /// there is one, so settings from before stay as they were.
  final Set<String> plainKinds;

  /// The day (`yyyy-mm-dd`) the offer to move to Kemlock Server was last read and shown, so it is read and shown
  /// at most once a day (add-kemlock-server-sync, task 12.2). Saved only once there is one.
  final String? kemlockOfferDay;

  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {
    'server': server,
    'email': email,
    'home': home,
    'mode': mode.name,
    'folderId': folderId,
    'seal': ?seal?.toJson(),
    'pickUp': pickUp,
    'pin': ?pin,
    if (plainKinds.isNotEmpty) 'plainKinds': [...plainKinds]..sort(),
    'kemlockOfferDay': ?kemlockOfferDay,
    ...extra,
  };

  VaultwardenTarget copyWith({
    VaultwardenMode? mode,
    Object? seal = keep,
    bool? pickUp,
    Object? pin = keep,
    Set<String>? plainKinds,
    String? kemlockOfferDay,
  }) => VaultwardenTarget(
    server: server,
    email: email,
    home: home,
    mode: mode ?? this.mode,
    folderId: folderId,
    seal: pick(seal, this.seal),
    pickUp: pickUp ?? this.pickUp,
    pin: pick(pin, this.pin),
    plainKinds: plainKinds ?? this.plainKinds,
    kemlockOfferDay: kemlockOfferDay ?? this.kemlockOfferDay,
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is VaultwardenTarget && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(server, email, home, mode);

  @override
  String toString() => 'VaultwardenTarget($server, $email, $home, ${mode.name})';
}

/// The signed-in session, stored as `backmycodes_vaultwarden`: never the
/// master password, only what it opened.
class VwCredentials {
  const VwCredentials({
    required this.deviceId,
    required this.userId,
    required this.userKey,
    required this.accessToken,
    required this.refreshToken,
    required this.expiresAt,
    this.kdf,
    this.rememberToken,
    this.clientId,
    this.clientSecret,
    this.extra = const {},
  });

  factory VwCredentials.fromJson(Map<String, Object?> json) => VwCredentials(
    deviceId: asString(json['deviceId']),
    userId: asString(json['userId']),
    userKey: asString(json['userKey']),
    accessToken: asString(json['accessToken']),
    refreshToken: asString(json['refreshToken']),
    expiresAt: asInt(json['expiresAt']) ?? 0,
    kdf: _kdf(json['kdf']),
    rememberToken: asOptionalString(json['rememberToken']),
    clientId: asOptionalString(json['clientId']),
    clientSecret: asOptionalString(json['clientSecret']),
    extra: extraKeys(json, const {'deviceId', 'userId', 'userKey', 'accessToken', 'refreshToken', 'expiresAt', 'kdf', 'rememberToken'}),
  );

  /// Made once per vault, so signing in again is the same device.
  final String deviceId;
  final String userId;

  /// The 64-byte user key, base64.
  final String userKey;
  final String accessToken;
  final String refreshToken;

  /// Epoch ms the access token ends.
  final int expiresAt;
  final BwKdf? kdf;

  /// Skips the second step at the next sign-in.
  final String? rememberToken;

  /// The personal API key, when the session came from it: Vaultwarden gives
  /// such a session no refresh token, so the key signs in again instead.
  final String? clientId;
  final String? clientSecret;
  final Map<String, Object?> extra;

  BwKey get key => BwKey.fromBytes(unb64(userKey));

  Map<String, Object?> toJson() => {
    'deviceId': deviceId,
    'userId': userId,
    'userKey': userKey,
    'accessToken': accessToken,
    'refreshToken': refreshToken,
    'expiresAt': expiresAt,
    'kdf': ?kdf?.toJson(),
    'rememberToken': ?rememberToken,
    'clientId': ?clientId,
    'clientSecret': ?clientSecret,
    ...extra,
  };

  VwCredentials withTokens({required String accessToken, required String refreshToken, required int expiresAt}) => VwCredentials(
    deviceId: deviceId,
    userId: userId,
    userKey: userKey,
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: expiresAt,
    kdf: kdf,
    rememberToken: rememberToken,
    clientId: clientId,
    clientSecret: clientSecret,
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is VwCredentials && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(deviceId, userId);

  /// Leaves the keys and tokens out, so they never end up in a log.
  @override
  String toString() => 'VwCredentials($userId, device $deviceId)';
}

BwKdf? _kdf(Object? json) {
  if (json is! Map<String, Object?>) return null;
  try {
    return BwKdf.fromJson(json);
  } on FormatException {
    return null;
  }
}
