/// What a vault keeps of a Kemlock Server sign-in, as sealed values of the
/// vault (`VaultStore.saveEncryptedValue`), per vault and gone with it
/// (`VaultRegistry.removeVaultData` removes keys by their suffix, and a
/// key-pair replacement re-seals every sealed value):
///
/// - [keyKemlockSession], the tokens and the device's key reference;
/// - [keyKemlockAccount], the account's user key, key pairs and the
///   `opaqueEnrolled` record, in `add-account-crypto`'s format (written by
///   the sign-in);
/// - [keyKemlockCache], the items as this phone last opened them, the
///   cursor and the manifest (`km_cache.dart`).
///
/// Turning sync off deletes all three. The trusted-device copy on the server
/// and the hardware key stay until the person removes trust.
///
/// Pure Dart, no Flutter.
library;

import '../../../models/json.dart';

/// Where the tokens and the device key's reference are kept.
const keyKemlockSession = 'backmycodes_kemlock_session';

/// Where the account's keys and its `opaqueEnrolled` record are kept.
const keyKemlockAccount = 'backmycodes_kemlock_account';

/// Where the opened items, the cursor and the manifest are kept.
const keyKemlockCache = 'backmycodes_kemlock_cache';

/// An access token, the refresh token that renews it, and when each ends.
class KmTokens {
  const KmTokens({required this.access, required this.refresh, required this.accessExpiresAt, required this.refreshExpiresAt});

  /// Reads a token answer: `{accessToken, expiresIn, refreshToken, refreshExpiresIn, …}`, with the
  /// times counted from [now] (epoch ms). A body that lacks a token throws a [FormatException].
  factory KmTokens.fromResponse(Map<String, Object?> json, int now) {
    final access = json['accessToken'];
    final refresh = json['refreshToken'];
    if (access is! String || access.isEmpty || refresh is! String || refresh.isEmpty) throw const FormatException('no tokens');
    return KmTokens(
      access: access,
      refresh: refresh,
      accessExpiresAt: now + (asInt(json['expiresIn']) ?? 0) * 1000,
      refreshExpiresAt: now + (asInt(json['refreshExpiresIn']) ?? 0) * 1000,
    );
  }

  factory KmTokens.fromJson(Map<String, Object?> json) => KmTokens(
    access: asString(json['access']),
    refresh: asString(json['refresh']),
    accessExpiresAt: asInt(json['accessExpiresAt']) ?? 0,
    refreshExpiresAt: asInt(json['refreshExpiresAt']) ?? 0,
  );

  final String access;
  final String refresh;

  /// Epoch ms.
  final int accessExpiresAt;
  final int refreshExpiresAt;

  Map<String, Object?> toJson() => {
    'access': access,
    'refresh': refresh,
    'accessExpiresAt': accessExpiresAt,
    'refreshExpiresAt': refreshExpiresAt,
  };

  /// Leaves the tokens out, so they never end up in a log.
  @override
  String toString() => 'KmTokens(expiresAt: $accessExpiresAt)';
}

/// The signed-in session, stored as [keyKemlockSession]: never the
/// password, never a hash of it.
class KmSession {
  const KmSession({required this.userId, required this.deviceId, required this.tokens, this.deviceKey, this.extra = const {}});

  factory KmSession.fromJson(Map<String, Object?> json) => KmSession(
    userId: asString(json['userId']),
    deviceId: asString(json['deviceId']),
    tokens: KmTokens.fromJson(json['tokens'] is Map<String, Object?> ? json['tokens']! as Map<String, Object?> : const {}),
    deviceKey: json['deviceKey'] is Map<String, Object?> ? json['deviceKey']! as Map<String, Object?> : null,
    extra: extraKeys(json, const {'userId', 'deviceId', 'tokens', 'deviceKey'}),
  );

  final String userId;

  /// The device id the server knows this phone by.
  final String deviceId;
  final KmTokens tokens;

  /// How to find the device key the tokens are bound to: `{protection, tag}` for a hardware key, and
  /// for the software key sealed here the scalar too (`km_device_key.dart`).
  final Map<String, Object?>? deviceKey;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  KmSession withTokens(KmTokens next) => KmSession(userId: userId, deviceId: deviceId, tokens: next, deviceKey: deviceKey, extra: extra);

  Map<String, Object?> toJson() => {'userId': userId, 'deviceId': deviceId, 'tokens': tokens.toJson(), 'deviceKey': ?deviceKey, ...extra};

  @override
  String toString() => 'KmSession($userId, $deviceId)';
}
