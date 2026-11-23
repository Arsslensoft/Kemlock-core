/// Where a vault syncs with Kemlock Server, as the settings keep it
/// (`SyncSettings.kemlock`). Like the other settings classes, each keeps the
/// keys it doesn't know and writes them back, so a later version's members
/// survive a round trip through this one.
///
/// Pure Dart, no Flutter.
library;

import '../../../models/json.dart';

/// A server of a vault's list: the home first, then its replicas.
class KemlockServer {
  const KemlockServer({required this.url, this.role = home, this.pin, this.identityKey, this.extra = const {}});

  factory KemlockServer.fromJson(Map<String, Object?> json) => KemlockServer(
    url: asString(json['url']),
    role: asString(json['role'], home),
    pin: asOptionalString(json['pin']),
    identityKey: asOptionalString(json['identityKey']),
    extra: extraKeys(json, const {'url', 'role', 'pin', 'identityKey'}),
  );

  /// The role of the server the vault was set up with.
  static const home = 'home';

  /// The role of a server that holds a copy and takes over when the home is down.
  static const replica = 'replica';

  /// The server's address, `https://kem.example.com`, as checked when it was added.
  final String url;

  /// [home] or [replica].
  final String role;

  /// The SHA-256 of the one certificate the person compared and trusted, for a server whose
  /// certificate the system doesn't trust; null for one it does. It never widens trust beyond
  /// that certificate.
  final String? pin;

  /// The server's identity key as first seen, base64url, which a promotion record is checked with.
  final String? identityKey;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'url': url, 'role': role, 'pin': ?pin, 'identityKey': ?identityKey, ...extra};

  @override
  bool operator ==(Object other) => other is KemlockServer && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(url, role);

  @override
  String toString() => 'KemlockServer($url, $role)';
}

/// Where the vault's own entries sync in Kemlock Server: the account, the
/// vault's server list and this phone's device id. The tokens and the
/// account's keys are not here: they are sealed apart (`km_session.dart`).
class KemlockTarget {
  const KemlockTarget({
    required this.accountId,
    required this.email,
    required this.servers,
    required this.deviceId,
    this.homeEpoch = 0,
    this.push = true,
    this.matching = false,
    this.matchingSeen = const {},
    this.extra = const {},
  });

  factory KemlockTarget.fromJson(Map<String, Object?> json) => KemlockTarget(
    accountId: asString(json['accountId']),
    email: asString(json['email']),
    servers: [
      if (json['servers'] case final List<Object?> servers)
        for (final server in servers.whereType<Map<String, Object?>>()) KemlockServer.fromJson(server),
    ],
    deviceId: asString(json['deviceId']),
    homeEpoch: asInt(json['homeEpoch']) ?? 0,
    push: json['push'] != false,
    matching: json['matching'] == true,
    matchingSeen: {
      if (json['matchingSeen'] case final Map<String, Object?> seen)
        for (final MapEntry(:key, :value) in seen.entries)
          if (value is int) key: value,
    },
    extra: extraKeys(json, const {'accountId', 'email', 'servers', 'deviceId', 'homeEpoch', 'push', 'matching', 'matchingSeen'}),
  );

  /// The account's id, a UUID.
  final String accountId;

  /// The email the account signed in with.
  final String email;

  /// The vault's server list, the home first.
  final List<KemlockServer> servers;

  /// This phone's device id: the Vaultwarden one for a vault that syncs or synced with Vaultwarden
  /// on the same server, so the server shows one device for both APIs, else one made for this vault.
  final String deviceId;

  /// The home's epoch, which a promotion record must exceed.
  final int homeEpoch;

  /// Whether the server's nudges ("sync now" and approval requests from other devices) reach this phone
  /// through the push relay. On until turned off (owner decision 7); written only when off.
  final bool push;

  /// Whether the person turned on server matching for the vault (add-duplicate-cleaner, task group 7): a run then
  /// sends each login's `cred` tags beside its write, and the server groups them. Off until turned on, and written only
  /// when on. The server holds the switch too; a run that finds it off there turns this off.
  final bool matching;

  /// For each space whose server matching this member was told about, when it was last changed (Unix seconds), so the
  /// notice is shown once. Written only when not empty.
  final Map<String, int> matchingSeen;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// The server the vault syncs with first: the first of the list with the home role, else the first.
  KemlockServer get home => servers.firstWhere((server) => server.role == KemlockServer.home, orElse: () => servers.first);

  Map<String, Object?> toJson() => {
    'accountId': accountId,
    'email': email,
    'servers': [for (final server in servers) server.toJson()],
    'deviceId': deviceId,
    'homeEpoch': homeEpoch,
    if (!push) 'push': false,
    if (matching) 'matching': true,
    if (matchingSeen.isNotEmpty) 'matchingSeen': matchingSeen,
    ...extra,
  };

  /// A copy with the given members changed.
  KemlockTarget copyWith({
    List<KemlockServer>? servers,
    String? deviceId,
    int? homeEpoch,
    bool? push,
    bool? matching,
    Map<String, int>? matchingSeen,
  }) => KemlockTarget(
    accountId: accountId,
    email: email,
    servers: servers ?? this.servers,
    deviceId: deviceId ?? this.deviceId,
    homeEpoch: homeEpoch ?? this.homeEpoch,
    push: push ?? this.push,
    matching: matching ?? this.matching,
    matchingSeen: matchingSeen ?? this.matchingSeen,
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is KemlockTarget && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(accountId, email, servers.length);

  /// Leaves nothing secret out: there is nothing secret here, but the email stays out of logs.
  @override
  String toString() => 'KemlockTarget($accountId, ${servers.length} servers)';
}
