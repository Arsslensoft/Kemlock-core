import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// COSE's number for ES256, ECDSA with P-256 and SHA-256: the only kind of
/// passkey Kemlock makes or keeps.
const coseEs256 = -7;

/// A passkey: a P-256 key pair a site or an app registered for one of its
/// users, which signs that user in. Keys it doesn't know are kept in
/// [extra] and written back.
///
/// A passkey belongs to the vault itself and never to a shared space:
/// several people signing in as one account defeats it, and the copy the
/// phone's passkey provider reads is per vault. [spaceId] is always null.
class Passkey implements VaultEntry<Passkey> {
  const Passkey({
    required this.id,
    required this.credentialId,
    required this.rpId,
    this.rpName,
    required this.userHandle,
    required this.userName,
    this.userDisplayName,
    required this.privateKey,
    this.algorithm = coseEs256,
    this.label,
    this.note,
    this.tags,
    required this.addedAt,
    this.updatedAt,
    this.links = const [],
    this.extra = const {},
  });

  factory Passkey.fromJson(Map<String, Object?> json) => Passkey(
    id: asString(json['id']),
    credentialId: asString(json['credentialId']),
    rpId: asString(json['rpId']),
    rpName: asOptionalString(json['rpName']),
    userHandle: asString(json['userHandle']),
    userName: asString(json['userName']),
    userDisplayName: asOptionalString(json['userDisplayName']),
    privateKey: asString(json['privateKey']),
    algorithm: asInt(json['algorithm']) ?? coseEs256,
    label: asOptionalString(json['label']),
    note: asOptionalString(json['note']),
    tags: json['tags'] is List ? (json['tags']! as List<Object?>).whereType<String>().toList() : null,
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    links: readLinks(json['links']),
    extra: extraKeysOfBody(json, _keys, fields: false),
  );

  static const _keys = {
    'id',
    'credentialId',
    'rpId',
    'rpName',
    'userHandle',
    'userName',
    'userDisplayName',
    'privateKey',
    'algorithm',
    'label',
    'note',
    'tags',
    'addedAt',
    'updatedAt',
  };

  @override
  final String id;

  /// The credential's id, base64url without padding, as sites receive it.
  final String credentialId;

  /// The relying party: the site's domain, such as `github.com`.
  final String rpId;

  /// The name the site gave itself, when it gave one.
  final String? rpName;

  /// The site's id for the user, base64url without padding.
  final String userHandle;

  /// The account's name at the site, usually an email address.
  final String userName;
  final String? userDisplayName;

  /// The private key, PKCS#8 DER in base64. Never shown.
  final String privateKey;

  /// The COSE algorithm, [coseEs256].
  final int algorithm;

  /// A name the person gave the passkey, shown instead of the site's.
  final String? label;
  final String? note;
  final List<String>? tags;

  /// Epoch ms the passkey was made or added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// What the passkey is listed as: its label, the site's name, or its domain.
  String get displayName => switch (label?.trim()) {
    final label? when label.isNotEmpty => label,
    _ => switch (rpName?.trim()) {
      final name? when name.isNotEmpty => name,
      _ => rpId,
    },
  };

  @override
  String? get spaceId => null;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'credentialId': credentialId,
    'rpId': rpId,
    'rpName': ?rpName,
    'userHandle': userHandle,
    'userName': userName,
    'userDisplayName': ?userDisplayName,
    'privateKey': privateKey,
    'algorithm': algorithm,
    'label': ?label,
    'note': ?note,
    'tags': ?tags,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    'links': ?writeLinks(links),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an
  /// optional field. The key and what the site knows it by never change.
  Passkey copyWith({
    String? id,
    Object? rpName = keep,
    String? userName,
    Object? userDisplayName = keep,
    Object? label = keep,
    Object? note = keep,
    Object? tags = keep,
    int? addedAt,
    Object? updatedAt = keep,
    List<ItemLink>? links,
  }) => Passkey(
    id: id ?? this.id,
    credentialId: credentialId,
    rpId: rpId,
    rpName: pick(rpName, this.rpName),
    userHandle: userHandle,
    userName: userName ?? this.userName,
    userDisplayName: pick(userDisplayName, this.userDisplayName),
    privateKey: privateKey,
    algorithm: algorithm,
    label: pick(label, this.label),
    note: pick(note, this.note),
    tags: pick(tags, this.tags),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    links: links ?? this.links,
    extra: extraSetting(extra, links: links != null),
  );

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  Passkey withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  Passkey stamped(int at) => copyWith(updatedAt: at);

  /// Passkeys stay in the vault's own scope, so this returns it unchanged.
  @override
  Passkey inSpace(String? scope) => this;

  @override
  bool operator ==(Object other) => other is Passkey && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'Passkey($id, $rpId, $userName)';
}
