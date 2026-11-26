import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// Counter-based (RFC 4226) or time-based (RFC 6238). A key holds no other kind.
enum KeyAccountType {
  totp,
  hotp;

  static KeyAccountType parse(Object? value) => value == 'hotp' ? hotp : totp;
}

/// An account as a key listed it at a read, for [KeyAccount]s to be made
/// equal to (openspec: add-security-key-codes, decision 4).
class KeyAccountSeen {
  const KeyAccountSeen({required this.name, required this.type, this.algorithm = 'SHA1', this.touch, this.tags, this.note});

  /// The account's name on the key.
  final String name;
  final KeyAccountType type;
  final String algorithm;

  /// Null when the read ended before the key said: what was known stays.
  final bool? touch;

  /// The tags and note an account moved from the vault brings with it.
  final List<String>? tags;
  final String? note;
}

/// What the vault remembers of an account whose secret lives on a security
/// key (openspec: add-security-key-codes, decision 3): which key, the name
/// the key is asked by, and the tags and note given in the app. It has no
/// secret, no code and no digits, and never gets one: those names are not
/// written even when a file carried them.
class KeyAccount implements VaultEntry<KeyAccount> {
  const KeyAccount({
    required this.id,
    required this.device,
    this.keyName,
    required this.name,
    this.issuer = '',
    required this.label,
    this.period = 30,
    this.type = KeyAccountType.totp,
    this.algorithm = 'SHA1',
    this.touch = false,
    this.tags,
    this.note,
    required this.addedAt,
    this.updatedAt,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory KeyAccount.fromJson(Map<String, Object?> json) => KeyAccount(
    id: asString(json['id']),
    device: asString(json['device']),
    keyName: asOptionalString(json['keyName']),
    name: asString(json['name']),
    issuer: asString(json['issuer']),
    label: asString(json['label']),
    period: asInt(json['period']) ?? 30,
    type: KeyAccountType.parse(json['type']),
    algorithm: asString(json['algorithm'], 'SHA1'),
    touch: asBool(json['touch']) ?? false,
    tags: asStrings(json['tags']),
    note: asOptionalString(json['note']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    links: readLinks(json['links']),
    fields: readFields(json['fields']),
    extra: extraKeysOfBody(json, _keys),
  );

  /// The keys this version reads, and the three it never keeps.
  static const _keys = {
    'id',
    'device',
    'keyName',
    'name',
    'issuer',
    'label',
    'period',
    'type',
    'algorithm',
    'touch',
    'tags',
    'note',
    'addedAt',
    'updatedAt',
    ...neverWritten,
  };

  /// What an entry never holds, whatever a file said.
  static const neverWritten = {'secret', 'code', 'digits'};

  @override
  final String id;

  /// The id the key's code application gives when it is opened, in hex. It
  /// changes when the application is reset.
  final String device;

  /// The key's name at the last read ("YubiKey 5C NFC"), for the section's
  /// title when the key is away. Absent when the key gave none.
  final String? keyName;

  /// The account's name on the key, which the key is asked by.
  final String name;

  /// Read from [name]; empty when the name has no issuer.
  final String issuer;
  final String label;

  /// Seconds per code, read from [name]; time-based accounts only.
  final int period;
  final KeyAccountType type;

  /// 'SHA1', 'SHA256' or 'SHA512'.
  final String algorithm;

  /// The key works its code out only when touched.
  final bool touch;

  /// Given in the app and kept in the vault alone.
  final List<String>? tags;
  final String? note;

  /// Epoch ms the account was first seen.
  final int addedAt;
  final int? updatedAt;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// What a row or a toast calls it.
  String get displayName => issuer.isNotEmpty ? issuer : label;

  bool get isTimeBased => type == KeyAccountType.totp;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'device': device,
    'keyName': ?keyName,
    'name': name,
    'issuer': issuer,
    'label': label,
    'period': period,
    'type': type.name,
    'algorithm': algorithm,
    if (touch) 'touch': true,
    'tags': ?tags,
    'note': ?note,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  KeyAccount copyWith({
    String? id,
    String? device,
    Object? keyName = keep,
    String? name,
    String? issuer,
    String? label,
    int? period,
    KeyAccountType? type,
    String? algorithm,
    bool? touch,
    Object? tags = keep,
    Object? note = keep,
    int? addedAt,
    Object? updatedAt = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => KeyAccount(
    id: id ?? this.id,
    device: device ?? this.device,
    keyName: pick(keyName, this.keyName),
    name: name ?? this.name,
    issuer: issuer ?? this.issuer,
    label: label ?? this.label,
    period: period ?? this.period,
    type: type ?? this.type,
    algorithm: algorithm ?? this.algorithm,
    touch: touch ?? this.touch,
    tags: pick(tags, this.tags),
    note: pick(note, this.note),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is KeyAccount && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// An on-key account belongs to the vault alone, never to a shared space.
  @override
  String? get spaceId => null;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  KeyAccount withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  KeyAccount stamped(int at) => copyWith(updatedAt: at);

  @override
  KeyAccount inSpace(String? scope) => this;

  @override
  String toString() => 'KeyAccount(${toJson()})';
}
