import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';
import 'website_rule.dart';

/// totp: RFC 6238 time-based codes. hotp: RFC 4226 counter-based codes.
/// steam: Steam Guard, a TOTP variant with 5-character alphanumeric codes.
enum OtpType {
  totp,
  hotp,
  steam;

  static OtpType? parse(Object? value) => switch (value) {
    'totp' => totp,
    'hotp' => hotp,
    'steam' => steam,
    _ => null,
  };
}

/// One account the app makes codes for, in the JSON the vault holds
/// (`types.ts`). Keys it doesn't know are kept in [extra] and written back.
class OtpAccount implements VaultEntry<OtpAccount> {
  const OtpAccount({
    required this.id,
    this.type,
    this.name,
    required this.issuer,
    required this.label,
    required this.secret,
    this.algorithm = 'SHA1',
    this.digits = 6,
    this.period = 30,
    this.counter,
    this.pinned,
    this.tags,
    this.order,
    this.note,
    this.noBackupCodes,
    this.spaceId,
    required this.addedAt,
    this.updatedAt,
    this.breachesDismissed,
    this.websites,
    this.uris,
    this.linkedLoginId,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory OtpAccount.fromJson(Map<String, Object?> json) => OtpAccount(
    id: asString(json['id']),
    type: OtpType.parse(json['type']),
    name: asOptionalString(json['name']),
    issuer: asString(json['issuer']),
    label: asString(json['label']),
    secret: asString(json['secret']),
    algorithm: asString(json['algorithm'], 'SHA1'),
    digits: asInt(json['digits']) ?? 6,
    period: asInt(json['period']) ?? 30,
    counter: asInt(json['counter']),
    pinned: asBool(json['pinned']),
    tags: asStrings(json['tags']),
    order: asInt(json['order']),
    note: asOptionalString(json['note']),
    noBackupCodes: asBool(json['noBackupCodes']),
    spaceId: asOptionalString(json['spaceId']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    breachesDismissed: asStrings(json['breachesDismissed']),
    websites: readWebsites(json).websites,
    uris: readWebsites(json).uris,
    linkedLoginId: asOptionalString(json['linkedLoginId']),
    links: readLinks(json['links']),
    fields: readFields(json['fields']),
    extra: extraKeysOfBody(json, {..._keys, if (json['linkedLoginId'] is String) 'linkedLoginId'}),
  );

  static const _keys = {
    'id',
    'type',
    'name',
    'issuer',
    'label',
    'secret',
    'algorithm',
    'digits',
    'period',
    'counter',
    'pinned',
    'tags',
    'order',
    'note',
    'noBackupCodes',
    'spaceId',
    'addedAt',
    'updatedAt',
    'breachesDismissed',
    'websites',
    'uris',
  };

  @override
  final String id;

  /// Absent on accounts saved before HOTP and Steam support, which are all TOTP.
  final OtpType? type;

  /// What the item is called, when the person named it; without it the item is named by its issuer and label.
  final String? name;
  final String issuer;
  final String label;
  final String secret;

  /// 'SHA1', 'SHA256' or 'SHA512'.
  final String algorithm;

  /// 6 or 8. Ignored for Steam, whose codes are always 5 characters.
  final int digits;

  /// Seconds per code; TOTP and Steam only.
  final int period;

  /// HOTP only: the counter the shown code was generated from.
  final int? counter;

  /// Shown in the Pinned section at the top of the list.
  final bool? pinned;

  /// User-defined labels the list can be filtered by.
  final List<String>? tags;

  /// Position in the custom sort order, lowest first.
  final int? order;
  final String? note;

  /// The service doesn't hand out backup codes, so the coverage check skips it.
  final bool? noBackupCodes;

  /// The shared space this account belongs to; absent for the vault's own accounts.
  @override
  final String? spaceId;

  /// Epoch ms the account was added.
  final int addedAt;

  /// Epoch ms of the last change, so sync can tell which copy is newer; addedAt if never changed.
  final int? updatedAt;

  /// The breaches of this account's service that were marked dealt with, by Have I Been
  /// Pwned's name for each (openspec: breach-alerts). Absent when there are none.
  final List<String>? breachesDismissed;

  /// The websites the person gave the account, as hosts (`normaliseWebsite`), where AutoFill
  /// suggests its code with those the 2FA directory gives it (openspec: account-websites).
  /// Absent when there are none.
  final List<String>? websites;

  /// Each website with the rule that says where it fills, always the full list when it is
  /// set; null when the account holds hosts alone. Written only when it says more than
  /// `websites` does, and builds that know no rules keep it in `extra`.
  final List<WebsiteRule>? uris;

  /// The websites with their rules: `uris`, else each host on the default rule.
  List<WebsiteRule> get rules => uris ?? [for (final host in websites ?? const <String>[]) WebsiteRule(host)];

  Websites _changed(Object? websites, Object? uris) =>
      changeWebsites((websites: this.websites, uris: this.uris), websites: websites, uris: uris);

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// The id of the login this code was made from, which the importer writes: the login shows the code, and the code is linked
  /// to it. Read as a link on both items and never copied into [links]; unlinking them removes it.
  final String? linkedLoginId;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// The type, with accounts from before HOTP and Steam read as TOTP.
  OtpType get kind => type ?? OtpType.totp;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'type': ?type?.name,
    'name': ?name,
    'issuer': issuer,
    'label': label,
    'secret': secret,
    'algorithm': algorithm,
    'digits': digits,
    'period': period,
    'counter': ?counter,
    'pinned': ?pinned,
    'tags': ?tags,
    'order': ?order,
    'note': ?note,
    'noBackupCodes': ?noBackupCodes,
    'spaceId': ?spaceId,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    if (breachesDismissed?.isNotEmpty ?? false) 'breachesDismissed': breachesDismissed,
    ...writeWebsites(websites, uris),
    'linkedLoginId': ?linkedLoginId,
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  OtpAccount copyWith({
    String? id,
    Object? type = keep,
    Object? name = keep,
    String? issuer,
    String? label,
    String? secret,
    String? algorithm,
    int? digits,
    int? period,
    Object? counter = keep,
    Object? pinned = keep,
    Object? tags = keep,
    Object? order = keep,
    Object? note = keep,
    Object? noBackupCodes = keep,
    Object? spaceId = keep,
    int? addedAt,
    Object? updatedAt = keep,
    Object? breachesDismissed = keep,
    Object? websites = keep,
    Object? uris = keep,
    Object? linkedLoginId = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => OtpAccount(
    id: id ?? this.id,
    type: pick(type, this.type),
    name: pick(name, this.name),
    issuer: issuer ?? this.issuer,
    label: label ?? this.label,
    secret: secret ?? this.secret,
    algorithm: algorithm ?? this.algorithm,
    digits: digits ?? this.digits,
    period: period ?? this.period,
    counter: pick(counter, this.counter),
    pinned: pick(pinned, this.pinned),
    tags: pick(tags, this.tags),
    order: pick(order, this.order),
    note: pick(note, this.note),
    noBackupCodes: pick(noBackupCodes, this.noBackupCodes),
    spaceId: pick(spaceId, this.spaceId),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    breachesDismissed: pick(breachesDismissed, this.breachesDismissed),
    websites: _changed(websites, uris).websites,
    uris: _changed(websites, uris).uris,
    linkedLoginId: pick(linkedLoginId, this.linkedLoginId),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extraWithUrls(extra, (websites: this.websites, uris: this.uris), _changed(websites, uris)),
  );

  @override
  bool operator ==(Object other) => other is OtpAccount && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  OtpAccount withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  OtpAccount stamped(int at) => copyWith(updatedAt: at);

  /// As in the TypeScript, an empty scope counts as none.
  @override
  OtpAccount inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  /// Never the secret, nor the note: what prints can end up in a log.
  @override
  String toString() => 'OtpAccount($id, $issuer, $label)';
}
