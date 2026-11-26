import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';
import 'website_rule.dart';

/// One backup code of a service.
class BackupCode {
  const BackupCode({required this.code, this.used = false, this.usedAt, this.extra = const {}});

  factory BackupCode.fromJson(Map<String, Object?> json) => BackupCode(
    code: asString(json['code']),
    used: json['used'] == true,
    usedAt: asInt(json['usedAt']),
    extra: extraKeys(json, const {'code', 'used', 'usedAt'}),
  );

  final String code;
  final bool used;

  /// Epoch ms of when the code was marked used.
  final int? usedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'code': code, 'used': used, 'usedAt': ?usedAt, ...extra};

  BackupCode copyWith({String? code, bool? used, Object? usedAt = keep}) =>
      BackupCode(code: code ?? this.code, used: used ?? this.used, usedAt: pick(usedAt, this.usedAt), extra: extra);

  @override
  bool operator ==(Object other) => other is BackupCode && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => code.hashCode;

  /// Never the code: what prints can end up in a log.
  @override
  String toString() => 'BackupCode(used: $used)';
}

/// A service and the backup codes it gave, in the JSON the vault holds
/// (`types.ts`). Keys it doesn't know are kept in [extra] and written back.
class BackupService implements VaultEntry<BackupService> {
  const BackupService({
    required this.id,
    this.name,
    required this.serviceName,
    required this.codes,
    this.note,
    this.spaceId,
    required this.addedAt,
    this.updatedAt,
    this.breachesDismissed,
    this.websites,
    this.uris,
    this.sitesAsRead = false,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory BackupService.fromJson(Map<String, Object?> json) {
    final sites = readWebsites(json);
    // A body whose websites don't write back exactly (see [writesBackWebsites]) keeps them as it held them, and so does one whose
    // `name` isn't a text: whatever the person didn't edit is written back as it was
    final exact = writesBackWebsites(json, sites);
    return BackupService(
      id: asString(json['id']),
      name: asOptionalString(json['name']),
      serviceName: asString(json['serviceName']),
      codes: [for (final code in (json['codes'] as List<Object?>?) ?? const []) BackupCode.fromJson(code! as Map<String, Object?>)],
      note: asOptionalString(json['note']),
      spaceId: asOptionalString(json['spaceId']),
      addedAt: asInt(json['addedAt']) ?? 0,
      updatedAt: asInt(json['updatedAt']),
      breachesDismissed: asStrings(json['breachesDismissed']),
      websites: sites.websites,
      uris: sites.uris,
      sitesAsRead: !exact,
      links: readLinks(json['links']),
      fields: readFields(json['fields']),
      extra: extraKeysOfBody(json, {
        'id',
        if (json['name'] is String) 'name',
        'serviceName',
        'codes',
        'note',
        'spaceId',
        'addedAt',
        'updatedAt',
        'breachesDismissed',
        if (exact) ...const ['websites', 'uris'],
      }),
    );
  }

  @override
  final String id;

  /// What the item is called, when the person named it; without it the item is named by [serviceName].
  final String? name;
  final String serviceName;
  final List<BackupCode> codes;
  final String? note;

  /// The shared space this service belongs to; absent for the vault's own services.
  @override
  final String? spaceId;

  /// Epoch ms the service was added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// The breaches of this service that were marked dealt with, by Have I Been Pwned's name
  /// for each (openspec: breach-alerts). Absent when there are none.
  final List<String>? breachesDismissed;

  /// The hosts the codes are used on (`normaliseWebsite`), as on a login. A code linked to an item that has websites shows
  /// that item's and doesn't write its own. Absent when there are none.
  final List<String>? websites;

  /// Each website with the rule that says where it fills, always the full list when it is set; null when the service
  /// holds hosts alone. Written only when it says more than `websites` does.
  final List<WebsiteRule>? uris;

  /// Whether the body's `websites` and `uris` could not be written back exactly from [websites] and [uris]: it holds them among
  /// [extra] as it had them, and writes none of its own until the websites are edited.
  final bool sitesAsRead;

  /// The websites with their rules: `uris`, else each host on the default rule.
  List<WebsiteRule> get rules => uris ?? [for (final host in websites ?? const <String>[]) WebsiteRule(host)];

  Websites _changed(Object? websites, Object? uris) =>
      changeWebsites((websites: this.websites, uris: this.uris), websites: websites, uris: uris);

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': ?name,
    'serviceName': serviceName,
    'codes': [for (final code in codes) code.toJson()],
    'note': ?note,
    'spaceId': ?spaceId,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    if (breachesDismissed?.isNotEmpty ?? false) 'breachesDismissed': breachesDismissed,
    if (!sitesAsRead) ...writeWebsites(websites, uris),
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  BackupService copyWith({
    String? id,
    Object? name = keep,
    String? serviceName,
    List<BackupCode>? codes,
    Object? note = keep,
    Object? spaceId = keep,
    int? addedAt,
    Object? updatedAt = keep,
    Object? breachesDismissed = keep,
    Object? websites = keep,
    Object? uris = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) {
    // An edit of the websites replaces the members the body held; one of the name replaces a name that wasn't a text
    final sitesEdited = !identical(websites, keep) || !identical(uris, keep);
    final held = {
      for (final MapEntry(:key, :value) in extra.entries)
        if (!(sitesEdited && sitesAsRead && (key == 'websites' || key == 'uris')) && !(!identical(name, keep) && key == 'name')) key: value,
    };
    return BackupService(
    id: id ?? this.id,
    name: pick(name, this.name),
    serviceName: serviceName ?? this.serviceName,
    codes: codes ?? this.codes,
    note: pick(note, this.note),
    spaceId: pick(spaceId, this.spaceId),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    breachesDismissed: pick(breachesDismissed, this.breachesDismissed),
    websites: _changed(websites, uris).websites,
    uris: _changed(websites, uris).uris,
    sitesAsRead: sitesAsRead && !sitesEdited,
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extraSetting(
      extraWithUrls(held, (websites: this.websites, uris: this.uris), _changed(websites, uris)),
      links: links != null,
      fields: fields != null,
    ),
    );
  }

  @override
  bool operator ==(Object other) => other is BackupService && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself: not by its id, nor
  /// by any of [ownIds], the other ids that name it (its item id, which an entry with a legacy id doesn't share). It is not stamped.
  @override
  BackupService withLinks(List<ItemLink> links, {Iterable<String> ownIds = const []}) =>
      copyWith(links: normaliseLinks(links, ownIds: [id, ...ownIds]));

  @override
  BackupService stamped(int at) => copyWith(updatedAt: at);

  /// As in the TypeScript, an empty scope counts as none.
  @override
  BackupService inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  /// Never the codes, nor the note: what prints can end up in a log.
  @override
  String toString() => 'BackupService($id, $serviceName, ${codes.length} codes)';
}
