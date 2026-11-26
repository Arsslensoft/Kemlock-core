import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// The most address lines an identity keeps.
const identityAddressLines = 3;

/// What an identity document is.
enum IdentityDocumentType {
  passport('passport'),
  driversLicence('driversLicence'),
  idCard('idCard'),
  taxNumber('taxNumber'),
  other('other');

  const IdentityDocumentType(this.wire);

  /// The value stored in the vault.
  final String wire;

  /// The type stored as [value]; an unknown one is [other].
  static IdentityDocumentType fromWire(String? value) => values.firstWhere((type) => type.wire == value, orElse: () => other);
}

/// An identity's postal address.
class IdentityAddress {
  const IdentityAddress({this.lines, this.city, this.region, this.postalCode, this.country, this.extra = const {}});

  factory IdentityAddress.fromJson(Map<String, Object?> json) => IdentityAddress(
    lines: asStrings(json['lines']),
    city: asOptionalString(json['city']),
    region: asOptionalString(json['region']),
    postalCode: asOptionalString(json['postalCode']),
    country: asOptionalString(json['country']),
    extra: extraKeys(json, _keys),
  );

  static const _keys = {'lines', 'city', 'region', 'postalCode', 'country'};

  /// Up to [identityAddressLines] lines.
  final List<String>? lines;
  final String? city;
  final String? region;
  final String? postalCode;

  /// An ISO 3166-1 alpha-2 code when picked from the list, else as typed.
  final String? country;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// Whether no part of the address is set.
  bool get isEmpty => toJson().isEmpty;

  Map<String, Object?> toJson() => {
    if (lines?.isNotEmpty ?? false) 'lines': lines,
    'city': ?city,
    'region': ?region,
    'postalCode': ?postalCode,
    'country': ?country,
    ...extra,
  };

  @override
  bool operator ==(Object other) => other is IdentityAddress && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(city, postalCode, country);
}

/// A passport, licence, ID card or number an identity holds.
class IdentityDocument {
  const IdentityDocument({
    required this.id,
    this.type = 'other',
    required this.number,
    this.issuingCountry,
    this.issuingAuthority,
    this.issuedOn,
    this.expiresOn,
    this.extra = const {},
  });

  factory IdentityDocument.fromJson(Map<String, Object?> json) => IdentityDocument(
    id: asString(json['id']),
    // Kept as read, so a type from a later version survives; [kind] reads it as other.
    type: asString(json['type'], IdentityDocumentType.other.wire),
    number: asString(json['number']),
    issuingCountry: asOptionalString(json['issuingCountry']),
    issuingAuthority: asOptionalString(json['issuingAuthority']),
    issuedOn: asOptionalString(json['issuedOn']),
    expiresOn: asOptionalString(json['expiresOn']),
    extra: extraKeys(json, _keys),
  );

  static const _keys = {'id', 'type', 'number', 'issuingCountry', 'issuingAuthority', 'issuedOn', 'expiresOn'};

  final String id;

  /// A [IdentityDocumentType.wire] value, or one a later version wrote.
  final String type;

  /// The document's number. A secret.
  final String number;
  final String? issuingCountry;
  final String? issuingAuthority;

  /// `yyyy-mm-dd`.
  final String? issuedOn;

  /// `yyyy-mm-dd`.
  final String? expiresOn;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// The type this version shows; [IdentityDocumentType.other] for an unknown one.
  IdentityDocumentType get kind => IdentityDocumentType.fromWire(type);

  /// Whether the expiry date is before the day of [now].
  bool isExpired(DateTime now) {
    final expires = DateTime.tryParse(expiresOn ?? '');
    if (expires == null) return false;
    return DateTime(expires.year, expires.month, expires.day).isBefore(DateTime(now.year, now.month, now.day));
  }

  IdentityDocument copyWith({
    String? type,
    String? number,
    Object? issuingCountry = keep,
    Object? issuingAuthority = keep,
    Object? issuedOn = keep,
    Object? expiresOn = keep,
  }) => IdentityDocument(
    id: id,
    type: type ?? this.type,
    number: number ?? this.number,
    issuingCountry: pick(issuingCountry, this.issuingCountry),
    issuingAuthority: pick(issuingAuthority, this.issuingAuthority),
    issuedOn: pick(issuedOn, this.issuedOn),
    expiresOn: pick(expiresOn, this.expiresOn),
    extra: extra,
  );

  Map<String, Object?> toJson() => {
    'id': id,
    'type': type,
    'number': number,
    'issuingCountry': ?issuingCountry,
    'issuingAuthority': ?issuingAuthority,
    'issuedOn': ?issuedOn,
    'expiresOn': ?expiresOn,
    ...extra,
  };

  @override
  bool operator ==(Object other) => other is IdentityDocument && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  /// Never the number, which logs and test failures would show.
  @override
  String toString() => 'IdentityDocument($id, $type)';
}

/// A person's details kept in the vault: name parts, contact details, one
/// postal address and the identity documents they hold. Keys it doesn't know
/// are kept in [extra] and written back, as on every model.
class Identity implements VaultEntry<Identity> {
  const Identity({
    required this.id,
    required this.name,
    this.title,
    this.givenName,
    this.middleName,
    this.familyName,
    this.company,
    this.email,
    this.phone,
    this.username,
    this.birthDate,
    this.address,
    this.documents,
    this.note,
    this.tags,
    this.pinned,
    this.spaceId,
    this.source,
    required this.addedAt,
    this.updatedAt,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory Identity.fromJson(Map<String, Object?> json) => Identity(
    id: asString(json['id']),
    name: asString(json['name']),
    title: asOptionalString(json['title']),
    givenName: asOptionalString(json['givenName']),
    middleName: asOptionalString(json['middleName']),
    familyName: asOptionalString(json['familyName']),
    company: asOptionalString(json['company']),
    email: asOptionalString(json['email']),
    phone: asOptionalString(json['phone']),
    username: asOptionalString(json['username']),
    birthDate: asOptionalString(json['birthDate']),
    address: switch (json['address']) {
      final Map<String, Object?> map => IdentityAddress.fromJson(map),
      _ => null,
    },
    documents: switch (json['documents']) {
      final List<Object?> list => [
        for (final item in list)
          if (item is Map<String, Object?>) IdentityDocument.fromJson(item),
      ],
      _ => null,
    },
    note: asOptionalString(json['note']),
    tags: asStrings(json['tags']),
    pinned: asBool(json['pinned']),
    spaceId: asOptionalString(json['spaceId']),
    source: asOptionalString(json['source']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    links: readLinks(json['links']),
    fields: readFields(json['fields']),
    extra: extraKeysOfBody(json, _keys),
  );

  static const _keys = {
    'id',
    'name',
    'title',
    'givenName',
    'middleName',
    'familyName',
    'company',
    'email',
    'phone',
    'username',
    'birthDate',
    'address',
    'documents',
    'note',
    'tags',
    'pinned',
    'spaceId',
    'source',
    'addedAt',
    'updatedAt',
  };

  @override
  final String id;

  /// What the person calls it: "Me".
  final String name;
  final String? title;
  final String? givenName;
  final String? middleName;
  final String? familyName;
  final String? company;
  final String? email;
  final String? phone;
  final String? username;

  /// `yyyy-mm-dd`.
  final String? birthDate;
  final IdentityAddress? address;
  final List<IdentityDocument>? documents;
  final String? note;
  final List<String>? tags;

  /// Shown first in the list.
  final bool? pinned;

  /// The shared space this identity belongs to; absent for the vault's own.
  @override
  final String? spaceId;

  /// Where the identity came from, such as an importer.
  final String? source;

  /// Epoch ms the identity was added.
  final int addedAt;

  /// Epoch ms of the last change, so sync can tell which copy is newer.
  final int? updatedAt;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isPinned => pinned ?? false;

  /// The given, middle and family names in order, or null when none is set.
  String? get fullName {
    final parts = [givenName, middleName, familyName].map((part) => part?.trim() ?? '').where((part) => part.isNotEmpty).toList();
    return parts.isEmpty ? null : parts.join(' ');
  }

  /// Whether any detail besides the name is set.
  bool get hasDetails {
    bool set(String? value) => value?.trim().isNotEmpty ?? false;
    return [title, givenName, middleName, familyName, company, email, phone, username, birthDate, note].any(set) ||
        !(address?.isEmpty ?? true) ||
        (documents?.isNotEmpty ?? false);
  }

  /// An identity needs a name and at least one detail.
  bool get isComplete => name.trim().isNotEmpty && hasDetails;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'title': ?title,
    'givenName': ?givenName,
    'middleName': ?middleName,
    'familyName': ?familyName,
    'company': ?company,
    'email': ?email,
    'phone': ?phone,
    'username': ?username,
    'birthDate': ?birthDate,
    if (address != null && !address!.isEmpty) 'address': address!.toJson(),
    if (documents?.isNotEmpty ?? false) 'documents': [for (final document in documents!) document.toJson()],
    'note': ?note,
    'tags': ?tags,
    'pinned': ?pinned,
    'spaceId': ?spaceId,
    'source': ?source,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  Identity copyWith({
    String? id,
    String? name,
    Object? title = keep,
    Object? givenName = keep,
    Object? middleName = keep,
    Object? familyName = keep,
    Object? company = keep,
    Object? email = keep,
    Object? phone = keep,
    Object? username = keep,
    Object? birthDate = keep,
    Object? address = keep,
    Object? documents = keep,
    Object? note = keep,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    Object? source = keep,
    int? addedAt,
    Object? updatedAt = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => Identity(
    id: id ?? this.id,
    name: name ?? this.name,
    title: pick(title, this.title),
    givenName: pick(givenName, this.givenName),
    middleName: pick(middleName, this.middleName),
    familyName: pick(familyName, this.familyName),
    company: pick(company, this.company),
    email: pick(email, this.email),
    phone: pick(phone, this.phone),
    username: pick(username, this.username),
    birthDate: pick(birthDate, this.birthDate),
    address: pick(address, this.address),
    documents: pick(documents, this.documents),
    note: pick(note, this.note),
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    source: pick(source, this.source),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extraSetting(extra, links: links != null, fields: fields != null),
  );

  @override
  bool operator ==(Object other) => other is Identity && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  Identity withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  Identity stamped(int at) => copyWith(updatedAt: at);

  @override
  Identity inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  /// Never the details, which logs and test failures would show.
  @override
  String toString() => 'Identity($id, $name)';
}
