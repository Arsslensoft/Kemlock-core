import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// The digits of a card number typed or pasted: spaces, dashes and every
/// other character leave, so "4111-1111 1111-1111" is 4111111111111111.
String cardDigits(String text) => text.replaceAll(RegExp(r'[^0-9]'), '');

/// Whether [text] is only digits with the spaces and dashes people group a
/// card number by.
bool isCardNumberText(String text) => RegExp(r'^[0-9 \-]*$').hasMatch(text);

/// A year from one or two digits as people type it: 29 is 2029, 2029 stays.
/// Null for a year outside 0 to 99 and 1000 to 9999.
int? cardYear(int? year) {
  if (year == null) return null;
  if (year >= 0 && year <= 99) return 2000 + year;
  if (year >= 1000 && year <= 9999) return year;
  return null;
}

/// A month and a year from "05/29", "5/2029", "05-29" or "0529", either part
/// null when it isn't there or isn't valid.
({int? month, int? year}) parseCardExpiry(String text) {
  final parts = text.trim().split(RegExp(r'[\s/\-.]+')).where((part) => part.isNotEmpty).toList();
  final digitsOnly = RegExp(r'^[0-9]+$');
  if (parts.any((part) => !digitsOnly.hasMatch(part))) return (month: null, year: null);
  if (parts.length == 1 && parts.first.length == 4) {
    // "0529": month then a two-digit year.
    return (month: _month(int.tryParse(parts.first.substring(0, 2))), year: cardYear(int.tryParse(parts.first.substring(2))));
  }
  if (parts.length == 1) return (month: _month(int.tryParse(parts.first)), year: null);
  if (parts.length != 2) return (month: null, year: null);
  return (month: _month(int.tryParse(parts[0])), year: cardYear(int.tryParse(parts[1])));
}

int? _month(int? value) => value != null && value >= 1 && value <= 12 ? value : null;

/// A payment card kept in the vault: a name, the cardholder, the number as
/// digits, a brand, the expiry, the security code and PIN, and a "valid
/// from" month. Keys it doesn't know are kept in [extra] and written back,
/// as on every model.
class PaymentCard implements VaultEntry<PaymentCard> {
  const PaymentCard({
    required this.id,
    required this.name,
    this.cardholder,
    this.number,
    this.brand,
    this.expMonth,
    this.expYear,
    this.code,
    this.pin,
    this.validFromMonth,
    this.validFromYear,
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

  factory PaymentCard.fromJson(Map<String, Object?> json) => PaymentCard(
    id: asString(json['id']),
    name: asString(json['name']),
    cardholder: asOptionalString(json['cardholder']),
    number: asOptionalString(json['number']),
    brand: asOptionalString(json['brand']),
    expMonth: asInt(json['expMonth']),
    expYear: asInt(json['expYear']),
    code: asOptionalString(json['code']),
    pin: asOptionalString(json['pin']),
    validFromMonth: asInt(json['validFromMonth']),
    validFromYear: asInt(json['validFromYear']),
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
    'cardholder',
    'number',
    'brand',
    'expMonth',
    'expYear',
    'code',
    'pin',
    'validFromMonth',
    'validFromYear',
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

  /// What the person calls it: "Everyday Visa".
  final String name;
  final String? cardholder;

  /// The card number as digits only (`cardDigits`).
  final String? number;

  /// Stored, not derived from the number: a co-branded card may differ.
  final String? brand;

  /// 1 to 12.
  final int? expMonth;

  /// Four digits.
  final int? expYear;

  /// The security code. A secret.
  final String? code;

  /// The PIN. A secret.
  final String? pin;
  final int? validFromMonth;
  final int? validFromYear;
  final String? note;
  final List<String>? tags;

  /// Shown first in the list.
  final bool? pinned;

  /// The shared space this card belongs to; absent for the vault's own.
  @override
  final String? spaceId;

  /// Where the card came from, such as an importer.
  final String? source;

  /// Epoch ms the card was added.
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

  /// A card needs a name and a number or a cardholder.
  bool get isComplete => name.trim().isNotEmpty && ((number?.isNotEmpty ?? false) || (cardholder?.trim().isNotEmpty ?? false));

  /// The last four digits of the number, or all of a shorter one; null without a number.
  String? get lastFour {
    final digits = number;
    if (digits == null || digits.isEmpty) return null;
    return digits.length <= 4 ? digits : digits.substring(digits.length - 4);
  }

  /// Whether the expiry month has ended at [now]. With a year and no month
  /// the card lasts to the end of the year, and without a year it never expires.
  bool isExpired(DateTime now) {
    final year = expYear;
    if (year == null) return false;
    if (now.year != year) return now.year > year;
    final month = expMonth;
    return month != null && now.month > month;
  }

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'cardholder': ?cardholder,
    'number': ?number,
    'brand': ?brand,
    'expMonth': ?expMonth,
    'expYear': ?expYear,
    'code': ?code,
    'pin': ?pin,
    'validFromMonth': ?validFromMonth,
    'validFromYear': ?validFromYear,
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
  PaymentCard copyWith({
    String? id,
    String? name,
    Object? cardholder = keep,
    Object? number = keep,
    Object? brand = keep,
    Object? expMonth = keep,
    Object? expYear = keep,
    Object? code = keep,
    Object? pin = keep,
    Object? validFromMonth = keep,
    Object? validFromYear = keep,
    Object? note = keep,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    Object? source = keep,
    int? addedAt,
    Object? updatedAt = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => PaymentCard(
    id: id ?? this.id,
    name: name ?? this.name,
    cardholder: pick(cardholder, this.cardholder),
    number: pick(number, this.number),
    brand: pick(brand, this.brand),
    expMonth: pick(expMonth, this.expMonth),
    expYear: pick(expYear, this.expYear),
    code: pick(code, this.code),
    pin: pick(pin, this.pin),
    validFromMonth: pick(validFromMonth, this.validFromMonth),
    validFromYear: pick(validFromYear, this.validFromYear),
    note: pick(note, this.note),
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    source: pick(source, this.source),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is PaymentCard && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  PaymentCard withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  PaymentCard stamped(int at) => copyWith(updatedAt: at);

  @override
  PaymentCard inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  /// Never the number, code or PIN, which logs and test failures would show.
  @override
  String toString() => 'PaymentCard($id, $name)';
}
