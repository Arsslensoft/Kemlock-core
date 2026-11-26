import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// How someone's key reached the vault.
abstract final class ContactSource {
  static const qr = 'qr';
  static const file = 'file';
  static const paste = 'paste';

  /// Found by email in the Web Key Directory of the address's domain.
  static const wkd = 'wkd';

  /// Found by email on keys.openpgp.org.
  static const keyserver = 'keyserver';

  /// Typed in, with no key: a contact made without one.
  static const manual = 'manual';
}

/// A person kept in the vault: a contact, with their company, email, phone and address and, when there is one,
/// their OpenPGP public key. It holds no private key. Keys it doesn't know are kept in [extra] and
/// written back.
///
/// [publicKey] is the binary transferable public key in base64, trimmed to
/// what its owner signed. A contact may have none: it is then empty, [hasKey] is
/// false, the body holds no `public` and [source] is [ContactSource.manual]. The contact is checked when [checkedFingerprint]
/// is the fingerprint of that key: the mark belongs to the key that was
/// compared, so another key put under the same contact is not checked.
/// The check covers the addresses the key carried when it was compared,
/// [checkedAddresses]; one the key's owner adds later is not checked.
/// Contacts stay in the vault's own scope, as passkeys do: a check is one
/// person's own statement.
class Contact implements VaultEntry<Contact> {
  const Contact({
    required this.id,
    required this.name,
    this.publicKey = '',
    required this.source,
    this.company,
    this.email,
    this.phone,
    this.address,
    this.sourceEmail,
    this.checkedAt,
    this.checkedFingerprint,
    this.checkedAddresses,
    this.note,
    required this.addedAt,
    this.updatedAt,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory Contact.fromJson(Map<String, Object?> json) => Contact(
    id: asString(json['id']),
    name: asString(json['name']),
    company: asOptionalString(json['company']),
    email: asOptionalString(json['email']),
    phone: asOptionalString(json['phone']),
    address: asOptionalString(json['address']),
    publicKey: asString(json['public']),
    source: asString(json['source']),
    sourceEmail: asOptionalString(json['sourceEmail']),
    checkedAt: asInt(json['checkedAt']),
    checkedFingerprint: asOptionalString(json['checkedFingerprint']),
    checkedAddresses: asStrings(json['checkedAddresses']),
    note: asOptionalString(json['note']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    links: readLinks(json['links']),
    fields: readFields(json['fields']),
    extra: extraKeysOfBody(json, _keys),
  );

  static const _keys = {
    'id',
    'name',
    'company',
    'email',
    'phone',
    'address',
    'public',
    'source',
    'sourceEmail',
    'checkedAt',
    'checkedFingerprint',
    'checkedAddresses',
    'note',
    'addedAt',
    'updatedAt',
  };

  /// A random UUID. It is never derived from the fingerprint: a sealed
  /// Vaultwarden value names the entry's id in the clear.
  @override
  final String id;

  /// What the list shows; the name of the key's first user ID by default.
  final String name;

  /// The person's company, when it was given.
  final String? company;

  /// Their email address: what the contact is told by with [phone], not the address a key was found for ([sourceEmail]).
  final String? email;
  final String? phone;

  /// Free text, with line breaks.
  final String? address;

  /// The transferable public key, base64; see the class comment. Empty for a contact with no key.
  final String publicKey;

  /// Whether the contact has a public key.
  bool get hasKey => publicKey.isNotEmpty;

  /// One of [ContactSource]; a value this version doesn't know is kept.
  final String source;

  /// The address the key was found for, when [source] is
  /// [ContactSource.wkd] or [ContactSource.keyserver]; absent otherwise.
  final String? sourceEmail;

  /// Epoch ms of the day the fingerprint was compared; null when it never was.
  final int? checkedAt;

  /// The upper-case hexadecimal fingerprint that was compared.
  final String? checkedFingerprint;

  /// The addresses of the key's user IDs, in lower case, when it was
  /// compared: those the check covers. Absent from a check made by a
  /// version before this field, which covers the addresses of the key as
  /// this version first reads it, and is written down then
  /// (`withCheckedAddresses`); versions before it keep it as a key they
  /// don't know.
  final List<String>? checkedAddresses;
  final String? note;

  /// Epoch ms the contact was added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  @override
  String? get spaceId => null;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'company': ?company,
    'email': ?email,
    'phone': ?phone,
    'address': ?address,
    if (publicKey.isNotEmpty) 'public': publicKey,
    'source': source,
    'sourceEmail': ?sourceEmail,
    'checkedAt': ?checkedAt,
    'checkedFingerprint': ?checkedFingerprint,
    'checkedAddresses': ?checkedAddresses,
    'note': ?note,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an
  /// optional field.
  Contact copyWith({
    String? id,
    String? name,
    Object? company = keep,
    Object? email = keep,
    Object? phone = keep,
    Object? address = keep,
    String? publicKey,
    String? source,
    Object? sourceEmail = keep,
    Object? checkedAt = keep,
    Object? checkedFingerprint = keep,
    Object? checkedAddresses = keep,
    Object? note = keep,
    int? addedAt,
    Object? updatedAt = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => Contact(
    id: id ?? this.id,
    name: name ?? this.name,
    company: pick(company, this.company),
    email: pick(email, this.email),
    phone: pick(phone, this.phone),
    address: pick(address, this.address),
    publicKey: publicKey ?? this.publicKey,
    source: source ?? this.source,
    sourceEmail: pick(sourceEmail, this.sourceEmail),
    checkedAt: pick(checkedAt, this.checkedAt),
    checkedFingerprint: pick(checkedFingerprint, this.checkedFingerprint),
    checkedAddresses: pick(checkedAddresses, this.checkedAddresses),
    note: pick(note, this.note),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extraSetting(extra, links: links != null, fields: fields != null),
  );

  /// A copy marked as compared [at] (epoch ms) for the key whose
  /// fingerprint is [fingerprint], upper-case hexadecimal, and which
  /// carried [addresses] then. Without [addresses], the check covers the
  /// key as it is, as one made before checks kept them.
  Contact checked(String fingerprint, int at, {Iterable<String>? addresses}) => copyWith(
    checkedAt: at,
    checkedFingerprint: fingerprint,
    checkedAddresses: addresses == null ? unset : ({for (final address in addresses) address.toLowerCase()}.toList()..sort()),
  );

  /// A copy with the mark taken back, and the addresses it covered.
  Contact unchecked() => copyWith(checkedAt: unset, checkedFingerprint: unset, checkedAddresses: unset);

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself: not by its id, nor
  /// by any of [ownIds], the other ids that name it (its item id, which an entry with a legacy id doesn't share). It is not stamped.
  @override
  Contact withLinks(List<ItemLink> links, {Iterable<String> ownIds = const []}) =>
      copyWith(links: normaliseLinks(links, ownIds: [id, ...ownIds]));

  @override
  Contact stamped(int at) => copyWith(updatedAt: at);

  /// Contacts stay in the vault's own scope, so this returns it unchanged.
  @override
  Contact inSpace(String? scope) => this;

  @override
  bool operator ==(Object other) => other is Contact && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'Contact($id, $name)';
}
