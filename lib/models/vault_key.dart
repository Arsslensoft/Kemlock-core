import 'custom_field.dart';
import 'item_link.dart';
import 'json.dart';
import 'vault_entry.dart';

/// What a key is for, as the vault names it.
abstract final class KeyKind {
  static const ssh = 'ssh';
  static const signing = 'signing';
  static const exchange = 'exchange';
  static const pgp = 'pgp';

  /// A PKCS#8 key of an algorithm Kemlock doesn't know.
  static const other = 'other';
}

/// Where a key came from.
abstract final class KeyOrigin {
  static const generated = 'generated';
  static const imported = 'imported';
}

/// A key pair kept in the vault: an SSH, signing, exchange or PGP key, or a
/// private key of an algorithm Kemlock doesn't know. Keys it doesn't know
/// are kept in [extra] and written back.
///
/// [privateKey] is PKCS#8 DER for every key but a PGP key, whose private
/// half is its binary transferable secret key, exactly as given, and whose
/// [publicKey] is the transferable public key. Any other key's public half
/// is its SPKI DER, absent for an algorithm Kemlock doesn't know. Both are
/// base64.
///
/// The kind and the algorithm never change once a key is in the vault, nor
/// do the halves of any key but a PGP key. A PGP key's halves change only
/// through [withHalves], when the key is changed in its sheet or two copies
/// of it are combined (openspec: add-pgp-key-editing); each keeps its
/// primary fingerprint and every packet the key held, and only adds. A
/// combined key's packets are then in the merge's own order, no longer
/// exactly as given. No other change replaces a half: one that takes a
/// packet away on purpose is an exception of its own, and is named here.
///
/// Moving a PGP key to an OpenPGP card (openspec: add-openpgp-card) is that
/// exception: [movedToCard] puts GnuPG's stub, which holds no secret, in
/// place of the private half, and leaves the public half byte for byte as
/// it was. It is saved with `updateKey`, not through [withHalves].
class VaultKey implements VaultEntry<VaultKey> {
  const VaultKey({
    required this.id,
    required this.name,
    required this.kind,
    required this.algorithm,
    this.bits,
    required this.privateKey,
    this.publicKey,
    required this.origin,
    this.protected,
    this.note,
    this.tags,
    this.pinned,
    this.spaceId,
    required this.addedAt,
    this.updatedAt,
    this.card,
    this.links = const [],
    this.fields = const [],
    this.extra = const {},
  });

  factory VaultKey.fromJson(Map<String, Object?> json) => VaultKey(
    id: asString(json['id']),
    name: asString(json['name']),
    kind: asString(json['kind'], KeyKind.other),
    algorithm: asString(json['algorithm']),
    bits: asInt(json['bits']),
    privateKey: asString(json['private']),
    publicKey: asOptionalString(json['public']),
    origin: asString(json['origin'], KeyOrigin.imported),
    protected: asBool(json['protected']),
    note: asOptionalString(json['note']),
    tags: json['tags'] is List ? (json['tags']! as List<Object?>).whereType<String>().toList() : null,
    pinned: asBool(json['pinned']),
    spaceId: asOptionalString(json['spaceId']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    card: json['card'] is Map ? Map<String, Object?>.from(json['card']! as Map) : null,
    links: readLinks(json['links']),
    fields: readFields(json['fields']),
    extra: extraKeysOfBody(json, {..._keys, if (json['card'] is Map) 'card'}),
  );

  static const _keys = {
    'id',
    'name',
    'kind',
    'algorithm',
    'bits',
    'private',
    'public',
    'origin',
    'protected',
    'note',
    'tags',
    'pinned',
    'spaceId',
    'addedAt',
    'updatedAt',
  };

  @override
  final String id;
  final String name;

  /// One of [KeyKind].
  final String kind;

  /// `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa`, `x25519`, `ml-kem-768`,
  /// `ml-kem-1024`, `ml-dsa-65`, `pgp`, or the dotted OID of one Kemlock
  /// doesn't know.
  final String algorithm;

  /// An RSA key's size.
  final int? bits;

  /// The private half, base64; see the class comment. Never shown unasked.
  final String privateKey;

  /// The public half, base64; see the class comment.
  final String? publicKey;

  /// One of [KeyOrigin].
  final String origin;

  /// A PGP key that keeps its own passphrase.
  final bool? protected;
  final String? note;
  final List<String>? tags;
  final bool? pinned;

  @override
  final String? spaceId;

  /// Epoch ms the key was added.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// For a PGP key whose private half is on a security key's OpenPGP
  /// card (openspec: add-openpgp-card): `aid`, the card's application
  /// identifier in 32 hexadecimal digits, and `slots`, the fingerprint held
  /// in each place it uses (`sig`, `dec`, `aut`). Written only for such a
  /// key. It is not one of the halves, and may change.
  final Map<String, Object?>? card;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// The custom fields (see [CustomField]); none when it holds no `fields`.
  final List<CustomField> fields;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isPinned => pinned ?? false;

  /// Whether the private half is on a card: [privateKey] is then GnuPG's
  /// stub, with no secret in it.
  bool get isOnCard => card != null;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'kind': kind,
    'algorithm': algorithm,
    'bits': ?bits,
    'private': privateKey,
    'public': ?publicKey,
    'origin': origin,
    'protected': ?protected,
    'note': ?note,
    'tags': ?tags,
    'pinned': ?pinned,
    'spaceId': ?spaceId,
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    'card': ?card,
    'links': ?writeLinks(links),
    'fields': ?writeFields(fields),
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an
  /// optional field. The algorithm and the kind never change, and the
  /// halves change only through [withHalves].
  VaultKey copyWith({
    String? id,
    String? name,
    Object? note = keep,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    int? addedAt,
    Object? updatedAt = keep,
    Object? card = keep,
    List<ItemLink>? links,
    List<CustomField>? fields,
  }) => VaultKey(
    id: id ?? this.id,
    name: name ?? this.name,
    kind: kind,
    algorithm: algorithm,
    bits: bits,
    privateKey: privateKey,
    publicKey: publicKey,
    origin: origin,
    protected: protected,
    note: pick(note, this.note),
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    card: pick(card, this.card),
    links: links ?? this.links,
    fields: fields ?? this.fields,
    extra: extraSetting(extra, links: links != null, fields: fields != null),
  );

  /// This key once its private half moved to an OpenPGP card (design
  /// decision 12 of add-openpgp-card): GnuPG's [stub] in place of the
  /// secret, base64, and the [card] that holds it, changed [at]. The
  /// public half, the name, note, tags, pin and space stay as they are, so
  /// that sync carries the change to the other devices under the same id.
  VaultKey movedToCard({required String stub, required Map<String, Object?> card, required int at}) => VaultKey(
    id: id,
    name: name,
    kind: kind,
    algorithm: algorithm,
    bits: bits,
    privateKey: stub,
    publicKey: publicKey,
    origin: origin,
    protected: true,
    note: note,
    tags: tags,
    pinned: pinned,
    spaceId: spaceId,
    addedAt: addedAt,
    updatedAt: at,
    card: card,
    links: links,
    fields: fields,
    extra: extra,
  );

  /// The same PGP key with new halves, base64 as the class says, and
  /// [protected] as the new private half is: the one way a half grows.
  /// Every other field, [extra] and [card] included, stays, so a key on a
  /// card that grows keeps its card. The caller has checked that the new
  /// halves are the same key grown (`replaceKeyHalves`). Throws a
  /// [StateError] for a key of any other kind.
  VaultKey withHalves({required String privateKey, required String publicKey, required bool protected}) {
    if (kind != KeyKind.pgp) throw StateError('the halves of a $kind key never change');
    return VaultKey(
      id: id,
      name: name,
      kind: kind,
      algorithm: algorithm,
      bits: bits,
      privateKey: privateKey,
      publicKey: publicKey,
      origin: origin,
      protected: protected ? true : null,
      note: note,
      tags: tags,
      pinned: pinned,
      spaceId: spaceId,
      addedAt: addedAt,
      updatedAt: updatedAt,
      card: card,
      links: links,
      fields: fields,
      extra: extra,
    );
  }

  @override
  int get changedAt => updatedAt ?? addedAt;

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself.
  /// It is not stamped.
  @override
  VaultKey withLinks(List<ItemLink> links) => copyWith(links: normaliseLinks(links, ownIds: [id]));

  @override
  VaultKey stamped(int at) => copyWith(updatedAt: at);

  @override
  VaultKey inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  @override
  bool operator ==(Object other) => other is VaultKey && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  @override
  String toString() => 'VaultKey($id, $name, $kind, $algorithm)';
}
