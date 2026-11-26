import 'item_link.dart';
import 'json.dart';
import 'secure_note.dart' show NoteAttachment;
import 'vault_entry.dart';

/// A File item (Kemlock Server kind `file`): one encrypted file and what names it. The file is stored apart from the
/// vault as a `KMA1` file under its own key, which [file] holds, exactly as a note's attachment is
/// (`NoteAttachment`). The item holds no custom fields and no attachments. Keys it doesn't know are kept in [extra] and
/// written back.
///
/// The body is `{ id, name, notes?, favorite?, file, tags?, pinned?, spaceId?, links?, addedAt, updatedAt? }`. The web vault
/// may write one with no `addedAt`, which reads as 0.
class VaultFile implements VaultEntry<VaultFile> {
  const VaultFile({
    required this.id,
    required this.name,
    this.notes,
    this.favorite,
    required this.file,
    this.tags,
    this.pinned,
    this.spaceId,
    this.links = const [],
    required this.addedAt,
    this.updatedAt,
    this.extra = const {},
  });

  factory VaultFile.fromJson(Map<String, Object?> json) => VaultFile(
    id: asString(json['id']),
    name: asString(json['name']),
    notes: asOptionalString(json['notes']),
    favorite: asBool(json['favorite']),
    file: switch (json['file']) {
      final Map<String, Object?> file => NoteAttachment.fromJson(file),
      _ => NoteAttachment.fromJson(const {}),
    },
    tags: asStrings(json['tags']),
    pinned: asBool(json['pinned']),
    spaceId: asOptionalString(json['spaceId']),
    links: readLinks(json['links']),
    addedAt: asInt(json['addedAt']) ?? 0,
    updatedAt: asInt(json['updatedAt']),
    extra: extraKeysOfBody(json, {..._keys, if (json['file'] is Map) 'file'}, fields: false),
  );

  static const _keys = {'id', 'name', 'notes', 'favorite', 'tags', 'pinned', 'spaceId', 'addedAt', 'updatedAt'};

  @override
  final String id;

  /// What the item is called: usually the file's name.
  final String name;
  final String? notes;
  final bool? favorite;

  /// The file: its id, name, size, media type, key and, once it is on the server, `kemlockFile` among its `extra`.
  final NoteAttachment file;
  final List<String>? tags;
  final bool? pinned;

  @override
  final String? spaceId;

  /// The items linked to this one, as a body holds them (see [ItemLink]); none when it holds no `links`.
  @override
  final List<ItemLink> links;

  /// Epoch ms the item was added; 0 when the body says none.
  final int addedAt;

  /// Epoch ms of the last change; addedAt if never changed.
  final int? updatedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isPinned => pinned ?? false;

  @override
  int get changedAt => updatedAt ?? addedAt;

  @override
  Map<String, Object?> toJson() => {
    'id': id,
    'name': name,
    'notes': ?notes,
    'favorite': ?favorite,
    'file': file.toJson(),
    'tags': ?tags,
    'pinned': ?pinned,
    'spaceId': ?spaceId,
    'links': ?writeLinks(links),
    'addedAt': addedAt,
    'updatedAt': ?updatedAt,
    ...extra,
  };

  /// A copy with the given fields changed. Pass [unset] to remove an optional field.
  VaultFile copyWith({
    String? id,
    String? name,
    Object? notes = keep,
    Object? favorite = keep,
    NoteAttachment? file,
    Object? tags = keep,
    Object? pinned = keep,
    Object? spaceId = keep,
    List<ItemLink>? links,
    int? addedAt,
    Object? updatedAt = keep,
  }) => VaultFile(
    id: id ?? this.id,
    name: name ?? this.name,
    notes: pick(notes, this.notes),
    favorite: pick(favorite, this.favorite),
    file: file ?? this.file,
    tags: pick(tags, this.tags),
    pinned: pick(pinned, this.pinned),
    spaceId: pick(spaceId, this.spaceId),
    links: links ?? this.links,
    addedAt: addedAt ?? this.addedAt,
    updatedAt: pick(updatedAt, this.updatedAt),
    extra: extraSetting(extra, links: links != null),
  );

  /// A copy that links to [links] and no other item: they are sorted by id, each once, and never the item itself: not by its id, nor
  /// by any of [ownIds], the other ids that name it (its item id, which an entry with a legacy id doesn't share). It is not stamped.
  @override
  VaultFile withLinks(List<ItemLink> links, {Iterable<String> ownIds = const []}) =>
      copyWith(links: normaliseLinks(links, ownIds: [id, ...ownIds]));

  @override
  VaultFile stamped(int at) => copyWith(updatedAt: at);

  @override
  VaultFile inSpace(String? scope) => copyWith(spaceId: scope != null && scope.isNotEmpty ? scope : unset);

  @override
  bool operator ==(Object other) => other is VaultFile && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => id.hashCode;

  /// Never the file's key, which logs and test failures would show.
  @override
  String toString() => 'VaultFile($id, $name)';
}
