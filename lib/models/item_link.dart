import 'json.dart';

final _uuid = RegExp(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');

/// An item that another item is linked to: the entry `{ "id": "<item uuid>" }` of a body's `links`
/// (`crypto.md`, "Item bodies"). A link is two-way: both bodies name each other.
///
/// The id is the lower-case hyphenated UUID of the linked item, which is its entry id or
/// `kmItemId` of it (see `lib/vault/item_links.dart`). Keys of the entry this version doesn't know are
/// kept in [extra]. An entry that can't be read (not an object, no UUID `id`) is an [ItemLink.unread]:
/// it keeps its JSON, whatever it is, and stays where it is, after the others. A list read from a
/// body and written back unchanged is the list the body held, entry by entry.
class ItemLink {
  const ItemLink(this.id, {this.extra = const {}}) : _source = null, isReadable = true;

  /// An entry this version can't read, kept as [raw].
  const ItemLink.unread(Object? raw) : id = '', extra = const {}, _source = raw, isReadable = false;

  const ItemLink._read(this.id, this.extra, this._source) : isReadable = true;

  /// An entry of `links`; never throws. What isn't an object with a UUID `id` is an [ItemLink.unread].
  factory ItemLink.fromJson(Object? json) {
    if (json is Map<String, Object?>) {
      final id = json['id'];
      if (id is String && _uuid.hasMatch(id)) {
        return ItemLink._read(id, extraKeys(json, const {'id'}), json);
      }
    }
    return ItemLink.unread(json);
  }

  /// The linked item's UUID, hyphenated. Empty for an entry that is not [isReadable].
  final String id;

  /// Keys of the entry this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// False for an entry this version can't read, which is only kept.
  final bool isReadable;

  /// The entry as read, written back as it was; null for a link made here.
  final Object? _source;

  /// [id] in lower case, which is how ids are compared.
  String get key => id.toLowerCase();

  Object? toJson() => switch (_source) {
    final Map<String, Object?> source => {...source},
    final Object? raw when !isReadable => raw,
    _ => {'id': id, ...extra},
  };

  @override
  bool operator ==(Object other) => other is ItemLink && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => isReadable ? key.hashCode : 0;

  @override
  String toString() => isReadable ? 'ItemLink($id)' : 'ItemLink(unread)';
}

/// The entries of a body's `links`, in the order the body holds them, none for a member that isn't a list.
List<ItemLink> readLinks(Object? json) => json is List ? [for (final entry in json) ItemLink.fromJson(entry)] : const [];

/// The `links` member for [links], or null when there are none and the member is left out.
List<Object?>? writeLinks(List<ItemLink> links) => links.isEmpty ? null : [for (final link in links) link.toJson()];

/// [links] as a body holds them once edited: the readable ones sorted by id (compared as lower-case text), each
/// once and none that is [ownIds] (the item's own ids), then the entries that can't be read, as they were.
/// An entry that is kept is the one already there, with whatever else it carries.
List<ItemLink> normaliseLinks(Iterable<ItemLink> links, {Iterable<String> ownIds = const []}) {
  final own = {for (final id in ownIds) id.toLowerCase()};
  final held = <String, ItemLink>{};
  final unread = <ItemLink>[];
  for (final link in links) {
    if (!link.isReadable) {
      unread.add(link);
    } else if (!own.contains(link.key)) {
      held.putIfAbsent(link.key, () => link);
    }
  }
  final keys = held.keys.toList()..sort();
  return [for (final key in keys) held[key]!, ...unread];
}

/// What a list of links can say.
extension ItemLinks on List<ItemLink> {
  /// The links this version can read.
  Iterable<ItemLink> get readable => where((link) => link.isReadable);

  /// The lower-case ids of [readable].
  Set<String> get ids => {for (final link in readable) link.key};

  /// Whether the list names [id], whatever its case.
  bool names(String id) => readable.any((link) => link.key == id.toLowerCase());

  /// This list with [id] added, if it isn't there, and sorted.
  List<ItemLink> adding(String id, {Iterable<String> ownIds = const []}) =>
      names(id) ? this : normaliseLinks([...this, ItemLink(id.toLowerCase())], ownIds: ownIds);

  /// This list without [id].
  List<ItemLink> removing(String id) => [
    for (final link in this)
      if (!link.isReadable || link.key != id.toLowerCase()) link,
  ];
}
