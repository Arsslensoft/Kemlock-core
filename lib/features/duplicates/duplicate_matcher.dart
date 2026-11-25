// Finding the items a vault holds more than once (the add-duplicate-cleaner
// plan, design 5).
//
// The stored tags only suggest: items that share a tag under their owner's
// key are candidates, and so are items that share a tag under a key made for
// this run, which is how an item held in the vault and in a space is found.
// A group is shown only once the values behind it are compared, so a tag
// that was forged, or that collided, leaves no group.
//
// Pure Dart, no Flutter package and no isolate: the app runs [findDuplicates] in an isolate above [isolateItemThreshold]
// items (160,000 HMACs for 5,000 items shouldn't hold up the screen), and the browser extension runs it in its background.
library;

import '../../core/ids.dart';
import '../../crypto/account/dedup.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart';
import 'dedup_cache.dart';
import 'dedup_tagger.dart';
import 'duplicate_normalise.dart';
import 'duplicate_rules.dart';
import 'duplicate_tags.dart';

/// Above this many items the match runs in an isolate.
const isolateItemThreshold = 2000;

/// Items the vault holds more than once: at least two of one kind, and the reason they are shown.
final class DuplicateGroup {
  const DuplicateGroup({required this.reason, required this.items});

  /// The strongest kind of match between them, or [DuplicateReason.inTwoPlaces] when they are
  /// not all in one owner's items.
  final DuplicateReason reason;

  /// The items, in the order the vault lists them. Two or more, all of one kind.
  final List<DedupItem> items;

  /// What a dismissal of this group is remembered by: its item ids. A group that gains another
  /// item has another key, so a dismissed group returns when a new copy joins it.
  String get key => dismissalKey(items.map((item) => item.id));

  /// Whether the items are in more than one place: the vault and a space, or two spaces.
  bool get acrossPlaces => items.map((item) => item.slot).toSet().length > 1;
}

/// The key of a dismissal of the items [ids]: the ids sorted and joined.
String dismissalKey(Iterable<String> ids) => (ids.toList()..sort()).join('|');

/// [groups] without the ones whose key is in [dismissed].
List<DuplicateGroup> withoutDismissed(List<DuplicateGroup> groups, Iterable<Object?> dismissed) {
  final keys = {
    for (final key in dismissed)
      if (key is String) key,
  };
  return [
    for (final group in groups)
      if (!keys.contains(group.key)) group,
  ];
}

/// One group before it is built from the items: the reason and the indexes of its items.
typedef _IndexGroup = ({DuplicateReason reason, List<int> indexes});

/// The groups of [items], whose stored tags are [tags] (by owner slot and item id, as
/// `DedupStore.refresh` gives them).
///
/// Candidates come from [tags] within each owner, and, when the items are in more than one place,
/// from tags made under [runKey] (32 random bytes unless given), which are not kept and whose
/// dedup key is wiped after. Each candidate group is then split by the kind of item, since a key
/// and a contact with one fingerprint are not one, and checked against the items' own values.
List<DuplicateGroup> findDuplicates({
  required List<DedupItem> items,
  required Map<String, Map<String, DedupItemTags>> tags,
  SiteResolver sites = const SiteResolver(),
  KeyIdentityOf? keyIdentityOf,
  List<int>? runKey,
}) => _build(items, _findIndexes(items, tags, sites, keyIdentityOf, runKey));

/// The groups a server's [hints] come to once the phone checks them: each hint is a set of indexes into [items] that
/// the server says share a tag, and it is shown only as far as the items' own values bear it out. A hint is split by
/// the kind of item, as candidates are, and compared as the tags' own inputs are, so a group the server got wrong, or
/// whose passwords differ, leaves no group "in two places" or "same sign-in" behind: two logins with one site and
/// username and two passwords are shown as the same account, never as the same sign-in, and logins with no input in
/// common are not shown at all. Nothing is merged on the server's word.
List<DuplicateGroup> verifyHints({
  required List<DedupItem> items,
  required Iterable<Iterable<int>> hints,
  SiteResolver sites = const SiteResolver(),
  KeyIdentityOf? keyIdentityOf,
}) {
  final groups = <_IndexGroup>[];
  for (final hint in hints) {
    final byType = <Type, List<int>>{};
    for (final index in hint.toSet()) {
      if (index >= 0 && index < items.length) {
        byType.putIfAbsent(items[index].item.runtimeType, () => []).add(index);
      }
    }
    for (final same in byType.values) {
      if (same.length >= 2) {
        groups.addAll(_verified(items, same, sites, keyIdentityOf));
      }
    }
  }
  groups.sort((a, b) => a.indexes.first.compareTo(b.indexes.first));
  return _build(items, groups);
}

List<DuplicateGroup> _build(List<DedupItem> items, List<_IndexGroup> found) => [
  for (final group in found) DuplicateGroup(reason: group.reason, items: [for (final index in group.indexes) items[index]]),
];

List<_IndexGroup> _findIndexes(
  List<DedupItem> items,
  Map<String, Map<String, DedupItemTags>> tags,
  SiteResolver sites,
  KeyIdentityOf? keyIdentityOf,
  List<int>? runKey,
) {
  final candidates = _candidates(items, tags, sites, keyIdentityOf, runKey);
  final groups = <_IndexGroup>[];
  for (final candidate in candidates) {
    groups.addAll(_verified(items, candidate, sites, keyIdentityOf));
  }
  groups.sort((a, b) => a.indexes.first.compareTo(b.indexes.first));
  return groups;
}

/// Sets of item indexes, joined as tags say two items are one.
final class _Sets {
  _Sets(int size) : _parent = List<int>.generate(size, (i) => i);

  final List<int> _parent;

  int find(int i) {
    var node = i;
    while (_parent[node] != node) {
      _parent[node] = _parent[_parent[node]];
      node = _parent[node];
    }
    return node;
  }

  void union(int a, int b) {
    final x = find(a);
    final y = find(b);
    if (x != y) {
      _parent[y] = x;
    }
  }
}

/// The candidate sets, each of at least two item indexes of one kind of item.
List<List<int>> _candidates(
  List<DedupItem> items,
  Map<String, Map<String, DedupItemTags>> tags,
  SiteResolver sites,
  KeyIdentityOf? keyIdentityOf,
  List<int>? runKey,
) {
  final indexOf = {for (var i = 0; i < items.length; i++) items[i].id: i};
  final sets = _Sets(items.length);

  // Within an owner: the stored tags, bucketed by value and compared in constant time
  for (final owner in tags.values) {
    final first = <DuplicateTag, int>{};
    for (final MapEntry(:key, :value) in owner.entries) {
      final index = indexOf[key];
      if (index == null) {
        continue;
      }
      for (final tag in value.tags) {
        final known = first[tag];
        if (known == null) {
          first[tag] = index;
        } else {
          sets.union(known, index);
        }
      }
    }
  }

  // Across owners: tags under a key made for this run, which nothing keeps
  if (items.map((item) => item.slot).toSet().length > 1) {
    final dedup = dedupKey(runKey ?? randomBytes(dedupKeyLength), Owner.user(newUuid()), 1);
    try {
      final first = <DuplicateTag, int>{};
      for (var i = 0; i < items.length; i++) {
        for (final tag in itemTags(items[i].item, dedup, sites: sites, keyIdentityOf: keyIdentityOf)) {
          final known = first[tag];
          if (known == null) {
            first[tag] = i;
          } else {
            sets.union(known, i);
          }
        }
      }
    } finally {
      wipe(dedup);
    }
  }

  final byRoot = <int, List<int>>{};
  for (var i = 0; i < items.length; i++) {
    byRoot.putIfAbsent(sets.find(i), () => []).add(i);
  }
  // A key and a contact with one fingerprint are not grouped: one kind of item to a group
  final out = <List<int>>[];
  for (final members in byRoot.values) {
    if (members.length < 2) {
      continue;
    }
    final byType = <Type, List<int>>{};
    for (final index in members) {
      byType.putIfAbsent(items[index].item.runtimeType, () => []).add(index);
    }
    out.addAll(byType.values.where((same) => same.length >= 2));
  }
  return out;
}

/// The groups in [candidate] that the items' own values bear out, with their reasons. Two items
/// are one when they share a tag input, which is the plain value a tag is the keyed hash of.
List<_IndexGroup> _verified(List<DedupItem> items, List<int> candidate, SiteResolver sites, KeyIdentityOf? keyIdentityOf) {
  final sets = _Sets(candidate.length);
  final inputs = [for (final index in candidate) tagInputsOf(items[index].item, sites: sites, keyIdentityOf: keyIdentityOf)];
  final shared = <TagInput, List<int>>{};
  for (var i = 0; i < candidate.length; i++) {
    for (final input in inputs[i]) {
      final holders = shared.putIfAbsent(input, () => []);
      if (!holders.contains(i)) {
        holders.add(i);
      }
    }
  }
  for (final holders in shared.values) {
    for (var i = 1; i < holders.length; i++) {
      sets.union(holders.first, holders[i]);
    }
  }
  final kinds = <int, Set<TagKind>>{};
  for (final MapEntry(:key, :value) in shared.entries) {
    if (value.length >= 2) {
      kinds.putIfAbsent(sets.find(value.first), () => {}).add(key.kind);
    }
  }
  final byRoot = <int, List<int>>{};
  for (var i = 0; i < candidate.length; i++) {
    byRoot.putIfAbsent(sets.find(i), () => []).add(candidate[i]);
  }
  final groups = <_IndexGroup>[];
  for (final MapEntry(:key, :value) in byRoot.entries) {
    if (value.length < 2) {
      continue;
    }
    final reason = DuplicateReason.strongest(kinds[key] ?? const {});
    if (reason == null) {
      continue;
    }
    final places = {for (final index in value) items[index].slot};
    groups.add((reason: places.length > 1 ? DuplicateReason.inTwoPlaces : reason, indexes: value..sort()));
  }
  return groups;
}
