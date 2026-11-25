// What the cleaner does with the groups Kemlock Server suggests (the add-duplicate-cleaner plan, design 9 and task
// 7.3). They are hints and nothing more:
//
// - a server group is opened and compared on the phone before it is shown, so a group whose logins don't share a
//   site, a username and a password is not shown as the same sign-in, and one the server got wrong is not shown;
// - nothing merges on the server's word, and everything the server could suggest the phone finds itself;
// - a "Not duplicates" another device shared is learned from the server leaving a group out: `GET /duplicates` drops
//   a group a dismissal covers, so a group of logins this phone found as the same sign-in, whose tags it knows the
//   server holds, and which the server doesn't list, was answered there. It is left out here too.
//
// Pure Dart, no Flutter package.
library;

import '../../crypto/account/encoding.dart';
import '../../crypto/account/legacy_ids.dart';
import '../../models/login.dart';
import '../sync/kemlock/km_dedup_api.dart';
import 'dedup_cache.dart';
import 'dedup_tagger.dart';
import 'duplicate_matcher.dart';
import 'duplicate_normalise.dart';
import 'duplicate_rules.dart';
import 'duplicate_tags.dart';

/// The server's item id of each of the vault's own logins in [items], by index: the id the login's item has in the
/// account's vault (`user:<accountId>`), which is the login's own id when it is a UUID and else its legacy-id UUID.
Map<String, int> serverItemIds(List<DedupItem> items, String accountId) {
  final owner = Owner.user(accountId);
  final byServerId = <String, int>{};
  for (var i = 0; i < items.length; i++) {
    final entry = items[i];
    if (entry.item is! Login || entry.slot != vaultSlot) {
      continue;
    }
    try {
      byServerId[itemUuid(entry.id, owner)] = i;
    } on MalformedException {
      // An id the legacy-id rule doesn't map: not an item the server can hold
    }
  }
  return byServerId;
}

/// The server item ids of the logins of [group], all of them, or null when one isn't a login of the vault's own (a
/// group in a space, or of another kind, is not shared with the server).
List<String>? serverIdsOfGroup(DuplicateGroup group, String accountId) {
  final owner = Owner.user(accountId);
  final ids = <String>[];
  for (final entry in group.items) {
    if (entry.item is! Login || entry.slot != vaultSlot) {
      return null;
    }
    try {
      ids.add(itemUuid(entry.id, owner));
    } on MalformedException {
      return null;
    }
  }
  return ids;
}

/// [found], the groups the phone found, with the server's [hints] taken in as hints.
///
/// A hint is mapped to the vault's logins by their server ids, opened and compared (`verifyHints`), and a group it
/// makes that [found] lacks is added. A group of [found] that is the same sign-in is left out when the server answered
/// it: every one of its logins has `cred` tags this phone knows the server holds at their current revision
/// ([KmHints.tagged]), none changed after the run read the groups ([KmHints.at]), and no server group has two of them.
List<DuplicateGroup> withServerHints({
  required List<DuplicateGroup> found,
  required List<DedupItem> items,
  required KmHints hints,
  required String accountId,
  SiteResolver sites = const SiteResolver(),
  KeyIdentityOf? keyIdentityOf,
}) {
  if (!hints.enabled) {
    return found;
  }
  final byServerId = serverItemIds(items, accountId);
  final hinted = <Set<int>>[
    for (final group in hints.groups) {for (final id in group) ?byServerId[id]},
  ];
  final checked = verifyHints(items: items, hints: hinted, sites: sites, keyIdentityOf: keyIdentityOf);
  final known = {for (final group in found) group.key};
  final out = <DuplicateGroup>[];
  for (final group in found) {
    if (!_answeredByServer(group, hinted, hints, accountId)) {
      out.add(group);
    }
  }
  for (final group in checked) {
    if (known.add(group.key) && !_answeredByServer(group, hinted, hints, accountId)) {
      out.add(group);
    }
  }
  return out;
}

bool _answeredByServer(DuplicateGroup group, List<Set<int>> hinted, KmHints hints, String accountId) {
  if (group.reason != DuplicateReason.sameSignIn) {
    return false;
  }
  final ids = serverIdsOfGroup(group, accountId);
  if (ids == null) {
    return false;
  }
  for (var i = 0; i < ids.length; i++) {
    if (!hints.tagged.contains(ids[i]) || group.items[i].changedAt > hints.at) {
      return false;
    }
  }
  // Everything about the group is on the server, so a server that doesn't list it was told it isn't one
  final wanted = ids.toSet();
  final listed = hints.groups.any((hint) => hint.where(wanted.contains).length >= 2);
  return !listed;
}

/// What the answers hold of "Not duplicates" shared with the server, by the group's key: the id of the dismissal
/// `POST /duplicates/dismissals` made, which `DELETE /duplicates/dismissals/{id}` takes back.
extension SharedDismissals on DedupAnswers {
  Map<String, String> get sharedDismissals {
    final stored = extra['sharedDismissals'];
    return {
      if (stored is Map<String, Object?>)
        for (final MapEntry(:key, :value) in stored.entries)
          if (value is String) key: value,
    };
  }

  /// These answers with the group [key]'s dismissal shared as [dismissalId].
  DedupAnswers withShared(String key, String dismissalId) => DedupAnswers(
    dismissed: dismissed,
    merges: merges,
    extra: {
      ...extra,
      'sharedDismissals': {...sharedDismissals, key: dismissalId},
    },
  );

  /// These answers without the dismissal of the group [key], shared or not.
  DedupAnswers withoutDismissal(String key) {
    final shared = {...sharedDismissals}..remove(key);
    return DedupAnswers(
      dismissed: [
        for (final other in dismissed)
          if (other != key) other,
      ],
      merges: merges,
      extra: {
        for (final MapEntry(key: name, :value) in extra.entries)
          if (name != 'sharedDismissals') name: value,
        if (shared.isNotEmpty) 'sharedDismissals': shared,
      },
    );
  }
}
