/// Server matching on the phone's side of a Kemlock Server run (add-duplicate-cleaner, design 9 and task group
/// 7). The owner decides, per vault or per space, that the server may group their items' tags; until then a
/// run sends nothing but items.
///
/// What may leave the phone is fixed here:
///
/// - **Only `cred` tags.** [KmCredTags] is the one place a tag for the server is made, and it makes a login's
///   `cred` tags and nothing else: no `account` tag, and no tag at all for a code, passkey, card, note, key,
///   backup-code list or identity, which are matched on the phone only.
/// - **Under their own key.** The key is `HKDF(user key, owner = user:<account id>, key version)` of
///   `crypto.md` "Duplicate tags", at the key version the server holds ([KmMatchingSettings.tagVersion]); the
///   phone's own cache keeps its root and never uploads. The key is held while a run goes and wiped after.
/// - **Beside the ciphertext.** [kmWriteTags] gives the tags of a batch's writes for [KmApi.batchTagged]: a sync's
///   batches and the move's go through it.
/// - **Backfilled.** An item whose revision no tag was stored for (written through the Bitwarden API, or from before
///   matching was turned on) gets its tags with `PUT /items/{id}/tags` and `If-Match` ([kmBackfill]); one whose
///   revision moved is left for the next run. The cache keeps, per item, the key version and revision it last had
///   tags stored for.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/dedup.dart';
import '../../../crypto/account/encoding.dart';
import '../../../models/login.dart';
import '../../duplicates/duplicate_normalise.dart' show SiteResolver;
import '../../duplicates/duplicate_rules.dart';
import 'km_api.dart';
import 'km_cache.dart';
import 'km_dedup_api.dart';
import 'km_kinds.dart';

/// What a run asks of the account's keys to make an owner's dedup key.
abstract interface class KmDedupKeys {
  /// The owner's dedup key at key [version], 32 bytes the caller wipes.
  Uint8List dedupKeyAt(int version);
}

/// The `cred` tags of one owner at one key version.
class KmCredTags {
  KmCredTags({required this._key, required this.version, this.sites = const SiteResolver()});

  final Uint8List _key;

  /// The dedup key version the tags are made under.
  final int version;
  final SiteResolver sites;

  /// The `cred` tags of an entry of [kind], or null when none go: every kind but a login, and a login with no
  /// password (a password never makes a tag alone).
  KmTagSet? tagsFor(String kind, Map<String, Object?> entry) {
    if (kind != KmKind.login) {
      return null;
    }
    final Login login;
    try {
      login = Login.fromJson(entry);
    } on Object {
      return null;
    }
    final tags = <Uint8List>[];
    for (final input in loginCredInputs(login, sites)) {
      // The rule of this file: nothing but `cred` ever reaches the server
      if (input.kind != TagKind.cred) {
        continue;
      }
      tags.add(dedupTag(_key, input.kind.name, input.values));
    }
    return tags.isEmpty ? null : (version: version, tags: tags);
  }

  /// Wipes the key.
  void dispose() => wipe(_key);
}

/// What a run needs of server matching for one owner.
class KmDedup {
  KmDedup({required this.keys, this.sites = const SiteResolver(), this.onHints, this.onSettings, this.perRun = 300});

  final KmDedupKeys keys;

  /// How a website becomes a site, as the cleaner reads it.
  final SiteResolver sites;

  /// Told the server's groups after a run, with what the phone knows of its own tags.
  final void Function(KmHints hints)? onHints;

  /// Told whether the server has matching on for the owner, after it was asked: the phone's switch follows it, so
  /// matching turned off on another device is off here too. Not told when the server couldn't be asked.
  final void Function(bool enabled)? onSettings;

  /// The most items a run backfills, so a first backfill of a large vault is spread over the runs.
  final int perRun;
}

/// An owner's matching, open for one run: the key version the server holds and the tags made under it.
class KmMatching {
  KmMatching({required this.version, required this.tags});

  final int version;
  final KmCredTags tags;

  /// Asks the server about [owner] and opens its matching, or returns null when it is off there (or the server
  /// can't say, which leaves the run's writes without tags: it still works, and the next run backfills). Tells
  /// [KmDedup.onSettings] what the server said. A session the server ended is rethrown.
  static Future<KmMatching?> open(KmConnection connection, Uri server, KmDedup dedup, String owner) async {
    final KmMatchingSettings settings;
    try {
      settings = await connection.call((token) => KmDedupApi(connection.api).settings(server, token, owner));
    } on KmError catch (e) {
      if (e.problem == KmProblem.sessionEnded) {
        rethrow;
      }
      return null;
    }
    dedup.onSettings?.call(settings.enabled);
    if (!settings.enabled) {
      return null;
    }
    final key = dedup.keys.dedupKeyAt(settings.tagVersion);
    return KmMatching(
      version: settings.tagVersion,
      tags: KmCredTags(key: key, version: settings.tagVersion, sites: dedup.sites),
    );
  }

  /// Wipes the dedup key.
  void dispose() => tags.dispose();
}

/// A write of a batch that may carry tags: the item's id, its kind and its entry. A tombstone has none.
typedef KmTaggable = ({String itemId, String kind, Map<String, Object?>? json});

/// The tags of [writes], by item id, for [KmApi.batchTagged]: `cred` tags of logins, and nothing for any other
/// kind, a deletion, or a login with no password. Empty when [tags] is null (matching is off). This is the
/// provider every batch goes through: a run's and the move's. A key rotation's re-wrapped writes take no tags on the
/// server: the version moves, and [kmBackfill] gives the tags again under it.
Map<String, KmTagSet> kmWriteTags(KmCredTags? tags, Iterable<KmTaggable> writes) {
  if (tags == null) {
    return const {};
  }
  final out = <String, KmTagSet>{};
  for (final write in writes) {
    final json = write.json;
    if (json == null) {
      continue;
    }
    final set = tags.tagsFor(write.kind, json);
    if (set != null) {
      out[write.itemId] = set;
    }
  }
  return out;
}

const _taggedKey = 'dedupTags';

/// What the cache remembers of an item's tags on the server.
extension KmTaggedItem on KmCachedItem {
  /// Whether the server holds tags for this revision under key [version] (or the item has none to hold).
  bool taggedFor(int version) => extra[_taggedKey] == '$version:$revision';

  /// The same item, marked as tagged for its revision under key [version].
  KmCachedItem withTags(int version) => KmCachedItem(
    revision: revision,
    kind: kind,
    keyVersion: keyVersion,
    hash: hash,
    entry: entry,
    entryId: entryId,
    deletedAt: deletedAt,
    heldSince: heldSince,
    opaque: opaque,
    extra: {...extra, _taggedKey: '$version:$revision'},
  );
}

/// Gives the tags of the logins in [work] that the server holds none for, at most [limit] of them:
/// `PUT /items/{id}/tags` with `If-Match` the revision the cache has. A login with no `cred` tag to give is only
/// marked. A revision the server has moved past is left, and the next sync reads the new one; a key version that
/// moved ends the pass, and the next run asks for it. Matching found off ends it too and tells [onSettings].
Future<void> kmBackfill({
  required KmConnection connection,
  required Uri server,
  required KmMatching matching,
  required KmCache work,
  int limit = 300,
  void Function(bool enabled)? onSettings,
}) async {
  final api = KmDedupApi(connection.api);
  var sent = 0;
  for (final MapEntry(:key, :value) in work.items.entries.toList()) {
    if (value.kind != KmKind.login || !value.applied || value.taggedFor(matching.version)) {
      continue;
    }
    final set = matching.tags.tagsFor(value.kind, value.entry!);
    if (set == null) {
      work.items[key] = value.withTags(matching.version);
      continue;
    }
    if (sent >= limit) {
      return;
    }
    sent++;
    final result = await connection.call((token) => api.putTags(server, token, key, value.revision, set));
    if (result == KmTagsResult.stored) {
      work.items[key] = value.withTags(matching.version);
    } else if (result == KmTagsResult.matchingOff) {
      onSettings?.call(false);
      return;
    } else if (result == KmTagsResult.staleVersion) {
      return;
    }
  }
}

/// Reads the server's groups of [owner] and hands them to [KmDedup.onHints] with the ids of the logins this phone
/// knows the server holds tags for, at the run's time [now]. Nothing is told when the server's key version isn't
/// the run's: those groups were made under other tags.
Future<void> kmReportHints({
  required KmConnection connection,
  required Uri server,
  required String owner,
  required KmMatching matching,
  required KmCache work,
  required KmDedup dedup,
  required int now,
}) async {
  final onHints = dedup.onHints;
  if (onHints == null) {
    return;
  }
  final hints = await connection.call((token) => KmDedupApi(connection.api).hints(server, token, owner));
  if (!hints.enabled || hints.tagVersion != matching.version) {
    return;
  }
  onHints(
    hints.seenBy(
      tagged: {
        for (final MapEntry(:key, :value) in work.items.entries)
          if (value.kind == KmKind.login && value.applied && value.taggedFor(matching.version)) key,
      },
      at: now,
    ),
  );
}
