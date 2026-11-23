/// The duplicate cleaner's routes of the Kemlock API (add-duplicate-cleaner, task group 7), written against the
/// server's `crates/kemlock-api-kem/src/routes/duplicates.rs`:
///
/// - `GET` and `PUT /kem/v1/duplicates/settings?owner=`: whether server matching is on for an owner
///   (`user:<uuid>` or `space:<uuid>`), who changed it and when, and the dedup key version tags must carry;
/// - `DELETE /kem/v1/duplicates/tags?owner=`: turns it off and deletes the owner's tags;
/// - `PUT /kem/v1/items/{id}/tags` with `If-Match`: the tags of an item already stored, without resending it;
/// - `GET /kem/v1/duplicates?owner=`: groups of item ids that share a tag, which are hints, and how many items
///   wait for tags;
/// - `POST /kem/v1/duplicates/dismissals` and `DELETE /kem/v1/duplicates/dismissals/{id}`: a "Not duplicates"
///   every device of the owner sees.
///
/// A tag is 32 bytes of base64url, made on the phone under a key the server doesn't hold, and the only tags this
/// version ever makes for the server are `cred` ones (`km_dedup.dart`).
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import '../../../models/json.dart';
import 'km_api.dart';

/// What `GET` and `PUT /duplicates/settings` say about an owner.
class KmMatchingSettings {
  const KmMatchingSettings({required this.owner, required this.enabled, required this.tagVersion, this.changedBy, this.changedAt});

  /// Reads the server's answer. A field of the wrong type is a [FormatException].
  factory KmMatchingSettings.fromJson(Map<String, Object?> json) {
    final owner = json['owner'];
    final enabled = json['enabled'];
    final version = json['tagVersion'];
    if (owner is! String || enabled is! bool || version is! int) {
      throw const FormatException('a matching settings answer');
    }
    return KmMatchingSettings(
      owner: owner,
      enabled: enabled,
      tagVersion: version,
      changedBy: asOptionalString(json['changedBy']),
      changedAt: asInt(json['changedAt']),
    );
  }

  /// `user:<uuid>` or `space:<uuid>`.
  final String owner;

  /// Whether the server groups the owner's tags. Off until the person, or a space's admins, turn it on.
  final bool enabled;

  /// The dedup key version tags are grouped under; a new user key or space key moves it up.
  final int tagVersion;

  /// Who last turned it on or off (a user id), so every member of a space can be told who allowed it.
  final String? changedBy;

  /// When, in Unix seconds.
  final int? changedAt;
}

/// What `GET /duplicates` says: groups of the owner's items that share a tag, and how many wait for tags.
class KmHints {
  const KmHints({
    required this.owner,
    required this.enabled,
    required this.tagVersion,
    required this.groups,
    required this.waiting,
    this.tagged = const {},
    this.at = 0,
  });

  /// Reads the server's answer. A field of the wrong type is a [FormatException].
  factory KmHints.fromJson(Map<String, Object?> json) {
    final owner = json['owner'];
    final enabled = json['enabled'];
    final version = json['tagVersion'];
    final groups = json['groups'];
    final waiting = json['waiting'];
    if (owner is! String || enabled is! bool || version is! int || groups is! List<Object?> || waiting is! int) {
      throw const FormatException('a duplicates answer');
    }
    final read = <List<String>>[];
    for (final group in groups) {
      final items = group is Map<String, Object?> ? group['items'] : null;
      if (items is! List<Object?> || items.any((item) => item is! String)) {
        throw const FormatException('a duplicate group names its items');
      }
      read.add([for (final item in items) item! as String]);
    }
    return KmHints(owner: owner, enabled: enabled, tagVersion: version, groups: read, waiting: waiting);
  }

  final String owner;
  final bool enabled;

  /// The dedup key version the groups were made under.
  final int tagVersion;

  /// Item ids, two or more to a group: a hint, which the phone opens and compares before it shows a group.
  final List<List<String>> groups;

  /// Live items without tags at their current revision. It counts every kind, so it is never 0 for a vault that holds
  /// a code or a note: only logins are given tags.
  final int waiting;

  /// The ids of the logins whose `cred` tags this phone knows the server holds at their current revision, which is
  /// what lets it read a group the server leaves out as one answered "Not duplicates". Filled by the run.
  final Set<String> tagged;

  /// Epoch ms the run that read it finished.
  final int at;

  /// The same hints with what the run knows of its own.
  KmHints seenBy({required Set<String> tagged, required int at}) =>
      KmHints(owner: owner, enabled: enabled, tagVersion: tagVersion, groups: groups, waiting: waiting, tagged: tagged, at: at);
}

/// How the server answered a `PUT /items/{id}/tags`.
enum KmTagsResult {
  /// The tags are stored for the revision the request named.
  stored,

  /// Server matching is off for the item's owner (409 `server-matching-off`).
  matchingOff,

  /// The tags were made under another dedup key version than the owner's current one (409 `stale-dedup-version`).
  staleVersion,

  /// The item has another revision than the request's `If-Match`, so these tags are not for it: they are made again
  /// from the next revision, at the next sync.
  staleItem,
}

/// The duplicate-cleaner routes, over a [KmApi]. Each call takes the server and an access token, as
/// `KmConnection.call` hands them to its request.
class KmDedupApi {
  KmDedupApi(this.api);

  final KmApi api;

  /// Whether server matching is on for [owner], and the key version.
  Future<KmMatchingSettings> settings(Uri server, String token, String owner) async {
    final json = await api.call('GET', server, '/duplicates/settings', token: token, query: {'owner': owner});
    return _settings(json);
  }

  /// Turns server matching on for [owner] (a person for their vault, a space's admins for their space).
  Future<KmMatchingSettings> turnOn(Uri server, String token, String owner) async {
    final json = await api.call('PUT', server, '/duplicates/settings', token: token, query: {'owner': owner}, body: {'enabled': true});
    return _settings(json);
  }

  /// Turns server matching off for [owner] and deletes every tag it uploaded (`DELETE /duplicates/tags`).
  Future<KmMatchingSettings> deleteTags(Uri server, String token, String owner) async {
    final json = await api.call('DELETE', server, '/duplicates/tags', token: token, query: {'owner': owner});
    return _settings(json);
  }

  /// The groups of [owner]'s items that share a tag.
  Future<KmHints> hints(Uri server, String token, String owner) async {
    final json = await api.call('GET', server, '/duplicates', token: token, query: {'owner': owner});
    if (json == null) {
      throw const KmError(KmProblem.server, message: 'a duplicates answer');
    }
    try {
      return KmHints.fromJson(json);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }

  /// Stores [tags] for item [itemId] at [revision] (`If-Match`). A 409 is told apart by its problem: matching off, a
  /// key version that moved, or an item that has another revision. Anything else throws.
  Future<KmTagsResult> putTags(Uri server, String token, String itemId, int revision, KmTagSet tags) async {
    try {
      await api.call(
        'PUT',
        server,
        '/items/$itemId/tags',
        token: token,
        headers: {'If-Match': '$revision'},
        body: {
          'tags': [for (final Uint8List tag in tags.tags) b64urlEncode(tag)],
          'tagVersion': tags.version,
        },
      );
      return KmTagsResult.stored;
    } on KmError catch (e) {
      if (e.problem != KmProblem.stale) {
        rethrow;
      }
      return switch (e.slug) {
        'server-matching-off' => KmTagsResult.matchingOff,
        'stale-dedup-version' => KmTagsResult.staleVersion,
        _ => KmTagsResult.staleItem,
      };
    }
  }

  /// Saves "Not duplicates" for the group [itemIds] (two to 500 items of [owner]) and returns the answer's id.
  Future<String> dismiss(Uri server, String token, String owner, List<String> itemIds) async {
    final json = await api.call('POST', server, '/duplicates/dismissals', token: token, body: {'owner': owner, 'items': itemIds});
    final id = json?['id'];
    if (id is! String) {
      throw const KmError(KmProblem.server, message: 'a dismissal answer');
    }
    return id;
  }

  /// Takes a saved "Not duplicates" back.
  Future<void> undismiss(Uri server, String token, String dismissalId) async {
    await api.call('DELETE', server, '/duplicates/dismissals/$dismissalId', token: token);
  }

  KmMatchingSettings _settings(Map<String, Object?>? json) {
    if (json == null) {
      throw const KmError(KmProblem.server, message: 'a matching settings answer');
    }
    try {
      return KmMatchingSettings.fromJson(json);
    } on FormatException catch (e) {
      throw KmError(KmProblem.server, message: e.message);
    }
  }
}
