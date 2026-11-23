import 'dart:convert';

import 'package:http/http.dart' as http;

import 'fake_kemlock_server.dart';

/// One owner's server matching switch, as the server holds it.
class FakeMatching {
  bool enabled = false;
  int version = 1;
  String? changedBy;
  int? changedAt;
}

/// The tags the server holds for one item: the revision and key version they were made for.
typedef FakeTagRow = ({int revision, int version, List<String> tags});

/// What a request put on the server's tags: the item, the key version and the base64url tags, and the route that
/// carried them (`batch`, `put` or `tags`).
typedef FakeTagWrite = ({String item, int version, List<String> tags, String route});

/// [FakeKemlockServer] with the duplicate cleaner's routes of the server's code
/// (`crates/kemlock-api-kem/src/routes/duplicates.rs`) for the account's own vault and for spaces:
///
/// - `tags` and `tagVersion` inside an item of `PUT /items/{id}` and of a write of `items:batch`, taken together or
///   not at all; ignored (the item is written) when matching is off or the version isn't the owner's; a write without
///   tags clears the item's tags, and a batch answers `tags` with one `{item, stored, matches}` per write that had tags;
/// - `PUT /items/{id}/tags` with `If-Match`: 409 `server-matching-off`, `stale-dedup-version` (with
///   `currentTagVersion`) and `stale-revision`, in the server's order;
/// - `GET` and `PUT /duplicates/settings`, `DELETE /duplicates/tags`: off deletes the owner's tags; a space's switch
///   takes an admin (403 for a member), and a space the account isn't in is a 404;
/// - `GET /duplicates`: groups of live items that share a tag at their current revision and the owner's version,
///   without the groups a dismissal covers, and `waiting`, which counts every live item without tags;
/// - `POST /duplicates/dismissals` and `DELETE /duplicates/dismissals/{id}`.
///
/// Items and tags are the account's own vault's; a space has a switch and nothing else.
class FakeDedupServer extends FakeKemlockServer {
  FakeDedupServer({super.userId});

  /// The switches by owner (`user:<uuid>` or `space:<uuid>`), made off at the first version when asked for.
  final matching = <String, FakeMatching>{};

  /// The account's role in each space it is in: `admin` or `member`. A space not listed isn't the account's.
  final spaceRoles = <String, String>{};

  /// The vault's tags by item id.
  final tags = <String, FakeTagRow>{};

  /// The saved "Not duplicates" answers: id to item ids.
  final dismissals = <String, List<String>>{};

  /// Every tag that reached the server in a request, in order.
  final tagWrites = <FakeTagWrite>[];

  /// How many times `DELETE /duplicates/tags` was called.
  var tagDeletes = 0;

  /// The time (Unix seconds) a change of a switch is dated with.
  var clockSeconds = 1795000000;

  var _dismissalCount = 0;

  FakeMatching of(String owner) => matching.putIfAbsent(owner, FakeMatching.new);

  /// Turns the vault's matching on, as the person did from the app.
  void turnOn({int version = 1}) {
    of(owner)
      ..enabled = true
      ..version = version;
  }

  /// A key replacement: the version moves up and the vault's tags are deleted, as the server's does.
  int rotate() {
    final state = of(owner);
    state.version++;
    tags.clear();
    return state.version;
  }

  /// The vault's live items that have tags at their current revision and the owner's version.
  Map<String, FakeTagRow> get validTags => {
    for (final MapEntry(:key, :value) in tags.entries)
      if (items[key] != null && !items[key]!.deleted && items[key]!.revision == value.revision && value.version == of(owner).version)
        key: value,
  };

  @override
  Future<http.Response> handle(http.Request request) async {
    final path = request.url.path;
    final route = path.startsWith('/kem/v1') ? path.substring('/kem/v1'.length) : '';
    final batch = route == '/items:batch' && request.method == 'POST';
    final put = RegExp(r'^/items/([^/]+)$').hasMatch(route) && request.method == 'PUT';
    final response = await super.handle(request);
    if ((!batch && !put) || response.statusCode < 200 || response.statusCode >= 300) {
      return response;
    }
    final body = jsonDecode(request.body) as Map<String, Object?>;
    final written = batch
        ? [for (final write in (body['writes']! as List<Object?>).cast<Map<String, Object?>>()) write['item']! as Map<String, Object?>]
        : [body];
    final outcomes = <Map<String, Object?>>[];
    for (final item in written) {
      final id = item['id']! as String;
      final stored = items[id]!;
      final sent = item['tags'];
      final version = item['tagVersion'];
      final state = of(owner);
      var kept = false;
      if (sent is List<Object?> && version is int) {
        tagWrites.add((item: id, version: version, tags: [for (final tag in sent) tag! as String], route: batch ? 'batch' : 'put'));
        if (!stored.deleted && state.enabled && version == state.version) {
          tags[id] = (revision: stored.revision, version: version, tags: [for (final tag in sent) tag! as String]);
          kept = true;
        }
        outcomes.add({'item': id, 'stored': kept, 'matches': <String>[]});
      }
      if (!kept) {
        // A write without tags, or with ones the server drops, leaves the item with none for its revision
        tags.remove(id);
      }
    }
    if (outcomes.isEmpty) {
      return response;
    }
    final answer = jsonDecode(response.body) as Map<String, Object?>;
    if (batch) {
      answer['tags'] = outcomes;
    } else {
      answer['tagsStored'] = outcomes.single['stored'];
    }
    return http.Response(jsonEncode(answer), response.statusCode, headers: response.headers);
  }

  http.Response? _refuseOwner(String? asked, {bool changing = false}) {
    if (asked == null) {
      return problem(400, 'invalid-request');
    }
    if (asked == owner) {
      return null;
    }
    final role = spaceRoles[asked];
    if (role == null) {
      return problem(404, 'not-found');
    }
    if (changing && role != 'admin') {
      return problem(403, 'forbidden');
    }
    return null;
  }

  Map<String, Object?> _settings(String asked) {
    final state = of(asked);
    return {
      'owner': asked,
      'enabled': state.enabled,
      'tagVersion': state.version,
      'changedBy': state.changedBy,
      'changedAt': state.changedAt,
    };
  }

  void _set(String asked, bool enabled) {
    final state = of(asked);
    state
      ..enabled = enabled
      ..changedBy = userId
      ..changedAt = clockSeconds;
    if (!enabled && asked == owner) {
      tags.clear();
    }
  }

  @override
  Future<http.Response?> tokenRoute(http.Request request, String route) async {
    final method = request.method;
    final asked = request.url.queryParameters['owner'];
    if (route == '/duplicates/settings' && method == 'GET') {
      return _refuseOwner(asked) ?? answer(_settings(asked!));
    }
    if (route == '/duplicates/settings' && method == 'PUT') {
      final refused = _refuseOwner(asked, changing: true);
      if (refused != null) {
        return refused;
      }
      _set(asked!, (jsonDecode(request.body) as Map<String, Object?>)['enabled']! as bool);
      return answer(_settings(asked));
    }
    if (route == '/duplicates/tags' && method == 'DELETE') {
      final refused = _refuseOwner(asked, changing: true);
      if (refused != null) {
        return refused;
      }
      tagDeletes++;
      _set(asked!, false);
      return answer(_settings(asked));
    }
    if (route == '/duplicates' && method == 'GET') {
      return _refuseOwner(asked) ?? _report(asked!);
    }
    final putTags = RegExp(r'^/items/([^/]+)/tags$').firstMatch(route);
    if (putTags != null && method == 'PUT') {
      return _putTags(request, putTags[1]!);
    }
    if (route == '/duplicates/dismissals' && method == 'POST') {
      final body = jsonDecode(request.body) as Map<String, Object?>;
      final ids = [...(body['items']! as List<Object?>).cast<String>()]..sort();
      if (ids.toSet().length < 2 || ids.length > 500) {
        return problem(400, 'invalid-request');
      }
      final id = '00000000-0000-4000-8000-${(++_dismissalCount).toString().padLeft(12, '0')}';
      dismissals[id] = ids;
      return answer({'id': id, 'owner': body['owner'], 'items': ids, 'by': userId, 'at': clockSeconds}, status: 201);
    }
    final dismissal = RegExp(r'^/duplicates/dismissals/([^/]+)$').firstMatch(route);
    if (dismissal != null && method == 'DELETE') {
      dismissals.remove(dismissal[1]);
      return http.Response('', 204, headers: {'dpop-nonce': 'nonce-1'});
    }
    return super.tokenRoute(request, route);
  }

  http.Response _report(String asked) {
    final state = of(asked);
    final groups = <Map<String, Object?>>[];
    var waiting = 0;
    if (state.enabled && asked == owner) {
      final valid = validTags;
      final byTag = <String, Set<String>>{};
      for (final MapEntry(:key, :value) in valid.entries) {
        for (final tag in value.tags) {
          byTag.putIfAbsent(tag, () => {}).add(key);
        }
      }
      final seen = <String>{};
      for (final ids in byTag.values) {
        final sorted = [...ids]..sort();
        if (sorted.length < 2 || !seen.add(sorted.join('|'))) {
          continue;
        }
        // A dismissal covers a group whose items are all among the ones it named
        if (dismissals.values.any((dismissed) => sorted.every(dismissed.contains))) {
          continue;
        }
        groups.add({'items': sorted});
      }
      waiting = items.values.where((item) => !item.deleted && !valid.containsKey(item.id)).length;
    }
    return answer({'owner': asked, 'enabled': state.enabled, 'tagVersion': state.version, 'groups': groups, 'waiting': waiting});
  }

  http.Response _putTags(http.Request request, String id) {
    final ifMatch = request.headers['If-Match'] ?? request.headers['if-match'];
    if (ifMatch == null) {
      return problem(428, 'precondition-required');
    }
    final expected = int.parse(ifMatch.replaceAll(RegExp('[W/"]'), ''));
    final item = items[id];
    if (item == null) {
      return problem(404, 'not-found');
    }
    final state = of(owner);
    if (!state.enabled) {
      return problem(409, 'server-matching-off');
    }
    final body = jsonDecode(request.body) as Map<String, Object?>;
    final version = body['tagVersion']! as int;
    final sent = [for (final tag in (body['tags']! as List<Object?>)) tag! as String];
    if (version != state.version) {
      return problem(409, 'stale-dedup-version', extra: {'currentTagVersion': state.version});
    }
    if (item.deleted) {
      return problem(404, 'not-found');
    }
    if (item.revision != expected) {
      return problem(409, 'stale-revision', extra: {'itemId': id, 'currentRevision': item.revision});
    }
    tagWrites.add((item: id, version: version, tags: sent, route: 'tags'));
    tags[id] = (revision: expected, version: version, tags: sent);
    final mine = {...sent};
    final others = [
      for (final MapEntry(:key, :value) in validTags.entries)
        if (key != id && value.tags.any(mine.contains)) key,
    ];
    return answer({'matches': others});
  }
}
