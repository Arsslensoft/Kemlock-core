/// Keeping the breach list current (openspec: breach-alerts): while the person has it turned on, the app asks Have I Been
/// Pwned, at most once a day, whether it has listed a breach the device doesn't know, and takes its list if so. Both requests
/// are the same from every device and carry nothing from the vault. A check that fails changes nothing and is tried again the
/// next time.
///
/// Pure Dart, no Flutter: the app wraps it in providers, and the browser extension's core runs it over its own client.
library;

import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../../core/network/answers.dart' show readAnswer;
import '../../core/storage/key_value_store.dart';
import 'breach_list.dart';

/// Where the breach data comes from, and where its credit links to.
const hibpSite = 'https://haveibeenpwned.com';

/// The list taken from Have I Been Pwned, trimmed as the bundled one is. It is public
/// data and belongs to the device, not to a vault; a reset removes it with the rest.
const keyBreachList = 'backmycodes_breach_list';

/// When the last check was made, in epoch ms, and the latest breach it saw:
/// `{"at": 1763200000000, "latest": "Adobe"}`.
const keyBreachCheck = 'backmycodes_breach_check';

/// Asks Have I Been Pwned through [client], which tests replace with a `MockClient`,
/// and keeps what it learns in [store].
class BreachRefresh {
  BreachRefresh({
    required this.client,
    this.userAgent,
    required this.store,
    required this.now,
    this.timeout = const Duration(seconds: 30),
  });

  final http.Client client;

  /// The `User-Agent`, which the service refuses a request without, or null to leave it to the client (a browser sets its own).
  final Future<String> Function()? userAgent;
  final KeyValueStore store;
  final DateTime Function() now;

  /// How long to wait for each answer.
  final Duration timeout;

  /// The least time between two checks.
  static const interval = Duration(hours: 24);

  /// The whole list is a little over a megabyte; anything far past that isn't it.
  static const maxBytes = 8 << 20;

  static final _latest = Uri.parse('$hibpSite/api/v3/latestbreach');
  static final _all = Uri.parse('$hibpSite/api/v3/breaches');

  /// The list a check stored, or null when there is none or it can't be read.
  BreachList? stored() {
    final raw = store.getItem(keyBreachList);
    if (raw == null) return null;
    try {
      final list = BreachList.fromJson(jsonDecode(raw) as Map<String, Object?>);
      return list.entries.isEmpty ? null : list;
    } catch (_) {
      return null;
    }
  }

  /// The later of the [bundled] list and the stored one. A list stored the day the
  /// bundled copy was made is the later one: it was taken because it had a breach more.
  BreachList inUse(BreachList bundled) {
    final downloaded = stored();
    return downloaded != null && downloaded.updated.compareTo(bundled.updated) >= 0 ? downloaded : bundled;
  }

  /// When the last check was made (epoch ms), or null when there was none.
  int? get lastCheckAt => _lastCheck().at;

  /// Checks for breaches newer than [current], unless a check was made in the last 24
  /// hours and [force] isn't set. True when a newer list was stored. Never throws: a
  /// failure leaves everything as it was, the time of the last check included.
  Future<bool> run(BreachList current, {bool force = false}) async {
    final (:at, :latest) = _lastCheck();
    final time = now();
    final recent = at != null && time.millisecondsSinceEpoch - at < interval.inMilliseconds && time.millisecondsSinceEpoch >= at;
    if (!force && recent) return false;
    try {
      // A few hundred bytes: the one breach listed last
      final newest = jsonDecode(await _get(_latest));
      final name = newest is Map<String, Object?> ? newest['Name'] : null;
      if (name is! String || name.isEmpty) return false;
      // Known already, or seen by the last check: the newest may be one the list leaves out
      if (current.has(name) || name == latest) {
        _recordCheck(time, name);
        return false;
      }
      final all = jsonDecode(await _get(_all));
      if (all is! List<Object?>) return false;
      final list = BreachList.fromHibp(all, updated: time.toUtc().toIso8601String().substring(0, 10));
      // Far fewer breaches than the device already has isn't the list
      if (list.entries.length * 2 < current.entries.length) return false;
      _recordCheck(time, name);
      // The newest is one the list leaves out, and nothing else is new
      if (list.entries.every((breach) => current.has(breach.name))) return false;
      store.setItem(keyBreachList, jsonEncode(list.toJson()));
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The body of a 200 answer to a GET of [url], within [timeout] and [maxBytes]: an answer
  /// past [maxBytes] is dropped there, not read whole first.
  Future<String> _get(Uri url) async {
    Future<http.Response> ask() async {
      final request = http.Request('GET', url);
      final agent = userAgent;
      if (agent != null) request.headers['User-Agent'] = await agent();
      return readAnswer(await client.send(request), maxBytes);
    }

    final response = await ask().timeout(timeout);
    if (response.statusCode != 200) throw http.ClientException('status ${response.statusCode}', url);
    return utf8.decode(response.bodyBytes);
  }

  ({int? at, String? latest}) _lastCheck() {
    try {
      final json = jsonDecode(store.getItem(keyBreachCheck) ?? '');
      if (json is Map<String, Object?>) {
        return (at: json['at'] is int ? json['at']! as int : null, latest: json['latest'] is String ? json['latest']! as String : null);
      }
    } catch (_) {
      // Nothing recorded, or not as this version writes it: check again
    }
    return (at: null, latest: null);
  }

  void _recordCheck(DateTime time, String latest) =>
      store.setItem(keyBreachCheck, jsonEncode({'at': time.millisecondsSinceEpoch, 'latest': latest}));
}
