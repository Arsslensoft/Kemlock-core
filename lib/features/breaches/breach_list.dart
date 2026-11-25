/// The data breaches Kemlock knows of, from Have I Been Pwned's list, trimmed to what the
/// app shows (openspec: breach-alerts). `assets/data/breaches.json` is made from the API's
/// answer by `tool/breaches/update.dart`, and the online update (`breach_refresh.dart`)
/// trims a newer answer the same way, through [BreachList.fromHibp].
///
/// Nothing here needs Flutter, so the tool runs with `dart run`.
library;

import '../accounts/service_names.dart';

/// The notice the trimmed list carries, as the licence of the data asks.
const breachLicense =
    'Breach data from Have I Been Pwned (https://haveibeenpwned.com), licensed under the Creative Commons '
    'Attribution 4.0 International License (https://creativecommons.org/licenses/by/4.0/). Trimmed to verified '
    'breaches of a service with a domain, and to their name, domain, dates, size and whether passwords were taken.';

/// One breach of one service.
class Breach {
  const Breach({
    required this.name,
    required this.title,
    required this.domain,
    required this.breachDate,
    required this.addedDate,
    required this.pwnCount,
    required this.passwords,
  });

  /// A row of the trimmed list: `[name, title, domain, breach date, added date, accounts,
  /// 1 when passwords were taken]`. Null when [row] isn't one; values past the seventh are
  /// a later version's and are ignored.
  static Breach? fromRow(Object? row) {
    if (row is! List<Object?> || row.length < 7) return null;
    final [name, title, domain, breachDate, addedDate, pwnCount, passwords, ...] = row;
    if (name is! String || name.isEmpty || title is! String || domain is! String || domain.isEmpty) return null;
    if (breachDate is! String || addedDate is! String || _day(breachDate) == null || _day(addedDate) == null) return null;
    if (pwnCount is! num) return null;
    return Breach(
      name: name,
      title: title.isEmpty ? name : title,
      domain: domain,
      breachDate: breachDate,
      addedDate: addedDate,
      pwnCount: pwnCount.round(),
      passwords: passwords == 1 || passwords == true,
    );
  }

  /// A breach as Have I Been Pwned's API gives it, or null for one the list leaves out:
  /// unverified, of no one service, a spam list, a stealer log, malware, fabricated or
  /// retired.
  static Breach? fromHibp(Object? json) {
    if (json is! Map<String, Object?>) return null;
    const leftOut = ['IsFabricated', 'IsRetired', 'IsSpamList', 'IsMalware', 'IsStealerLog'];
    if (json['IsVerified'] != true || leftOut.any((flag) => json[flag] == true)) return null;
    final added = json['AddedDate'];
    final classes = json['DataClasses'];
    return fromRow([
      json['Name'],
      json['Title'],
      json['Domain'] is String ? (json['Domain']! as String).trim().toLowerCase() : null,
      json['BreachDate'],
      // "2013-12-04T00:00:00Z": the day is enough
      added is String && added.length >= 10 ? added.substring(0, 10) : null,
      json['PwnCount'],
      classes is List<Object?> && classes.contains('Passwords') ? 1 : 0,
    ]);
  }

  /// Have I Been Pwned's id for the breach, which doesn't change: what "dealt with" keeps.
  final String name;

  /// The breach as people know it, usually the service's name.
  final String title;

  /// The service's domain, in lower case.
  final String domain;

  /// The day the breach happened, `yyyy-mm-dd`.
  final String breachDate;

  /// The day Have I Been Pwned listed it, `yyyy-mm-dd`.
  final String addedDate;

  /// How many accounts the breach held.
  final int pwnCount;

  /// Passwords, in any form, were among the data.
  final bool passwords;

  /// The year the breach happened.
  int get year => _day(breachDate)!.year;

  /// The day the breach happened, at midnight UTC.
  DateTime get happened => _day(breachDate)!;

  /// Epoch ms of the end of the day the breach was listed. An entry added before then
  /// was in the vault when the breach became known; the list only keeps the day, so an
  /// entry added later that same day counts as there too.
  int get listedBy => _day(addedDate)!.add(const Duration(days: 1)).millisecondsSinceEpoch;

  List<Object?> toRow() => [name, title, domain, breachDate, addedDate, pwnCount, passwords ? 1 : 0];

  @override
  bool operator ==(Object other) => other is Breach && other.name == name;

  @override
  int get hashCode => name.hashCode;

  @override
  String toString() => 'Breach($name, $domain, $breachDate, listed $addedDate)';
}

/// The list of breaches, indexed by the keys of each service's name and domain.
class BreachList {
  BreachList._(this.source, this.updated, this.license, this.entries, this._byKey, this._names);

  /// Reads the trimmed list. A row that can't be read is skipped.
  factory BreachList.fromJson(Map<String, Object?> json) {
    final rows = json['entries'];
    return BreachList._of(
      [for (final row in rows is List<Object?> ? rows : const <Object?>[]) ?Breach.fromRow(row)],
      source: json['source'] is String ? json['source']! as String : '',
      updated: json['updated'] is String ? json['updated']! as String : '',
      license: json['license'] is String ? json['license']! as String : '',
    );
  }

  /// Trims the answer of Have I Been Pwned's `/api/v3/breaches`, read on the day [updated]
  /// (`yyyy-mm-dd`).
  factory BreachList.fromHibp(List<Object?> breaches, {required String updated}) => BreachList._of(
    [for (final breach in breaches) ?Breach.fromHibp(breach)],
    source: 'https://haveibeenpwned.com',
    updated: updated,
    license: breachLicense,
  );

  factory BreachList._of(List<Breach> entries, {required String source, required String updated, required String license}) {
    final byKey = <String, List<Breach>>{};
    final names = <String>{};
    final kept = <Breach>[];
    for (final breach in entries) {
      if (!names.add(breach.name)) continue;
      kept.add(breach);
      for (final key in {...keysFor(breach.title), ...keysFor(breach.domain)}) {
        byKey.putIfAbsent(key, () => []).add(breach);
      }
    }
    return BreachList._(source, updated, license, List.unmodifiable(kept), byKey, names);
  }

  /// A list with nothing in it, for before one is loaded.
  static final BreachList empty = BreachList._of(const [], source: '', updated: '', license: '');

  static const asset = 'assets/data/breaches.json';

  /// Where the data comes from: https://haveibeenpwned.com.
  final String source;

  /// The day the copy was made, `yyyy-mm-dd`.
  final String updated;

  /// The data's licence notice, to keep with it.
  final String license;

  /// Every breach, in the data's order.
  final List<Breach> entries;

  final Map<String, List<Breach>> _byKey;
  final Set<String> _names;

  /// Whether the list has the breach Have I Been Pwned calls [name].
  bool has(String name) => _names.contains(name);

  /// The breaches of the service [name] is: an account's issuer, a backup-code list's
  /// service name or a domain, compared as the logos and the 2FA directory compare names
  /// (see [keysFor]). The earliest listed comes first.
  List<Breach> of(String name) {
    final found = <Breach>{};
    for (final key in keysFor(name)) {
      found.addAll(_byKey[key] ?? const []);
    }
    return found.toList()..sort((a, b) => a.addedDate.compareTo(b.addedDate));
  }

  Map<String, Object?> toJson() => {
    'source': source,
    'updated': updated,
    'license': license,
    'entries': [for (final breach in entries) breach.toRow()],
  };
}

final _dayForm = RegExp(r'^\d{4}-\d{2}-\d{2}$');

/// The day `yyyy-mm-dd` names, at midnight UTC, or null when it isn't one.
DateTime? _day(String text) => _dayForm.hasMatch(text) ? DateTime.tryParse('${text}T00:00:00Z') : null;
