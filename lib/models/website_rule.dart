import '../core/websites.dart';
import 'json.dart';

/// Bitwarden's `UriMatchStrategy` numbers, which is how a rule is stored so
/// that it crosses between Kemlock and Bitwarden formats unchanged. A website
/// with no number is on the default rule.
abstract final class WebsiteMatch {
  static const baseDomain = 0;
  static const host = 1;
  static const startsWith = 2;
  static const exact = 3;
  static const regularExpression = 4;
  static const never = 5;
}

/// One website of a login or code and the rule that says where it fills
/// (the add-cards-identities-and-websites plan, design decision 5).
///
/// [uri] is what the rule needs: the host for Default, Base domain, Host and
/// Never; the address for Starts with and Exact; the pattern for Regular
/// expression; and for a URI read from a Bitwarden item, exactly as read.
/// [match] is Bitwarden's number, null for Default. A number this version
/// doesn't know is kept, and fills nowhere. Keys it doesn't know are kept in
/// [extra] and written back.
class WebsiteRule {
  const WebsiteRule(this.uri, {this.match, this.extra = const {}});

  factory WebsiteRule.fromJson(Map<String, Object?> json) =>
      WebsiteRule(asString(json['uri']), match: asInt(json['match']), extra: extraKeys(json, const {'uri', 'match'}));

  final String uri;

  /// A [WebsiteMatch] number, null for the default rule, or a number of a later version.
  final int? match;

  /// Keys this version doesn't know, such as Bitwarden's `uriChecksum`, kept as they were.
  final Map<String, Object?> extra;

  /// Whether [match] is the default rule or one this version knows.
  bool get isKnown => match == null || (match! >= WebsiteMatch.baseDomain && match! <= WebsiteMatch.never);

  /// Whether the rule fills on a host, so its host is in `websites` for builds that
  /// know no rules: Default, Base domain, Host, Starts with and Exact. Regular
  /// expression, Never and an unknown rule are not.
  bool get fillsOnHost => isKnown && match != WebsiteMatch.regularExpression && match != WebsiteMatch.never;

  /// The host this website fills on, as `websites` keeps it; null for a rule
  /// that fills on none, and for a [uri] that holds no host.
  String? get host => fillsOnHost ? normaliseWebsite(uri) : null;

  /// Whether this is a bare host on the default rule, which is all `websites`
  /// alone can say, so nothing more is written for it.
  bool get isBareDefault => match == null && extra.isEmpty && normaliseWebsite(uri) == uri;

  /// This website with another rule, keeping what it holds beyond the number.
  WebsiteRule withMatch(int? next, {String? uri}) => WebsiteRule(uri ?? this.uri, match: next, extra: extra);

  Map<String, Object?> toJson() => {'uri': uri, 'match': ?match, ...extra};

  @override
  bool operator ==(Object other) => other is WebsiteRule && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(uri, match);

  @override
  String toString() => 'WebsiteRule($uri, $match)';
}

/// The hosts of [rules] for builds that know no rules, in order, each once:
/// those of the websites whose rule fills on a host.
List<String> fillHosts(List<WebsiteRule> rules) => <String>{for (final rule in rules) ?rule.host}.toList();

/// Whether [rules] say more than a list of hosts does, so `uris` is written.
bool needsUris(List<WebsiteRule> rules) => rules.any((rule) => !rule.isBareDefault);

/// [rules] reconciled with [websites], the hosts a build that knows no rules
/// left (design decision 5):
///
/// - each host of [websites] that no website of [rules] fills on joins at the
///   end on the default rule;
/// - a website that fills on a host that [websites] no longer holds was
///   removed there, and goes;
/// - the others, Regular expression, Never, an unknown rule and a [WebsiteRule.uri]
///   with no host, stay: [websites] never held them.
List<WebsiteRule> reconcileRules(List<WebsiteRule> rules, List<String> websites) {
  final wanted = websites.toSet();
  final held = <String>{};
  final kept = <WebsiteRule>[];
  for (final rule in rules) {
    final host = rule.host;
    if (host != null) {
      if (!wanted.contains(host)) continue;
      held.add(host);
    }
    kept.add(rule);
  }
  return [
    ...kept,
    for (final host in wanted)
      if (!held.contains(host)) WebsiteRule(host),
  ];
}

/// The `uris` of [json] as rules, or null when it has none.
List<WebsiteRule>? rulesFromJson(Object? value) => value is List
    ? [
        for (final item in value)
          if (item is Map<String, Object?>) WebsiteRule.fromJson(item),
      ]
    : null;

/// The two lists of a login or code as stored: `websites` and `uris`.
typedef Websites = ({List<String>? websites, List<WebsiteRule>? uris});

/// Reads `websites` and `uris` from a stored item. Without `uris` it is the
/// hosts alone, as before. With it, [reconcileRules] brings in what a build
/// that knows no rules did to `websites`, and `websites` is what is derived.
///
/// With [urls] (a login), a body that holds neither `uris` nor `websites` but the web vault's own `urls` has its addresses read
/// as websites on the default rule ([websitesOfUrls]).
Websites readWebsites(Map<String, Object?> json, {bool urls = false}) {
  final hosts = asStrings(json['websites']);
  final rules = rulesFromJson(json['uris']);
  if (rules == null) {
    return (urls && hosts == null ? websitesOfUrls(json['urls']) : null) ?? (websites: hosts, uris: null);
  }
  final reconciled = reconcileRules(rules, hosts ?? const []);
  return (websites: fillHosts(reconciled), uris: reconciled);
}

/// The websites of a body that holds only `urls` (`crypto.md`, "Login websites": a login written before `uris` has `urls` alone, and
/// every address in it is on the default rule): the host of each address that has one, each once, in order. Null when there is none.
Websites? websitesOfUrls(Object? urls) {
  if (urls is! List) return null;
  final hosts = <String>{
    for (final url in urls)
      if (url is String) ?normaliseWebsite(url),
  };
  return hosts.isEmpty ? null : (websites: hosts.toList(), uris: null);
}

/// Whether writing [read], the websites read from [json], gives back exactly the `websites` and `uris` members [json] holds, and none
/// where it holds none. When it doesn't (a web vault body that spells every address as a `uris` entry, a `websites` that isn't a list
/// of texts, a `uris` with no `websites` beside it), a model that must write the body back as it was keeps the two members as they
/// were among its unknown keys, and writes none of its own until the websites are edited.
bool writesBackWebsites(Map<String, Object?> json, Websites read) {
  final written = writeWebsites(read.websites, read.uris);
  return const [
    'websites',
    'uris',
  ].every((key) => json.containsKey(key) == written.containsKey(key) && jsonEquals(json[key], written[key]));
}

/// Whether [json] is a body that holds only `urls` and no `uris` or `websites`, whose websites [readWebsites] reads with `urls: true`
/// are none of its own. Such a body is written back without them until its websites are edited.
bool websitesFromUrls(Map<String, Object?> json) =>
    rulesFromJson(json['uris']) == null && asStrings(json['websites']) == null && websitesOfUrls(json['urls']) != null;

/// The `websites` and `uris` entries of a stored item: hosts derived from the
/// rules when there are any, and `uris` only when it says more than the hosts.
Map<String, Object?> writeWebsites(List<String>? websites, List<WebsiteRule>? uris) {
  final hosts = uris == null ? websites : fillHosts(uris);
  return {
    if (hosts?.isNotEmpty ?? false) 'websites': hosts,
    if (uris != null && needsUris(uris)) 'uris': [for (final rule in uris) rule.toJson()],
  };
}

/// What a `copyWith` of `websites` and `uris` makes of them. Changing
/// `websites` alone is what a build that knows no rules does, so [reconcileRules]
/// applies to the rules kept; changing [uris] derives `websites` from them.
/// Passing both, [uris] wins, unless it removes the rules: then [websites] says
/// the hosts that stay, or, if it is [keep], the hosts as they were.
/// A [keep] changes nothing and [unset] removes.
Websites changeWebsites(Websites current, {Object? websites = keep, Object? uris = keep}) {
  if (!identical(uris, keep)) {
    final rules = pick<List<WebsiteRule>>(uris, null);
    if (rules != null) return (websites: fillHosts(rules), uris: rules);
    return (websites: identical(websites, keep) ? current.websites : pick<List<String>>(websites, null), uris: null);
  }
  if (identical(websites, keep)) return current;
  final hosts = pick<List<String>>(websites, null);
  final rules = current.uris;
  if (rules == null) return (websites: hosts, uris: null);
  final reconciled = reconcileRules(rules, hosts ?? const []);
  return (websites: fillHosts(reconciled), uris: reconciled);
}

/// What an editor of websites hands to `copyWith` for the [rules] it made, both
/// at once: nothing for none, the hosts alone when each is a bare host on the
/// default rule, else the rules with the hosts derived from them. Pass
/// `websites ?? unset` and `uris ?? unset`.
Websites websitesOf(List<WebsiteRule> rules) {
  if (rules.isEmpty) return (websites: null, uris: null);
  return (websites: fillHosts(rules), uris: needsUris(rules) ? rules : null);
}

/// The websites as a login's `urls` member holds them (`crypto.md`, "Login websites"): the addresses of [rules] in order,
/// without the regular expressions.
List<String> urlsOf(List<WebsiteRule> rules) => [
  for (final rule in rules)
    if (rule.match != WebsiteMatch.regularExpression) rule.uri,
];

/// [extra] with its `urls` in step with the websites [changed] to, for an item whose websites were edited: the web vault's
/// own key, written beside `websites` and `uris`, would otherwise go stale. It is done only when the body already held
/// `urls` as a list, and only when [changed] differs from [before]; an item nobody edited, or one that never had `urls`,
/// is written exactly as it was.
///
/// With rules ([Websites.uris]) the addresses are those of the rules. With hosts alone they are the ones `urls` held whose host is
/// still listed, as they were (a full address is not collapsed to its host), then each host no address covers, which is new.
/// An edit also drops the `websites` and `uris` members a model kept among its unknown keys because it could not write them back
/// exactly: the typed ones replace them.
Map<String, Object?> extraWithUrls(Map<String, Object?> extra, Websites before, Websites changed) {
  if (_sameWebsites(before, changed)) {
    return extra;
  }
  final out = {
    for (final MapEntry(:key, :value) in extra.entries)
      if (key != 'websites' && key != 'uris') key: value,
  };
  final held = extra['urls'];
  if (held is! List) {
    return out;
  }
  final rules = changed.uris;
  return {...out, 'urls': rules != null ? urlsOf(rules) : _urlsKept(held, changed.websites ?? const [])};
}

/// The addresses of [held] whose host is in [hosts] (or that have none, which are not ours to drop), then each host of [hosts] that
/// no address covers.
List<Object?> _urlsKept(List<Object?> held, List<String> hosts) {
  final listed = hosts.toSet();
  final covered = <String>{};
  final out = <Object?>[];
  for (final url in held) {
    final host = url is String ? normaliseWebsite(url) : null;
    if (host == null) {
      out.add(url);
    } else if (listed.contains(host)) {
      out.add(url);
      covered.add(host);
    }
  }
  return [
    ...out,
    for (final host in hosts)
      if (!covered.contains(host)) host,
  ];
}

bool _sameWebsites(Websites a, Websites b) =>
    jsonEquals(a.websites, b.websites) &&
    jsonEquals(a.uris?.map((rule) => rule.toJson()).toList(), b.uris?.map((rule) => rule.toJson()).toList());
