// The Public Suffix List (publicsuffix.org, MPL 2.0), bundled as
// assets/data/public_suffix_list.dat and refreshed before each release by
// tool/autofill/update_public_suffix_list.sh. It tells which part of a host
// a site owns: accounts.example.com and mail.example.com are both
// example.com's, while alice.herokuapp.com and bob.herokuapp.com are two
// sites, since anyone can open one under herokuapp.com.
import 'websites.dart';

/// The list's rules, as publicsuffix.org's algorithm reads them: a
/// suffix (`com`, `co.uk`, `herokuapp.com`), a wildcard (`*.ck`) or an
/// exception to a wildcard (`!www.ck`). Names in other scripts are kept
/// in their ASCII form, as hosts reach AutoFill.
class PublicSuffixList {
  PublicSuffixList._(this._rules, this._wildcards, this._exceptions);

  /// Reads the list's text; comments and blank lines are skipped, and a rule
  /// ends at the first whitespace, as the format says.
  factory PublicSuffixList.parse(String text) {
    final rules = <String>{};
    final wildcards = <String>{};
    final exceptions = <String>{};
    for (final raw in text.split('\n')) {
      final line = raw.trim();
      if (line.isEmpty || line.startsWith('//')) continue;
      var rule = line.split(RegExp(r'\s')).first.toLowerCase();
      final exception = rule.startsWith('!');
      if (exception) rule = rule.substring(1);
      final wildcard = rule.startsWith('*.');
      if (wildcard) rule = rule.substring(2);
      rule = rule.split('.').map((l) => l.runes.every((c) => c < 0x80) ? l : 'xn--${punycodeEncode(l)}').join('.');
      (exception
              ? exceptions
              : wildcard
              ? wildcards
              : rules)
          .add(rule);
    }
    return PublicSuffixList._(rules, wildcards, exceptions);
  }

  final Set<String> _rules;

  /// The parents of a wildcard: `ck` for `*.ck`.
  final Set<String> _wildcards;
  final Set<String> _exceptions;

  /// The number of labels of [host]'s public suffix.
  int _suffixLabels(List<String> labels) {
    // An exception wins: its suffix is the rule less its first label
    for (var i = 0; i < labels.length; i++) {
      if (_exceptions.contains(labels.sublist(i).join('.'))) return labels.length - i - 1;
    }
    // Otherwise the longest rule that matches, a wildcard counting its own label; `*` by default
    for (var i = 0; i < labels.length; i++) {
      final rest = labels.sublist(i).join('.');
      if (_rules.contains(rest)) return labels.length - i;
      if (i + 1 < labels.length && _wildcards.contains(labels.sublist(i + 1).join('.'))) return labels.length - i;
    }
    return 1;
  }

  /// The public suffix [host] is under: `co.uk` for `www.example.co.uk`.
  String publicSuffix(String host) {
    final labels = host.toLowerCase().split('.');
    return labels.sublist(labels.length - _suffixLabels(labels)).join('.');
  }

  /// The part of [host] a site owns, one label more than its public suffix
  /// (`example.co.uk` for `www.example.co.uk`), or null when [host] is a
  /// public suffix itself.
  String? registrableDomain(String host) {
    final labels = host.toLowerCase().split('.');
    final suffix = _suffixLabels(labels);
    if (labels.length <= suffix) return null;
    return labels.sublist(labels.length - suffix - 1).join('.');
  }
}
