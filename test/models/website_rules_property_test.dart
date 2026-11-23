@TestOn('vm')
library;

import 'dart:convert';
import 'dart:math';

import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

import '../compat/before_cards/login.dart' as before_cards;

typedef _Json = Map<String, Object?>;

const _hosts = ['a.example', 'b.example', 'c.example', 'd.example', 'e.example', 'f.example'];

_Json _roundTrip(_Json json) => jsonDecode(jsonEncode(json)) as _Json;

/// A random rule for a random host, on every kind of rule, unknown ones too.
WebsiteRule _randomRule(Random random) {
  final host = _hosts[random.nextInt(_hosts.length)];
  return switch (random.nextInt(8)) {
    0 => WebsiteRule(host),
    1 => WebsiteRule(host, match: WebsiteMatch.baseDomain),
    2 => WebsiteRule(host, match: WebsiteMatch.host),
    3 => WebsiteRule('https://$host/login', match: WebsiteMatch.startsWith),
    4 => WebsiteRule('https://$host/', match: WebsiteMatch.exact),
    5 => WebsiteRule('^https://$host/', match: WebsiteMatch.regularExpression),
    6 => WebsiteRule(host, match: WebsiteMatch.never),
    _ => WebsiteRule(host, match: 9),
  };
}

/// What the rules that no older build can see are: a regular expression, Never, or a rule from a later version.
bool _hidden(WebsiteRule rule) => rule.match == WebsiteMatch.regularExpression || rule.match == WebsiteMatch.never || !rule.isKnown;

// the add-cards-identities-and-websites plan, task 5.2
void main() {
  for (final seed in [1, 2, 3, 4, 5]) {
    test('after each read, websites are the hosts of the fill rules and no hidden rule is lost (seed $seed)', () {
      final random = Random(seed);
      var login = const Login(id: 'l1', name: 'Login', password: 'x', addedAt: 1);
      for (var step = 0; step < 150; step++) {
        final hiddenBefore = login.rules.where(_hidden).toList();
        if (random.nextBool()) {
          // This version edits the rules, with every rule among them
          // Two bare hosts on Default are one website: only hosts hold no more than websites does
          final bare = <String>{};
          final rules = [for (var i = random.nextInt(5); i > 0; i--) _randomRule(random)]
              .where((rule) => !rule.isBareDefault || bare.add(rule.uri))
              .toList();
          login = Login.fromJson(_roundTrip(login.copyWith(uris: rules).toJson()));
          expect(login.rules, rules, reason: 'a write and a read keep the rules as they were (step $step)');
        } else {
          // An older build edits websites alone and writes the item back with `uris` in its extra keys
          final older = before_cards.Login.fromJson(_roundTrip(login.toJson()));
          final wanted = {
            for (final host in _hosts)
              if (random.nextBool()) host,
          }.toList();
          final edited = older.copyWith(websites: wanted.isEmpty ? unset : wanted);
          login = Login.fromJson(_roundTrip(edited.toJson()));
          // Every host it left is a website that fills on it, and none of the hidden rules is gone
          final filled = {for (final rule in login.rules) ?rule.host};
          expect(filled, wanted.toSet(), reason: 'the hosts the older build left fill (step $step)');
          for (final rule in hiddenBefore) {
            expect(login.rules, contains(rule), reason: '$rule survives an older edit (step $step)');
          }
        }
        final rules = login.uris;
        if (rules != null) {
          expect(login.websites ?? const <String>[], fillHosts(rules), reason: 'websites are derived from the rules (step $step)');
        }
        expect(<String>{...?login.websites}.length, (login.websites ?? const <String>[]).length, reason: 'each host once (step $step)');
        // What is stored reads back as it is
        expect(Login.fromJson(_roundTrip(login.toJson())), login, reason: 'a second read changes nothing (step $step)');
      }
    });
  }
}
