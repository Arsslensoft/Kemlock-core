@TestOn('vm')
library;

import 'package:kemlock_core/core/website_input.dart';
import 'package:kemlock_core/core/website_rules.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

// the add-cards-identities-and-websites plan, task 7.1
void main() {
  String? uri(int? match, String text) => websiteInput(match, text).uri;

  test('Default, Base domain and Never keep the host alone', () {
    for (final match in [null, WebsiteMatch.baseDomain, WebsiteMatch.never]) {
      expect(uri(match, 'https://Mail.Larkspur.example:8443/login?x=1'), 'mail.larkspur.example', reason: '$match');
      expect(uri(match, 'www.example.org'), 'example.org', reason: '$match');
    }
  });

  test('Host keeps the port that was typed, and no path', () {
    expect(uri(WebsiteMatch.host, 'https://NAS.home.example:5001/admin'), 'nas.home.example:5001');
    expect(uri(WebsiteMatch.host, 'nas.home.example'), 'nas.home.example');
    expect(uri(WebsiteMatch.host, '10.0.0.20:8080'), '10.0.0.20:8080');
  });

  test('Starts with and Exact keep the address, with its scheme and host in lowercase and the rest as written', () {
    for (final match in [WebsiteMatch.startsWith, WebsiteMatch.exact]) {
      expect(uri(match, 'HTTPS://Intranet.Example.co/Login?Next=/Home'), 'https://intranet.example.co/Login?Next=/Home', reason: '$match');
      expect(uri(match, 'https://www.example.co/'), 'https://www.example.co/', reason: '$match');
      expect(uri(match, 'intranet.example.co/login'), 'intranet.example.co/login', reason: '$match');
    }
  });

  test('Starts with and Exact write the host in its ASCII form and drop a user', () {
    expect(uri(WebsiteMatch.exact, 'https://user:pw@bücher.example:8080/x'), 'https://xn--bcher-kva.example:8080/x');
  });

  test('an address that holds no host, or holds a space, has no address', () {
    for (final match in [null, WebsiteMatch.host, WebsiteMatch.startsWith, WebsiteMatch.exact]) {
      expect(uri(match, 'my bank'), isNull, reason: '$match');
      expect(uri(match, 'localhost'), isNull, reason: '$match');
      expect(websiteInput(match, 'my bank').refusal, isNull, reason: '$match');
    }
    expect(uri(WebsiteMatch.exact, 'https:///path'), isNull);
  });

  test('empty text has no address, whatever the rule', () {
    for (final match in [null, WebsiteMatch.host, WebsiteMatch.exact, WebsiteMatch.regularExpression]) {
      expect(websiteInput(match, '  '), (uri: null, refusal: null), reason: '$match');
    }
  });

  test('a Regular expression keeps the pattern as typed', () {
    const pattern = r'^https://([a-z]+\.)?example\.co/';
    expect(websiteInput(WebsiteMatch.regularExpression, pattern), (uri: pattern, refusal: null));
  });

  test('a refused pattern comes back with its reason and no address', () {
    expect(websiteInput(WebsiteMatch.regularExpression, r'(a)\1'), (uri: null, refusal: PatternRefusal.backReference));
    expect(websiteInput(WebsiteMatch.regularExpression, '(?=a)b'), (uri: null, refusal: PatternRefusal.lookaround));
    expect(websiteInput(WebsiteMatch.regularExpression, 'a' * (maxPatternLength + 1)), (uri: null, refusal: PatternRefusal.tooLong));
    expect(websiteInput(WebsiteMatch.regularExpression, 'a{101}'), (uri: null, refusal: PatternRefusal.repeatTooBig));
  });

  test('a rule this version does not know reads text as a host', () {
    expect(uri(9, 'https://Later.example/x'), 'later.example');
  });
}
