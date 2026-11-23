@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

import '../compat/before_cards/login.dart' as before_cards;

typedef _Json = Map<String, Object?>;

// The three websites of "Example Co SSO": a default one, one on a host that anyone can open a site under, and one that never fills.
const _sso = Login(
  id: 'l1',
  name: 'Example Co SSO',
  username: 'ada',
  password: 'hunter2',
  websites: ['example.co', 'example-co.okta.com'],
  uris: [
    WebsiteRule('example.co'),
    WebsiteRule('example-co.okta.com', match: WebsiteMatch.host),
    WebsiteRule('wiki.example.co', match: WebsiteMatch.never),
  ],
  addedAt: 1,
);

List<String> _uris(Login login) => [for (final rule in login.rules) '${rule.uri}:${rule.match}'];

_Json _roundTrip(_Json json) => jsonDecode(jsonEncode(json)) as _Json;

// the add-cards-identities-and-websites plan, task 5.1
void main() {
  group('a login whose websites all use the default rule', () {
    const login = Login(id: 'l1', name: 'GitHub', password: 'x', websites: ['github.com'], addedAt: 1);

    test('is stored exactly as before, with no uris', () {
      expect(jsonEncode(login.toJson()), '{"id":"l1","name":"GitHub","password":"x","websites":["github.com"],"addedAt":1}');
      expect(Login.fromJson(login.toJson()).uris, isNull);
      expect(Login.fromJson(login.toJson()).rules.map((rule) => rule.uri), ['github.com']);
    });

    test('is stored the same when its rules are listed but all bare hosts on Default', () {
      final listed = login.copyWith(uris: [const WebsiteRule('github.com')]);
      expect(listed.toJson().keys, isNot(contains('uris')));
      expect(listed.toJson()['websites'], ['github.com']);
    });
  });

  group('writing', () {
    test('derives websites from the rules that fill on a host, in uris order, each once', () {
      final login = _sso.copyWith(
        uris: [
          const WebsiteRule('b.example', match: WebsiteMatch.exact),
          const WebsiteRule('a.example'),
          const WebsiteRule('b.example', match: WebsiteMatch.host),
          const WebsiteRule('^https://x\\.example/', match: WebsiteMatch.regularExpression),
          const WebsiteRule('never.example', match: WebsiteMatch.never),
          const WebsiteRule('later.example', match: 9),
        ],
      );

      expect(login.websites, ['b.example', 'a.example']);
      expect(login.toJson()['websites'], ['b.example', 'a.example']);
      expect((login.toJson()['uris']! as List).length, 6);
    });

    test('writes uris after websites, with the number of each rule and no number for Default', () {
      final json = _sso.toJson();

      expect(json.keys.toList().sublist(json.keys.length - 3), ['websites', 'uris', 'addedAt']);
      expect(json['uris'], [
        {'uri': 'example.co'},
        {'uri': 'example-co.okta.com', 'match': 1},
        {'uri': 'wiki.example.co', 'match': 5},
      ]);
    });

    test('keeps what a rule holds beyond its number, such as a Bitwarden checksum', () {
      final json = {
        ..._sso.toJson(),
        'websites': ['example.co'],
        'uris': [
          {'uri': 'https://example.co/login', 'match': 3, 'uriChecksum': 'abc='},
        ],
      };

      expect(Login.fromJson(json).toJson()['uris'], json['uris']);
    });

    test('a login and an account take the same rules', () {
      const account = OtpAccount(id: 'a1', issuer: 'GitHub', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
      final ruled = account.copyWith(uris: _sso.uris);

      expect(ruled.websites, ['example.co', 'example-co.okta.com']);
      expect(OtpAccount.fromJson(_roundTrip(ruled.toJson())), ruled);
      expect(OtpAccount.fromJson(_roundTrip(ruled.toJson())).uris, _sso.uris);
    });
  });

  group('reading what an older build wrote', () {
    // An older build reads websites alone, keeps uris in extra, and writes both back
    Login olderEdit(Login login, List<String> websites) {
      final older = before_cards.Login.fromJson(_roundTrip(login.toJson()));
      return Login.fromJson(_roundTrip(older.copyWith(websites: websites.isEmpty ? unset : websites).toJson()));
    }

    test('an older build fills on the hosts of the first two websites only', () {
      final older = before_cards.Login.fromJson(_roundTrip(_sso.toJson()));

      expect(older.websites, ['example.co', 'example-co.okta.com']);
      expect(older.extra['uris'], _sso.toJson()['uris']);
    });

    test('a login the older build only renamed keeps its three websites and their rules', () {
      final older = before_cards.Login.fromJson(_roundTrip(_sso.toJson())).copyWith(name: 'Renamed');

      final read = Login.fromJson(_roundTrip(older.toJson()));

      expect(read.name, 'Renamed');
      expect(read.uris, _sso.uris);
      expect(read.websites, _sso.websites);
    });

    test('a host added there joins on Default, after the other websites', () {
      final read = olderEdit(_sso, ['example.co', 'example-co.okta.com', 'example.org']);

      expect(_uris(read), ['example.co:null', 'example-co.okta.com:1', 'wiki.example.co:5', 'example.org:null']);
      expect(read.websites, ['example.co', 'example-co.okta.com', 'example.org']);
    });

    test('a website whose host was removed there goes, and one on Never stays', () {
      final read = olderEdit(_sso, ['example.co']);

      expect(_uris(read), ['example.co:null', 'wiki.example.co:5']);
      expect(read.websites, ['example.co']);
    });

    test('removing every website there keeps a Regular expression or Never one, which that version never showed', () {
      final read = olderEdit(_sso, []);

      expect(_uris(read), ['wiki.example.co:5']);
      expect(read.websites, isEmpty);
    });

    test('a number this version does not know is kept, fills nowhere, and is written back', () {
      final json = {
        ..._sso.toJson(),
        'websites': ['example.co'],
        'uris': [
          {'uri': 'example.co'},
          {'uri': 'future.example', 'match': 9},
        ],
      };
      final read = Login.fromJson(json);

      expect(read.rules.last.isKnown, isFalse);
      expect(read.websites, ['example.co']);
      expect(read.toJson()['uris'], json['uris']);
      expect(olderEdit(read, ['example.co']).rules.last.match, 9, reason: 'an older edit that leaves the other hosts keeps it');
    });

    test('an item with no uris reads as its websites on Default, as today', () {
      final read = Login.fromJson({
        'id': 'l',
        'name': 'n',
        'websites': ['a.example', 'b.example'],
        'addedAt': 1,
      });

      expect(read.uris, isNull);
      expect(_uris(read), ['a.example:null', 'b.example:null']);
    });
  });

  group('copyWith', () {
    test('websites alone is what an older build does: the rules of the hosts kept stay', () {
      final changed = _sso.copyWith(websites: ['example-co.okta.com']);

      expect(_uris(changed), ['example-co.okta.com:1', 'wiki.example.co:5']);
      expect(changed.websites, ['example-co.okta.com']);
    });

    test('uris derives websites, and wins over websites passed beside it', () {
      final changed = _sso.copyWith(
        websites: ['ignored.example'],
        uris: [const WebsiteRule('only.example', match: WebsiteMatch.exact)],
      );

      expect(changed.websites, ['only.example']);
      expect(changed.uris, hasLength(1));
    });

    test('uris removed leaves the hosts as they were', () {
      final changed = _sso.copyWith(uris: unset);

      expect(changed.uris, isNull);
      expect(changed.websites, ['example.co', 'example-co.okta.com']);
      expect(changed.toJson().keys, isNot(contains('uris')));
    });
  });

  group('what an editor hands to copyWith', () {
    test('uris removed with websites passed beside it leaves those hosts', () {
      final changed = _sso.copyWith(websites: ['only.example'], uris: unset);

      expect(changed.uris, isNull);
      expect(changed.websites, ['only.example']);
      expect(changed.toJson()['websites'], ['only.example']);
      expect(changed.toJson().keys, isNot(contains('uris')));
    });

    test('both removed leave no websites', () {
      final changed = _sso.copyWith(websites: unset, uris: unset);

      expect(changed.websites, isNull);
      expect(changed.toJson().keys, isNot(contains('websites')));
    });

    test('websitesOf is nothing for none and hosts alone for bare hosts on Default', () {
      final none = websitesOf(const []);
      expect((none.websites, none.uris), (null, null));
      final plain = websitesOf(const [WebsiteRule('example.co'), WebsiteRule('example.org'), WebsiteRule('example.co')]);
      expect(plain.websites, ['example.co', 'example.org']);
      expect(plain.uris, isNull);
    });

    test('websitesOf keeps the rules once one says more than a host, with the hosts derived', () {
      final made = websitesOf(const [
        WebsiteRule('example.co'),
        WebsiteRule('example-co.okta.com', match: WebsiteMatch.host),
        WebsiteRule('wiki.example.co', match: WebsiteMatch.never),
      ]);

      expect(made.websites, ['example.co', 'example-co.okta.com']);
      expect(made.uris, hasLength(3));
    });

    test('a login given the pair is stored with the hosts alone, or with its rules', () {
      final plain = websitesOf(const [WebsiteRule('example.co')]);
      final hosts = _sso.copyWith(websites: plain.websites ?? unset, uris: plain.uris ?? unset);
      expect(hosts.uris, isNull);
      expect(hosts.toJson()['websites'], ['example.co']);

      final rules = websitesOf(const [WebsiteRule('wiki.example.co', match: WebsiteMatch.never)]);
      final never = _sso.copyWith(websites: rules.websites ?? unset, uris: rules.uris ?? unset);
      expect(_uris(never), ['wiki.example.co:5']);
      expect(never.toJson().keys, isNot(contains('websites')));
    });
  });

  group('the fixtures that exist', () {
    for (final file in ['test/fixtures/logins/export-with-logins-plain.json']) {
      test('every login and account in $file round-trips byte for byte', () {
        final json = jsonDecode(File(file).readAsStringSync()) as _Json;
        for (final entry in [...?(json['logins'] as List<Object?>?), ...?(json['accounts'] as List<Object?>?)]) {
          final item = entry! as _Json;
          final read = item.containsKey('issuer') ? OtpAccount.fromJson(item).toJson() : Login.fromJson(item).toJson();
          expect(jsonEncode(read), jsonEncode(item));
        }
      });
    }
  });
}
