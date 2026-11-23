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

// the add-cards-identities-and-websites plan, task 5.3. The fixture is written by hand and is not regenerated.
void main() {
  final fixture = jsonDecode(File('test/fixtures/logins/sync-with-uris.json').readAsStringSync()) as _Json;
  final login = fixture['login']! as _Json;
  final account = fixture['account']! as _Json;
  final matches = [null, 0, 1, 2, 3, 4, 5, 9];

  test('the login reads into every rule, and writes back as it was written, byte for byte', () {
    final written = login['written']! as _Json;

    final read = Login.fromJson(written);

    expect([for (final rule in read.rules) rule.match], matches);
    expect(read.websites, ['example.co', 'accounts.larkspur.example', 'example-co.okta.com', 'intranet.example.co']);
    expect(read.rules.last.isKnown, isFalse);
    expect(jsonEncode(read.toJson()), jsonEncode(written));
  });

  test('the account reads into its rules and writes back as it was written', () {
    final written = account['written']! as _Json;

    final read = OtpAccount.fromJson(written);

    expect([for (final rule in read.rules) rule.match], [1, null, 4, 5]);
    expect(read.websites, ['github.example.org', 'example.co']);
    expect(jsonEncode(read.toJson()), jsonEncode(written));
  });

  test('a phone on the previous version writes the entries back with the rules in its extra keys', () {
    final older = before_cards.Login.fromJson(login['written']! as _Json)
        .copyWith(name: 'Renamed by an older phone', updatedAt: 1795300060000);

    expect(jsonEncode(older.toJson()), jsonEncode(login['olderWritesBack']));
    expect(older.websites, [
      'example.co',
      'accounts.larkspur.example',
      'example-co.okta.com',
      'intranet.example.co',
    ], reason: 'it fills on the hosts');
  });

  test('this version reads what the previous one wrote back, with every rule kept', () {
    final read = Login.fromJson(login['olderWritesBack']! as _Json);
    final original = Login.fromJson(login['written']! as _Json);

    expect(read.name, 'Renamed by an older phone');
    expect(read.uris, original.uris);
    expect(jsonEquals(read.toJson(), {...original.toJson(), 'name': read.name, 'updatedAt': 1795300060000}), isTrue);

    final readAccount = OtpAccount.fromJson(account['olderWritesBack']! as _Json);
    expect(readAccount.uris, OtpAccount.fromJson(account['written']! as _Json).uris);
    expect(readAccount.issuer, 'Example Co SSO');
  });

  test('every rule of the fixture is one this version names, the last excepted', () {
    final rules = Login.fromJson(login['written']! as _Json).rules;

    expect(rules.where((rule) => rule.isKnown), hasLength(7));
    expect(rules.where((rule) => rule.fillsOnHost).map((rule) => rule.match), [null, 0, 1, 2, 3]);
    expect(rules[5].match, WebsiteMatch.regularExpression);
    expect(rules[6].match, WebsiteMatch.never);
  });
}
