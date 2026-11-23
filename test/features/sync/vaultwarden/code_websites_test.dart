@TestOn('vm')
library;

// A code's own websites in its Vaultwarden item (the add-cards-identities-and-websites
// plan, tasks 8.1 to 8.3): written after the directory's URI with Bitwarden's rule
// numbers, patched and never rebuilt, brought back when a Bitwarden app edits them,
// and pinned by test/fixtures/vaultwarden/code-websites.json.
import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_sync.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/website_rule.dart';
import 'package:test/test.dart';

import 'fake_vaultwarden.dart';
import 'vw_kit.dart';

/// One phone syncing a vault's own entries with the home; the 2FA directory knows GitHub's website.
class _Phone {
  _Phone(this.server, this.target) : reader = VwReader(server.userKey);

  final FakeVaultwarden server;
  final VaultwardenTarget target;
  final VwReader reader;
  Lists lists = const Lists();
  ScopeState state = const ScopeState(known: []);
  late VwCredentials credentials = server.credentials();

  Future<VwSyncResult> sync() async {
    final at = server.revision + 500;
    final result = await VaultwardenScopeSync(
      connection: VwConnection(
        api: VwApi(server.client),
        server: FakeVaultwarden.url,
        credentials: credentials,
        onCredentials: (next) async => credentials = next,
      ),
      reader: reader,
      target: target,
      websiteFor: (issuer) => issuer == 'GitHub' ? 'github.com' : null,
    ).sync(lists, state, now: at);
    lists = applyScope(lists, null, result.doc);
    state = ScopeState(known: result.known, lastSyncAt: at, extra: result.state);
    return result;
  }

  OtpAccount get account => lists.accounts.single;

  /// The account changed on this phone, newer than everything the server holds.
  void edit(OtpAccount Function(OtpAccount account) change) =>
      lists = Lists(accounts: [change(account).copyWith(updatedAt: server.revision + 400)]);
}

const _github = OtpAccount(id: 'a1', issuer: 'GitHub', label: 'octocat', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
const _hostRule = WebsiteRule('github.example.org', match: WebsiteMatch.host);

OtpAccount _withRules(OtpAccount account, List<WebsiteRule> rules) {
  final made = websitesOf(rules);
  return account.copyWith(websites: made.websites ?? unset, uris: made.uris ?? unset);
}

/// The one login item Kemlock made for the code.
Map<String, Object?> _codeItem(FakeVaultwarden server) =>
    server.ciphers.values.singleWhere((cipher) => cipher['type'] == 1 && cipher['deletedDate'] == null);

Map<String, Object?> _loginOf(Map<String, Object?> cipher) => cipher['login']! as Map<String, Object?>;

List<Map<String, Object?>> _rawUris(Map<String, Object?> cipher) =>
    (_loginOf(cipher)['uris']! as List<Object?>).cast<Map<String, Object?>>();

/// The item's URIs, decrypted, with their rule numbers.
Future<List<(String, int?)>> _uris(FakeVaultwarden server, Map<String, Object?> cipher) async => [
  for (final uri in _rawUris(cipher)) (await bwDecryptString(uri['uri']! as String, server.userKey), (uri['match'] as num?)?.toInt()),
];

/// The item's Kemlock field.
Future<PlainField> _fieldOf(FakeVaultwarden server, Map<String, Object?> cipher) async {
  for (final field in (cipher['fields']! as List<Object?>).cast<Map<String, Object?>>()) {
    if (await bwDecryptString(field['name']! as String, server.userKey) == fieldName) {
      return PlainField.tryParse(await bwDecryptString(field['value']! as String, server.userKey))!;
    }
  }
  throw StateError('The item has no Kemlock field');
}

/// A Bitwarden app's edit of the item's URIs.
void _editUris(
  FakeVaultwarden server,
  Map<String, Object?> cipher,
  List<Map<String, Object?>> Function(List<Map<String, Object?>> uris) change,
) {
  server.put({
    ...cipher,
    'login': {..._loginOf(cipher), 'uris': change(_rawUris(cipher))},
  }, id: cipher['id']! as String);
}

String _rules(OtpAccount account) => [for (final rule in account.rules) '${rule.uri}:${rule.match}'].join(' ');

final _fixture = jsonDecode(File('test/fixtures/vaultwarden/code-websites.json').readAsStringSync()) as Map<String, Object?>;

void main() {
  late FakeVaultwarden server;
  late VaultwardenTarget target;

  setUp(() async {
    server = FakeVaultwarden();
    target = await makeHome(server, VaultwardenMode.plain);
  });

  Future<_Phone> phoneWith(OtpAccount account) async {
    final phone = _Phone(server, target)..lists = Lists(accounts: [account]);
    await phone.sync();
    return phone;
  }

  group('a code without websites of its own', () {
    test('writes the single URI it always wrote, and no sum', () async {
      await phoneWith(_github);
      final item = _codeItem(server);

      expect(await _uris(server, item), [('github.com', null)]);
      final field = await _fieldOf(server, item);
      expect(field.uriSum, isNull);
      expect(field.extra, isEmpty);
      expect(field.toText(), isNot(contains('uriSum')));
    });

    test('keeps a URI a Bitwarden app added through a rename, and takes none in', () async {
      final phone = await phoneWith(_github);
      final key = server.userKey;
      final added = {'uri': await bwEncryptString('https://other.example', key), 'match': null};
      _editUris(server, _codeItem(server), (uris) => [...uris, added]);

      phone.edit((account) => account.copyWith(issuer: 'GitHub Inc'));
      await phone.sync();

      final item = _codeItem(server);
      expect(await bwDecryptString(item['name']! as String, key), 'GitHub Inc');
      expect(await _uris(server, item), [('github.com', null), ('https://other.example', null)]);
      expect((await _fieldOf(server, item)).uriSum, isNull);
      expect(phone.account.websites, isNull);
    });
  });

  group('a code with websites of its own', () {
    test('lists them after the directory’s URI with Bitwarden’s rule numbers, and carries the sum of those', () async {
      await phoneWith(_withRules(_github, const [_hostRule, WebsiteRule('wiki.example.org', match: WebsiteMatch.never)]));
      final item = _codeItem(server);

      expect(await _uris(server, item), [('github.com', null), ('github.example.org', 1), ('wiki.example.org', 5)]);
      expect((await _fieldOf(server, item)).uriSum, urisSum([(uri: 'github.example.org', match: 1), (uri: 'wiki.example.org', match: 5)]));
    });

    test('does not list the directory’s website twice when the code has it on Default', () async {
      await phoneWith(_withRules(_github, const [WebsiteRule('github.com')]));

      expect(await _uris(server, _codeItem(server)), [('github.com', null)]);
    });

    test('keeps the URIs and the sum through a rename', () async {
      final phone = await phoneWith(_withRules(_github, const [_hostRule]));
      final before = await _fieldOf(server, _codeItem(server));

      phone.edit((account) => account.copyWith(issuer: 'GitHub'));
      phone.edit((account) => account.copyWith(label: 'hubot'));
      await phone.sync();

      final item = _codeItem(server);
      expect(await _uris(server, item), [('github.com', null), ('github.example.org', 1)]);
      expect((await _fieldOf(server, item)).uriSum, before.uriSum);
    });

    test('patches the URIs when the websites change on the phone: added, removed and given another rule', () async {
      final phone = await phoneWith(_withRules(_github, const [_hostRule, WebsiteRule('wiki.example.org')]));

      phone.edit(
        (account) =>
            _withRules(account, const [WebsiteRule('github.example.org', match: WebsiteMatch.exact), WebsiteRule('app.example.org')]),
      );
      await phone.sync();

      final item = _codeItem(server);
      expect(await _uris(server, item), [('github.com', null), ('github.example.org', 3), ('app.example.org', null)]);
      expect(
        (await _fieldOf(server, item)).uriSum,
        urisSum([(uri: 'github.example.org', match: 3), (uri: 'app.example.org', match: null)]),
      );
    });

    test('drops the sum with the last website, and the URIs it wrote', () async {
      final phone = await phoneWith(_withRules(_github, const [_hostRule]));

      phone.edit((account) => account.copyWith(websites: unset, uris: unset));
      await phone.sync();

      final item = _codeItem(server);
      expect(await _uris(server, item), [('github.com', null)]);
      expect((await _fieldOf(server, item)).uriSum, isNull);
    });

    test('a URI added in a Bitwarden app survives a website added on the phone, which then gains the sum', () async {
      final phone = await phoneWith(_github);
      final added = {'uri': await bwEncryptString('https://other.example', server.userKey), 'match': null};
      _editUris(server, _codeItem(server), (uris) => [...uris, added]);

      phone.edit((account) => _withRules(account, const [_hostRule]));
      await phone.sync();

      final item = _codeItem(server);
      expect(await _uris(server, item), [('github.com', null), ('https://other.example', null), ('github.example.org', 1)]);
      expect(
        (await _fieldOf(server, item)).uriSum,
        urisSum([(uri: 'https://other.example', match: null), (uri: 'github.example.org', match: 1)]),
      );
    });

    test('a rule changed in a Bitwarden app reaches the code, here and on a second phone', () async {
      final first = await phoneWith(_withRules(_github, const [_hostRule]));
      final item = _codeItem(server);
      _editUris(
        server,
        item,
        (uris) => [
          uris[0],
          {...uris[1], 'match': 3},
        ],
      );

      final second = _Phone(server, target);
      await second.sync();
      expect(_rules(second.account), 'github.example.org:3');
      expect(second.account.websites, ['github.example.org']);

      await first.sync();
      expect(_rules(first.account), 'github.example.org:3');
    });

    test('a website added in a Bitwarden app becomes one of the code’s, and one it removed goes', () async {
      final first = await phoneWith(_withRules(_github, const [_hostRule]));
      final added = {'uri': await bwEncryptString('https://intranet.example.org/login', server.userKey), 'match': 2};
      _editUris(server, _codeItem(server), (uris) => [...uris, added]);

      await first.sync();
      expect(_rules(first.account), 'github.example.org:1 https://intranet.example.org/login:2');

      _editUris(server, _codeItem(server), (uris) => [uris[0], uris[2]]);
      await first.sync();
      expect(_rules(first.account), 'https://intranet.example.org/login:2');
    });

    test('an address that is not a host is kept only on Starts with, Exact and Regular expression', () async {
      final first = await phoneWith(_withRules(_github, const [_hostRule]));
      final key = server.userKey;
      final android = {'uri': await bwEncryptString('androidapp://githubapp', key), 'match': null};
      final pattern = {'uri': await bwEncryptString(r'^https://([a-z]+\.)?example\.org/', key), 'match': 4};
      _editUris(server, _codeItem(server), (uris) => [...uris, android, pattern]);

      await first.sync();
      expect(_rules(first.account), r'github.example.org:1 ^https://([a-z]+\.)?example\.org/:4');
    });

    test('an item with no sum takes nothing in, though a URI of its own differs', () async {
      final phone = await phoneWith(_github);
      final added = {'uri': await bwEncryptString('https://other.example', server.userKey), 'match': 1};
      _editUris(server, _codeItem(server), (uris) => [...uris, added]);

      await phone.sync();

      expect(phone.account.websites, isNull);
      expect(phone.account.uris, isNull);
    });
  });

  test('a linked login’s URIs are never written', () async {
    final key = server.userKey;
    final login = await putUserLogin(server, key);
    final cipher = VwCipher(server.ciphers[login['id']]!);
    final claim = EntryClaim(cipher, id: 'a1', kind: EntryKind.account, form: VaultwardenMode.plain, own: false, entry: _github);

    final body = await VwWriter(
      userKey: key,
      userId: FakeVaultwarden.userId,
    ).update(claim, _withRules(_github, const [_hostRule]), home: 'h');

    expect(_loginOf(body)['uris'], _loginOf(cipher.json)['uris']);
  });

  group('the fixture of a code with a website of its own', () {
    final item = _fixture['item']! as Map<String, Object?>;
    final edited = _fixture['afterBitwardenEdit']! as Map<String, Object?>;

    List<({String uri, int? match})> afterTheFirst(Object? uris) => [
      for (final uri in (uris! as List<Object?>).cast<Map<String, Object?>>().skip(1))
        (uri: uri['uri']! as String, match: uri['match'] as int?),
    ];

    test('its field reads into the code with the sum, and writes back byte for byte', () {
      final plain = PlainField.tryParse(item['field']! as String)!;

      expect(plain.uriSum, item['uriSum']);
      expect(plain.sum, item['valuesSum']);
      expect(_rules(plain.entry as OtpAccount), 'github.example.org:1');
      expect(plain.toText(), item['field']);
    });

    test('the sums are those of the URIs after the first, and a Bitwarden edit changes it', () {
      expect(urisSum(afterTheFirst(item['uris'])), item['uriSum']);
      expect(urisSum(afterTheFirst(edited['uris'])), edited['uriSum']);
      expect(edited['uriSum'], isNot(item['uriSum']));
      expect(valuesSum((item['values']! as Map<String, Object?>).cast<String, Object?>()), item['valuesSum']);
    });

    /// The item as the server holds it, with [uris].
    Future<VwCipher> cipherWith(BwKey key, Object? uris) async {
      final values = (item['values']! as Map<String, Object?>).cast<String, Object?>();
      return VwCipher({
        'id': 'c1',
        'type': 1,
        'revisionDate': '2026-11-21T09:00:00.000000Z',
        'creationDate': '2026-11-21T09:00:00.000000Z',
        'name': await bwEncryptString(values['name']! as String, key),
        'notes': await bwEncryptString(values['notes']! as String, key),
        'favorite': values['favorite'],
        'fields': [
          {
            'type': 1,
            'name': await bwEncryptString(fieldName, key),
            'value': await bwEncryptString(item['field']! as String, key),
            'linkedId': null,
          },
        ],
        'login': {
          'username': await bwEncryptString(values['username']! as String, key),
          'password': null,
          'totp': await bwEncryptString(values['totp']! as String, key),
          'uris': [
            for (final uri in (uris! as List<Object?>).cast<Map<String, Object?>>())
              {'uri': await bwEncryptString(uri['uri']! as String, key), 'match': uri['match']},
          ],
        },
      });
    }

    test('a reader keeps the rule while the URIs are as Kemlock wrote them, and takes the edited one in', () async {
      final key = BwKey.random();
      final home = _fixture['home']! as String;

      final same = await VwReader(key).read([await cipherWith(key, item['uris'])], home: home);
      expect(_rules(same.entries.single.entry! as OtpAccount), 'github.example.org:1');

      final after = await VwReader(key).read([await cipherWith(key, edited['uris'])], home: home);
      final account = after.entries.single.entry! as OtpAccount;
      expect(_rules(account), 'github.example.org:3');
      expect(account.websites, ['github.example.org']);
    });
  });
}
