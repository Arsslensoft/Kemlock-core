@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/features/duplicates/dedup_cache.dart';
import 'package:kemlock_core/features/duplicates/dedup_tagger.dart';
import 'package:kemlock_core/features/duplicates/duplicate_matcher.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

const _spaceId = 'team_Alpha-01';
final _spaceKey = Uint8List.fromList(List<int>.generate(32, (i) => 200 - i));

Login _login(
  String id, {
  String username = 'sam',
  String password = 'hunter2',
  String site = 'larkspur.example',
  String? spaceId,
  int at = 1,
}) => Login(id: id, name: 'Login $id', username: username, password: password, websites: [site], spaceId: spaceId, addedAt: at);

OtpAccount _code(String id, String issuer, String secret) => OtpAccount(id: id, issuer: issuer, label: 'me', secret: secret, addedAt: 1);

SecureNote _note(String id, String text) => SecureNote(id: id, title: 'Note $id', text: text, addedAt: 1);

Passkey _passkey(String id, String rp, String credential) =>
    Passkey(id: id, credentialId: credential, rpId: rp, userHandle: 'h', userName: 'u', privateKey: 'k', addedAt: 1);

BackupService _codes(String id, String name, List<String> codes) => BackupService(
  id: id,
  serviceName: name,
  codes: [for (final code in codes) BackupCode(code: code)],
  addedAt: 1,
);

VaultKey _key(String id) => VaultKey(
  id: id,
  name: 'key $id',
  kind: KeyKind.ssh,
  algorithm: 'ed25519',
  privateKey: 'private $id',
  publicKey: 'public $id',
  origin: KeyOrigin.generated,
  addedAt: 1,
);

Contact _contact(String id) => Contact(id: id, name: 'Contact $id', publicKey: 'AAAA', source: ContactSource.file, addedAt: 1);

// A key and a contact are told by one fingerprint here, which is what would put them in one group
String? _identityOf(Object item) => item is VaultKey || item is Contact ? 'SHA256:one-fingerprint' : null;

/// The tags the cache would hold for [items], by owner slot and item id.
Map<String, Map<String, DedupItemTags>> _tagged(List<DedupItem> items, {bool withSpace = false}) {
  final cache = DedupCache.fresh('list');
  final spaces = withSpace ? [(id: _spaceId, key: _spaceKey)] : <({String id, Uint8List key})>[];
  final result = refreshTags(cache, items, dedupOwners(cache, spaces), keyIdentityOf: _identityOf);
  return {for (final MapEntry(:key, :value) in result.cache.owners.entries) key: value.items};
}

List<DuplicateGroup> _find(List<DedupItem> items, {bool withSpace = false, Map<String, Map<String, DedupItemTags>>? tags}) =>
    findDuplicates(
      items: items,
      tags: tags ?? _tagged(items, withSpace: withSpace),
      keyIdentityOf: _identityOf,
    );

/// Each group as its reason and sorted ids.
List<String> _summary(List<DuplicateGroup> groups) => [
  for (final group in groups) '${group.reason.name}: ${(group.items.map((item) => item.id).toList()..sort()).join(',')}',
];

void main() {
  group('the reason of a group', () {
    test('is the same sign-in for one site, username and password', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b'),
          _login('c', username: 'other'),
        ],
      );

      expect(_summary(_find(items)), ['sameSignIn: a,b']);
    });

    test('is the same account for one site and username with two passwords', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', password: 'correct horse'),
        ],
      );

      expect(_summary(_find(items)), ['sameAccount: a,b']);
    });

    test('is the strongest kind the group shares: a login that shares a cred is a sign-in', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b'),
          _login('c', password: 'other'),
        ],
      );

      final groups = _find(items);

      expect(_summary(groups), ['sameSignIn: a,b,c']);
    });

    test('is the same code for one secret under two issuers', () {
      final items = dedupItems(
        accounts: [
          _code('a', 'Google', 'JBSWY3DPEHPK3PXP'),
          _code('b', 'google.com', 'jbsw y3dp ehpk 3pxp'),
          _code('c', 'Other', 'KRSXG5CTMVRXEZLU'),
        ],
      );

      expect(_summary(_find(items)), ['sameCode: a,b']);
    });

    test('is the same passkey, note, backup codes, card, identity and key', () {
      final items = dedupItems(
        passkeys: [_passkey('p1', 'example.com', 'c1'), _passkey('p2', 'Example.com', 'c1'), _passkey('p3', 'example.com', 'c2')],
        notes: [_note('n1', 'text  '), _note('n2', 'text'), _note('n3', 'other')],
        services: [
          _codes('s1', 'GitLab', ['1', '2']),
          _codes('s2', 'Other name', ['2', '1']),
        ],
        cards: [
          const PaymentCard(id: 'card1', name: 'Visa', number: '4111 1111 1111 1111', expMonth: 12, expYear: 2030, addedAt: 1),
          const PaymentCard(id: 'card2', name: 'Visa again', number: '4111111111111111', expMonth: 12, expYear: 2030, addedAt: 1),
        ],
        identities: [
          const Identity(id: 'i1', name: 'Home', givenName: 'Sam', familyName: 'Ng', email: 'sam@example.org', addedAt: 1),
          const Identity(id: 'i2', name: 'Work', givenName: 'sam', familyName: 'ng', email: 'SAM@example.org', addedAt: 1),
        ],
        keys: [_key('key1'), _key('key2')],
      );

      expect(_summary(_find(items)), [
        'sameCodes: s1,s2',
        'sameNote: n1,n2',
        'samePasskey: p1,p2',
        'sameKey: key1,key2',
        'sameCard: card1,card2',
        'sameIdentity: i1,i2',
      ], reason: 'in the order the items are listed');
    });
  });

  group('what is not a group', () {
    test('is one item, or items with nothing in common', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', username: 'other'),
          _login('c', site: 'beta.example'),
        ],
      );

      expect(_find(items), isEmpty);
    });

    test('is a login with no password beside one with: they still share an account', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          Login(id: 'b', name: 'B', username: 'sam', websites: const ['larkspur.example'], addedAt: 1),
        ],
      );

      expect(_summary(_find(items)), ['sameAccount: a,b']);
    });

    test('is a key and a contact with one fingerprint', () {
      final items = dedupItems(keys: [_key('k')], contacts: [_contact('c')]);

      expect(_find(items), isEmpty);
    });

    test('is a forged tag: items whose tags say they are one but whose values are not', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', username: 'other', site: 'beta.example'),
        ],
      );
      final tags = _tagged(items);
      final owner = Map<String, DedupItemTags>.of(tags[vaultSlot]!);
      owner['b'] = DedupItemTags(owner['b']!.at, owner['a']!.tags);

      expect(_find(items, tags: {vaultSlot: owner}), isEmpty);
    });

    test('is a tag of an item the vault no longer holds', () {
      final items = dedupItems(logins: [_login('a'), _login('b')]);
      final tags = _tagged(items);

      expect(_find([items.first], tags: tags), isEmpty);
    });
  });

  group('in two places', () {
    test('is one login in the vault and in a space, which no owner can see alone', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', spaceId: _spaceId),
        ],
      );
      final tags = _tagged(items, withSpace: true);

      expect(tags[vaultSlot]!.keys, {'a'});
      expect(tags[spaceSlot(_spaceId)]!.keys, {'b'});
      expect(_summary(_find(items, tags: tags)), ['inTwoPlaces: a,b']);
      expect(_find(items, tags: tags).single.acrossPlaces, isTrue);
    });

    test('is a vault login and a space login of one account with two passwords too', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', spaceId: _spaceId, password: 'other'),
        ],
      );

      expect(_summary(_find(items, withSpace: true)), ['inTwoPlaces: a,b']);
    });

    test('keeps the groups inside one owner as they are', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b'),
          _login('c', spaceId: _spaceId, site: 'beta.example'),
        ],
      );

      final groups = _find(items, withSpace: true);

      expect(_summary(groups), ['sameSignIn: a,b']);
      expect(groups.single.acrossPlaces, isFalse);
    });

    test('is still found when the space has no key, as the run key tags every item the phone can open', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', spaceId: _spaceId),
        ],
      );

      expect(_summary(_find(items)), ['inTwoPlaces: a,b']);
    });

    test('keeps no tag of its own: the stored tags are as they were after a match', () {
      final items = dedupItems(
        logins: [
          _login('a'),
          _login('b', spaceId: _spaceId),
        ],
      );
      final tags = _tagged(items, withSpace: true);
      final before = {for (final MapEntry(:key, :value) in tags.entries) key: value.length};

      _find(items, tags: tags);

      expect({for (final MapEntry(:key, :value) in tags.entries) key: value.length}, before);
    });
  });

  group('dismissals', () {
    test('hide a group by its item ids, and the group returns when a third item joins', () {
      final two = dedupItems(notes: [_note('n1', 'same'), _note('n2', 'same')]);
      final three = dedupItems(notes: [_note('n1', 'same'), _note('n2', 'same'), _note('n3', 'same')]);
      final dismissed = [_find(two).single.key];

      expect(withoutDismissed(_find(two), dismissed), isEmpty);
      expect(withoutDismissed(_find(three), dismissed), hasLength(1));
      expect(_find(two).single.key, dismissalKey(['n2', 'n1']), reason: 'the order of the ids does not matter');
    });

    test('ignore an entry that is not a key', () {
      final two = dedupItems(notes: [_note('n1', 'same'), _note('n2', 'same')]);

      expect(withoutDismissed(_find(two), [1, null, {}]), hasLength(1));
    });
  });
}
