@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/crypto/keys/keys.dart' show unionPublicKeys;
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

import '../contacts/contacts_kit.dart';
import '../keys/pgp_kit.dart';

const now = 1_800_000_000_000;

VaultKey _key(String id, {String name = 'laptop', int? updatedAt, String? spaceId}) => VaultKey(
  id: id,
  name: name,
  kind: KeyKind.ssh,
  algorithm: 'ed25519',
  privateKey: 'PRIV$id',
  publicKey: 'PUB$id',
  origin: KeyOrigin.generated,
  addedAt: 100,
  updatedAt: updatedAt,
  spaceId: spaceId,
);

SecureNote _note(String id, {String name = 'Passport', int? updatedAt, String? spaceId}) =>
    SecureNote(id: id, title: name, addedAt: 100, updatedAt: updatedAt, spaceId: spaceId);

KeyAccount _onKey(String id, {String name = 'work', int? updatedAt}) => KeyAccount(
  id: id,
  device: '0102030405060708',
  keyName: 'YubiKey',
  name: 'Bank:$id',
  issuer: 'Bank',
  label: id,
  tags: [name],
  addedAt: 100,
  updatedAt: updatedAt,
);

Passkey _passkey(String id, {String name = 'Work', int? updatedAt}) => Passkey(
  id: id,
  credentialId: 'cred-$id',
  rpId: 'example.com',
  userHandle: 'aGFuZGxl',
  userName: 'me',
  privateKey: 'KEY$id',
  label: name,
  addedAt: 100,
  updatedAt: updatedAt,
);

/// A different key for each id, so no two of the contacts these tests make are the same key under two ids.
final _keyOfId = <String, String>{};
const _otherKeys = [alan, signOnly, rsa3072, graceOther, v6, expired, revoked];

Contact _contact(String id, {String name = 'Alan Turing', int? updatedAt, String? key, int? checkedAt}) => contactOf(
  key ?? _keyOfId.putIfAbsent(id, () => _otherKeys[_keyOfId.length % _otherKeys.length]),
  id: id,
  name: name,
  addedAt: 100,
  updatedAt: updatedAt,
  checkedAt: checkedAt,
);

/// The ways each kind sits in [Lists] and [SyncDoc], so one set of tests covers all of them.
typedef _Kind = ({
  String name,
  VaultEntry<Object?> Function(String id, {String name, int? updatedAt}) make,
  Lists Function(List<VaultEntry<Object?>> items) lists,
  List<VaultEntry<Object?>> Function(Lists lists) read,
  String Function(VaultEntry<Object?> item) nameOf,
});

final List<_Kind> _kinds = [
  (
    name: 'keys',
    make: (id, {name = 'laptop', updatedAt}) => _key(id, name: name, updatedAt: updatedAt),
    lists: (items) => Lists(keys: items.cast()),
    read: (lists) => lists.keys,
    nameOf: (item) => (item as VaultKey).name,
  ),
  (
    name: 'notes',
    make: (id, {name = 'laptop', updatedAt}) => _note(id, name: name, updatedAt: updatedAt),
    lists: (items) => Lists(notes: items.cast()),
    read: (lists) => lists.notes,
    nameOf: (item) => (item as SecureNote).title,
  ),
  (
    name: 'passkeys',
    make: (id, {name = 'laptop', updatedAt}) => _passkey(id, name: name, updatedAt: updatedAt),
    lists: (items) => Lists(passkeys: items.cast()),
    read: (lists) => lists.passkeys,
    nameOf: (item) => (item as Passkey).label!,
  ),
  (
    name: 'accounts on a security key',
    make: (id, {name = 'work', updatedAt}) => _onKey(id, name: name, updatedAt: updatedAt),
    lists: (items) => Lists(keyAccounts: items.cast()),
    read: (lists) => lists.keyAccounts,
    // Their tags, which two phones must agree on.
    nameOf: (item) => (item as KeyAccount).tags!.single,
  ),
  (
    name: 'contacts',
    make: (id, {name = 'laptop', updatedAt}) => _contact(id, name: name, updatedAt: updatedAt),
    lists: (items) => Lists(contacts: items.cast()),
    read: (lists) => lists.contacts,
    nameOf: (item) => (item as Contact).name,
  ),
];

SyncDoc _doc(Lists lists, [List<Tombstone> deleted = const []]) => SyncDoc(
  keys: lists.keys,
  notes: lists.notes,
  passkeys: lists.passkeys,
  keyAccounts: lists.keyAccounts,
  contacts: lists.contacts,
  deleted: deleted,
);

void main() {
  for (final kind in _kinds) {
    group('merging ${kind.name}', () {
      test('brings down what another phone added, and uploads what this one did', () {
        final merged = mergeScope(kind.lists([kind.make('mine')]), [], _doc(kind.lists([kind.make('theirs')])), now: now);

        expect([for (final item in kind.read(merged.doc)) item.id], ['mine', 'theirs']);
        expect(merged.known..sort(), ['mine', 'theirs']);
      });

      test('keeps the most recently changed copy, from either side', () {
        final mine = kind.make('a', name: 'mine', updatedAt: 300);
        final theirs = kind.make('a', name: 'theirs', updatedAt: 200);
        expect(kind.nameOf(kind.read(mergeScope(kind.lists([mine]), ['a'], _doc(kind.lists([theirs])), now: now).doc).single), 'mine');

        final older = kind.make('a', name: 'mine', updatedAt: 150);
        expect(kind.nameOf(kind.read(mergeScope(kind.lists([older]), ['a'], _doc(kind.lists([theirs])), now: now).doc).single), 'theirs');
      });

      test('records a deletion made here, so other phones drop it', () {
        final merged = mergeScope(kind.lists([]), ['gone'], _doc(kind.lists([kind.make('gone')])), now: now);

        expect(kind.read(merged.doc), isEmpty);
        expect(merged.doc.deleted.single.id, 'gone');
      });

      test("takes another phone's deletion", () {
        final merged = mergeScope(
          kind.lists([kind.make('gone')]),
          ['gone'],
          _doc(kind.lists([]), [const Tombstone(id: 'gone', at: now - 10)]),
          now: now,
        );

        expect(kind.read(merged.doc), isEmpty);
        expect(merged.known, isEmpty);
      });

      test('an Undo after the deletion synced outlives the tombstone, on every phone', () {
        final restored = kind.make('back', updatedAt: now - 5);
        final merged = mergeScope(
          kind.lists([restored]),
          [],
          _doc(kind.lists([]), [const Tombstone(id: 'back', at: now - 10)]),
          now: now,
        );

        expect([for (final item in kind.read(merged.doc)) item.id], ['back']);
        expect(merged.doc.deleted, isEmpty);
        // The other phone, which deleted it, takes it back
        final other = mergeScope(kind.lists([]), [], merged.doc, now: now);
        expect([for (final item in kind.read(other.doc)) item.id], ['back']);
      });

      test('compares documents by their items too', () {
        expect(sameDoc(_doc(kind.lists([kind.make('a')])), _doc(kind.lists([kind.make('a')]))), isTrue);
        expect(sameDoc(_doc(kind.lists([kind.make('a')])), _doc(kind.lists([kind.make('a', name: 'other')]))), isFalse);
      });
    });
  }

  group('PGP keys', () {
    late VaultKey key;
    final changedAt = DateTime.utc(2026, 11, 20, 12);

    /// [key] as a phone that made [change] at [updatedAt] holds it.
    Future<VaultKey> changed(crypto.PgpChange change, int updatedAt, {VaultKey? from}) async {
      final made = await crypto.makeKey(crypto.PgpChangeRequest(unb64((from ?? key).privateKey), change, now: changedAt));
      return (from ?? key)
          .withHalves(privateKey: b64(made.private), publicKey: b64(made.public!), protected: false)
          .copyWith(updatedAt: updatedAt);
    }

    /// One sync of [local] against [remote], as the sync code runs it.
    Future<({SyncDoc doc, List<String> known})> sync(VaultKey local, VaultKey? remote) async {
      final doc = remote == null ? null : _doc(Lists(keys: [remote]));
      return mergeScope(await combineKeyCopies(Lists(keys: [local]), doc), [local.id], doc, now: now);
    }

    setUpAll(() async => key = await pgpVaultKey(updatedAt: 100));

    test('a subkey added on one phone and a user ID on the other: both, on both phones', () async {
      final withSubkey = await changed(const crypto.AddPgpSubkey(type: crypto.PgpKeyType.ed25519, use: crypto.PgpSubkeyUse.encrypt), 300);
      final withUserId = await changed(const crypto.AddPgpUserId(name: 'Ada', email: 'ada@work.example'), 200);

      final first = await sync(withSubkey, withUserId);
      final merged = first.doc.keys.single;
      final info = crypto.readPgpKeyInfo(unb64(merged.publicKey!));
      expect(info.userIds, hasLength(2));
      expect(info.subkeys, hasLength(3));
      expect(merged.updatedAt, 301, reason: 'a millisecond after the later copy');
      expect((merged.id, merged.name, merged.addedAt), (key.id, key.name, key.addedAt));

      // The other phone gets the same, and its second sync changes nothing
      final other = await sync(withUserId, merged);
      expect(other.doc.keys.single, merged);
      expect(sameDoc(other.doc, first.doc), isTrue);
      final again = await sync(merged, merged);
      expect(again.doc.keys.single, merged);
      expect(sameDoc(again.doc, first.doc), isTrue);

      // The same pair the other way round makes the same entry, stamp and all
      final mirrored = await sync(withUserId, withSubkey);
      expect(mirrored.doc.keys.single, merged);
    });

    test('a revocation on one phone survives an extension on the other', () async {
      final revoked = await changed(const crypto.RevokePgpKey(reason: crypto.PgpRevocationReason.compromised), 200);
      final extended = await changed(crypto.SetPgpExpiry(DateTime.utc(2032), alsoSubkeys: true), 300);

      for (final (local, remote) in [(revoked, extended), (extended, revoked)]) {
        final merged = (await sync(local, remote)).doc.keys.single;
        final info = crypto.readPgpKeyInfo(unb64(merged.privateKey));
        expect(info.primary.revoked, isTrue);
        expect(info.primary.expires, DateTime.utc(2032));
      }
    });

    test('a copy that holds nothing new, or that does not read, changes nothing', () async {
      final extended = await changed(crypto.SetPgpExpiry(DateTime.utc(2032), alsoSubkeys: true), 300);
      expect((await sync(extended, key)).doc.keys.single, extended);
      expect((await sync(key.copyWith(updatedAt: 50), extended)).doc.keys.single, extended);
      final broken = VaultKey.fromJson({...extended.toJson(), 'private': 'AAAA', 'updatedAt': 400});
      final kept = (await sync(broken, key)).doc.keys.single;
      expect((kept.privateKey, kept.updatedAt), (key.privateKey, 401), reason: 'the copy that reads, as the later');
    });

    test('keys of other kinds, and copies of two different keys under one id, merge as before', () async {
      final mine = _key('a', updatedAt: 300);
      final theirs = VaultKey.fromJson({..._key('a', updatedAt: 200).toJson(), 'private': 'OTHER', 'public': 'OTHER'});
      expect((await sync(mine, theirs)).doc.keys.single, mine);

      final other = await pgpVaultKey(path: 'gnupg/editing/protected.secret.asc', id: key.id, updatedAt: 200);
      final later = await changed(crypto.SetPgpExpiry(DateTime.utc(2032), alsoSubkeys: true), 300);
      expect((await sync(later, other)).doc.keys.single, later);
      expect((await sync(other.copyWith(updatedAt: 400), later)).doc.keys.single, other.copyWith(updatedAt: 400));
    });

    // Joined with add-pgp-contacts and add-security-key-codes: their lists ride beside the keys
    test('a key combined in a scope with contacts and accounts on a key leaves every other list as it was', () async {
      final withSubkey = await changed(const crypto.AddPgpSubkey(type: crypto.PgpKeyType.ed25519, use: crypto.PgpSubkeyUse.encrypt), 300);
      final withUserId = await changed(const crypto.AddPgpUserId(name: 'Ada', email: 'ada@work.example'), 200);
      final others = Lists(notes: [_note('n1')], passkeys: [_passkey('p1')], keyAccounts: [_onKey('ka1')], contacts: [_contact('c1')]);
      final local = Lists(
        keys: [withSubkey],
        notes: others.notes,
        passkeys: others.passkeys,
        keyAccounts: others.keyAccounts,
        contacts: others.contacts,
      );
      final remote = _doc(
        Lists(
          keys: [withUserId],
          notes: others.notes,
          passkeys: others.passkeys,
          keyAccounts: others.keyAccounts,
          contacts: others.contacts,
        ),
      );

      final combined = await combineKeyCopies(local, remote);
      expect(combined.keys.single.updatedAt, 301);
      expect(
        (combined.notes, combined.passkeys, combined.keyAccounts, combined.contacts),
        (others.notes, others.passkeys, others.keyAccounts, others.contacts),
      );

      final merged = mergeScope(combined, remote.ids.toList(), remote, now: now);
      expect(merged.doc.deleted, isEmpty, reason: 'nothing this phone holds reads as deleted here');
      expect(merged.doc.keyAccounts, others.keyAccounts);
      expect(merged.doc.contacts, others.contacts);
    });

    test('in one run a PGP key is combined by mergePgpKeys alone, and a contact by unionPublicKeys alone', () async {
      final withSubkey = await changed(const crypto.AddPgpSubkey(type: crypto.PgpKeyType.ed25519, use: crypto.PgpSubkeyUse.encrypt), 300);
      final withUserId = await changed(const crypto.AddPgpUserId(name: 'Ada', email: 'ada@work.example'), 200);
      final mine = _contact('c1', key: grace1, updatedAt: 300);
      final theirs = _contact('c1', key: grace2, updatedAt: 200);
      final remote = _doc(Lists(keys: [withUserId], contacts: [theirs]));

      final combined = await combineKeyCopies(Lists(keys: [withSubkey], contacts: [mine]), remote);
      expect(combined.contacts.single, same(mine), reason: 'a contact is not combined before the merge');
      final merged = mergeScope(combined, const [], remote, now: now).doc;

      final union = await crypto.mergePgpKeys(unb64(withSubkey.privateKey), unb64(withUserId.privateKey), preferA: true);
      expect(merged.keys.single, combined.keys.single, reason: 'the merge keeps the combined key whole');
      expect(merged.keys.single.privateKey, b64(union));
      expect(merged.contacts.single.publicKey, b64(unionPublicKeys(keyBytes(grace1), keyBytes(grace2))));
    });
  });

  test('a note that keeps a security key’s management key keeps it through a merge and the synced file', () {
    const piv = NotePivKey(key: '12345678', algorithm: '3des', managementKey: 'a1b2c3d4');
    final mine = _note('k', name: 'Management key', updatedAt: 300).copyWith(piv: piv);
    final theirs = _note('k', name: 'Management key, edited', updatedAt: 400).copyWith(piv: piv);
    final merged = mergeScope(
      Lists(notes: [mine]),
      ['k'],
      _doc(Lists(notes: [theirs])),
      now: now,
    );

    final synced = SyncDoc.fromJson(merged.doc.toJson());
    expect(synced.notes.single.title, 'Management key, edited');
    expect(synced.notes.single.piv, piv);
  });

  group('scopes', () {
    test('keys and notes go to their space, passkeys stay with the vault', () {
      final all = Lists(
        keys: [
          _key('k1'),
          _key('k2', spaceId: 'family'),
        ],
        notes: [
          _note('n1', spaceId: 'family'),
          _note('n2'),
        ],
        passkeys: [_passkey('p1')],
      );

      final family = scopeLists(all, 'family');
      final own = scopeLists(all, null);

      expect((family.keys.single.id, family.notes.single.id), ('k2', 'n1'));
      expect(family.passkeys, isEmpty);
      expect((own.keys.single.id, own.notes.single.id, own.passkeys.single.id), ('k1', 'n2', 'p1'));
    });

    test("a space's document puts its keys and notes in the space, and never brings passkeys", () {
      final all = Lists(keys: [_key('k1')], passkeys: [_passkey('p1')]);
      final spaceDoc = Lists(keys: [_key('k9')], notes: [_note('n9')], passkeys: [_passkey('p9')]);

      final next = applyScope(all, 'family', spaceDoc);

      expect({for (final key in next.keys) key.id: key.spaceId}, {'k1': null, 'k9': 'family'});
      expect(next.notes.single.spaceId, 'family');
      expect([for (final passkey in next.passkeys) passkey.id], ['p1']);
    });

    // openspec: add-security-key-codes, task 8.4
    test('accounts on a security key stay with the vault, and a space’s document never brings them', () {
      final all = Lists(keys: [_key('k1')], keyAccounts: [_onKey('o1')]);

      expect(scopeLists(all, 'family').keyAccounts, isEmpty);
      expect(scopeLists(all, null).keyAccounts.single.id, 'o1');
      expect(scopeLists(all, 'family').toJson().containsKey('keyAccounts'), isFalse);
      final next = applyScope(all, 'family', Lists(keyAccounts: [_onKey('o9')]));
      expect([for (final account in next.keyAccounts) account.id], ['o1']);
      expect(
        [
          for (final account in applyScope(all, null, Lists(keyAccounts: [_onKey('o9')])).keyAccounts) account.id,
        ],
        ['o9'],
      );
    });

    test('a document without accounts on a key is written as before, with no list for them', () {
      final merged = mergeScope(Lists(keys: [_key('k1')]), const [], null, now: now);

      expect(merged.doc.toJson().keys, ['accounts', 'backupServices', 'keys', 'deleted']);
    });

    test("the vault's own document places its items as it does accounts", () {
      final all = Lists(
        notes: [
          _note('n1'),
          _note('n2', spaceId: 'family'),
        ],
        passkeys: [_passkey('p1')],
      );

      final next = applyScope(
        all,
        null,
        Lists(
          notes: [_note('n1', name: 'changed')],
          passkeys: [_passkey('p2')],
        ),
      );

      expect([for (final note in next.notes) (note.id, note.title)], [('n1', 'changed'), ('n2', 'Passport')]);
      expect([for (final passkey in next.passkeys) passkey.id], ['p2']);
    });
  });

  // openspec: add-pgp-contacts, task 7.1
  group("other people's keys", () {
    bool revokedKey(Contact contact) => readTransferableKey(unb64(contact.publicKey)).info.primary.revoked;
    int subkeys(Contact contact) => readTransferableKey(unb64(contact.publicKey)).info.subkeys.length;

    test('a deletion wins over an older copy, and loses to a later change', () {
      final older = _doc(Lists(contacts: [_contact('c1', updatedAt: now - 500)]), [const Tombstone(id: 'c1', at: now - 100)]);
      expect(
        mergeScope(
          Lists(contacts: [_contact('c1', updatedAt: now - 500)]),
          ['c1'],
          older,
          now: now,
        ).doc.contacts,
        isEmpty,
      );

      final later = mergeScope(
        Lists(
          contacts: [_contact('c1', name: 'renamed', updatedAt: now - 50)],
        ),
        ['c1'],
        older,
        now: now,
      );
      expect(later.doc.contacts.single.name, 'renamed');
      expect(later.doc.deleted, isEmpty);
    });

    test('two copies of one id holding different ages of the same key merge to the union, the later fields winning', () {
      final here = _contact('c1', key: grace1, name: 'Grace (renamed here)', updatedAt: now - 10, checkedAt: 77);
      final there = _contact('c1', key: grace2, name: 'Grace', updatedAt: now - 500);

      final merged = mergeScope(
        Lists(contacts: [here]),
        ['c1'],
        _doc(Lists(contacts: [there])),
        now: now,
      ).doc.contacts.single;

      expect((merged.name, merged.checkedAt, merged.updatedAt), ('Grace (renamed here)', 77, now - 10));
      expect(merged.publicKey, b64(unionPublicKeys(keyBytes(grace1), keyBytes(grace2))));
      expect(subkeys(merged), 2);
      // The other phone, which holds the other copy, ends with the very same contact
      final other = mergeScope(
        Lists(contacts: [there]),
        ['c1'],
        _doc(Lists(contacts: [here])),
        now: now,
      ).doc.contacts.single;
      expect(other, merged);
    });

    test('a revocation one phone learned of survives a later edit made on another', () {
      final revokedThere = _contact('c1', key: grace3, updatedAt: now - 500);
      final renamedHere = _contact('c1', key: grace1, name: 'Grace', updatedAt: now - 10);

      final merged = mergeScope(
        Lists(contacts: [renamedHere]),
        ['c1'],
        _doc(Lists(contacts: [revokedThere])),
        now: now,
      ).doc.contacts.single;

      expect(merged.name, 'Grace');
      expect(revokedKey(merged), isTrue);
    });

    test('a copy holding nothing more leaves the contact byte for byte as it was', () {
      final all = contactOf(
        grace1,
        id: 'c1',
        addedAt: 100,
        updatedAt: now - 10,
      ).copyWith(publicKey: b64(unionPublicKeys(keyBytes(grace1), keyBytes(grace2))));
      final old = _contact('c1', key: grace1, updatedAt: now - 500);

      final result = mergeScope(
        Lists(contacts: [all]),
        ['c1'],
        _doc(Lists(contacts: [old])),
        now: now,
      );

      expect(result.doc.contacts.single, all);
    });

    test('two different keys under one id: the later change wins whole', () {
      final here = _contact('c1', key: grace1, updatedAt: now - 10);
      final there = _contact('c1', key: graceOther, updatedAt: now - 5);

      final merged = mergeScope(
        Lists(contacts: [here]),
        ['c1'],
        _doc(Lists(contacts: [there])),
        now: now,
      ).doc.contacts.single;

      expect(merged, there);
    });

    test('the same key under two ids becomes one, the checked one, with a tombstone for the other', () {
      final unchecked = _contact('a-here', key: grace2, name: 'Grace H.', updatedAt: now - 5);
      final checked = _contact('b-there', key: grace1, name: 'Grace Hopper', updatedAt: now - 500, checkedAt: 77);

      final result = mergeScope(
        Lists(contacts: [unchecked]),
        [],
        _doc(Lists(contacts: [checked])),
        now: now,
      );

      final kept = result.doc.contacts.single;
      expect((kept.id, kept.name, kept.checkedAt, kept.checkedFingerprint), ('b-there', 'Grace Hopper', 77, graceFingerprint));
      // Nothing the other copy's key held is lost
      expect(subkeys(kept), 2);
      expect(result.doc.deleted, [const Tombstone(id: 'a-here', at: now)]);
      expect(result.known, ['b-there']);
      // The other phone comes to the same contact and the same deletion
      final other = mergeScope(
        Lists(contacts: [checked]),
        [],
        _doc(Lists(contacts: [unchecked])),
        now: now,
      );
      expect(other.doc.contacts.single, kept);
      expect(other.doc.deleted, result.doc.deleted);
    });

    test('of two unchecked copies of one key the one changed last is kept', () {
      final first = _contact('a', key: alan, name: 'older', updatedAt: now - 500);
      final second = _contact('b', key: alan, name: 'newer', updatedAt: now - 5);

      final result = mergeScope(
        Lists(contacts: [first]),
        [],
        _doc(Lists(contacts: [second])),
        now: now,
      );

      expect(result.doc.contacts.single.name, 'newer');
      expect([for (final tomb in result.doc.deleted) tomb.id], ['a']);
    });

    test('a contact whose key cannot be read is kept as it is, and never taken for another', () {
      final broken = _contact('x1', key: alan).copyWith(publicKey: 'AAAA');
      final alsoBroken = _contact('x2', key: alan).copyWith(publicKey: 'AAAA');

      final result = mergeScope(
        Lists(contacts: [broken]),
        [],
        _doc(Lists(contacts: [alsoBroken])),
        now: now,
      );

      expect(result.doc.contacts, [broken, alsoBroken]);
      expect(result.doc.deleted, isEmpty);
    });

    test("stay with the vault: a space's lists and document never hold one", () {
      final all = Lists(
        contacts: [_contact('c1'), _contact('c2')],
        notes: [_note('n1', spaceId: 'family')],
      );

      expect(scopeLists(all, null).contacts.map((c) => c.id), ['c1', 'c2']);
      expect(scopeLists(all, 'family').contacts, isEmpty);
      expect(scopeLists(all, 'family').toJson().keys, isNot(contains('contacts')));
      expect(_contact('c1').inSpace('family').spaceId, isNull);
      // A space's document that names contacts, written by something else, brings none in and removes none
      final next = applyScope(
        all,
        'family',
        Lists(
          contacts: [_contact('c9')],
          notes: [_note('n1', spaceId: 'family')],
        ),
      );
      expect(next.contacts.map((c) => c.id), ['c1', 'c2']);
    });

    test("the vault's own document places its contacts, and a deletion there removes one here", () {
      final all = Lists(contacts: [_contact('c1'), _contact('c2')]);

      final next = applyScope(
        all,
        null,
        Lists(
          contacts: [
            _contact('c1', name: 'renamed'),
            _contact('c3'),
          ],
        ),
      );

      expect([for (final contact in next.contacts) (contact.id, contact.name)], [('c1', 'renamed'), ('c3', 'Alan Turing')]);
    });

    test('a document without contacts is written without the contacts key, and one with them reads back', () {
      expect(SyncDoc(notes: [_note('n1')]).toJson().keys, ['accounts', 'backupServices', 'notes', 'deleted']);
      expect(mergeScope(Lists(notes: [_note('n1')]), [], null, now: now).doc.toJson().keys, isNot(contains('contacts')));

      final doc = SyncDoc(
        contacts: [_contact('c1', checkedAt: 77)],
        deleted: const [Tombstone(id: 'gone', at: 5)],
      );
      final read = SyncDoc.fromJson(jsonDecode(jsonEncode(doc.toJson())) as Map<String, Object?>);

      expect(read.contacts, doc.contacts);
      expect(read.extra, isEmpty);
      expect(sameDoc(read, doc), isTrue);
      expect(sameDoc(read, SyncDoc(contacts: [_contact('c1')], deleted: doc.deleted)), isFalse);
    });
  });
}
