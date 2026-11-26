@TestOn('vm')
library;

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/item_link.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/vault/item_links.dart';
import 'package:test/test.dart';

const _login = 'aaaaaaaa-0000-4000-8000-000000000001';
const _code = 'aaaaaaaa-0000-4000-8000-000000000002';
const _note = 'aaaaaaaa-0000-4000-8000-000000000003';
const _card = 'aaaaaaaa-0000-4000-8000-000000000004';
const _gone = 'aaaaaaaa-0000-4000-8000-0000000000ff';
const _account = '11111111-2222-4333-8444-555555555555';

final _owner = Owner.user(_account);

const _l = Login(id: _login, name: 'Mail', addedAt: 1);
const _o = OtpAccount(id: _code, issuer: 'Mail', label: 'me', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);
const _n = SecureNote(id: _note, title: 'Note', addedAt: 1);
const _c = PaymentCard(id: _card, name: 'Card', addedAt: 1);

void main() {
  group('linkIdOf', () {
    test('is the id of an entry whose id is a UUID', () {
      expect(linkIdOf(_l), _login);
      expect(linkIdOf(_l, account: _owner), _login);
    });

    test('is the legacy-id UUID for the account of an entry whose id is not one', () {
      const legacy = Login(id: 'acc-1', name: 'Old', addedAt: 1);
      expect(linkIdOf(legacy, account: _owner), itemUuid('acc-1', _owner));
      expect(isLinkId(linkIdOf(legacy, account: _owner)), isTrue);
    });

    test('is the legacy-id UUID for the space of an entry in a space', () {
      const legacy = Login(id: 'acc-1', name: 'Old', spaceId: 'family', addedAt: 1);
      expect(linkIdOf(legacy, account: _owner), itemUuid('acc-1', Owner.space(spaceUuid('family'))));
      expect(linkIdOf(legacy), itemUuid('acc-1', Owner.space(spaceUuid('family'))));
    });

    test('is the entry id itself, which is no link id, for a legacy id with no owner', () {
      const legacy = Login(id: 'acc-1', name: 'Old', addedAt: 1);
      expect(linkIdOf(legacy), 'acc-1');
      expect(isLinkId(linkIdOf(legacy)), isFalse);
    });
  });

  group('linkEntries', () {
    test('writes both ends, sorted and stamped', () {
      final linked = linkEntries(_l, _n, now: 50);
      expect(linked.a.links.map((link) => link.id), [_note]);
      expect(linked.b.links.map((link) => link.id), [_login]);
      expect((linked.a.changedAt, linked.b.changedAt), (50, 50));
    });

    test('links nothing twice', () {
      final once = linkEntries(_l, _n, now: 50);
      final twice = linkEntries(once.a, once.b, now: 99);
      expect(identical(twice.a, once.a), isTrue);
      expect(identical(twice.b, once.b), isTrue);
    });

    test('adds to what an end already links to, in order of id', () {
      final first = linkEntries(_l, _n, now: 1);
      final second = linkEntries(first.a, _c, now: 2);
      expect(second.a.links.map((link) => link.id), [_note, _card]);
      expect(second.b.links.map((link) => link.id), [_login]);
    });

    test('leaves an item alone with itself, and an entry that has no item id yet', () {
      expect(identical(linkEntries(_l, _l, now: 5).a, _l), isTrue);
      const legacy = Login(id: 'acc-1', name: 'Old', addedAt: 1);
      final unchanged = linkEntries(legacy, _n, now: 5);
      expect(identical(unchanged.a, legacy), isTrue);
      expect(identical(unchanged.b, _n), isTrue);
      // with the account it can be linked, by its legacy-id UUID
      final linked = linkEntries(legacy, _n, now: 5, account: _owner);
      expect(linked.a.links.single.id, itemUuid('acc-1', _owner));
    });

    test('leaves a code and its login that are tied by linkedLoginId or accountId', () {
      const code = OtpAccount(id: _code, issuer: 'X', label: 'me', secret: 'S', linkedLoginId: _login, addedAt: 1);
      expect(identical(linkEntries(_l, code, now: 5).b, code), isTrue);
      final holder = _l.copyWith(accountId: _code);
      expect(identical(linkEntries(holder, _o, now: 5).a, holder), isTrue);
    });
  });

  group('unlinkEntries', () {
    test('removes both ends, and leaves the other links', () {
      final both = linkEntries(_l, _n, now: 1);
      final withCard = linkEntries(both.a, _c, now: 2);
      final unlinked = unlinkEntries(withCard.a, both.b, now: 9);
      expect(unlinked.a.links.map((link) => link.id), [_card]);
      expect(unlinked.b.links, isEmpty);
      expect((unlinked.a.changedAt, unlinked.b.changedAt), (9, 9));
    });

    test('removes the end that is left when only one names the other', () {
      final one = _l.withLinks([const ItemLink(_note)]);
      final unlinked = unlinkEntries(one, _n, now: 9);
      expect(unlinked.a.links, isEmpty);
      expect(identical(unlinked.b, _n), isTrue);
    });

    test('clears the linkedLoginId of a code, from either side', () {
      const code = OtpAccount(id: _code, issuer: 'X', label: 'me', secret: 'S', linkedLoginId: _login, addedAt: 1);
      for (final (a, b) in <(VaultEntry<dynamic>, VaultEntry<dynamic>)>[(code, _l), (_l, code)]) {
        final unlinked = unlinkEntries(a, b, now: 9);
        final cleared = (unlinked.a is OtpAccount ? unlinked.a : unlinked.b) as OtpAccount;
        expect(cleared.linkedLoginId, isNull);
        expect(cleared.changedAt, 9);
      }
    });

    test('clears the accountId of a login that holds the code', () {
      final holder = _l.copyWith(accountId: _code);
      final unlinked = unlinkEntries(holder, _o, now: 9);
      expect((unlinked.a as Login).accountId, isNull);
      expect(unlinked.a.changedAt, 9);
      expect(identical(unlinked.b, _o), isTrue);
    });

    test('leaves entries that were not linked as they are', () {
      final unlinked = unlinkEntries(_l, _n, now: 9);
      expect(identical(unlinked.a, _l), isTrue);
      expect(identical(unlinked.b, _n), isTrue);
    });
  });

  group('linkedItemsOf', () {
    test('finds the items of its links, and the same from the other end', () {
      final both = linkEntries(_l, _n, now: 1);
      final lists = Lists(logins: [both.a as Login], notes: [both.b as SecureNote], cards: const [_c]);
      final fromLogin = linkedItemsOf(lists, both.a);
      expect(fromLogin.map((item) => item.id), [_note]);
      expect(fromLogin.single.entry, both.b);
      expect((fromLogin.single.oneWay, fromLogin.single.viaLinkedLogin), (false, false));
      final fromNote = linkedItemsOf(lists, both.b);
      expect(fromNote.single.entry, both.a);
    });

    test('keeps a link to an item the vault does not hold', () {
      final login = _l.withLinks([const ItemLink(_gone)]);
      final items = linkedItemsOf(Lists(logins: [login]), login);
      expect(items.single.id, _gone);
      expect(items.single.entry, isNull);
    });

    test('shows a link that only one end names, from both ends, as one way', () {
      final login = _l.withLinks([const ItemLink(_note)]);
      final lists = Lists(logins: [login], notes: const [_n]);
      final forward = linkedItemsOf(lists, login).single;
      expect((forward.entry, forward.oneWay), (_n, true));
      final reverse = linkedItemsOf(lists, _n).single;
      expect((reverse.id, reverse.entry, reverse.oneWay), (_login, login, true));
    });

    test('reads linkedLoginId on both items, and accountId on both', () {
      const code = OtpAccount(id: _code, issuer: 'X', label: 'me', secret: 'S', linkedLoginId: _login, addedAt: 1);
      final lists = Lists(logins: const [_l], accounts: const [code]);
      final fromCode = linkedItemsOf(lists, code).single;
      expect((fromCode.id, fromCode.entry, fromCode.viaLinkedLogin, fromCode.oneWay), (_login, _l, true, false));
      final fromLogin = linkedItemsOf(lists, _l).single;
      expect((fromLogin.id, fromLogin.entry, fromLogin.viaLinkedLogin), (_code, code, true));

      final holder = _l.copyWith(accountId: _code);
      final byAccount = Lists(logins: [holder], accounts: const [_o]);
      expect(linkedItemsOf(byAccount, holder).single.entry, _o);
      expect(linkedItemsOf(byAccount, _o).single.entry, holder);
      expect(linkedItemsOf(byAccount, _o).single.viaLinkedLogin, isTrue);
    });

    test('shows an item once when links and the older tie both name it', () {
      const code = OtpAccount(id: _code, issuer: 'X', label: 'me', secret: 'S', linkedLoginId: _login, addedAt: 1);
      final both = code.withLinks([const ItemLink(_login)]);
      final login = _l.withLinks([const ItemLink(_code)]);
      final items = linkedItemsOf(Lists(logins: [login], accounts: [both]), login);
      expect(items, hasLength(1));
      expect(items.single.viaLinkedLogin, isTrue);
    });

    test('finds a legacy-id entry by the id its link holds, for the account', () {
      const legacy = Login(id: 'acc-1', name: 'Old', addedAt: 1);
      final linked = linkEntries(legacy, _n, now: 1, account: _owner);
      final lists = Lists(logins: [linked.a as Login], notes: [linked.b as SecureNote]);
      expect(linkedItemsOf(lists, linked.a, account: _owner).single.entry, linked.b);
      final back = linkedItemsOf(lists, linked.b, account: _owner).single;
      expect((back.id, back.entry), (itemUuid('acc-1', _owner), linked.a));
    });
  });

  group('mendedLinks', () {
    test('writes the end that is missing, stamped, and nothing else', () {
      final login = _l.withLinks([const ItemLink(_note)]);
      final mended = mendedLinks(Lists(logins: [login], notes: const [_n]), now: 70);
      expect(mended, hasLength(1));
      expect(mended.single.id, _note);
      expect(mended.single.links.map((link) => link.id), [_login]);
      expect(mended.single.changedAt, 70);
    });

    test('has nothing to mend for a link both name, a link to nothing, or a tie of a code and its login', () {
      final both = linkEntries(_l, _n, now: 1);
      expect(mendedLinks(Lists(logins: [both.a as Login], notes: [both.b as SecureNote]), now: 5), isEmpty);
      expect(
        mendedLinks(
          Lists(
            logins: [
              _l.withLinks([const ItemLink(_gone)]),
            ],
          ),
          now: 5,
        ),
        isEmpty,
      );
      const code = OtpAccount(id: _code, issuer: 'X', label: 'me', secret: 'S', linkedLoginId: _login, addedAt: 1);
      expect(
        mendedLinks(
          Lists(
            logins: [
              _l.withLinks([const ItemLink(_code)]),
            ],
            accounts: const [code],
          ),
          now: 5,
        ),
        isEmpty,
      );
    });
  });
}
