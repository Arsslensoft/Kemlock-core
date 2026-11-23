@TestOn('vm')
library;

// The Kemlock Server run (add-kemlock-server-sync, task 8.2): the cache and the
// delta, the merge, the checked batches and the 409 loop, a run that is cut
// short, and what the run leaves alone, against the fake server.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sync.dart';
import 'package:kemlock_core/features/sync/removal_guard.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'fake_km_crypto.dart';
import 'km_sync_kit.dart';

const _a = '3f2c9a71-e4b0-4856-8a00-0000000000a1';
const _b = '3f2c9a71-e4b0-4856-8a00-0000000000b2';
const _c = '3f2c9a71-e4b0-4856-8a00-0000000000c3';

({FakeKemlockServer server, KmClock clock}) _world() => (server: FakeKemlockServer()..checkTokens = false, clock: KmClock());

List<String> _routes(FakeKemlockServer server) => [for (final request in server.requests) '${request.method} ${request.url.path}'];

void main() {
  group('a first run', () {
    test('puts each entry up as one item of its kind at revision 1, and keeps the cache with the cursor', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)], logins: [login(_b)]),
      );

      final result = await phone.run();

      expect(w.server.items.keys, unorderedEquals([_a, _b]));
      expect(w.server.items[_a]!.kind, 'otp');
      expect(w.server.items[_b]!.kind, 'login');
      expect(w.server.items.values.map((item) => item.revision), [1, 1]);
      expect(w.server.items[_a]!.owner, 'user:${w.server.userId}');
      expect(result.known, unorderedEquals([_a, _b]));
      expect(phone.cache.cursor, isNotNull);
      expect(phone.cache.items[_a]!.entry?['issuer'], _a);
      expect(phone.stores, 1);
    });

    test('is taken by another phone of the account, whole', () async {
      final w = _world();
      final first = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(
          accounts: [acct(_a, secret: 'KRSXG5CTMVRXEZLU')],
          logins: [login(_b, password: 'hunter2')],
        ),
      );
      await first.run();

      final second = first.another();
      await second.run();

      expect(second.lists.accounts.single.secret, 'KRSXG5CTMVRXEZLU');
      expect(second.lists.logins.single.password, 'hunter2');
      expect(w.server.items.values.map((item) => item.revision), [1, 1], reason: 'taking writes nothing');
    });

    test('puts nothing on the server in the clear: no secret appears in what it holds', () async {
      final w = _world();
      await KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a, secret: 'JBSWY3DPEHPK3PXP')]),
      ).run();

      for (final item in w.server.items.values) {
        expect(utf8.decode(item.ciphertext!, allowMalformed: true), isNot(contains('JBSWY3DPEHPK3PXP')));
        expect(jsonEncode(item.toJson()), isNot(contains('JBSWY3DPEHPK3PXP')));
      }
    });
  });

  group('a run takes only what changed', () {
    test('sends the cursor back unread, and asks for nothing once it has seen everything', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      await phone.run();
      final cursor = phone.cache.cursor;
      w.server.requests.clear();
      w.server.events.clear();

      await phone.run();

      // The manifest is read every run, even when nothing changed: it is how the phone sees the server
      // withholding or rolling back an item (add-kemlock-server-sync, design 5)
      expect(_routes(w.server), ['GET /kem/v1/sync', 'GET /kem/v1/manifests/user:00000000-0000-4000-8000-000000000001']);
      expect(w.server.requests.first.url.queryParameters['since'], cursor);
      expect(w.server.events, ['sync'], reason: 'nothing written');
    });

    test('downloads only what another phone changed since', () async {
      final w = _world();
      final first = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );
      await first.run();
      final second = first.another();
      await second.run();
      await first.run();
      first.lists = Lists(
        accounts: [
          acct(_a, label: 'renamed', updatedAt: w.clock.ms + 1),
          acct(_b),
        ],
      );
      await first.run();
      w.server.requests.clear();

      await second.run();

      final answered = [for (final request in w.server.requests) request.url.path];
      // The manifest is read every run, to see the server withholding or rolling back an item (design 5)
      expect(answered, ['/kem/v1/sync', '/kem/v1/manifests/user:00000000-0000-4000-8000-000000000001']);
      expect(second.lists.accounts.firstWhere((account) => account.id == _a).label, 'renamed');
    });

    test('starts again without a cursor when the server no longer trusts it', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      w.server.staleBefore = w.server.seq + 1;
      w.server.requests.clear();

      await phone.run();

      // Only the sync calls: the manifest, read every run (design 5), carries no cursor
      final since = [
        for (final request in w.server.requests.where((r) => r.url.path.endsWith('/sync'))) request.url.queryParameters['since'],
      ];
      expect(since, hasLength(2), reason: 'refused, then read again');
      expect(since.first, isNotNull);
      expect(since.last, isNull);
      expect(phone.lists.accounts.single.id, _a);
    });

    test('reads every page of a long delta', () async {
      final w = _world();
      w.server.pageSize = 2;
      final first = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 5; i++) acct('3f2c9a71-e4b0-4856-8a00-00000000010$i')]),
      );
      await first.run();
      w.server.requests.clear();

      final second = first.another();
      await second.run();

      expect(second.lists.accounts, hasLength(5));
      expect(w.server.requests.where((r) => r.url.path.endsWith('/sync')), hasLength(3));
    });
  });

  group('entries merge on the phone as WebDAV sync merges them', () {
    test('two phones edit one login: both keep the later password, the other among the previous ones', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(logins: [login(_a, password: 'pw-0', updatedAt: 100)]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      one.lists = Lists(
        logins: [one.lists.logins.single.copyWith(password: 'pw-one', updatedAt: w.clock.ms + 10)],
      );
      two.lists = Lists(
        logins: [two.lists.logins.single.copyWith(password: 'pw-two', updatedAt: w.clock.ms + 20)],
      );

      await one.run();
      await two.run();
      await one.run();

      for (final phone in [one, two]) {
        expect(phone.lists.logins.single.password, 'pw-two');
        expect(phone.lists.logins.single.previousPasswords?.map((previous) => previous.password), contains('pw-one'));
      }
      expect(w.server.items[_a]!.revision, 3);
    });

    test('a deletion arrives as a tombstone and removes the entry on the other phone', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );
      await one.run();
      final two = one.another();
      await two.run();

      one.lists = Lists(accounts: [acct(_b)]);
      await one.run();
      await two.run();

      expect(w.server.items[_a]!.deleted, isTrue);
      expect(w.server.items[_a]!.revision, 2);
      expect(w.server.items[_a]!.ciphertext, isNull);
      expect(two.ids, [_b]);
    });

    test('an entry edited after a delete elsewhere stays, with the edit, and comes back to the phone that deleted it', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      one.lists = const Lists();
      await one.run();
      two.lists = Lists(
        accounts: [acct(_a, label: 'edited', updatedAt: w.clock.ms + 1)],
      );

      await two.run();
      await one.run();

      expect(two.lists.accounts.single.label, 'edited');
      expect(one.lists.accounts.single.label, 'edited');
      expect(w.server.items[_a]!.deleted, isFalse);
      expect(w.server.items[_a]!.revision, 3, reason: 'written over the tombstone');
    });

    test('an entry unchanged since the last sync is deleted by a tombstone seen later', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a, updatedAt: 5)]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      one.lists = const Lists();
      await one.run();
      w.clock.tick();

      await two.run();

      expect(two.ids, isEmpty);
    });
  });

  group('writes go up in checked batches', () {
    test('1,200 entries take three batches of at most 500, and a batch resent after a failure makes no second copy', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 1200; i++) acct('3f2c9a71-e4b0-4856-8a00-${i.toString().padLeft(12, '0')}')]),
      );
      var batches = 0;
      w.server.respond = (request) async {
        if (request.url.path.endsWith('/items:batch') && ++batches == 2) return http.Response('', 500);
        return w.server.handle(request);
      };

      await expectLater(phone.run(), throwsA(isA<KmError>()));
      expect(w.server.items, hasLength(500), reason: 'the first batch was stored, the second refused');
      expect(phone.stored, isNull, reason: 'a run that dies stores nothing');

      w.server.respond = null;
      w.server.events.clear();
      await phone.run();

      expect(w.server.items, hasLength(1200));
      expect(w.server.items.values.every((item) => item.revision == 1), isTrue, reason: 'no second copy of what already went up');
      expect(w.server.events.where((event) => event == 'batch'), hasLength(2), reason: '700 left: 500 and 200');
    });

    test('a write another phone beat is merged again and sent with the new revision', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      one.lists = Lists(
        accounts: [acct(_a, label: 'from one', updatedAt: w.clock.ms + 100000)],
      );
      two.lists = Lists(
        accounts: [acct(_a, label: 'from two', updatedAt: w.clock.ms + 10)],
      );
      var interrupted = false;
      w.server.respond = (request) async {
        if (!interrupted && request.url.path.endsWith('/items:batch')) {
          interrupted = true;
          w.server.respond = null;
          await two.run();
        }
        return w.server.handle(request);
      };

      await one.run();

      expect(w.server.staleBatches, 1);
      expect(w.server.items[_a]!.revision, 3, reason: 'two wrote revision 2, one then wrote 3');
      expect(one.lists.accounts.single.label, 'from one', reason: 'the later edit wins the merge');
      await two.run();
      expect(two.lists.accounts.single.label, 'from one');
    });

    test('gives up after three attempts when another phone keeps winning, and keeps the entries', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      phone.lists = Lists(
        accounts: [acct(_a, label: 'mine', updatedAt: w.clock.ms + 1)],
      );
      // The first run's own batch is not an attempt of the run that gives up
      w.server.requests.clear();
      w.server.respond = (request) async => request.url.path.endsWith('/items:batch')
          ? w.server.problem(409, 'stale-revision', extra: {'itemId': _a, 'currentRevision': 9})
          : w.server.handle(request);

      await expectLater(phone.run(), throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.stale)));

      expect(phone.lists.accounts.single.label, 'mine');
      expect(w.server.requests.where((r) => r.url.path.endsWith('/items:batch')), hasLength(3));
    });
  });

  group('a run cut short', () {
    test('killed after the delta and the writes, before the store: the next run repeats and makes nothing twice', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );
      phone.failStore = true;

      await expectLater(phone.run(), throwsA(isA<StateError>()));
      expect(phone.stored, isNull);
      expect(w.server.items, hasLength(2), reason: 'the writes went up');

      phone.failStore = false;
      w.server.events.clear();
      await phone.run();

      expect(w.server.items.values.map((item) => item.revision), [1, 1], reason: 'no entry written twice');
      expect(w.server.events, ['sync'], reason: 'the delta brought the phone’s own items back, and nothing differed');
      expect(phone.cache.cursor, isNotNull);
    });

    test('dropped midway through the delta: the next run reads again from the old cursor and loses nothing', () async {
      final w = _world();
      w.server.pageSize = 2;
      final first = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 5; i++) acct('3f2c9a71-e4b0-4856-8a00-00000000010$i')]),
      );
      await first.run();
      final second = first.another();
      var pages = 0;
      w.server.respond = (request) async =>
          request.url.path.endsWith('/sync') && ++pages == 2 ? http.Response('', 500) : w.server.handle(request);

      await expectLater(second.run(), throwsA(isA<KmError>()));
      expect(second.stored, isNull);
      w.server.respond = null;
      await second.run();

      expect(second.lists.accounts, hasLength(5));
    });
  });

  group('what the run leaves alone', () {
    test('an item of a kind this version does not know is never read, deleted or written', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      final sealed = await phone.crypto.sealItem(
        itemId: _c,
        revision: 1,
        kind: 'future-thing',
        plaintext: Uint8List.fromList(utf8.encode('{"id":"$_c","number":"4111"}')),
      );
      w.server.write(id: _c, kind: 'future-thing', revision: 1, ciphertext: sealed.ciphertext, itemKey: sealed.itemKey);
      final before = jsonEncode(w.server.items[_c]!.toJson());

      final result = await phone.run();
      phone.lists = const Lists();
      await phone.run();

      expect(result.skipped, 1);
      expect(phone.ids, isEmpty, reason: 'not in the vault');
      expect(w.server.items[_c]!.deleted, isFalse, reason: 'not deleted though the phone removed everything it holds');
      expect(jsonEncode(w.server.items[_c]!.toJson()), before, reason: 'not written');
      expect(phone.cache.items[_c]!.opaque, isTrue);
    });

    test('an item whose entry is not the one its id names is left alone', () async {
      final w = _world();
      final phone = KmPhone(w.server, clock: w.clock);
      final sealed = await phone.crypto.sealItem(
        itemId: _c,
        revision: 1,
        kind: 'login',
        plaintext: Uint8List.fromList(utf8.encode('{"id":"$_b","name":"spoof"}')),
      );
      w.server.write(id: _c, kind: 'login', revision: 1, ciphertext: sealed.ciphertext, itemKey: sealed.itemKey);

      await phone.run();

      expect(phone.ids, isEmpty);
      expect(phone.cache.items[_c]!.opaque, isTrue);
    });

    test('an item that does not open is left alone, and the run goes on', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      final stranger = KmPhone(w.server, clock: w.clock);
      final sealed = await stranger.crypto.sealItem(
        itemId: _c,
        revision: 1,
        kind: 'login',
        plaintext: Uint8List.fromList(utf8.encode('{"id":"$_c"}')),
      );
      w.server.write(id: _c, kind: 'login', revision: 1, ciphertext: sealed.ciphertext, itemKey: sealed.itemKey);

      final result = await phone.run();

      expect(result.skipped, 1);
      expect(phone.ids, [_a]);
    });

    test('an item with another owner or another format is left alone', () async {
      final w = _world();
      final phone = KmPhone(w.server, clock: w.clock);
      w.server.items[_c] = FakeItem(
        id: _c,
        owner: 'space:00000000-0000-4000-8000-0000000000ff',
        kind: 'login',
        revision: 1,
        keyVersion: 1,
        seq: 1,
        ciphertext: Uint8List(40),
        itemKey: Uint8List(60),
      );

      final result = await phone.run();

      expect(result.skipped, 1);
      expect(phone.ids, isEmpty);
    });
  });

  group('older ids keep working', () {
    test('an entry with an id like acc-1 syncs under its mapped UUID and comes back as acc-1', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct('acc-1', secret: 'KRSXG5CTMVRXEZLU')]),
      );
      await one.run();

      final uuid = itemUuid('acc-1', one.crypto.owner);
      expect(w.server.items.keys, [uuid]);
      expect(isUuidLike(uuid), isTrue);

      final two = one.another();
      await two.run();
      expect(two.lists.accounts.single.id, 'acc-1');
      expect(two.lists.accounts.single.secret, 'KRSXG5CTMVRXEZLU');
    });

    test('two phones from 0.1.0 both send acc-1 under the same UUID, and the merge pairs them', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct('acc-1', label: 'one', updatedAt: 10)]),
      );
      final two = KmPhone(
        w.server,
        clock: w.clock,
        crypto: one.crypto.alike(),
        lists: Lists(accounts: [acct('acc-1', label: 'two', updatedAt: 20)]),
      );

      await one.run();
      await two.run();
      await one.run();

      expect(w.server.items, hasLength(1));
      expect(one.lists.accounts.single.label, 'two');
      expect(two.lists.accounts.single.label, 'two');
    });

    test('a deletion of acc-1 reaches the other phone through the mapped UUID', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct('acc-1')]),
      );
      await one.run();
      final two = one.another();
      await two.run();

      one.lists = const Lists();
      await one.run();
      await two.run();

      expect(w.server.items.values.single.deleted, isTrue);
      expect(two.ids, isEmpty);
    });
  });

  group('the removal guard', () {
    test('a run that would remove many entries stops and asks, and goes on once the user chooses', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 8; i++) acct('3f2c9a71-e4b0-4856-8a00-00000000020$i')]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      two.lists = const Lists();

      await expectLater(
        two.run(),
        throwsA(isA<KmSyncError>().having((e) => e.issue, 'issue', KmSyncIssue.removals).having((e) => e.count, 'count', 8)),
      );
      expect(w.server.items.values.every((item) => !item.deleted), isTrue, reason: 'nothing was written');

      await two.run(choice: RemovalChoice.remove);
      expect(w.server.items.values.every((item) => item.deleted), isTrue);
    });

    test('Keep everything brings back what is missing on either side', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 8; i++) acct('3f2c9a71-e4b0-4856-8a00-00000000030$i')]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      two.lists = const Lists();

      await two.run(choice: RemovalChoice.keep);

      expect(two.lists.accounts, hasLength(8));
      expect(w.server.items.values.every((item) => !item.deleted), isTrue);
    });
  });

  group('siblings', () {
    /// A version of [entry] that reached the server apart from its head, sealed as the phone's account seals.
    Future<void> sibling(FakeKemlockServer server, KmPhone phone, Login entry, {int revision = 1, String kind = 'login'}) async {
      final sealed = await phone.crypto.sealItem(
        itemId: entry.id,
        revision: revision,
        kind: kind,
        plaintext: Uint8List.fromList(utf8.encode(jsonEncode(entry.toJson()))),
      );
      server.addSibling(id: entry.id, kind: kind, revision: revision, ciphertext: sealed.ciphertext, itemKey: sealed.itemKey);
    }

    Future<({FakeKemlockServer server, KmClock clock, KmPhone first})> head({String password = 'pw'}) async {
      final w = _world();
      final first = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(logins: [login(_b, password: password, updatedAt: 1000)]),
      );
      await first.run();
      return (server: w.server, clock: w.clock, first: first);
    }

    test('a newer sibling is merged into the head, written as the next revision, and resolved', () async {
      final w = await head();
      await sibling(w.server, w.first, login(_b, password: 'other', updatedAt: 2000));

      final second = w.first.another();
      await second.run();

      final merged = second.lists.logins.single;
      expect(merged.password, 'other', reason: 'the later version of the two wins, as it does between two phones');
      expect(merged.previousPasswords!.map((previous) => previous.password), contains('pw'), reason: 'and the losing password is kept');
      expect(w.server.items[_b]!.revision, 2, reason: 'written once more, after the head it replaces');
      expect(w.server.siblings.containsKey(_b), isFalse, reason: 'the server lists no set once it is resolved');
      expect(_routes(w.server), contains('POST /kem/v1/items/$_b/siblings/resolve'));
      expect(w.server.events.indexOf('resolve'), greaterThan(w.server.events.lastIndexOf('batch')), reason: 'after the write, not before');
      expect(second.cache.items[_b]!.revision, 2);
    });

    test('an older sibling adds nothing, and the head is still written again so the server can drop it', () async {
      final w = await head();
      await sibling(w.server, w.first, login(_b, password: 'older', updatedAt: 500));

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins.single.password, 'pw');
      expect(w.server.items[_b]!.revision, 2);
      expect(w.server.siblings.containsKey(_b), isFalse, reason: 'the server lists no set once it is resolved');
    });

    test('a head sent to another server cannot resolve yet: the run goes on, and the next merges again into a newer version', () async {
      final w = await head();
      await sibling(w.server, w.first, login(_b, password: 'other', updatedAt: 2000));
      w.server.headSent.add(_b);

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins.single.password, 'other', reason: 'the merge is kept');
      expect(w.server.items[_b]!.revision, 2);
      expect(w.server.siblings[_b], hasLength(1), reason: 'still held beside the head');

      w.server.headSent.clear();
      final third = w.first.another();
      await third.run();

      expect(w.server.items[_b]!.revision, 3, reason: 'a newer version than the one that was sent');
      expect(w.server.siblings.containsKey(_b), isFalse, reason: 'the server lists no set once it is resolved');
      expect(third.lists.logins.single.password, 'other');
    });

    test('a deleted sibling older than the head\'s last edit does not take the entry', () async {
      final w = await head();
      w.server.deletionTime = 500;
      final gone = w.server.addSibling(id: _b, kind: 'login', revision: 2);
      expect(gone.deleted, isTrue);

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins.single.id, _b, reason: 'an edit made after a deletion outlives it');
      expect(w.server.items[_b]!.deleted, isFalse);
      expect(w.server.items[_b]!.revision, 2);
      expect(w.server.siblings.containsKey(_b), isFalse, reason: 'the server lists no set once it is resolved');
    });

    test('a deleted sibling made after the head\'s last edit takes the entry, and the deletion is written and resolved', () async {
      final w = await head();
      w.server.deletionTime = w.clock.ms;
      w.server.addSibling(id: _b, kind: 'login', revision: 2);

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins, isEmpty);
      expect(w.server.items[_b]!.deleted, isTrue);
      expect(w.server.items[_b]!.revision, 2);
      expect(w.server.siblings.containsKey(_b), isFalse, reason: 'the server lists no set once it is resolved');
    });

    test('a set with a version of another kind is left alone', () async {
      final w = await head();
      await sibling(w.server, w.first, login(_b, password: 'other', updatedAt: 2000), kind: 'card');

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins.single.password, 'pw');
      expect(w.server.items[_b]!.revision, 1, reason: 'not written');
      expect(w.server.siblings[_b], hasLength(1));
      expect(w.server.events, isNot(contains('resolve')));
    });

    test('a set with a version that does not open is left alone', () async {
      final w = await head();
      // Another account's keys, whichever crypto the run's phones use: this version must not open
      final sealed = await FakeKmCrypto().sealItem(
        itemId: _b,
        revision: 1,
        kind: 'login',
        plaintext: Uint8List.fromList(utf8.encode(jsonEncode(login(_b, password: 'x').toJson()))),
      );
      w.server.addSibling(id: _b, kind: 'login', revision: 1, ciphertext: sealed.ciphertext, itemKey: sealed.itemKey);

      final second = w.first.another();
      await second.run();

      expect(second.lists.logins.single.password, 'pw');
      expect(w.server.items[_b]!.revision, 1, reason: 'not written');
      expect(w.server.siblings[_b], hasLength(1));
      expect(w.server.events, isNot(contains('resolve')));
    });

    test('an item with no sibling is not written again and nothing is resolved', () async {
      final w = await head();

      await w.first.another().run();

      expect(w.server.items[_b]!.revision, 1);
      expect(w.server.events, isNot(contains('resolve')));
    });
  });
}

bool isUuidLike(String text) => RegExp(r'^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$').hasMatch(text);
