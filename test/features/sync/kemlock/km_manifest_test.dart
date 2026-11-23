@TestOn('vm')
library;

// The manifest check of every Kemlock Server run (add-kemlock-server-sync, task
// 8.4): a rolled-back, missing or resurrected item and a manifest that fails
// stop the run before anything is stored; an item no manifest lists is held and
// applied once one does; a run that wrote sends exactly one manifest, after its
// last batch.
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'fake_km_crypto.dart';
import 'km_sync_kit.dart';

const _a = '3f2c9a71-e4b0-4856-8a00-0000000000a1';
const _b = '3f2c9a71-e4b0-4856-8a00-0000000000b2';
const _c = '3f2c9a71-e4b0-4856-8a00-0000000000c3';

({FakeKemlockServer server, KmClock clock}) _world() => (server: FakeKemlockServer()..checkTokens = false, clock: KmClock());

Manifest _published(FakeKemlockServer server) => Manifest.parse(b64urlDecode(server.manifest!['manifest']!));

/// A manifest as another device would sign it: of everything the server holds now, or what [include] keeps.
Future<void> _publish(FakeKemlockServer server, FakeKmCrypto crypto, {int? counter, bool Function(FakeItem item)? include}) async {
  final current = server.manifest == null ? 0 : _published(server).counter;
  final manifest = Manifest(
    owner: crypto.owner,
    counter: counter ?? current + 1,
    entries: [
      for (final item in server.items.values)
        if (include == null || include(item))
          ManifestEntry(
            itemId: uuidBytes(item.id),
            revision: item.revision,
            ciphertextHash: item.deleted ? Uint8List(32) : Uint8List.fromList(hash.sha256.convert(item.ciphertext!).bytes),
            deleted: item.deleted,
          ),
    ],
  );
  final signed = await crypto.signManifest(manifest);
  server.manifest = {'manifest': b64urlEncode(signed.bytes), 'signature': b64urlEncode(signed.signature)};
}

Matcher get _older => isA<KmSyncError>().having((e) => e.issue, 'issue', KmSyncIssue.older);

Future<(Uint8List, Uint8List)> _sealed(FakeKmCrypto crypto, String id, int revision, String kind, String json) async {
  final sealed = await crypto.sealItem(itemId: id, revision: revision, kind: kind, plaintext: Uint8List.fromList(utf8.encode(json)));
  return (sealed.ciphertext, sealed.itemKey);
}

void main() {
  group('the manifest a run signs', () {
    test('a run that wrote sends exactly one manifest, after its last batch, and one that wrote nothing sends none', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [for (var i = 0; i < 1200; i++) acct('3f2c9a71-e4b0-4856-8a00-${i.toString().padLeft(12, '0')}')]),
      );

      await phone.run();

      expect(w.server.events.where((event) => event == 'batch'), hasLength(3));
      expect(w.server.events.where((event) => event == 'manifest'), hasLength(1));
      expect(w.server.events.last, 'manifest');
      w.server.events.clear();

      await phone.run();
      await phone.run();

      expect(w.server.events.where((event) => event == 'manifest'), isEmpty);
    });

    test('lists what the phone accepted, with each revision and ciphertext hash, signed by the account, counting up', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );

      await phone.run();

      final first = _published(w.server);
      expect(first.counter, 1);
      expect(first.owner, phone.crypto.owner);
      expect(first.entries, hasLength(2));
      for (final entry in first.entries) {
        final item = w.server.items[uuidText(entry.itemId)]!;
        expect(entry.revision, item.revision);
        expect(entry.ciphertextHash, hash.sha256.convert(item.ciphertext!).bytes);
        expect(entry.deleted, isFalse);
      }
      await phone.crypto.alike().verifyManifest(
        b64urlDecode(w.server.manifest!['manifest']!),
        b64urlDecode(w.server.manifest!['signature']!),
      );

      phone.lists = Lists(
        accounts: [acct(_a, label: 'edited', updatedAt: w.clock.ms + 1)],
      );
      await phone.run();

      final second = _published(w.server);
      expect(second.counter, 2);
      expect(second.entryFor(uuidBytes(_b))!.deleted, isTrue, reason: 'a deletion is listed as a tombstone with a zero hash');
      expect(second.entryFor(uuidBytes(_a))!.revision, 2);
    });
  });

  group('an older copy of the vault stops the run before anything is stored', () {
    test('revision 3 served where this phone holds 5, and where the manifest says 5', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await one.run();
      final (oldCiphertext, oldKey) = (w.server.items[_a]!.ciphertext!, w.server.items[_a]!.itemKey!);
      one.lists = Lists(
        accounts: [acct(_a, label: 'v2', updatedAt: w.clock.ms + 1)],
      );
      await one.run();
      final two = one.another();
      await two.run();
      final before = jsonEncode(two.stored);
      final listsBefore = two.lists;
      // The server hands the first revision back
      w.server.write(id: _a, kind: 'otp', revision: 1, ciphertext: oldCiphertext, itemKey: oldKey);

      await expectLater(two.run(), throwsA(_older));
      expect(jsonEncode(two.stored), before, reason: 'nothing stored');
      expect(two.lists, listsBefore);

      final fresh = one.another();
      await expectLater(fresh.run(), throwsA(_older));
      expect(fresh.stored, isNull);
      expect(fresh.lists.ids, isEmpty);
    });

    test('an item the manifest lists as live that the server no longer serves', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );
      await one.run();
      w.server.items.remove(_a);

      final fresh = one.another();
      await expectLater(fresh.run(), throwsA(_older));
      expect(fresh.stored, isNull);
    });

    test('an entry deleted months ago and served again, though its tombstone has left the manifest', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a), acct(_b)]),
      );
      await one.run();
      final (oldCiphertext, oldKey) = (w.server.items[_a]!.ciphertext!, w.server.items[_a]!.itemKey!);
      final two = one.another();
      await two.run();
      one.lists = Lists(accounts: [acct(_b)]);
      await one.run();
      await two.run();
      expect(two.ids, [_b]);
      // The tombstone is gone from the server, the manifest and this phone's cache, but not from its record of deleted ids
      w.server.items.remove(_a);
      (two.stored! as Map<String, Object?>)['items'] = {
        for (final entry in ((two.stored! as Map<String, Object?>)['items']! as Map<String, Object?>).entries)
          if (entry.key != _a) entry.key: entry.value,
      };
      w.server.write(id: _a, kind: 'otp', revision: 3, ciphertext: oldCiphertext, itemKey: oldKey);
      await _publish(w.server, two.crypto, include: (item) => item.id != _a);

      await expectLater(two.run(), throwsA(_older));
    });
  });

  group('a manifest that fails stops the run too', () {
    test('a changed signature, a manifest of another account, and a counter lower than one already verified', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await one.run();
      one.lists = Lists(
        accounts: [acct(_a, label: 'v2', updatedAt: w.clock.ms + 1)],
      );
      await one.run();
      final two = one.another();
      await two.run();
      final good = Map.of(w.server.manifest!);
      final before = jsonEncode(two.stored);

      final tampered = b64urlDecode(good['signature']!)..[3] ^= 1;
      w.server.manifest = {...good, 'signature': b64urlEncode(tampered)};
      await expectLater(two.run(), throwsA(_older), reason: 'the signature');

      await _publish(w.server, FakeKmCrypto(), counter: 9);
      await expectLater(two.run(), throwsA(_older), reason: 'another account’s key');

      await _publish(w.server, one.crypto, counter: 1);
      await expectLater(two.run(), throwsA(_older), reason: 'a counter that went down');

      expect(jsonEncode(two.stored), before, reason: 'nothing stored by any of them');
    });

    test('a server that no longer has the manifest it once had', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      w.server.manifest = null;

      await expectLater(phone.run(), throwsA(_older));
    });
  });

  group('an item no signed manifest lists', () {
    test('is held, not applied, and applied once a later manifest lists it', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      final (ciphertext, key) = await _sealed(phone.crypto, _c, 1, 'otp', jsonEncode(acct(_c).toJson()));
      w.server.write(id: _c, kind: 'otp', revision: 1, ciphertext: ciphertext, itemKey: key);

      final held = await phone.run();

      expect(phone.ids, [_a], reason: 'not applied');
      expect(held.skipped, 1, reason: 'flagged');
      expect(phone.cache.items[_c]!.heldSince, isNotNull);
      expect(w.server.items[_c]!.revision, 1, reason: 'and left as it was');

      await _publish(w.server, phone.crypto);
      await phone.run();

      expect(phone.ids, [_a, _c]);
      expect(phone.cache.items[_c]!.heldSince, isNull);
    });

    test('does not stop the run for a day, then is a problem', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      final (ciphertext, key) = await _sealed(phone.crypto, _c, 1, 'otp', jsonEncode(acct(_c).toJson()));
      w.server.write(id: _c, kind: 'otp', revision: 1, ciphertext: ciphertext, itemKey: key);
      await phone.run();

      w.clock.ms += const Duration(hours: 23).inMilliseconds;
      await phone.run();
      w.clock.ms += const Duration(hours: 2).inMilliseconds;

      await expectLater(phone.run(), throwsA(_older));
    });

    test('is not listed by the manifest the phone signs, since it does not vouch for what nothing listed', () async {
      final w = _world();
      final phone = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await phone.run();
      final (ciphertext, key) = await _sealed(phone.crypto, _c, 1, 'otp', jsonEncode(acct(_c).toJson()));
      w.server.write(id: _c, kind: 'otp', revision: 1, ciphertext: ciphertext, itemKey: key);

      phone.lists = Lists(
        accounts: [acct(_a, label: 'edited', updatedAt: w.clock.ms + 1)],
      );
      await phone.run();

      expect(_published(w.server).entryFor(uuidBytes(_c)), isNull);
      expect(_published(w.server).entryFor(uuidBytes(_a)), isNotNull);
    });

    test('an item newer than its entry is held until a manifest lists that revision', () async {
      final w = _world();
      final one = KmPhone(
        w.server,
        clock: w.clock,
        lists: Lists(accounts: [acct(_a)]),
      );
      await one.run();
      final two = one.another();
      await two.run();
      final (ciphertext, key) = await _sealed(
        one.crypto,
        _a,
        2,
        'otp',
        jsonEncode(acct(_a, label: 'sneaked in', updatedAt: w.clock.ms + 5).toJson()),
      );
      w.server.write(id: _a, kind: 'otp', revision: 2, ciphertext: ciphertext, itemKey: key);

      await two.run();

      expect(two.lists.accounts.single.label, '', reason: 'the copy before is kept');
      expect(two.cache.items[_a]!.heldSince, isNotNull);

      await _publish(w.server, one.crypto);
      await two.run();

      expect(two.lists.accounts.single.label, 'sneaked in');
    });
  });
}
