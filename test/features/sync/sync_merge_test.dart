@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

const now = 1_800_000_000_000;

OtpAccount acct(
  String id, {
  OtpType? type,
  String? issuer,
  String? secret,
  int addedAt = 100,
  int? updatedAt,
  int? counter,
  String? note,
  String? spaceId,
  Map<String, Object?> extra = const {},
}) => OtpAccount(
  id: id,
  type: type,
  issuer: issuer ?? 'Issuer $id',
  label: '',
  secret: secret ?? 'SECRET${id.toUpperCase()}',
  addedAt: addedAt,
  updatedAt: updatedAt,
  counter: counter,
  note: note,
  spaceId: spaceId,
  extra: extra,
);

BackupService svc(String id, {List<BackupCode> codes = const [], int? updatedAt, String? spaceId}) =>
    BackupService(id: id, serviceName: 'Service $id', codes: codes, addedAt: 100, updatedAt: updatedAt, spaceId: spaceId);

SyncDoc doc(List<OtpAccount> accounts, [List<Tombstone> deleted = const []]) => SyncDoc(accounts: accounts, deleted: deleted);

List<String> ids(Iterable<Object> list) => [
  for (final entry in list)
    switch (entry) {
      OtpAccount(:final id) || BackupService(:final id) || Tombstone(:final id) => id,
      _ => throw ArgumentError.value(entry),
    },
];

void main() {
  group('mergeScope', () {
    test('uploads everything on the first sync', () {
      final merged = mergeScope(
        Lists(accounts: [acct('b'), acct('a')], backupServices: [svc('s')]),
        [],
        null,
        now: now,
      );

      expect(ids(merged.doc.accounts), ['a', 'b']);
      expect(ids(merged.doc.backupServices), ['s']);
      expect([...merged.known]..sort(), ['a', 'b', 's']);
    });

    test('brings down what another device added', () {
      final merged = mergeScope(Lists(accounts: [acct('a')]), ['a'], doc([acct('a'), acct('z')]), now: now);

      expect(ids(merged.doc.accounts), ['a', 'z']);
    });

    test('keeps the most recently changed copy, from either side', () {
      final mine = acct('a', note: 'mine', updatedAt: 300);
      final theirs = acct('a', note: 'theirs', updatedAt: 200);
      expect(mergeScope(Lists(accounts: [mine]), ['a'], doc([theirs]), now: now).doc.accounts[0].note, 'mine');

      final older = acct('a', note: 'mine', updatedAt: 150);
      expect(mergeScope(Lists(accounts: [older]), ['a'], doc([theirs]), now: now).doc.accounts[0].note, 'theirs');
    });

    test('records a deletion made here, so other devices drop the entry', () {
      final merged = mergeScope(Lists(accounts: [acct('a')]), ['a', 'gone'], doc([acct('a'), acct('gone')]), now: now);

      expect(ids(merged.doc.accounts), ['a']);
      expect(merged.doc.deleted, [const Tombstone(id: 'gone', at: now)]);
      expect(merged.known, ['a']);

      // The other device still has it, and drops it on its next sync
      final other = mergeScope(Lists(accounts: [acct('a'), acct('gone')]), ['a', 'gone'], merged.doc, now: now + 1);
      expect(ids(other.doc.accounts), ['a']);
    });

    test('keeps an entry changed after it was deleted elsewhere, and forgets the deletion', () {
      final restored = acct('a', updatedAt: now + 5);

      final merged = mergeScope(
        Lists(accounts: [restored]),
        [],
        doc([], [const Tombstone(id: 'a', at: now)]),
        now: now + 10,
      );

      expect(ids(merged.doc.accounts), ['a']);
      expect(merged.doc.deleted, isEmpty);
    });

    test('never lets an HOTP counter go back', () {
      final mine = acct('h', type: OtpType.hotp, counter: 4, updatedAt: 500);
      final theirs = acct('h', type: OtpType.hotp, counter: 9, updatedAt: 400, note: 'old');

      final merged = mergeScope(Lists(accounts: [mine]), ['h'], doc([theirs]), now: now);

      final account = merged.doc.accounts.single;
      expect(account.counter, 9);
      expect(account.updatedAt, 500);
      expect(account.note, isNull);
    });

    test('collapses the same account added on two devices before they first synced', () {
      final here = acct('x', issuer: 'GitHub', secret: 'S', addedAt: 100);
      final there = acct('y', issuer: 'GitHub', secret: 'S', addedAt: 200);

      final merged = mergeScope(Lists(accounts: [here]), [], doc([there]), now: now);

      expect(ids(merged.doc.accounts), ['y']);
      expect(merged.doc.deleted, [const Tombstone(id: 'x', at: now)]);
    });

    test('forgets deletions after six months', () {
      const old = now - tombstoneTtlMs - 1;

      final merged = mergeScope(
        const Lists(),
        [],
        doc([], [const Tombstone(id: 'old', at: old), const Tombstone(id: 'recent', at: now - 1)]),
        now: now,
      );

      expect(ids(merged.doc.deleted), ['recent']);
    });

    test('merges backup-code services the same way', () {
      final mine = svc('s', codes: [const BackupCode(code: '1', used: true)], updatedAt: 300);
      final theirs = svc('s', codes: [const BackupCode(code: '1')], updatedAt: 200);

      final merged = mergeScope(
        Lists(backupServices: [mine]),
        ['s'],
        SyncDoc(backupServices: [theirs]),
        now: now,
      );

      expect(merged.doc.backupServices[0].codes[0].used, isTrue);
    });

    test('carries the breaches an entry has marked dealt with, both ways', () {
      Map<String, Object?> account(String id, int updatedAt, [List<String>? dismissed]) => {
        'id': id,
        'issuer': 'Adobe',
        'label': '',
        'secret': 'SECRET$id',
        'addedAt': 100,
        'updatedAt': updatedAt,
        'breachesDismissed': ?dismissed,
      };
      final service = BackupService.fromJson(const {
        'id': 's',
        'serviceName': 'Adobe',
        'codes': <Object?>[],
        'addedAt': 100,
        'updatedAt': 300,
        'breachesDismissed': ['Adobe'],
      });
      final remote = SyncDoc.fromJson({
        'accounts': [
          account('mine', 200),
          account('theirs', 300, ['Adobe']),
        ],
      });

      final merged = mergeScope(
        Lists(
          accounts: [
            OtpAccount.fromJson(account('mine', 300, ['Adobe'])),
            OtpAccount.fromJson(account('theirs', 200)),
          ],
          backupServices: [service],
        ),
        ['mine', 'theirs'],
        remote,
        now: now,
      );

      final written = SyncDoc.fromJson(jsonDecode(jsonEncode(merged.doc.toJson())) as Map<String, Object?>);
      for (final entry in [for (final a in written.accounts) a.toJson(), for (final s in written.backupServices) s.toJson()]) {
        expect(entry['breachesDismissed'], ['Adobe'], reason: '${entry['id']}');
      }
    });

    test("keeps the keys of the server's copy that this version doesn't know", () {
      final remote = SyncDoc(
        accounts: [acct('a')],
        deleted: [
          const Tombstone(id: 'gone', at: now - 5, extra: {'by': 'tablet'}),
        ],
        extra: const {'format': 2},
      );

      final merged = mergeScope(Lists(accounts: [acct('a')]), ['a'], remote, now: now);

      expect(merged.doc.extra, {'format': 2});
      expect(merged.doc.deleted.single.extra, {'by': 'tablet'});
    });
  });

  group('SyncDoc', () {
    test('reads and writes the JSON the TypeScript app writes, keeping keys it does not know', () {
      const json =
          '{"accounts":[{"id":"a","issuer":"GitHub","label":"me","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1",'
          '"digits":6,"period":30,"addedAt":100,"updatedAt":200,"icon":"github"}],'
          '"backupServices":[{"id":"s","serviceName":"GitHub","codes":[{"code":"1234-5678","used":true,"usedAt":300}],'
          '"addedAt":100}],"deleted":[{"id":"gone","at":400,"by":"tablet"}],"format":2}';

      final read = SyncDoc.fromJson(jsonDecode(json) as Map<String, Object?>);

      expect(ids(read.accounts), ['a']);
      expect(read.backupServices.single.codes.single.used, isTrue);
      expect(read.deleted.single.at, 400);
      expect(jsonEncode(read.toJson()), json);
    });

    test('reads missing or broken lists as empty', () {
      final read = SyncDoc.fromJson({'accounts': 'nope', 'deleted': null});

      expect(read.accounts, isEmpty);
      expect(read.backupServices, isEmpty);
      expect(read.deleted, isEmpty);
      expect(jsonEncode(read.toJson()), '{"accounts":[],"backupServices":[],"deleted":[]}');
    });
  });

  group('sameDoc', () {
    test('ignores the order of entries and of their fields', () {
      final a = doc([
        acct('a', extra: const {'x': 1, 'y': 2}),
        acct('b'),
      ]);
      final b = doc([
        acct('b'),
        acct('a', extra: const {'y': 2, 'x': 1}),
      ]);
      final reordered = SyncDoc.fromJson(jsonDecode(canonical(b.toJson())) as Map<String, Object?>);

      expect(sameDoc(a, b), isTrue);
      expect(sameDoc(a, reordered), isTrue);
      expect(sameDoc(a, doc([acct('a')])), isFalse);
    });
  });

  group('stampChanged', () {
    test('marks only new and edited entries as changed now', () {
      final before = [acct('a'), acct('b', updatedAt: 50)];
      final after = [acct('a'), acct('b', updatedAt: 50, note: 'edit'), acct('c')];

      final stamped = stampChanged(after, before, now: now);

      expect(stamped[0], same(after[0]));
      expect(stamped[1].updatedAt, now);
      expect(stamped[2].updatedAt, now);
    });

    test('stamps backup services the same way', () {
      final before = [
        svc('s', codes: [const BackupCode(code: '1')]),
      ];
      final after = [
        svc('s', codes: [const BackupCode(code: '1', used: true)]),
      ];

      expect(stampChanged(after, before, now: now).single.updatedAt, now);
      expect(stampChanged(before, before, now: now).single, same(before.single));
    });
  });

  group('scopes', () {
    test('picks the entries of one scope', () {
      final lists = Lists(
        accounts: [
          acct('p'),
          acct('s', spaceId: 'fam'),
        ],
        backupServices: [
          svc('x'),
          svc('y', spaceId: 'fam'),
        ],
      );

      expect(ids(scopeLists(lists, null).accounts), ['p']);
      expect(ids(scopeLists(lists, null).backupServices), ['x']);
      expect(ids(scopeLists(lists, 'fam').accounts), ['s']);
      expect(ids(scopeLists(lists, 'fam').backupServices), ['y']);
    });

    test('tells lists apart by content and order', () {
      final lists = Lists(accounts: [acct('a'), acct('b')]);

      expect(sameLists(lists, Lists(accounts: [acct('a'), acct('b')])), isTrue);
      expect(sameLists(lists, Lists(accounts: [acct('b'), acct('a')])), isFalse);
      expect(
        sameLists(
          lists,
          Lists(
            accounts: [
              acct('a'),
              acct('b', note: 'n'),
            ],
          ),
        ),
        isFalse,
      );
    });
  });

  group('applyScope', () {
    test('replaces one scope and leaves the others alone', () {
      final mine = acct('p');
      final shared = acct('s1', spaceId: 'fam');
      final merged = doc([acct('s1', note: 'from family'), acct('s2')]);

      final result = applyScope(Lists(accounts: [mine, shared]), 'fam', merged);

      expect(
        [for (final a in result.accounts) (a.id, a.spaceId, a.note)],
        [('p', null, null), ('s1', 'fam', 'from family'), ('s2', 'fam', null)],
      );
    });

    test('removes entries the scope no longer has', () {
      final result = applyScope(Lists(accounts: [acct('a'), acct('b')]), null, doc([acct('a')]));

      expect(ids(result.accounts), ['a']);
    });

    test('takes an entry another device moved into this scope after it changed here', () {
      final here = acct('a', updatedAt: 100);
      final moved = acct('a', spaceId: 'fam', updatedAt: 200);

      final result = applyScope(Lists(accounts: [here]), 'fam', doc([moved]));

      expect(result.accounts, [moved]);
    });

    test('keeps an entry this device moved out of the scope more recently', () {
      final movedOut = acct('a', updatedAt: 300);
      final stale = acct('a', spaceId: 'fam', updatedAt: 200);

      final result = applyScope(Lists(accounts: [movedOut]), 'fam', doc([stale]));

      expect(result.accounts, [movedOut]);
    });

    test('keeps an entry where it is when a space holds something else under its id', () {
      final mine = acct('a', secret: 'MINE', updatedAt: 100);
      final job = svc('s', updatedAt: 100, spaceId: 'work');
      // Written by someone in the space who knows the ids, stamped far ahead
      final planted = SyncDoc(
        accounts: [acct('a', secret: 'THEIRS', spaceId: 'fam', updatedAt: 9000)],
        backupServices: [
          svc(
            's',
            codes: const [BackupCode(code: 'theirs', used: false)],
            updatedAt: 9000,
            spaceId: 'fam',
          ),
        ],
      );
      final all = Lists(accounts: [mine], backupServices: [job]);

      final result = applyScope(all, 'fam', planted);

      expect(result.accounts, [mine]);
      expect(result.backupServices, [job]);
      expect(heldElsewhere(all, 'fam', planted), {'a', 's'});
    });

    test('keeps an entry of a space when the vault’s own document holds something else under its id', () {
      final shared = acct('a', secret: 'SHARED', spaceId: 'fam', updatedAt: 100);
      final other = doc([acct('a', secret: 'OTHER', updatedAt: 200)]);

      expect(applyScope(Lists(accounts: [shared]), null, other).accounts, [shared]);
      expect(heldElsewhere(Lists(accounts: [shared]), null, other), {'a'});
    });

    test('names nothing kept out for a move, an older copy or an entry of the scope itself', () {
      final here = acct('a', updatedAt: 100);
      final inScope = acct('b', spaceId: 'fam', updatedAt: 100);
      final all = Lists(accounts: [here, inScope]);

      expect(heldElsewhere(all, 'fam', doc([acct('a', spaceId: 'fam', updatedAt: 200)])), isEmpty);
      expect(heldElsewhere(all, 'fam', doc([acct('a', secret: 'OLD', spaceId: 'fam', updatedAt: 50)])), isEmpty);
      expect(heldElsewhere(all, 'fam', doc([acct('b', secret: 'EDITED', spaceId: 'fam', updatedAt: 200), acct('new')])), isEmpty);
    });
  });
}
