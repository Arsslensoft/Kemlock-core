@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/account/manifest_compare.dart';
import 'package:test/test.dart';

Uint8List _id(int last) => Uint8List.fromList([...List.filled(15, 0x10), last]);

List<int> _ciphertext(int seed) => List.generate(40, (i) => seed + i);

void main() {
  final owner = Owner.user('11111111-2222-7333-8444-555555555555');
  final now = DateTime.utc(2026, 11, 21, 12);

  Manifest manifestOf(List<ManifestEntry> entries, {int counter = 5}) => Manifest(owner: owner, counter: counter, entries: entries);
  ManifestEntry live(int id, int revision, int seed) =>
      ManifestEntry.forItem(itemId: _id(id), revision: revision, ciphertext: _ciphertext(seed));
  ManifestEntry tombstone(int id, int revision) => ManifestEntry.forItem(itemId: _id(id), revision: revision);
  ServerItemState served(int id, int revision, int seed) =>
      ServerItemState.live(itemId: _id(id), revision: revision, ciphertext: _ciphertext(seed));

  Map<int, ItemVerdict> verdicts(Manifest manifest, List<ServerItemState> answer, [DeletedItems? deleted]) => {
    for (final finding in compareItems(manifest: manifest, deleted: deleted ?? DeletedItems(), answer: answer))
      finding.itemId.last: finding.verdict,
  };

  group('the six results', () {
    test('expected: the item matches the latest manifest, a live one and a tombstone', () {
      final manifest = manifestOf([live(1, 3, 10), tombstone(2, 4)]);
      expect(verdicts(manifest, [served(1, 3, 10), ServerItemState.tombstone(itemId: _id(2), revision: 4)]), {
        1: ItemVerdict.expected,
        2: ItemVerdict.expected,
      });
    });

    test('rolled back: a lower revision than the manifest lists, and the device copy stays', () {
      final manifest = manifestOf([live(1, 3, 10)]);
      final findings = compareItems(manifest: manifest, deleted: DeletedItems(), answer: [served(1, 2, 9)]);
      expect(findings.single.verdict, ItemVerdict.rolledBack);
      expect(findings.single.revision, 2);
      expect(findings.single.manifestRevision, 3);
      expect(findings.single.verdict.isApplied, isFalse);
    });

    test('missing: a listed live item withheld without a tombstone, and nothing is deleted', () {
      final manifest = manifestOf([live(1, 3, 10), live(2, 1, 20), tombstone(3, 2)]);
      final findings = compareItems(manifest: manifest, deleted: DeletedItems(), answer: [served(2, 1, 20)]);
      final byId = {for (final f in findings) f.itemId.last: f};
      expect(byId[1]!.verdict, ItemVerdict.missing);
      expect(byId[1]!.revision, isNull);
      expect(byId[2]!.verdict, ItemVerdict.expected);
      expect(byId.containsKey(3), isFalse, reason: 'a deleted entry the answer lacks is not missing');
      expect(ItemVerdict.missing.isApplied, isFalse);
    });

    test('unlisted: an item no signed manifest lists is held and flagged, not applied', () {
      final manifest = manifestOf([live(1, 3, 10)]);
      final result = verdicts(manifest, [served(1, 3, 10), served(9, 1, 50), ServerItemState.tombstone(itemId: _id(8), revision: 1)]);
      expect(result[9], ItemVerdict.unlisted);
      expect(result[8], ItemVerdict.unlisted);
      expect(ItemVerdict.unlisted.isApplied, isFalse);
      expect(ItemVerdict.unlisted.isFlagged, isTrue);
    });

    test('unlisted: an item newer than its entry is held until a manifest lists it', () {
      final manifest = manifestOf([live(1, 3, 10)]);
      expect(verdicts(manifest, [served(1, 4, 11)]), {1: ItemVerdict.unlisted});
      expect(verdicts(manifest, [ServerItemState.tombstone(itemId: _id(1), revision: 4)]), {1: ItemVerdict.unlisted});
    });

    test('resurrected: an id seen deleted reappears at or below its tombstone', () {
      final deleted = DeletedItems().recording(_id(1), 5, now);
      final manifest = manifestOf([live(1, 2, 10)]);
      expect(verdicts(manifest, [served(1, 5, 10)], deleted), {1: ItemVerdict.resurrected});
      expect(verdicts(manifest, [served(1, 2, 10)], deleted), {1: ItemVerdict.resurrected});
      expect(ItemVerdict.resurrected.isApplied, isFalse);
    });

    test('resurrected: the tombstone left the manifest, and the server replays the item', () {
      final deleted = DeletedItems().recording(_id(1), 5, now);
      final manifest = manifestOf([live(2, 1, 20)]);
      expect(verdicts(manifest, [served(1, 6, 10), served(2, 1, 20)], deleted), {1: ItemVerdict.resurrected, 2: ItemVerdict.expected});
    });

    test('resurrected: the manifest still lists the id deleted', () {
      final deleted = DeletedItems().recording(_id(1), 5, now);
      final manifest = manifestOf([tombstone(1, 5)]);
      expect(verdicts(manifest, [served(1, 5, 10)], deleted), {1: ItemVerdict.resurrected});
    });

    test('an undelete the writer signed, at a higher revision, is not resurrected', () {
      final deleted = DeletedItems().recording(_id(1), 5, now);
      final manifest = manifestOf([live(1, 6, 10)]);
      expect(verdicts(manifest, [served(1, 6, 10)], deleted), {1: ItemVerdict.expected});
    });

    test('a tombstone for an id seen deleted is expected, not resurrected', () {
      final deleted = DeletedItems().recording(_id(1), 5, now);
      final manifest = manifestOf([tombstone(1, 5)]);
      expect(verdicts(manifest, [ServerItemState.tombstone(itemId: _id(1), revision: 5)], deleted), {1: ItemVerdict.expected});
    });

    test('sibling: the same revision with another hash goes to the merge', () {
      final manifest = manifestOf([live(1, 3, 10)]);
      expect(verdicts(manifest, [served(1, 3, 77)]), {1: ItemVerdict.sibling});
      expect(ItemVerdict.sibling.isApplied, isTrue);
    });

    test('findings come in item id order, and an item answered twice is refused', () {
      final manifest = manifestOf([live(1, 1, 1), live(2, 1, 2), live(3, 1, 3)]);
      final findings = compareItems(manifest: manifest, deleted: DeletedItems(), answer: [served(3, 1, 3), served(1, 1, 1)]);
      expect(findings.map((f) => f.itemId.last), [1, 2, 3]);
      expect(
        () => compareItems(manifest: manifest, deleted: DeletedItems(), answer: [served(1, 1, 1), served(1, 1, 1)]),
        throwsA(isA<MalformedException>()),
      );
    });
  });

  group('the manifest itself', () {
    final held = ManifestRecord(manifestOf([live(1, 3, 10)], counter: 5));

    test('the first manifest, and a higher counter, are newer', () {
      expect(checkManifest(null, manifestOf([], counter: 1)), ManifestVerdict.newer);
      expect(checkManifest(held, manifestOf([live(1, 3, 10)], counter: 6)), ManifestVerdict.newer);
    });

    test('a lower counter rolls back the whole answer', () {
      expect(checkManifest(held, manifestOf([live(1, 3, 10)], counter: 4)), ManifestVerdict.rolledBack);
    });

    test('the same counter and bytes are the same; other bytes are a fork', () {
      expect(checkManifest(held, manifestOf([live(1, 3, 10)], counter: 5)), ManifestVerdict.same);
      expect(checkManifest(held, manifestOf([live(1, 4, 11)], counter: 5)), ManifestVerdict.fork);
    });

    test('a manifest of another owner is refused', () {
      final other = Manifest(owner: Owner.user('99999999-2222-7333-8444-555555555555'), counter: 6, entries: const []);
      expect(() => checkManifest(held, other), throwsA(isA<MalformedException>()));
    });

    test('a fork merges with the higher revision of each item winning', () {
      final a = manifestOf([live(1, 3, 10), live(2, 7, 20)], counter: 5);
      final b = manifestOf([live(1, 4, 11), live(3, 1, 30)], counter: 5);
      final merged = mergeSameCounter(a, b);
      expect(merged.entries.map((e) => (e.itemId.last, e.revision)), [(1, 4), (2, 7), (3, 1)]);
      expect(merged.counter, 5);
      expect(() => mergeSameCounter(a, manifestOf([], counter: 6)), throwsA(isA<MalformedException>()));
    });
  });

  group('the record of deleted ids', () {
    test('keeps the highest revision and the first sighting', () {
      final first = DeletedItems().recording(_id(1), 5, now);
      final higher = first.recording(_id(1), 7, now.add(const Duration(days: 1)));
      expect(higher.revisionOf(_id(1)), 7);
      expect(higher.toJson()['items'], {
        '${'10' * 15}01': {'revision': 7, 'seenAt': now.millisecondsSinceEpoch},
      });
      expect(first.recording(_id(1), 3, now).revisionOf(_id(1)), 5, reason: 'a lower revision does not replace it');
      expect(DeletedItems().revisionOf(_id(1)), isNull);
    });

    test('takes the tombstones of a manifest and of an answer', () {
      final manifest = manifestOf([live(1, 1, 1), tombstone(2, 4)]);
      final record = DeletedItems().recordingAll(
        manifest: manifest,
        answer: [
          served(3, 1, 3),
          ServerItemState.tombstone(itemId: _id(4), revision: 9),
        ],
        now: now,
      );
      expect(record.length, 2);
      expect(record.revisionOf(_id(2)), 4);
      expect(record.revisionOf(_id(4)), 9);
    });

    test('forgets an id seen more than 180 days ago, and no sooner', () {
      final record = DeletedItems().recording(_id(1), 5, now).recording(_id(2), 6, now.add(const Duration(days: 100)));
      expect(record.pruned(now.add(const Duration(days: 179))).length, 2);
      final later = record.pruned(now.add(const Duration(days: 181)));
      expect(later.length, 1);
      expect(later.revisionOf(_id(2)), 6);
    });

    test('round-trips through JSON and refuses a malformed record', () {
      final record = DeletedItems().recording(_id(1), 5, now).recording(_id(2), 6, now);
      final again = DeletedItems.fromJson(jsonDecode(jsonEncode(record.toJson())));
      expect(again.toJson(), record.toJson());
      expect(
        () => DeletedItems.fromJson({
          'items': {
            'xyz': {'revision': 1, 'seenAt': 1},
          },
        }),
        throwsA(isA<MalformedException>()),
      );
      expect(
        () => DeletedItems.fromJson({
          'items': {
            '10101010101010101010101010101001': {'revision': 1},
          },
        }),
        throwsA(isA<MalformedException>()),
      );
      expect(() => DeletedItems.fromJson({'items': {}, 'extra': 1}), throwsA(isA<MalformedException>()));
    });
  });
}
