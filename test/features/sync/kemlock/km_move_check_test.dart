@TestOn('vm')
library;

// The check step of a move (move-off-vaultwarden-sync, task 3.4): one manifest signed after the last
// batch, the vault read back from an empty cursor and compared with what was sent, a missing item or a
// changed byte failing the check and sent again next time, and a local edit after the copy being no
// mismatch, against the fake Kemlock Server.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_check.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_copy.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_plan.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_record.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_server.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

import 'km_move_kit.dart';
import 'km_sync_kit.dart';

/// Copy and files, as the runner does before the check.
Future<KmMoveRecord> _copied(MoveRig rig, KmMovePlan plan, {KmMoveRecord? from, FakeFileStore? store}) async {
  final copied = await KmMoveCopy(server: rig.moveServer).run(plan, from ?? newRecord(), now: moveNow, save: (next) async {});
  final files = await KmMoveFilesStep(
    server: rig.moveServer,
    store: store ?? FakeFileStore(),
  ).run(plan, copied.record, now: moveNow, save: (next) async {});
  return files.record;
}

Future<KmCheckResult> _check(MoveRig rig, KmMoveRecord record, {List<KmMoveRecord>? saved}) =>
    KmMoveCheck(server: rig.moveServer).run(record, now: moveNow, save: (next) async => saved?.add(next));

Lists _three() => Lists(accounts: [for (var i = 1; i <= 3; i++) account(uuidN(i))]);

void main() {
  test('signs exactly one manifest, after the last batch, listing every moved item, and the server returns it', () async {
    final rig = MoveRig();
    final plan = rig.plan(_three(), batchSize: 2);
    final record = await _copied(rig, plan);
    expect(rig.server.events.where((event) => event == 'manifest'), isEmpty, reason: 'nothing is signed before the check');

    final result = await _check(rig, record);

    final events = rig.server.events;
    expect(events.where((event) => event == 'manifest'), hasLength(1));
    expect(events.lastIndexOf('batch'), lessThan(events.indexOf('manifest')));
    final manifest = Manifest.parse(b64urlDecode(rig.server.manifest!['manifest']!));
    expect(manifest.entries, hasLength(3));
    expect(manifest.counter, 1);
    expect(result.record.checked, isTrue);
    expect(result.cache.items.keys, unorderedEquals([for (final item in plan.items) item.itemId]));
    expect(result.cache.cursor, isNotNull);
    expect(result.cache.manifest, isNotNull);
  });

  test('one missing item stops the move, goes back to the copy, and is sent again next time', () async {
    final rig = MoveRig();
    final plan = rig.plan(_three());
    final record = await _copied(rig, plan);
    final gone = rig.itemUuidOf(uuidN(2));
    rig.server.items.remove(gone);
    final saved = <KmMoveRecord>[];

    await expectLater(
      _check(rig, record, saved: saved),
      throwsA(isA<KmMoveError>().having((e) => e.issue, 'issue', KmMoveIssue.checkFailed).having((e) => e.ids, 'ids', [uuidN(2)])),
    );
    expect(saved.single.step, KmMoveStep.copy);
    expect(saved.single.redo, [uuidN(2)]);
    expect(saved.single.checked, isFalse);

    final again = await _copied(rig, plan, from: saved.single);
    final result = await _check(rig, again);

    expect(rig.server.items.containsKey(gone), isTrue);
    expect(result.record.checked, isTrue);
    expect(result.record.redo, isEmpty);
  });

  test('one changed byte in an item fails the check, and the next attempt writes it over itself', () async {
    final rig = MoveRig();
    final plan = rig.plan(_three());
    final record = await _copied(rig, plan);
    final damaged = rig.itemUuidOf(uuidN(1));
    rig.server.items[damaged]!.ciphertext![5] ^= 1;
    final saved = <KmMoveRecord>[];

    await expectLater(_check(rig, record, saved: saved), throwsA(isA<KmMoveError>().having((e) => e.ids, 'ids', [uuidN(1)])));

    final again = await _copied(rig, plan, from: saved.single);
    final result = await _check(rig, again);

    expect(rig.server.items[damaged]!.revision, 2);
    expect(result.record.checked, isTrue);
  });

  test('a local edit after the copy is no mismatch: only the hashes recorded when it was sent are compared', () async {
    final rig = MoveRig();
    final plan = rig.plan(_three());
    final record = await _copied(rig, plan);
    // The person edits an account after the copy; the check has no use for the vault's entries now
    final edited = account(uuidN(1), issuer: 'Renamed', updatedAt: 99);
    expect(kmEntryHash(edited.toJson()), isNot(record.sent[uuidN(1)]));

    final result = await _check(rig, record);

    expect(result.record.checked, isTrue);
    expect(result.record.sent[uuidN(1)], plan.items.first.hash);
  });

  test('compares a file with the SHA-256 recorded when it went up: one changed byte fails, and it goes up again', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final key = randomBytes(32);
    final plain = Uint8List.fromList(utf8.encode('passport scan'));
    store.files['f1'] = kma1EncryptSync(plain, key);
    final note = SecureNote(
      id: uuidN(7),
      title: 'Passport',
      addedAt: 1,
      attachments: [NoteAttachment(id: 'f1', name: 'scan.txt', size: plain.length, key: b64(key), addedAt: 1)],
    );
    final plan = rig.plan(Lists(notes: [note]));
    final record = await _copied(rig, plan, store: store);
    final sealed = rig.server.files.values.single.bytes!;
    sealed[sealed.length - 1] ^= 1;
    final saved = <KmMoveRecord>[];

    await expectLater(
      _check(rig, record, saved: saved),
      throwsA(isA<KmMoveError>().having((e) => e.issue, 'issue', KmMoveIssue.checkFailed)),
    );
    expect(saved.single.redoFiles, ['f1']);
    expect(saved.single.redo, [uuidN(7)]);

    final again = await _copied(rig, plan, from: saved.single, store: store);
    final result = await _check(rig, again);

    expect(result.record.checked, isTrue);
    expect(rig.server.files, hasLength(2), reason: 'the damaged file stays, the new one is the one the note names');
  });

  test('opens a file another phone uploaded with its key when it has no hash of it', () async {
    final rig = MoveRig();
    final other = rig.another();
    final key = randomBytes(32);
    final plain = Uint8List.fromList(utf8.encode('passport scan'));
    final sealed = kma1EncryptSync(plain, key);
    final note = SecureNote(
      id: uuidN(7),
      title: 'Passport',
      addedAt: 1,
      attachments: [NoteAttachment(id: 'f1', name: 'scan.txt', size: plain.length, key: b64(key), addedAt: 1)],
    );
    final plan = rig.plan(Lists(notes: [note]));
    await _copied(other, plan, store: FakeFileStore()..files['f1'] = sealed);

    // This phone never held the file: the record has no hash for it
    final record = await _copied(rig, plan, store: FakeFileStore());
    final result = await _check(rig, record);

    expect(record.files, isEmpty);
    expect(result.record.checked, isTrue);
  });

  test('stops as older data when the latest manifest lists an item the server no longer returns', () async {
    final rig = MoveRig();
    final plan = rig.plan(_three());
    final record = await _copied(rig, plan);
    await _check(rig, record);
    rig.server.items.remove(rig.itemUuidOf(uuidN(3)));

    await expectLater(_check(rig, record), throwsA(isA<KmSyncError>().having((e) => e.issue, 'issue', KmSyncIssue.older)));
  });
}
