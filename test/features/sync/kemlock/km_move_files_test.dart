@TestOn('vm')
library;

// The files step of a move (move-off-vaultwarden-sync, task 3.3): each moved note's file goes up as the
// phone's own KMA1 bytes, byte for byte, the note is written again naming it, and a file nobody can supply
// stops the move before the check.
import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_copy.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_plan.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_record.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_server.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

import 'km_move_kit.dart';
import 'km_sync_kit.dart';

const _noteId = '3f2c9a71-e4b0-4856-8a00-000000000001';
const _fileId = 'f1';

/// A note that names one file, and the file as the phone keeps it: `KMA1` under the attachment's own key.
({SecureNote note, Uint8List sealed}) _noteWithFile(
  FakeFileStore store, {
  String noteId = _noteId,
  String fileId = _fileId,
  String text = 'passport scan',
}) {
  final key = randomBytes(32);
  final plain = Uint8List.fromList(utf8.encode(text));
  final sealed = kma1EncryptSync(plain, key);
  store.files[fileId] = sealed;
  final note = SecureNote(
    id: noteId,
    title: 'Passport',
    addedAt: 1,
    attachments: [NoteAttachment(id: fileId, name: 'scan.txt', size: plain.length, key: b64(key), addedAt: 1)],
  );
  return (note: note, sealed: sealed);
}

Future<KmMoveRecord> _copyThenFiles(
  MoveRig rig,
  KmMovePlan plan,
  FakeFileStore store, {
  KmMoveRecord? from,
  List<KmMoveRecord>? saved,
}) async {
  final copied = await KmMoveCopy(server: rig.moveServer).run(plan, from ?? newRecord(), now: moveNow, save: (next) async {});
  final result = await KmMoveFilesStep(
    server: rig.moveServer,
    store: store,
  ).run(plan, copied.record, now: moveNow, save: (next) async => saved?.add(next));
  return result.record;
}

void main() {
  const noteId = _noteId;

  test('uploads a file as the phone’s KMA1 bytes, byte for byte, and writes the note naming it', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final made = _noteWithFile(store, noteId: noteId);
    final plan = rig.plan(Lists(notes: [made.note]));

    final record = await _copyThenFiles(rig, plan, store);

    expect(rig.server.files.values.single.bytes, made.sealed);
    final item = (await rig.read()).items[rig.itemUuidOf(noteId)]!;
    expect(item.revision, 2, reason: 'created by the copy, written again naming its file');
    final named = SecureNote.fromJson(item.entry!).files.single;
    expect(kmServerFileId(named), rig.server.files.keys.single);
    expect(record.sent[noteId], kmEntryHash(item.entry!));
    expect(record.files[_fileId], b64urlEncode(sha256.convert(made.sealed).bytes));
  });

  test('stops with “a file is missing”, naming the note, when the phone lacks the file, before anything is uploaded', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final made = _noteWithFile(store, noteId: noteId);
    store.files.clear();
    final plan = rig.plan(Lists(notes: [made.note]));

    await expectLater(
      _copyThenFiles(rig, plan, store),
      throwsA(
        isA<KmMoveError>().having((e) => e.issue, 'issue', KmMoveIssue.fileMissing).having((e) => e.detail, 'detail', contains(noteId)),
      ),
    );
    expect(rig.server.files, isEmpty);
    expect((await rig.read()).items[rig.itemUuidOf(noteId)]!.revision, 1, reason: 'the note is not written again');
  });

  test('a note that already names its file uploads nothing again when the step runs a second time', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final made = _noteWithFile(store, noteId: noteId);
    final plan = rig.plan(Lists(notes: [made.note]));
    final record = await _copyThenFiles(rig, plan, store);
    final events = [...rig.server.events];

    final again = await KmMoveFilesStep(server: rig.moveServer, store: store).run(plan, record, now: moveNow, save: (next) async {});

    expect(rig.server.files, hasLength(1));
    expect(rig.server.events.where((event) => event == 'file'), hasLength(events.where((event) => event == 'file').length));
    expect((await rig.read()).items[rig.itemUuidOf(noteId)]!.revision, 2);
    expect(again.record.sent[noteId], record.sent[noteId]);
  });

  test('adopts the file another phone uploaded and the phone lacks, without uploading', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final made = _noteWithFile(store, noteId: noteId);
    final plan = rig.plan(Lists(notes: [made.note]));
    // Another phone moved first and uploaded; this phone then lost its own copy of the file
    final other = FakeFileStore()..files[_fileId] = made.sealed;
    final firstRecord = await _copyThenFiles(rig.another(), plan, other);
    store.files.clear();

    final result = await KmMoveFilesStep(server: rig.moveServer, store: store).run(
      plan,
      newRecord().copyWith(sent: firstRecord.sent),
      now: moveNow,
      save: (next) async {},
    );

    expect(rig.server.files, hasLength(1));
    expect(result.skipped, isEmpty);
    expect(result.record.files.containsKey(_fileId), isFalse, reason: 'nothing local to hash; the check opens it with its key');
  });

  test('uploads a file a check found wrong again, under a new id', () async {
    final rig = MoveRig();
    final store = FakeFileStore();
    final made = _noteWithFile(store, noteId: noteId);
    final plan = rig.plan(Lists(notes: [made.note]));
    final record = await _copyThenFiles(rig, plan, store);
    final first = rig.server.files.keys.single;

    final again = await KmMoveFilesStep(server: rig.moveServer, store: store).run(
      plan,
      record.copyWith(redoFiles: [_fileId]),
      now: moveNow,
      save: (next) async {},
    );

    expect(rig.server.files, hasLength(2));
    final named = SecureNote.fromJson((await rig.read()).items[rig.itemUuidOf(noteId)]!.entry!).files.single;
    expect(kmServerFileId(named), isNot(first));
    expect(again.record.redoFiles, isEmpty);
  });
}
