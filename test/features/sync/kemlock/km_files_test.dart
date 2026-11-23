@TestOn('vm')
library;

// A note's files over Kemlock Server (add-kemlock-server-sync, task 8.5): the
// same KMA1 bytes, uploaded once their note's item is there, naming the
// server's file id, and fetched with a cap and a check.
import 'dart:typed_data';

import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_files.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

const _note = '3f2c9a71-e4b0-4856-8a00-0000000000d1';

({FakeKemlockServer server, KmClock clock}) _world() => (server: FakeKemlockServer()..checkTokens = false, clock: KmClock());

/// An attached file of [size] bytes: its sealed KMA1 bytes, and the attachment that names it.
({Uint8List sealed, NoteAttachment file}) _attachment(String id, int size) {
  final key = randomBytes(32);
  final plain = randomBytes(size);
  return (sealed: kma1EncryptSync(plain, key), file: NoteAttachment(id: id, name: '$id.jpg', size: size, key: b64(key), addedAt: 1));
}

SecureNote _noteWith(List<NoteAttachment> files, {int? updatedAt}) =>
    SecureNote(id: _note, title: 'Photos', addedAt: 1, updatedAt: updatedAt, attachments: files);

void main() {
  test('a 3 MB photo arrives byte for byte on the second phone, which opens it', () async {
    final w = _world();
    final photo = _attachment('photo-1', 3 * 1024 * 1024);
    final storeOne = FakeFileStore()..files['photo-1'] = photo.sealed;
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: storeOne,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );

    await one.run();

    expect(w.server.files, hasLength(1));
    expect(w.server.files.values.single.bytes, photo.sealed, reason: 'the KMA1 bytes as the phone keeps them');
    final named = one.lists.notes.single.files.single;
    expect(kmServerFileId(named), w.server.files.keys.single);
    expect(named.id, 'photo-1', reason: 'the phone’s own name for it stays');

    final storeTwo = FakeFileStore();
    final two = one.another(fileStore: storeTwo);
    await two.run();

    expect(storeTwo.files['photo-1'], photo.sealed);
    final opened = await kma1Decrypt(storeTwo.files['photo-1']!, unb64(photo.file.key));
    expect(opened, hasLength(3 * 1024 * 1024));
    expect(two.lists.notes.single.files.single.name, 'photo-1.jpg');
  });

  test('the note’s item goes up first, then the file, then the note again naming it, and the manifest last', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );

    await one.run();

    expect(w.server.events, ['sync', 'batch', 'file', 'batch', 'manifest']);
    expect(w.server.items[_note]!.revision, 2, reason: 'written, then written again with the file’s id');
  });

  test('a file is uploaded once: the next runs send nothing', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );
    await one.run();
    w.server.events.clear();

    await one.run();
    await one.run();

    expect(w.server.events.where((event) => event == 'file' || event == 'batch'), isEmpty);
    expect(w.server.files, hasLength(1));
  });

  test('a file this phone does not have is left for the phone that does, and the note is written without it', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore(),
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );

    await one.run();

    expect(w.server.files, isEmpty);
    expect(kmServerFileId(one.lists.notes.single.files.single), isNull);
    expect(w.server.items[_note]!.revision, 1);
  });

  test('a file the server will not take is skipped, and the run goes on', () async {
    final w = _world();
    w.server.maxFileSize = 500;
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );

    await one.run();

    expect(w.server.files, isEmpty);
    expect(w.server.items[_note], isNotNull);
    expect(kmServerFileId(one.lists.notes.single.files.single), isNull);
  });

  test('a file that is not the size its note says is not sent', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final wrong = NoteAttachment(id: 'photo-1', name: 'x.jpg', size: 999, key: photo.file.key, addedAt: 1);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([wrong]),
        ],
      ),
    );

    await one.run();

    expect(w.server.files, isEmpty);
  });

  test('a download stops at the size its note names, and nothing is stored', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );
    await one.run();
    final file = w.server.files.values.single;
    file.bytes = Uint8List.fromList([...file.bytes!, ...Uint8List(5000)]);

    final store = FakeFileStore();
    final two = one.another(fileStore: store);
    await two.run();

    expect(store.files, isEmpty, reason: 'more bytes than promised');
    expect(two.lists.notes, hasLength(1), reason: 'and the run still went through');
  });

  test('a download that does not open with its attachment’s key is thrown away, and fetched again at the next run', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );
    await one.run();
    final file = w.server.files.values.single;
    final damaged = Uint8List.fromList(file.bytes!)..[40] ^= 1;
    file.bytes = damaged;

    final store = FakeFileStore();
    final two = one.another(fileStore: store);
    await two.run();
    expect(store.files, isEmpty);

    file.bytes = photo.sealed;
    await two.run();
    expect(store.files['photo-1'], photo.sealed);
  });

  test('the files of an attachment a note no longer names are deleted from the server', () async {
    final w = _world();
    final photo = _attachment('photo-1', 1000);
    final one = KmPhone(
      w.server,
      clock: w.clock,
      fileStore: FakeFileStore()..files['photo-1'] = photo.sealed,
      lists: Lists(
        notes: [
          _noteWith([photo.file]),
        ],
      ),
    );
    await one.run();
    expect(w.server.files, hasLength(1));

    one.lists = Lists(notes: [_noteWith(const [], updatedAt: w.clock.ms + 1)]);
    await one.run();

    expect(w.server.files, isEmpty);
  });
}
