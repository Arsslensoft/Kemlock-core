@TestOn('vm')
library;

// A File item's file over Kemlock Server: uploaded once its item is there, named with its server id and hash, fetched on
// demand and by sync, sent again under a copy, and pushed at once with its item.
import 'dart:typed_data';

import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/kemlock/km_files.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_server.dart';
import 'package:kemlock_core/features/sync/kemlock/km_push.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:kemlock_core/vault/attachment_seal.dart';
import 'package:test/test.dart';

import 'fake_kemlock_server.dart';
import 'km_sync_kit.dart';

const _one = '3f2c9a71-e4b0-4856-8a00-0000000000f1';
const _two = '3f2c9a71-e4b0-4856-8a00-0000000000f2';

({FakeKemlockServer server, KmClock clock}) _world() => (server: FakeKemlockServer()..checkTokens = false, clock: KmClock());

/// A file of [size] bytes made as the app makes one: its sealed bytes, and the entry that names them, with its hash.
Future<SealedAttachment> _sealed(int size, {String name = 'Lease.pdf'}) => sealAttachment(randomBytes(size), name: name, now: 1);

/// The same file as an older version wrote it: no hash.
NoteAttachment _withoutHash(NoteAttachment file) =>
    NoteAttachment(id: file.id, name: file.name, size: file.size, type: file.type, key: file.key, addedAt: file.addedAt);

VaultFile _item(String id, NoteAttachment file, {int? updatedAt}) =>
    VaultFile(id: id, name: file.name, file: file, addedAt: 1, updatedAt: updatedAt);

KmEntry _entry(String id, NoteAttachment file) => (kind: KmKind.file, json: _item(id, file).toJson());

void main() {
  group('sync', () {
    test('the item goes up first, then the file, then the item again naming it and its hash, and the manifest last', () async {
      final w = _world();
      final made = await _sealed(3000);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );

      await one.run();

      expect(w.server.events, ['sync', 'batch', 'file', 'batch', 'manifest']);
      expect(w.server.items[_one]!.revision, 2);
      expect(w.server.files.values.single.bytes, made.sealed);
      final named = one.lists.files.single.file;
      expect(kmServerFileId(named), w.server.files.keys.single);
      expect(named.sha256, made.entry.sha256);
      expect(one.lists.files.single.updatedAt, isNotNull, reason: 'the item counts as changed');
    });

    test('an older attachment with no hash gets its hash when it goes up, and a file that does not open is not sent', () async {
      final w = _world();
      final made = await _sealed(1000);
      final other = await _sealed(1000);
      final broken = NoteAttachment(id: other.entry.id, name: 'x', size: 1000, key: made.entry.key, addedAt: 1);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()
          ..files[made.entry.id] = made.sealed
          ..files[other.entry.id] = other.sealed,
        lists: Lists(files: [_item(_one, _withoutHash(made.entry)), _item(_two, broken)]),
      );

      await one.run();

      expect(w.server.files, hasLength(1));
      final files = {for (final item in one.lists.files) item.id: item.file};
      expect(files[_one]!.sha256, made.entry.sha256);
      expect(kmServerFileId(files[_two]!), isNull, reason: 'the key does not open it');
    });

    test('a file the body already names is never sent again, and a file the phone lacks is left to another phone', () async {
      final w = _world();
      final made = await _sealed(1000);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();
      w.server.events.clear();

      await one.run();
      await one.run();

      expect(w.server.events.where((event) => event == 'file' || event == 'batch'), isEmpty);
      expect(w.server.files, hasLength(1));

      final small = await _sealed(10, name: 'b.txt');
      final lacking = one.another(
        fileStore: FakeFileStore(),
        lists: Lists(files: [_item(_two, small.entry)]),
      );
      await lacking.run();
      expect(w.server.files, hasLength(1), reason: 'nothing to send: the bytes are not on this phone');
      expect(w.server.items[_two]!.revision, 1);
    });

    test('a second phone fetches the file, opens it, and reads the item as the first wrote it', () async {
      final w = _world();
      final made = await _sealed(70 * 1024);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();

      final store = FakeFileStore();
      final two = one.another(fileStore: store);
      await two.run();

      expect(two.lists.files, one.lists.files);
      expect(store.files[made.entry.id], made.sealed);
      expect(await kma1Decrypt(store.files[made.entry.id]!, unb64(made.entry.key)), hasLength(70 * 1024));
    });

    test('a download stops at the size the item names, and a file that does not open is thrown away', () async {
      final w = _world();
      final made = await _sealed(1000);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();
      final file = w.server.files.values.single;
      file.bytes = Uint8List.fromList([...file.bytes!, ...Uint8List(5000)]);
      final store = FakeFileStore();
      final two = one.another(fileStore: store);

      await two.run();
      expect(store.files, isEmpty, reason: 'more bytes than promised');

      file.bytes = Uint8List.fromList(made.sealed)..[40] ^= 1;
      await two.run();
      expect(store.files, isEmpty, reason: 'it does not open');

      file.bytes = made.sealed;
      await two.run();
      expect(store.files[made.entry.id], made.sealed);
    });

    test('the server file a File item no longer names is deleted, once the item names the new one', () async {
      final w = _world();
      final first = await _sealed(1000);
      final second = await _sealed(1200, name: 'New lease.pdf');
      final store = FakeFileStore()
        ..files[first.entry.id] = first.sealed
        ..files[second.entry.id] = second.sealed;
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: store,
        lists: Lists(files: [_item(_one, first.entry)]),
      );
      await one.run();
      final oldFile = w.server.files.keys.single;

      one.lists = Lists(files: [_item(_one, second.entry, updatedAt: w.clock.ms + 1)]);
      await one.run();

      expect(w.server.files.keys, isNot(contains(oldFile)));
      expect(w.server.files.values.single.bytes, second.sealed);
      expect(kmServerFileId(one.lists.files.single.file), w.server.files.keys.single);
    });

    test('a run that fetches nothing asks the store for nothing', () async {
      final w = _world();
      final made = await _sealed(1000);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();

      final store = _WatchedStore(made.sealed);
      final files = KmFiles(store: store, connection: one.connection, server: FakeKemlockServer.url, fetchMissing: false);
      final fetched = await files.download(SyncDoc(files: one.lists.files), itemIdOf: (id) => id);

      expect(fetched, 0);
      expect(store.asked, isEmpty);
    });
  });

  group('kmFetchFile', () {
    Future<({KmPhone phone, SealedAttachment made})> uploaded(FakeKemlockServer server, KmClock clock) async {
      final made = await _sealed(2000);
      final phone = KmPhone(
        server,
        clock: clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await phone.run();
      return (phone: phone, made: made);
    }

    test('gives the plain bytes of the file the entry names, checked against its hash', () async {
      final w = _world();
      final up = await uploaded(w.server, w.clock);
      final entry = up.phone.lists.files.single.file;

      final plain = await kmFetchFile(connection: up.phone.connection, server: FakeKemlockServer.url, itemId: _one, entry: entry);

      expect(plain, hasLength(2000));
      expect(sha256Hex(plain), entry.sha256);
    });

    test('says why it cannot: no server file, a hash that differs, a size the server exceeds, a key that does not open it', () async {
      final w = _world();
      final up = await uploaded(w.server, w.clock);
      final entry = up.phone.lists.files.single.file;
      Future<KmFileProblem?> problem(NoteAttachment bad) async {
        try {
          await kmFetchFile(connection: up.phone.connection, server: FakeKemlockServer.url, itemId: _one, entry: bad);
          return null;
        } on KmFileError catch (e) {
          return e.problem;
        }
      }

      NoteAttachment changed({String? hash, int? size, String? key}) => NoteAttachment(
        id: entry.id,
        name: entry.name,
        size: size ?? entry.size,
        key: key ?? entry.key,
        addedAt: entry.addedAt,
        sha256: hash ?? entry.sha256,
        extra: entry.extra,
      );

      expect(await problem(up.made.entry), KmFileProblem.notOnServer);
      expect(await problem(changed(hash: '0' * 64)), KmFileProblem.hashMismatch);
      expect(await problem(changed(size: 100)), KmFileProblem.tooLarge);
      expect(await problem(changed(key: b64(randomBytes(32)))), KmFileProblem.damaged);
    });
  });

  group('a new item made from an old one', () {
    test('sends the sealed bytes again under the new item, keeping every member but the server id', () async {
      final w = _world();
      final made = await _sealed(5000);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();
      final original = one.lists.files.single.file;
      // The copy is saved first without the file, as a body never names a file the server lacks
      final copy = kmWithoutServerFiles(_entry(_two, original));
      expect(kmAttachmentsOf(copy).single.extra, isNot(contains(kmFileKey)));
      final other = one.another(lists: Lists(files: [_item(_two, kmAttachmentsOf(copy).single)]));
      await other.run();
      final files = KmFiles(store: FakeFileStore(), connection: other.connection, server: FakeKemlockServer.url);

      final sent = await files.resendFiles(_entry(_two, original), fromItemId: _one, toItemId: _two);

      expect(sent.failed, isEmpty);
      final entry = kmAttachmentsOf(sent.entry).single;
      expect(entry.id, original.id);
      expect(entry.key, original.key);
      expect(entry.sha256, original.sha256);
      expect(kmServerFileId(entry), isNot(kmServerFileId(original)));
      final under = w.server.files[kmServerFileId(entry)]!;
      expect(under.itemId, _two);
      expect(under.bytes, made.sealed, reason: 'as they were: nothing was decrypted');
    });

    test('a file gone from the old item stays unnamed and is listed', () async {
      final w = _world();
      final made = await _sealed(500);
      final one = KmPhone(
        w.server,
        clock: w.clock,
        fileStore: FakeFileStore()..files[made.entry.id] = made.sealed,
        lists: Lists(files: [_item(_one, made.entry)]),
      );
      await one.run();
      final original = one.lists.files.single.file;
      w.server.files.clear();
      final files = KmFiles(store: FakeFileStore(), connection: one.connection, server: FakeKemlockServer.url);

      final sent = await files.resendFiles(_entry(_two, original), fromItemId: _one, toItemId: _two);

      expect(sent.failed, [original.id]);
      expect(kmServerFileId(kmAttachmentsOf(sent.entry).single), isNull);
    });
  });

  group('kmPushItemWithFiles', () {
    test('writes the item, uploads the file, writes it again naming it, and deletes what it no longer names last', () async {
      final w = _world();
      final first = await _sealed(1000);
      final second = await _sealed(1500, name: 'New.pdf');
      final phone = KmPhone(w.server, clock: w.clock);
      final store = FakeFileStore()
        ..files[first.entry.id] = first.sealed
        ..files[second.entry.id] = second.sealed;
      final files = KmFiles(store: store, connection: phone.connection, server: FakeKemlockServer.url);
      final server = KmMoveServer(connection: phone.connection, server: FakeKemlockServer.url, crypto: phone.crypto);

      final pushed = await kmPushItemWithFiles(server: server, files: files, entry: _entry(_one, first.entry), now: 5);

      expect(w.server.events, ['batch', 'file', 'batch']);
      expect(pushed.revision, 2);
      expect(pushed.unsent, isEmpty);
      final named = kmAttachmentsOf(pushed.entry).single;
      expect(named.sha256, first.entry.sha256);
      expect(w.server.files[kmServerFileId(named)]!.bytes, first.sealed);

      w.server.events.clear();
      final again = await kmPushItemWithFiles(
        server: server,
        files: files,
        entry: _entry(_one, second.entry),
        revision: pushed.revision,
        previous: pushed.entry,
        now: 6,
      );

      expect(w.server.events, ['batch', 'file', 'batch']);
      expect(again.revision, 4);
      expect(w.server.files.keys, [kmServerFileId(kmAttachmentsOf(again.entry).single)], reason: 'the old file went last');

      w.server.events.clear();
      final unchanged = await kmPushItemWithFiles(
        server: server,
        files: files,
        entry: again.entry,
        revision: again.revision,
        previous: again.entry,
        now: 7,
      );
      expect(w.server.events, ['batch'], reason: 'a file the body names is not sent again');
      expect(unchanged.revision, 5);
    });

    test('a file the store lacks is left unsent and listed, the item written without it', () async {
      final w = _world();
      final made = await _sealed(1000);
      final phone = KmPhone(w.server, clock: w.clock);
      final files = KmFiles(store: FakeFileStore(), connection: phone.connection, server: FakeKemlockServer.url);
      final server = KmMoveServer(connection: phone.connection, server: FakeKemlockServer.url, crypto: phone.crypto);

      final pushed = await kmPushItemWithFiles(server: server, files: files, entry: _entry(_one, made.entry), now: 5);

      expect(pushed.revision, 1);
      expect(pushed.unsent, [made.entry.id]);
      expect(w.server.files, isEmpty);
    });
  });
}

/// A store that remembers what it was asked.
class _WatchedStore implements KmFileStore {
  _WatchedStore(this.sealed);

  final Uint8List sealed;
  final asked = <String>[];

  @override
  Future<bool> exists(String id) async {
    asked.add('exists $id');
    return false;
  }

  @override
  Future<Uint8List?> readSealed(String id) async {
    asked.add('read $id');
    return sealed;
  }

  @override
  Future<void> writeSealed(String id, Uint8List sealed) async {
    asked.add('write $id');
  }
}
