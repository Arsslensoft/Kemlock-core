/// Writes one note or File item to Kemlock Server now, with its files, in the order a full run follows
/// (`km_files.dart`): the item first, without a server file for the files just chosen, then each pending
/// file's exact `KMA1` bytes, then the item again naming each file in `kemlockFile` (and its `sha256`), then, last, the
/// removal from the server of the files the item named before and no longer does. A body never names a file the
/// server lacks, and a file the body already names is never sent again.
///
/// It is what the browser extension and the app's "add a file" call to upload at once, without two full syncs. It reads
/// no vault, so the caller says which revision the server holds. Files come from the [KmFiles.store]: it must hold the sealed
/// bytes (`readSealed`) of every pending file, and may answer null for the rest.
///
/// Pure Dart, no Flutter.
library;

import '../../../crypto/account/encoding.dart' show Owner;
import 'km_files.dart';
import 'km_kinds.dart';
import 'km_move_server.dart';

/// What [kmPushItemWithFiles] left on the server.
class KmPushResult {
  const KmPushResult({required this.entry, required this.revision, required this.unsent});

  /// The entry as the server holds it now: its files named when they went up.
  final KmEntry entry;

  /// The revision the server holds, which the next write of the item expects.
  final int revision;

  /// The attachment ids of the files the item names that have no server file: too large for the server, or not in the store. They
  /// are uploaded by a later run, or by another call, when the bytes are there.
  final List<String> unsent;

  @override
  String toString() => 'KmPushResult(revision $revision, ${unsent.length} unsent)';
}

/// Writes [entry], a note or a File item, to [server] and uploads the files it names that have no server file.
///
/// [revision] is the revision the server holds for the item (null for a new item). [previous] is the entry the server held
/// (null for a new item): the files it named that [entry] doesn't, and the ones a replaced file leaves, are deleted from the
/// server at the end. [now] (epoch ms) stamps the second write. The item's id is [kmItemId] of the entry's id under the
/// owner of [server]'s crypto.
///
/// Throws a [KmError] (a `stale` one when another device wrote the item since [revision]: nothing was stored by that write, and the
/// caller reads the item again) and leaves the server consistent whenever it stops: after the first write the item exists, and
/// a retry from the returned or the stored entry sends no file the body already names.
///
/// The caller's `kemlockFile` members are not trusted: the item is written naming only the server files [previous] names for an
/// attachment of the same id and key (with its `sha256`), and none for any other, whose file this call uploads from the store.
Future<KmPushResult> kmPushItemWithFiles({
  required KmMoveServer server,
  required KmFiles files,
  required KmEntry entry,
  int? revision,
  KmEntry? previous,
  required int now,
}) async {
  final trusted = kmTrustedFiles(entry, previous);
  final Owner owner = server.crypto.owner;
  final entryId = kmEntryId(trusted);
  final itemId = kmItemId(entryId, owner);

  Future<int> write(KmEntry next, int? expected) async {
    final stored = await server.send([
      KmMoveWrite(itemId: itemId, entryId: entryId, kind: next.kind, revision: (expected ?? 0) + 1, expected: expected, json: next.json),
    ]);
    return stored.single.revision;
  }

  var held = await write(trusted, revision);
  var current = trusted;
  final named = await files.uploadEntryFiles(trusted, itemId: itemId, now: now);
  if (named != null) {
    current = named;
    held = await write(named, held);
  }
  if (previous != null) {
    await files.deleteRemoved({itemId: _fileIds(previous)}, {itemId: _fileIds(current)});
  }
  return KmPushResult(
    entry: current,
    revision: held,
    unsent: [
      for (final file in kmAttachmentsOf(current))
        if (kmServerFileId(file) == null) file.id,
    ],
  );
}

Set<String> _fileIds(KmEntry entry) => {for (final file in kmAttachmentsOf(entry)) ?kmServerFileId(file)};
