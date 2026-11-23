/// The check step of a move (move-off-vaultwarden-sync, design 4, task 3.4): after the last batch and the
/// files, the phone signs one manifest for the user's owner, as `add-account-crypto` design 6 requires
/// after a move, then reads `GET /kem/v1/sync` from an empty cursor and compares it with what it sent.
/// Nothing is changed in the old store before this passes.
///
/// - **The manifest.** One manifest is signed above the counter of the latest one, and sent once. It
///   lists every item this move wrote at the revision and ciphertext hash the server holds, and every
///   other item the latest manifest already listed at that same state. An item no manifest lists is
///   left out, as a Kemlock sync holds it out of the merge until one does (`km_sync.dart`); an item the
///   latest manifest lists that the server no longer returns, or returns at a lower revision, stops
///   the move as older data. A 409 (another device signed first) reads again and signs again.
/// - **The read-back.** Each entry of the record's `sent` must come back: its id as a live item that
///   opens with the account crypto, with `sha256(canonical(toJson()))` equal to the hash recorded
///   when it was sent, and listed by the manifest the server returns at its revision and ciphertext
///   hash.
/// - **The files.** The server reports no size or SHA-256 for a file (task 1.1), so each file a moved
///   note names is downloaded and its SHA-256 compared with the one recorded when it went up, or, for
///   a file another phone uploaded that this phone lacks, opened with the attachment's own key.
///
/// A local edit made after the copy is no mismatch: the hashes compared are the ones recorded when
/// each entry was sent, never the vault's entries now, and an edit goes up at the first Kemlock sync.
///
/// When something differs, the record goes back to the copy step with the entries and files to send
/// again, and the move stops with [KmMoveIssue.checkFailed]; the next attempt resends what differs. The
/// cache the read-back built (the items, the cursor and the manifest) is returned on success, for the
/// first Kemlock sync to start from instead of reading everything again.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/manifest.dart';
import '../../../crypto/account/manifest_compare.dart';
import '../../../crypto/attachment_format.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';
import 'km_api.dart';
import 'km_cache.dart';
import 'km_files.dart';
import 'km_kinds.dart';
import 'km_move_plan.dart';
import 'km_move_record.dart';
import 'km_move_server.dart';
import 'km_sync.dart' show KmSyncError, KmSyncIssue;

/// How many times the check signs again when another device signs first.
const _attempts = 3;

/// What a check that passed leaves: the record with `checked` set, and the cache the read-back built.
typedef KmCheckResult = ({KmMoveRecord record, KmCache cache});

/// Signs the manifest and reads the vault back.
class KmMoveCheck {
  KmMoveCheck({required this.server});

  final KmMoveServer server;

  KmApi get _api => server.api;

  /// Runs the check for [record]'s sent entries. [save] stores the record when the check fails (back at
  /// the copy step, with what to send again) and when it passes. Throws a [KmMoveError] of
  /// [KmMoveIssue.checkFailed] when something differs, and a `KmSyncError` when the server hands back older
  /// data than its own manifest says.
  Future<KmCheckResult> run(KmMoveRecord record, {required int now, required Future<void> Function(KmMoveRecord next) save}) async {
    final owner = server.crypto.owner;
    final moved = {for (final entryId in record.sent.keys) kmItemId(entryId, owner)};
    for (var attempt = 1; ; attempt++) {
      final before = await server.read();
      final signed = await _sign(before, moved);
      try {
        await server.connection.call((token) => _api.putManifest(server.server, token, owner.toWire(), signed.bytes, signed.signature));
      } on KmError catch (e) {
        if (e.problem == KmProblem.stale && attempt < _attempts) {
          continue;
        }
        rethrow;
      }
      final back = await server.read();
      final fetched = await server.connection.call((token) => _api.manifest(server.server, token, owner.toWire()));
      if (fetched == null) {
        throw const KmMoveError(KmMoveIssue.checkFailed, detail: 'the server returns no manifest');
      }
      final manifest = await _verified(fetched.manifest, fetched.signature);

      final failures = _compare(record, back, manifest);
      final badFiles = await _checkFiles(record, back, failures);
      if (failures.isNotEmpty || badFiles.isNotEmpty) {
        final entries = {...failures, ...await _notesOf(badFiles, back, record)};
        final next = record.copyWith(
          step: KmMoveStep.copy,
          checked: false,
          redo: {...record.redo, ...entries}.toList(),
          redoFiles: {...record.redoFiles, ...badFiles}.toList(),
        );
        await save(next);
        throw KmMoveError(KmMoveIssue.checkFailed, ids: entries.toList(), detail: '${failures.length} entries, ${badFiles.length} files');
      }
      final passed = record.copyWith(checked: true, redo: const [], redoFiles: const []);
      await save(passed);
      return (record: passed, cache: _cacheOf(back, fetched, now));
    }
  }

  /// The manifest to send: above the latest counter, listing what this move wrote and what the latest
  /// manifest already listed unchanged.
  Future<({Uint8List bytes, Uint8List signature})> _sign(KmCache view, Set<String> moved) async {
    final owner = server.crypto.owner;
    final fetched = await server.connection.call((token) => _api.manifest(server.server, token, owner.toWire()));
    final latest = fetched == null ? null : await _verified(fetched.manifest, fetched.signature);
    final entries = <ManifestEntry>[];
    for (final MapEntry(key: id, value: item) in view.items.entries) {
      final bytes = uuidBytes(id);
      final hashBytes = item.deleted ? Uint8List(32) : b64urlDecode(item.hash);
      final listed = latest?.entryFor(bytes);
      var list = false;
      if (moved.contains(id) && !item.deleted) {
        list = true;
      } else if (listed != null) {
        if (item.revision < listed.revision) {
          throw KmSyncError(KmSyncIssue.older, detail: 'item $id at ${item.revision}, listed at ${listed.revision}');
        }
        list =
            item.revision == listed.revision &&
            item.deleted == listed.deleted &&
            b64urlEncode(hashBytes) == b64urlEncode(listed.ciphertextHash);
      }
      if (list) {
        entries.add(ManifestEntry(itemId: bytes, revision: item.revision, ciphertextHash: hashBytes, deleted: item.deleted));
      }
    }
    for (final listed in latest?.entries ?? const <ManifestEntry>[]) {
      if (!view.items.containsKey(uuidText(listed.itemId))) {
        throw KmSyncError(KmSyncIssue.older, detail: 'item ${uuidText(listed.itemId)} is listed and gone');
      }
    }
    final manifest = Manifest(owner: owner, counter: (latest?.counter ?? 0) + 1, entries: entries);
    final signed = await server.crypto.signManifest(manifest);
    return (bytes: signed.bytes, signature: signed.signature);
  }

  Future<Manifest> _verified(Uint8List bytes, Uint8List signature) async {
    try {
      return await server.crypto.verifyManifest(bytes, signature);
    } on CorruptedException {
      throw const KmSyncError(KmSyncIssue.older, detail: 'the manifest does not verify');
    } on MalformedException {
      throw const KmSyncError(KmSyncIssue.older, detail: 'the manifest is malformed');
    }
  }

  /// The entry ids that came back missing or different, or that the manifest doesn't list at their
  /// revision and ciphertext hash.
  Set<String> _compare(KmMoveRecord record, KmCache back, Manifest manifest) {
    final failures = <String>{};
    for (final MapEntry(key: entryId, value: sent) in record.sent.entries) {
      final id = kmItemId(entryId, server.crypto.owner);
      final item = back.items[id];
      if (item == null || item.deleted || !item.applied || kmEntryHash(item.entry!) != sent) {
        failures.add(entryId);
        continue;
      }
      final listed = manifest.entryFor(uuidBytes(id));
      if (listed == null || listed.deleted || listed.revision != item.revision || b64urlEncode(listed.ciphertextHash) != item.hash) {
        failures.add(entryId);
      }
    }
    return failures;
  }

  /// The attachment ids whose file doesn't match, among the notes that read back whole.
  Future<Set<String>> _checkFiles(KmMoveRecord record, KmCache back, Set<String> failed) async {
    final bad = <String>{};
    for (final entryId in record.sent.keys) {
      final id = kmItemId(entryId, server.crypto.owner);
      final item = back.items[id];
      if (failed.contains(entryId) || item == null || !item.applied || item.kind != KmKind.note) {
        continue;
      }
      for (final file in SecureNote.fromJson(item.entry!).files) {
        if (!await _fileMatches(record, id, file)) {
          bad.add(file.id);
        }
      }
    }
    return bad;
  }

  Future<bool> _fileMatches(KmMoveRecord record, String itemId, NoteAttachment file) async {
    final fileId = kmServerFileId(file);
    if (fileId == null) {
      return false;
    }
    final expected = kma1Length(file.size);
    final Uint8List bytes;
    // NOTE: the server's file answer carries no size and no SHA-256 (`FileDto` is `{fileId, itemId, size, status}`, and
    // the size is the one announced at upload), so the only way to know a stored file is whole is to download it and
    // hash it here. Keep this download unless the file route reports a SHA-256; a hash would then only replace it.
    try {
      bytes = await server.connection.call((token) => _api.downloadFile(server.server, token, itemId, fileId, maxBytes: expected));
    } on KmError catch (e) {
      // A file the server lacks, or holds longer than its note says, is a file that doesn't match
      if (e.status == 404 || e.problem == KmProblem.tooLarge) {
        return false;
      }
      rethrow;
    }
    if (bytes.length != expected) {
      return false;
    }
    final recorded = record.files[file.id];
    if (recorded != null) {
      return b64urlEncode(hash.sha256.convert(bytes).bytes) == recorded;
    }
    // Another phone uploaded it and this phone never held it: it must open with the attachment's own key
    try {
      await kma1Decrypt(bytes, unb64(file.key));
      return true;
    } on AttachmentDamagedError {
      return false;
    } on FormatException {
      return false;
    }
  }

  /// The entry ids of the notes that name [files].
  Future<Set<String>> _notesOf(Set<String> files, KmCache back, KmMoveRecord record) async => {
    for (final entryId in record.sent.keys)
      if (back.items[kmItemId(entryId, server.crypto.owner)] case final item? when item.applied && item.kind == KmKind.note)
        if (SecureNote.fromJson(item.entry!).files.any((file) => files.contains(file.id))) entryId,
  };

  /// The cache of the read-back: the items, the cursor, the manifest the server returned, and the
  /// deletions seen.
  KmCache _cacheOf(KmCache back, ({Uint8List manifest, Uint8List signature}) manifest, int now) {
    final at = DateTime.fromMillisecondsSinceEpoch(now);
    return KmCache(
      cursor: back.cursor,
      items: back.items,
      manifest: manifest.manifest,
      manifestSignature: manifest.signature,
      deleted: DeletedItems()
          .recordingAll(
            answer: [
              for (final MapEntry(:key, :value) in back.items.entries)
                if (value.deleted) ServerItemState.tombstone(itemId: uuidBytes(key), revision: value.revision),
            ],
            now: at,
          )
          .pruned(at),
    );
  }
}
