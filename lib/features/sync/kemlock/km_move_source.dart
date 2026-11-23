/// The first step of a move (move-off-vaultwarden-sync, design 1, task 3.1): the old store's ordinary
/// run, with files, merged into the vault before anything is copied. It is the engine's own run, as the
/// scheduler makes it: `VaultwardenScopeSync` through its backend, or the WebDAV personal run
/// (`runWebDavScope`). Both already have the MAC checks, the duplicate rules, the removal guard,
/// `combineKeyCopies` and the file downloads, so the move needs no second decoder.
///
/// A run that stops (removal guard, home gone, network, wrong key) stops the move with that run's own
/// error, which `problemOf` reads, before one request goes to the Kemlock API. A WebDAV run that leaves a
/// file to be fetched outside the run fetches it here, because the move can't reach its check while a
/// named file is neither on the phone nor on the Kemlock API.
///
/// Pure Dart, no Flutter.
library;

import '../../../crypto/attachment_format.dart';
import '../../../crypto/bytes.dart';
import '../../../models/secure_note.dart';
import '../attachment_sync.dart';
import '../removal_guard.dart';
import '../sync.dart';
import '../sync_merge.dart';
import '../sync_personal.dart';
import '../vaultwarden/vw_models.dart';
import '../vaultwarden/vw_sync.dart' show VwSyncResult;
import '../webdav.dart';
import 'km_move_record.dart';

/// What the old store's run returns: the merged document to take locally, the ids the scope holds now
/// and the state to keep, which the old scope goes on with (a plain home's copy keeps syncing).
class KmMoveSynced {
  const KmMoveSynced({required this.doc, required this.known, required this.state});

  final SyncDoc doc;
  final List<String> known;
  final Map<String, Object?> state;
}

/// The old store a move runs once and then copies.
abstract interface class KmMoveSource {
  /// [vaultwardenSource] or [webdavSource].
  String get name;

  /// The old store's address: the Vaultwarden server, or the WebDAV folder.
  String get server;

  /// A Vaultwarden home's id and how it keeps entries; null for WebDAV.
  String? get home;
  String? get mode;

  /// Runs once. [local] is the vault's own entries and [state] what the old scope's last run kept.
  /// Throws what that run throws.
  Future<KmMoveSynced> sync(Lists local, ScopeState state, {required int now, RemovalChoice? choice});
}

/// One Vaultwarden run of the vault's own scope, as `VaultwardenBackend.sync` makes it.
typedef VwRun = Future<VwSyncResult> Function(Lists local, ScopeState state, {required int now, RemovalChoice? choice});

/// A Vaultwarden home, sealed or plain.
class VaultwardenMoveSource implements KmMoveSource {
  VaultwardenMoveSource({required this.target, required this.run});

  final VaultwardenTarget target;
  final VwRun run;

  @override
  String get name => vaultwardenSource;

  @override
  String get server => target.server;

  @override
  String? get home => target.home;

  @override
  String? get mode => target.mode.name;

  @override
  Future<KmMoveSynced> sync(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final result = await run(local, state, now: now, choice: choice);
    return KmMoveSynced(doc: result.doc, known: result.known, state: result.state);
  }
}

/// A WebDAV personal vault.
class WebDavMoveSource implements KmMoveSource {
  WebDavMoveSource({required this.webDav, required this.target, this.files});

  final WebDav webDav;
  final SyncTarget target;

  /// The vault's attached files; without them, notes move without their files.
  final AttachmentSync? files;

  @override
  String get name => webdavSource;

  @override
  String get server => target.dav.url;

  @override
  String? get home => null;

  @override
  String? get mode => null;

  @override
  Future<KmMoveSynced> sync(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final run = await runWebDavScope(webDav: webDav, target: target, local: local, state: state, now: now, files: files);
    final attached = files;
    if (attached != null) {
      for (final file in run.missing) {
        await _fetch(attached, file);
      }
    }
    return KmMoveSynced(doc: run.doc, known: run.known, state: run.state);
  }

  /// Fetches one file the notes name and the phone lacks, and keeps it only once it opens with its key. A
  /// file the folder lacks, or that doesn't open, is left: the files step says which note misses it.
  Future<void> _fetch(AttachmentSync files, NoteAttachment file) async {
    final bytes = await webDav.readBytes(target.dav, syncedFileName(file.id), maxBytes: kma1Length(attachmentSizeLimit));
    if (bytes == null) return;
    try {
      await kma1Decrypt(bytes, unb64(file.key));
    } on AttachmentDamagedError {
      return;
    } on FormatException {
      return;
    }
    await files.store.writeSealed(files.vaultId, file.id, bytes);
  }
}
