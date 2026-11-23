/// One run of a moved WebDAV space whose copies are both synced (docs/plans/add-server-spaces.md, design 7, tasks 8.2 to 8.4):
/// the WebDAV file is a second target of the space's scope, beside the space on Kemlock Server. A run merges this phone's
/// entries three ways and writes the file exactly as today's sync writes it:
///
/// 1. the server space, through [server]: what other members changed comes down, by the field merge of the space's own run.
///    It goes first so that a copy the space says is closed, or an account that is no longer a member, is known before the file
///    is touched: such a run reads nothing from the file and writes nothing to it;
/// 2. the file, through [runWebDavScope], which is the ordinary run of a WebDAV space: it merges what step 1 left with the file,
///    files and counts included, and writes it back when it differs. What the server brought reaches the members who stay on
///    WebDAV here, and what an older phone wrote there (the frozen merges in `test/compat`) comes in. The write is the same
///    code's, so the bytes of the file are the ones today's sync writes for the same entries; an entry's collection is the
///    server space's metadata and never enters its JSON;
/// 3. the server space again, only when the file brought something this phone didn't hold, so what an older phone wrote goes up.
///
/// A joining phone reads the file once and writes it no more ([writeFile] false): step 2 only reads.
///
/// Which side wins a conflict is the merge's, as everywhere: for an entry both sides changed, the later `updatedAt` wins, field
/// by field for a login's passwords, and a deletion wins over an older copy and loses to a newer one (`mergeScope`). The
/// server space is merged first, then the file against the result, then the server space against what the file brought, so an
/// entry settles to the later of its copies on both sides within the one run.
///
/// A failure of one side doesn't stop the other. If the file can't be reached the server space still syncs. If the server space
/// fails, the file is read and never written, since its chain may close the copy: a failure after the chain was read carries the
/// closure it showed ([ClosedRunError]), and then the file is not even read. The run returns what did sync, with the failure for the
/// scheduler to show. Only when both fail does the run
/// throw. When the server space says this account isn't a member ([BridgeSignal.gone]), the empty answer it gave is never
/// carried into the file or the phone.
///
/// The space's entries pass to the server under the server's space id and come back under it; [applyScope] puts them in the
/// scope again, so the phone keeps the WebDAV id (`rescopedTo` in `space_scope.dart`, done by [server]).
library;

import '../../crypto/bytes.dart';
import '../../models/secure_note.dart';
import '../spaces/server_spaces.dart' show SpaceSyncError, SpaceSyncIssue;
import '../spaces/space_bridge.dart';
import 'attachment_sync.dart';
import 'kemlock/km_backend.dart' show KmSyncResult;
import 'sync.dart';
import 'sync_crypto.dart';
import 'sync_merge.dart';
import 'sync_personal.dart';
import 'webdav.dart';

/// Runs the server space once for what this phone holds: [local] is the space's entries and [state] what the last run kept.
typedef BridgeServerRun = Future<KmSyncResult> Function(Lists local, ScopeState state);

/// What a run of a moved space returns: the merged document to take locally, the ids it holds, the state to keep, how many
/// items were left alone, what the server space said of the WebDAV copy, and the failure of one side, if it had one.
typedef BridgedRun = ({
  SyncDoc doc,
  List<String> known,
  Map<String, Object?> state,
  int skipped,
  BridgeSignal? signal,
  SpaceCopyClosed? reason,
  Object? failure,
});

/// Syncs the moved space [scope] once, through the server space [server] runs and its file [target]. See the top of the file.
/// Throws the failure of the server space when both sides fail.
Future<BridgedRun> runBridged({
  required WebDav webDav,
  required SyncTarget target,
  required String scope,
  required Lists local,
  required ScopeState state,
  required int now,
  required BridgeServerRun server,
  bool writeFile = true,
  AttachmentSync? files,
  void Function(DavAccount dav, List<NoteAttachment> files)? fetchFiles,
}) async {
  // The file step on [lists] after [kept] state: the ordinary run of a WebDAV space, or, for a joining phone, one read
  Future<PersonalRun> fileStep(Lists lists, ScopeState kept) => writeFile
      ? runWebDavScope(webDav: webDav, target: target, local: lists, state: kept, now: now, files: files, fetchFiles: fetchFiles)
      : readWebDavOnce(webDav, target, lists, kept, now);

  // 1. The server space first, so a copy it says is closed, or an account that is no member, is known before the file is touched
  KmSyncResult? served;
  Object? failure;
  try {
    served = await server(local, state);
  } catch (e) {
    failure = e;
  }
  if (served == null) {
    final closed = failure is ClosedRunError ? failure : null;
    if (closed != null) {
      // The verified chain closes the copy, and a failure after it doesn't undo that: the file is neither read nor written, and
      // the failure is the run's problem
      return (
        doc: listsAsDoc(local),
        known: state.known,
        state: state.extra,
        skipped: 0,
        signal: BridgeSignal.closed,
        reason: closed.reason,
        failure: closed.cause,
      );
    }
    // The server space can't be reached or read, so nothing is known of its copy, which its chain may close: the file is read, so
    // what other phones wrote comes in, and never written. The run says the server failed. Both failing is the server's failure,
    // which came first.
    try {
      final alone = await readWebDavOnce(webDav, target, local, state, now);
      return (doc: alone.doc, known: alone.known, state: alone.state, skipped: 0, signal: null, reason: null, failure: failure);
    } catch (_) {
      throw failure!;
    }
  }
  final taken = takeBridgeSignal(served.state);
  if (taken.signal == BridgeSignal.uncompared) {
    // No fingerprint was compared for the space on this account, so nothing is known of its copy, which its chain may close: the
    // file is read, so what other phones wrote comes in, and never written. The note is left as it is for the person to go
    // through first contact, which the run's problem says; the empty answer of the server space is no deletion of anything
    try {
      final alone = await readWebDavOnce(webDav, target, local, state, now);
      return (
        doc: alone.doc,
        known: alone.known,
        state: alone.state,
        skipped: 0,
        signal: BridgeSignal.uncompared,
        reason: null,
        failure: const SpaceSyncError(SpaceSyncIssue.cantBeChecked, detail: 'no fingerprint was compared for this space on this account'),
      );
    } catch (e) {
      return (
        doc: listsAsDoc(local),
        known: state.known,
        state: state.extra,
        skipped: 0,
        signal: BridgeSignal.uncompared,
        reason: null,
        failure: e,
      );
    }
  }
  if (taken.signal == BridgeSignal.gone || taken.signal == BridgeSignal.pending) {
    // This account isn't in the space, or a joining phone found its move unfinished: the empty answer is no deletion of anything,
    // and the file is not touched
    return (
      doc: listsAsDoc(local),
      known: state.known,
      state: state.extra,
      skipped: 0,
      signal: taken.signal,
      reason: taken.reason,
      failure: null,
    );
  }
  if (taken.signal == BridgeSignal.closed) {
    // The copy is closed, by a removal, replaced keys or the Owner: nothing is read from the file or written to it, from now on
    return (
      doc: served.doc,
      known: served.known,
      state: taken.state,
      skipped: served.skipped,
      signal: BridgeSignal.closed,
      reason: taken.reason,
      failure: null,
    );
  }

  // 2. The file, with what the server space brought. It is given the ids the scope held after the last run, so what was
  // deleted on either side since is deleted in the file too.
  final afterServer = applyScope(local, scope, served.doc);
  final PersonalRun file;
  try {
    file = await fileStep(afterServer, ScopeState(known: state.known, lastSyncAt: state.lastSyncAt, extra: taken.state));
  } catch (e) {
    return (
      doc: served.doc,
      known: served.known,
      state: taken.state,
      skipped: served.skipped,
      signal: taken.signal,
      reason: taken.reason,
      failure: e,
    );
  }

  // 3. The server space again, when the file brought something this phone didn't hold: what an older phone wrote goes up
  final afterFile = applyScope(afterServer, scope, file.doc);
  if (sameLists(afterFile, afterServer)) {
    return (
      doc: file.doc,
      known: file.known,
      state: file.state,
      skipped: served.skipped,
      signal: taken.signal,
      reason: taken.reason,
      failure: null,
    );
  }
  SpaceCopyClosed? closedNow;
  try {
    final again = await server(afterFile, ScopeState(known: served.known, lastSyncAt: state.lastSyncAt, extra: file.state));
    final next = takeBridgeSignal(again.state);
    if (next.signal != BridgeSignal.gone) {
      return (
        doc: again.doc,
        known: again.known,
        state: next.state,
        skipped: again.skipped,
        signal: next.signal ?? taken.signal,
        reason: next.reason ?? taken.reason,
        failure: null,
      );
    }
  } catch (e) {
    // A chain that closed the copy meanwhile closes it, whatever else failed
    failure = e is ClosedRunError ? e.cause : e;
    if (e is ClosedRunError) {
      closedNow = e.reason;
    }
  }
  // The second run of the server space failed or said nothing usable: what the file step merged is kept, and goes up next time
  return (
    doc: file.doc,
    known: file.known,
    state: file.state,
    skipped: served.skipped,
    signal: closedNow == null ? taken.signal : BridgeSignal.closed,
    reason: closedNow ?? taken.reason,
    failure: failure,
  );
}

/// Reads the file once and merges it into [local], writing nothing: what a joining phone does with the copy it found, and a bridged
/// phone whose server space can't be read, since the chain it can't see may close the copy.
Future<PersonalRun> readWebDavOnce(WebDav webDav, SyncTarget target, Lists local, ScopeState state, int now) async {
  final remote = await webDav.readFile(target.dav, target.file);
  final remoteDoc = remote == null ? null : await decryptSyncFile(remote.text, unb64(target.key));
  final merged = mergeScope(await combineKeyCopies(local, remoteDoc), state.known, remoteDoc, now: now);
  return (doc: merged.doc, known: merged.known, state: state.extra, missing: const <NoteAttachment>[]);
}

/// [lists] as a document that deletes nothing: what a run that learned nothing from the server returns, so applying it changes nothing.
SyncDoc listsAsDoc(Lists lists) => SyncDoc(
  accounts: lists.accounts,
  backupServices: lists.backupServices,
  keys: lists.keys,
  notes: lists.notes,
  passkeys: lists.passkeys,
  keyAccounts: lists.keyAccounts,
  contacts: lists.contacts,
  logins: lists.logins,
  cards: lists.cards,
  identities: lists.identities,
);
