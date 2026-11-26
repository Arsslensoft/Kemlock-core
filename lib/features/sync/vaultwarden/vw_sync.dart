/// Syncing a vault's own entries with a home in a Vaultwarden account, item
/// by item: one entry is one item, so each write is checked on its own with
/// `lastKnownRevisionDate`, the way WebDAV sync checks its file with an ETag.
///
/// A run:
///
/// 1. reads the account's revision date, and stops when neither it nor this
///    phone's entries changed since the last run;
/// 2. reads the vault, finds the home note, and stops if it's gone or keeps
///    its entries another way than this phone expects;
/// 3. claims the home's items and decodes them, leaving any it can't read
///    out of the merge and untouched;
/// 4. makes the server's document: the entries, a tombstone for each item in
///    the trash, and one for each id this phone saw at its last sync that is
///    now gone (deleted for good, or its code taken off in Bitwarden);
/// 5. binds a new local account to a linked login with the same secret, so
///    the duplicate check doesn't strip the user's login;
/// 6. merges with `mergeScope`, as WebDAV sync does;
/// 7. works out the writes, creates and updates before removals, and stops
///    to ask when a run would remove more than a quarter of the entries, or
///    take that many off this phone with the runs of the last day;
/// 8. sends them, and starts again from 2 when an item changed meanwhile.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:crypto/crypto.dart';

import '../../../crypto/bytes.dart';
import '../../../models/backup_service.dart';
import '../../../models/contact.dart';
import '../../../models/otp_account.dart';
import '../../../models/passkey.dart';
import '../../../models/secure_note.dart';
import '../../../models/vault_entry.dart';
import '../../../models/vault_key.dart';
import '../../accounts/otp.dart' show normalizeSecret;
import '../removal_guard.dart';
import '../sync.dart';
import '../sync_crypto.dart';
import '../sync_merge.dart';
import 'vw_api.dart';
import 'vw_codec.dart';
import 'vw_file_sync.dart';
import 'vw_formats.dart';
import 'vw_items.dart';
import 'vw_models.dart';

export '../removal_guard.dart' show RemovalChoice, removalWindow, lostLately;

/// Why a Vaultwarden sync stopped before changing anything. The names are
/// the ends of the `sync.problem.*` message ids.
enum VwSyncIssue {
  /// The home note is gone from the vault, or in its trash.
  homeMissing,

  /// Another phone changed how the home keeps its entries.
  modeChanged,

  /// The run would remove many entries; the user decides.
  removals,
}

/// A sync that stopped before changing anything, and why.
class VwSyncError implements Exception {
  const VwSyncError(this.issue, {this.count = 0});

  final VwSyncIssue issue;

  /// For [VwSyncIssue.removals]: how many entries would go.
  final int count;

  @override
  String toString() => 'VwSyncError(${issue.name}${count > 0 ? ', $count' : ''})';
}

/// What a run returns: the merged document to take locally, the ids the
/// scope now holds, the state to keep for next time, how many items were
/// left alone because they can't be read, and the user's own logins that
/// hold codes, by entry id, as the server gave them (still encrypted), or
/// null when the run stopped at the revision date and they didn't change.
typedef VwSyncResult = ({
  SyncDoc doc,
  List<String> known,
  Map<String, Object?> state,
  int skipped,
  Map<String, Map<String, Object?>>? linked,
});

/// What a sync would do, worked out without writing anything: for setup to
/// say what the first sync does before sync is on.
class VwSyncPreview {
  const VwSyncPreview({
    this.toVault = const {},
    this.fromVault = const {},
    this.removedHere = 0,
    this.removedThere = 0,
    this.skipped = 0,
    this.tooLong = const [],
    this.paused = const {},
  });

  /// Entries this phone writes to Vaultwarden, new there or newer here, by kind.
  final Map<EntryKind, int> toVault;

  /// Entries this phone takes from Vaultwarden, new here or newer there, by kind.
  final Map<EntryKind, int> fromVault;

  /// Entries this phone loses, deleted on another device.
  final int removedHere;

  /// Entries Vaultwarden loses.
  final int removedThere;

  /// Items Kemlock can't read, which it leaves as they are.
  final int skipped;

  /// The ids of entries too long for a plain item's notes, which stay here.
  final List<String> tooLong;

  /// Keys, notes and passkeys a plain home would get in the clear once the
  /// user agrees to their kind, by kind: until then they stay here.
  final Map<EntryKind, int> paused;

  /// Accounts this phone writes to Vaultwarden.
  int get toVaultAccounts => toVault[EntryKind.account] ?? 0;

  /// Backup-code lists this phone writes to Vaultwarden.
  int get toVaultServices => toVault[EntryKind.backupService] ?? 0;

  /// Accounts this phone takes from Vaultwarden.
  int get fromVaultAccounts => fromVault[EntryKind.account] ?? 0;

  /// Backup-code lists this phone takes from Vaultwarden.
  int get fromVaultServices => fromVault[EntryKind.backupService] ?? 0;

  /// Whether the sync changes nothing on either side.
  bool get isEmpty => toVault.values.sum + fromVault.values.sum + removedHere + removedThere == 0;

  @override
  String toString() =>
      'VwSyncPreview(to Vaultwarden: ${_counts(toVault)}; from it: ${_counts(fromVault)}; '
      'removed here: $removedHere, there: $removedThere; skipped: $skipped)';
}

/// What the last run left for the sync sheet to say, read back from the
/// scope's state: entries waiting for the user to agree to their kind
/// being written plain, entries too long for the server, and why files
/// didn't go.
class VwRunReport {
  const VwRunReport({this.paused = const {}, this.tooLong = const [], this.noFiles});

  factory VwRunReport.fromState(Map<String, Object?> state) {
    final paused = state['paused'];
    return VwRunReport(
      paused: {
        if (paused is Map<String, Object?>)
          for (final MapEntry(:key, :value) in paused.entries)
            if ((EntryKind.parse(key), value) case (final kind?, final num count) when count > 0) kind: count.toInt(),
      },
      tooLong: [...?(state['tooLong'] as List<Object?>?)?.whereType<String>()],
      noFiles: VwFilesRefusal.values.where((reason) => reason.name == state[vwNoFilesKey]).firstOrNull,
    );
  }

  final Map<EntryKind, int> paused;
  final List<String> tooLong;
  final VwFilesRefusal? noFiles;

  bool get isEmpty => paused.isEmpty && tooLong.isEmpty && noFiles == null;
}

String _counts(Map<EntryKind, int> counts) => [for (final MapEntry(:key, :value) in counts.entries) '$value ${key.name}'].join(', ');

void _count(Map<EntryKind, int> counts, Object entry) => counts.update(EntryKind.of(entry), (n) => n + 1, ifAbsent: () => 1);

/// A Vaultwarden server and the session for it: refreshes the access token
/// when it's about to end, or once when the server refuses it, and hands
/// the new tokens to [onCredentials] to be stored.
class VwConnection {
  VwConnection({
    required this.api,
    required this.server,
    required this._credentials,
    required this.onCredentials,
    this._clock = DateTime.now,
  });

  final VwApi api;
  final Uri server;
  final Future<void> Function(VwCredentials credentials) onCredentials;
  final DateTime Function() _clock;
  VwCredentials _credentials;

  VwCredentials get credentials => _credentials;

  /// Calls [request] with a fresh access token.
  Future<T> call<T>(Future<T> Function(String token) request) async {
    if (_credentials.expiresAt - _clock().millisecondsSinceEpoch < 2 * 60 * 1000) await _refresh();
    try {
      return await request(_credentials.accessToken);
    } on VwError catch (e) {
      if (e.problem != VwProblem.signedOut) rethrow;
      await _refresh();
      return request(_credentials.accessToken);
    }
  }

  Future<void> _refresh() async {
    final credentials = _credentials;
    final VwTokens tokens;
    if (credentials.clientId case final clientId? when credentials.clientSecret != null) {
      // An API key's session has no refresh token: the key signs in again
      final login = await api.signInWithApiKey(
        server,
        clientId: clientId,
        clientSecret: credentials.clientSecret!,
        device: VwDevice(id: credentials.deviceId, type: api.info.deviceType, name: api.info.deviceName),
      );
      tokens = login.tokens;
    } else {
      tokens = await api.refresh(server, credentials.refreshToken);
    }
    _credentials = credentials.withTokens(accessToken: tokens.access, refreshToken: tokens.refresh, expiresAt: tokens.expiresAt);
    await onCredentials(_credentials);
  }

  /// The whole vault's items, still encrypted.
  Future<List<VwCipher>> ciphers() async {
    final vault = await call((token) => api.sync(server, token));
    return [for (final cipher in (vault['ciphers'] as List<Object?>? ?? const []).whereType<Map<String, Object?>>()) VwCipher(cipher)];
  }
}

/// A hash of one scope's entries whatever their order, to tell whether they
/// changed since the last run. Keys, notes and passkeys count only when
/// there are some, so a vault of codes alone hashes as it always did, and
/// so do the kinds the user agreed to have written plain ([agreed]), so
/// that agreeing makes the next run write them.
String scopeSum(Lists lists, {Set<String> agreed = const {}}) {
  List<Map<String, Object?>> sorted(List<VaultEntry> entries) => [
    for (final entry in [...entries]..sort((a, b) => a.id.compareTo(b.id))) entry.toJson(),
  ];
  return b64(
    sha256
        .convert(
          utf8.encode(
            canonical({
              'accounts': sorted(lists.accounts),
              'backupServices': sorted(lists.backupServices),
              if (lists.keys.isNotEmpty) 'keys': sorted(lists.keys),
              if (lists.notes.isNotEmpty) 'notes': sorted(lists.notes),
              if (lists.passkeys.isNotEmpty) 'passkeys': sorted(lists.passkeys),
              if (lists.contacts.isNotEmpty) 'contacts': sorted(lists.contacts),
              if (agreed.isNotEmpty) 'agreed': [...agreed]..sort(),
            }),
          ),
        )
        .bytes,
  );
}

/// How many attempts a run gets when items keep changing under it.
const _attempts = 3;

/// The scope state's key for the entries recent runs took off this phone, for the removal guard
/// (`removal_guard.dart`).
const vwLostKey = lostKey;

/// Syncs a vault's own entries with one home.
class VaultwardenScopeSync {
  VaultwardenScopeSync({required this.connection, required this.reader, required this.target, this.websiteFor, this.files});

  final VwConnection connection;
  final VwReader reader;
  final VaultwardenTarget target;

  /// The vault's attached files, synced as attachments of their notes'
  /// items; without them, notes sync without their files.
  final VwFiles? files;

  /// A new plain login's website, from the 2FA directory, for an issuer.
  final String? Function(String issuer)? websiteFor;

  String _sum(Lists lists) => scopeSum(lists, agreed: target.mode == VaultwardenMode.plain ? target.plainKinds : const {});

  Uint8List? get _sealKey => switch (target.seal) {
    final seal? => unb64(seal.key),
    null => null,
  };

  /// Runs once. [local] is this phone's entries in the scope and [state]
  /// what the last run kept. Throws a [VwSyncError] when it stops before
  /// changing anything, a [VwError] when the server can't be reached or
  /// refuses, and a `key` [SyncFileError] when the sealing key doesn't open
  /// the home.
  Future<VwSyncResult> sync(Lists local, ScopeState state, {required int now, RemovalChoice? choice}) async {
    final sum = _sum(local);
    final revision = await connection.call((token) => connection.api.revisionDate(connection.server, token));
    // Files to fetch or delete again need the vault read, whatever changed
    final filesWaiting = files != null && (state.extra[vwFetchKey] == true || pendingDeletes(state.extra).isNotEmpty);
    if (choice == null && !filesWaiting && state.lastSyncAt != null && state.extra['revision'] == revision && state.extra['sum'] == sum) {
      return (
        doc: SyncDoc(
          accounts: local.accounts,
          backupServices: local.backupServices,
          keys: local.keys,
          notes: local.notes,
          passkeys: local.passkeys,
          keyAccounts: local.keyAccounts,
          contacts: local.contacts,
          logins: local.logins,
          cards: local.cards,
          identities: local.identities,
          files: local.files,
        ),
        known: state.known,
        state: state.extra,
        skipped: (state.extra['skipped'] as num?)?.toInt() ?? 0,
        linked: null,
      );
    }
    for (var attempt = 1; ; attempt++) {
      try {
        return _keepOnKey(await _run(local, state, now: now, choice: choice, revision: revision), local);
      } on VwError catch (e) {
        // Another phone changed an item meanwhile: read it and merge again
        if (e.problem == VwProblem.outOfDate && attempt < _attempts) continue;
        rethrow;
      }
    }
  }

  /// What a first sync with [target] would do, worked out without writing
  /// anything, for setup to show before sync is on. With [newHome], the
  /// home isn't made yet, so Vaultwarden holds none of its entries; plain
  /// storage may still pick up logins with codes.
  Future<VwSyncPreview> preview(Lists local, {required int now, bool newHome = false}) async => (await _plan(
    local,
    const ScopeState(known: []),
    now: now,
    newHome: newHome,
  )).preview;

  Future<VwSyncResult> _run(Lists local, ScopeState state, {required int now, required int revision, RemovalChoice? choice}) async {
    final plan = await _plan(local, state, now: now, keepAll: choice == RemovalChoice.keep);

    // The guard: a run that would remove a lot stops and asks. So does one that takes a few entries
    // off this phone after the runs of the last day took others, when together they are a lot: a
    // server that withholds three items at a time would otherwise empty the vault run by run
    final guard = checkRemovals(
      removals: plan.removals,
      removedHere: plan.preview.removedHere,
      scope: plan.scope,
      recent: lostLately(state.extra, now),
      now: now,
      choice: choice,
    );
    if (guard.stop) throw VwSyncError(VwSyncIssue.removals, count: plan.removals);
    final lostNow = guard.lostNow;

    final writer = VwWriter(userKey: reader.userKey, userId: connection.credentials.userId);
    final creates = [for (final entry in plan.creates) await _create(writer, entry, sshKeyItems: plan.sshKeyItems)];
    final updates = [
      for (final (claim, entry) in plan.updates) (claim, await writer.update(claim, entry, home: target.home, sealKey: _sealKey)),
    ];

    // Creates and updates first, so a run cut short never leaves less than it found
    final api = connection.api;
    final server = connection.server;
    // Each entry's item as written, for its files
    final written = <String, VwCipher>{};
    for (final (index, body) in creates.indexed) {
      written[_idOf(plan.creates[index])] = VwCipher(await connection.call((token) => api.createCipher(server, token, body)));
    }
    for (final (claim, entry) in plan.restores) {
      final restored = VwCipher(await connection.call((token) => api.restoreCipher(server, token, claim.cipher.id)));
      final again = EntryClaim(
        restored,
        id: claim.id,
        kind: claim.kind,
        form: claim.form,
        own: claim.own,
        entry: claim.entry,
        fieldIndex: claim.fieldIndex,
      );
      final body = await writer.update(again, entry, home: target.home, sealKey: _sealKey);
      written[claim.id] = VwCipher(await connection.call((token) => api.updateCipher(server, token, restored.id, body)));
    }
    for (final (claim, body) in updates) {
      written[claim.id] = VwCipher(await connection.call((token) => api.updateCipher(server, token, claim.cipher.id, body)));
    }
    for (final claim in plan.unlinks) {
      final body = await writer.unlink(claim);
      await connection.call((token) => api.updateCipher(server, token, claim.cipher.id, body));
    }
    for (final id in plan.trash) {
      await connection.call((token) => api.trashCipher(server, token, id));
    }

    // Then the files of the notes whose items hold them now
    final files = this.files;
    final fileRun = files == null
        ? null
        : await files.sync(
            connection: connection,
            userKey: reader.userKey,
            mode: target.mode,
            notes: plan.doc.notes,
            items: {...plan.unchanged, ...written},
            before: plan.before,
            removed: removedFileIds(state.extra, local.notes),
            pending: pendingDeletes(state.extra),
          );
    final named = [
      for (final note in plan.doc.notes)
        for (final file in note.files) file.id,
    ];

    return (
      doc: plan.doc,
      known: plan.known,
      state: <String, Object?>{
        'revision': revision,
        'sum': _sum(plan.doc),
        'skipped': plan.skipped,
        if (lostNow.isNotEmpty)
          vwLostKey: [
            for (final run in lostNow) [run.at, run.count],
          ],
        if (plan.tooLong.isNotEmpty) 'tooLong': plan.tooLong,
        if (plan.paused.isNotEmpty) 'paused': {for (final MapEntry(:key, :value) in plan.paused.entries) key.name: value},
        if (fileRun != null && named.isNotEmpty) vwFileIdsKey: named,
        if (fileRun != null && fileRun.pendingDeletes.isNotEmpty) vwPendingDeletesKey: fileRun.pendingDeletes,
        if (fileRun?.refused case final refused?) vwNoFilesKey: refused.name,
        if (fileRun?.fetchLater ?? false) vwFetchKey: true,
      },
      skipped: plan.skipped,
      linked: plan.linked,
    );
  }

  /// Reads the vault and works out a run's writes, writing nothing.
  Future<_Plan> _plan(Lists local, ScopeState state, {required int now, bool keepAll = false, bool newHome = false}) async {
    final ciphers = await connection.ciphers();
    final read = await reader.read(
      ciphers,
      home: target.home,
      sealKey: _sealKey,
      pickUp: target.mode == VaultwardenMode.plain && target.pickUp,
    );
    if (!newHome) {
      final home = read.homes.firstWhereOrNull((claim) => claim.home.id == target.home && !claim.cipher.inTrash);
      if (home == null) throw const VwSyncError(VwSyncIssue.homeMissing);
      if (home.home.mode != target.mode) throw const VwSyncError(VwSyncIssue.modeChanged);
      if (target.mode == VaultwardenMode.sealed) {
        final sealKey = _sealKey;
        final seal = home.home.seal;
        if (sealKey == null || seal == null) throw const SyncFileError(SyncFileProblem.key);
        await decryptSyncFile(jsonEncode(seal), sealKey);
      }
    }

    // Each id's items: the one that counts, and any duplicates
    final byId = <String, List<EntryClaim>>{};
    for (final claim in read.entries) {
      (byId[claim.id] ??= []).add(claim);
    }
    final primary = <String, EntryClaim>{};
    final duplicates = <EntryClaim>[];
    final trashed = <String, EntryClaim>{};
    final protected = <String>{};
    for (final MapEntry(key: id, value: claims) in byId.entries) {
      final live = [
        for (final claim in claims)
          if (!claim.cipher.inTrash) claim,
      ];
      final readable = [
        for (final claim in live)
          if (!claim.unreadable) claim,
      ];
      if (readable.isEmpty) {
        if (live.isNotEmpty) {
          protected.add(id);
        } else {
          trashed[id] = claims.reduce((a, b) => (a.cipher.deletedMs ?? 0) >= (b.cipher.deletedMs ?? 0) ? a : b);
        }
        continue;
      }
      readable.sort((a, b) {
        // This home's form first, then the newest
        final form = (b.form == target.mode ? 1 : 0) - (a.form == target.mode ? 1 : 0);
        return form != 0 ? form : b.cipher.revisionMs.compareTo(a.cipher.revisionMs);
      });
      primary[id] = readable.first;
      duplicates.addAll(readable.skip(1));
    }

    // The server's document. The date of a deletion is the server's word: none is taken for later
    // than this run, so the phone keeps no deletion dated years ahead
    final remoteEntries = <Object>[];
    final tombstones = <Tombstone>[];
    for (final MapEntry(key: id, value: claim) in primary.entries) {
      if (claim.entry case final entry?) {
        remoteEntries.add(entry);
      } else if (claim.removedAt case final at?) {
        tombstones.add(Tombstone(id: id, at: min(at, now)));
      }
    }
    for (final MapEntry(key: id, value: claim) in trashed.entries) {
      tombstones.add(Tombstone(id: id, at: min(claim.cipher.deletedMs ?? now, now)));
    }
    final gone = state.lastSyncAt ?? now;
    for (final id in state.known) {
      if (!byId.containsKey(id)) tombstones.add(Tombstone(id: id, at: gone));
    }
    final remote = _doc(remoteEntries, deleted: keepAll ? const [] : tombstones);

    // Entries left out of the merge, kept here as they are: those whose item
    // can't be read
    final localEntries = _entriesOf(local);
    final localIds = {for (final entry in localEntries) _idOf(entry)};
    bool keptOut(Object entry) => protected.contains(_idOf(entry));

    // An account here with the same secret as a linked or picked-up login
    // takes the login's id: left to the merge's duplicate check, one copy
    // would go, and the login would lose its code
    final linkedBySecret = <String, String>{};
    for (final claim in primary.values) {
      if (!claim.own && claim.entry is OtpAccount && !localIds.contains(claim.id)) {
        linkedBySecret.putIfAbsent(normalizeSecret((claim.entry! as OtpAccount).secret), () => claim.id);
      }
    }
    final rebound = <String>{};
    final merging = <Object>[];
    for (final entry in localEntries) {
      if (keptOut(entry)) continue;
      if (entry is! OtpAccount) {
        merging.add(entry);
        continue;
      }
      final ownClaim = primary[entry.id];
      final bound = ownClaim == null || ownClaim.own ? linkedBySecret.remove(normalizeSecret(entry.secret)) : null;
      if (bound != null) rebound.add(entry.id);
      merging.add(bound == null ? entry : entry.copyWith(id: bound));
    }

    final known = [
      for (final id in state.known)
        if (!protected.contains(id)) id,
    ];
    final merged = mergeScope(await combineKeyCopies(_doc(merging), remote), keepAll ? const [] : known, remote, now: now);
    final entries = <String, Object>{for (final entry in _entriesOf(merged.doc)) _idOf(entry): entry};

    // Whether the user agreed to [entry]'s kind being written in the clear
    bool agreed(Object entry) {
      final kind = EntryKind.of(entry);
      return target.mode != VaultwardenMode.plain || !kind.isLater || target.plainKinds.contains(kind.name);
    }

    // A plain SSH key goes in an SSH key item where the server keeps them
    bool? sshKeyItems;
    Future<bool> keepsSshKeys() async => sshKeyItems ??= keepsSshKeyItems(await connection.api.config(connection.server));

    // Entries this run doesn't write, kept here as they are: in a plain
    // home, those of a kind the user hasn't agreed to have written in the
    // clear, and items whose notes are more than the server takes
    final paused = <EntryKind, int>{};
    final tooLong = <String>[];
    final heldNew = <String>{};
    Future<bool> held(Object entry, EntryClaim? into) async {
      if (!agreed(entry)) {
        _count(paused, entry);
        return true;
      }
      if (!tooLongForNotes(await _plainNotes(entry, into, keepsSshKeys))) return false;
      tooLong.add(_idOf(entry));
      return true;
    }

    // The writes, and what goes each way
    final creates = <Object>[];
    final restores = <(EntryClaim, Object)>[];
    final updates = <(EntryClaim, Object)>[];
    final trash = <String>[];
    final unlinks = <EntryClaim>[];
    final unchanged = <String, VwCipher>{};
    var removedThere = 0;
    final toVault = <EntryKind, int>{};
    for (final MapEntry(key: id, value: entry) in entries.entries) {
      final claim = primary[id];
      if (claim == null) {
        final inTrash = trashed[id];
        final restore = inTrash != null && inTrash.own && inTrash.form == target.mode && !inTrash.unreadable;
        if (await held(entry, restore ? inTrash : null)) {
          // Not in Vaultwarden, so not among what the scope holds either
          heldNew.add(id);
          continue;
        }
        if (restore) {
          restores.add((inTrash, entry));
        } else {
          creates.add(entry);
        }
        _count(toVault, entry);
        continue;
      }
      if (claim.form != target.mode) {
        // Left from before the home changed how it keeps entries; held, the old item stays
        if (await held(entry, null)) continue;
        creates.add(entry);
        _count(toVault, entry);
        if (claim.own) {
          trash.add(claim.cipher.id);
        } else {
          unlinks.add(claim);
        }
        continue;
      }
      final same = claim.entry != null && canonical(_json(claim.entry!)) == canonical(_json(entry));
      if (same) {
        unchanged[id] = claim.cipher;
      } else if (!await held(entry, claim)) {
        updates.add((claim, entry));
        _count(toVault, entry);
      }
    }
    for (final MapEntry(key: id, value: claim) in primary.entries) {
      if (entries.containsKey(id) || claim.entry == null) continue;
      removedThere++;
      if (claim.own) {
        trash.add(claim.cipher.id);
      } else {
        unlinks.add(claim);
      }
    }
    for (final claim in duplicates) {
      if (claim.own) {
        trash.add(claim.cipher.id);
      } else if (!claim.pickedUp) {
        unlinks.add(claim);
      }
    }

    // What this phone takes: new here, or changed by the merge
    final mine = {for (final entry in merging) _idOf(entry): canonical(_json(entry))};
    final fromVault = <EntryKind, int>{};
    for (final MapEntry(key: id, value: entry) in entries.entries) {
      if (mine[id] != canonical(_json(entry))) _count(fromVault, entry);
    }

    final removedHere = localEntries.where((entry) {
      final id = _idOf(entry);
      return !entries.containsKey(id) && !keptOut(entry) && !rebound.contains(id);
    }).length;
    final removedIds = {...trash, for (final claim in unlinks) claim.cipher.id};

    // The merge, and the entries left out of it as they were
    final kept = _doc([...entries.values, ...localEntries.where(keptOut)], deleted: merged.doc.deleted);
    return _Plan(
      creates: creates,
      restores: restores,
      updates: updates,
      unlinks: unlinks,
      trash: trash,
      removals: removedHere + removedThere,
      scope: max(localIds.length, primary.length),
      doc: kept,
      known: [
        for (final id in merged.known)
          if (!heldNew.contains(id)) id,
        ...protected,
      ],
      skipped: protected.length,
      tooLong: tooLong,
      paused: paused,
      sshKeyItems: sshKeyItems ?? false,
      unchanged: unchanged,
      before: {
        for (final MapEntry(key: id, value: claim) in primary.entries)
          if (claim.entry case final SecureNote note) id: note,
      },
      linked: {
        for (final MapEntry(key: id, value: claim) in primary.entries)
          if (!claim.own && claim.form == VaultwardenMode.plain && entries.containsKey(id) && !removedIds.contains(claim.cipher.id))
            id: claim.cipher.json,
      },
      preview: VwSyncPreview(
        toVault: toVault,
        fromVault: fromVault,
        removedHere: removedHere,
        removedThere: removedThere,
        skipped: protected.length,
        tooLong: tooLong,
        paused: paused,
      ),
    );
  }

  /// What a plain item of [entry] holds in its notes, or null when Kemlock
  /// writes none there: in a sealed home, or in the user's own login. [into]
  /// is the item it goes in, null for a new one.
  Future<String?> _plainNotes(Object entry, EntryClaim? into, Future<bool> Function() keepsSshKeys) async {
    if (target.mode != VaultwardenMode.plain) return null;
    final item = into != null && into.form == VaultwardenMode.plain ? into : null;
    if (EntryKind.of(entry).isLater) {
      final ssh =
          entry is VaultKey &&
          (item != null
              ? item.cipher.type == CipherType.sshKey
              : entry.kind == KeyKind.ssh && await keepsSshKeys() && await sshKeyValues(entry) != null);
      return laterValues(entry, sshItem: ssh)['notes'] as String?;
    }
    if (item != null && !item.own) return null;
    return plainValues(entry, own: true)['notes'] as String?;
  }

  Future<Map<String, Object?>> _create(VwWriter writer, Object entry, {bool sshKeyItems = false}) => writer.create(
    entry,
    form: target.mode,
    home: target.home,
    folderId: target.folderId,
    sealKey: _sealKey,
    website: entry is OtpAccount && target.mode == VaultwardenMode.plain ? websiteFor?.call(entry.issuer) : null,
    sshKeyItems: sshKeyItems,
  );
}

/// What a run works out before it writes: the writes, in the order they're
/// sent, and what this phone takes once they're done.
class _Plan {
  const _Plan({
    required this.creates,
    required this.restores,
    required this.updates,
    required this.unlinks,
    required this.trash,
    required this.removals,
    required this.scope,
    required this.doc,
    required this.known,
    required this.skipped,
    required this.linked,
    required this.preview,
    this.tooLong = const [],
    this.paused = const {},
    this.sshKeyItems = false,
    this.unchanged = const {},
    this.before = const {},
  });

  /// Entries with no item yet.
  final List<Object> creates;

  /// Kemlock's items to take out of the trash, and what they hold then.
  final List<(EntryClaim, Object)> restores;

  /// Items whose entry changed, and what they hold then.
  final List<(EntryClaim, Object)> updates;

  /// Logins of the user's to take the code off.
  final List<EntryClaim> unlinks;

  /// Kemlock's items to move to the trash, by cipher id.
  final List<String> trash;

  /// How many entries the run removes, here and in Vaultwarden, and how many
  /// the scope holds on the larger side: for the guard.
  final int removals;
  final int scope;

  final SyncDoc doc;
  final List<String> known;
  final int skipped;
  final Map<String, Map<String, Object?>> linked;
  final VwSyncPreview preview;

  /// Entries whose plain item would hold more notes than the server takes:
  /// not written, kept here.
  final List<String> tooLong;

  /// Entries of kinds the user hasn't agreed to have written plain, by kind.
  final Map<EntryKind, int> paused;

  /// Whether the server keeps SSH key items, when the run had to ask.
  final bool sshKeyItems;

  /// The items that already hold their entry as merged, by entry id.
  final Map<String, VwCipher> unchanged;

  /// Each note as its item held it before the run, by id.
  final Map<String, SecureNote> before;
}

Map<String, Object?> _json(Object entry) => (entry as VaultEntry).toJson();

String _idOf(Object entry) => (entry as VaultEntry).id;

/// [result] with this phone's accounts on a security key, its logins, cards, identities and File items in
/// its document, as they were. Vaultwarden holds none of them (it has no File type: a File item stays
/// on this phone and in the other syncs, and a run never uploads, deletes or drops one), plain or
/// sealed (an item with no secret has no place there; logins don't travel
/// there yet), and the vault takes the document in place of its lists
/// (openspec: add-security-key-codes, decision 10; add-passwords).
VwSyncResult _keepOnKey(VwSyncResult result, Lists local) => (
  doc: SyncDoc(
    accounts: result.doc.accounts,
    backupServices: result.doc.backupServices,
    keys: result.doc.keys,
    notes: result.doc.notes,
    passkeys: result.doc.passkeys,
    keyAccounts: local.keyAccounts,
    contacts: result.doc.contacts,
    logins: local.logins,
    cards: local.cards,
    identities: local.identities,
    files: local.files,
    deleted: result.doc.deleted,
    extra: result.doc.extra,
  ),
  known: result.known,
  state: result.state,
  skipped: result.skipped,
  linked: result.linked,
);

/// Every entry of [lists], of every kind.
List<Object> _entriesOf(Lists lists) => [
  ...lists.accounts,
  ...lists.backupServices,
  ...lists.keys,
  ...lists.notes,
  ...lists.passkeys,
  ...lists.contacts,
];

/// A document of [entries], each in the list of its kind.
SyncDoc _doc(Iterable<Object> entries, {List<Tombstone> deleted = const []}) => SyncDoc(
  accounts: [...entries.whereType<OtpAccount>()],
  backupServices: [...entries.whereType<BackupService>()],
  keys: [...entries.whereType<VaultKey>()],
  notes: [...entries.whereType<SecureNote>()],
  passkeys: [...entries.whereType<Passkey>()],
  contacts: [...entries.whereType<Contact>()],
  deleted: deleted,
);
