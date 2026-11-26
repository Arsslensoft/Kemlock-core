/// Sync, ported from `sync.ts`: one scope at a time, this device's
/// entries are merged with the encrypted file in a WebDAV folder the user
/// controls, and the result is written back when it differs. No Kemlock
/// server is involved.
///
/// The settings here are stored as JSON (see `sync_store.dart`), so each
/// class keeps the keys it doesn't know and writes them back.
library;

import 'dart:math' show max;

import '../../crypto/bytes.dart';
import '../../models/json.dart';
import '../spaces/server_spaces.dart' show SpaceSyncError, SpaceSyncIssue;
import '../spaces/space_bridge.dart' show ClosedRunError;
import 'kemlock/km_api.dart';
import 'kemlock/km_models.dart';
import 'kemlock/km_sync.dart';
import 'sync_crypto.dart';
import 'sync_merge.dart';
import 'vaultwarden/vw_api.dart';
import 'vaultwarden/vw_models.dart';
import 'vaultwarden/vw_sync.dart';
import 'webdav.dart';

/// Where one scope syncs to, and the key its file is encrypted with.
class SyncTarget {
  const SyncTarget({required this.dav, required this.file, required this.key, this.kdf, this.extra = const {}});

  factory SyncTarget.fromJson(Map<String, Object?> json) => SyncTarget(
    dav: DavAccount.fromJson(_object(json['dav'])),
    file: asString(json['file']),
    key: asString(json['key']),
    kdf: json['kdf'] is Map<String, Object?> ? Kdf.fromJson(json['kdf']! as Map<String, Object?>) : null,
    extra: extraKeys(json, const {'dav', 'file', 'key', 'kdf'}),
  );

  final DavAccount dav;

  /// The file's name in the folder.
  final String file;

  /// AES-256 key, base64.
  final String key;

  /// Set for a vault's own file, whose key comes from a passphrase.
  final Kdf? kdf;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'dav': dav.toJson(), 'file': file, 'key': key, 'kdf': ?kdf?.toJson(), ...extra};

  @override
  bool operator ==(Object other) => other is SyncTarget && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(dav, file);

  /// Leaves the key and the password out, so they never end up in a log.
  @override
  String toString() => 'SyncTarget($dav, $file)';
}

/// A shared space this vault belongs to.
class Space {
  const Space({required this.id, required this.name, required this.target, required this.joinedAt, this.extra = const {}});

  factory Space.fromJson(Map<String, Object?> json) => Space(
    id: asString(json['id']),
    name: asString(json['name']),
    target: SyncTarget.fromJson(_object(json['target'])),
    joinedAt: asInt(json['joinedAt']) ?? 0,
    extra: extraKeys(json, const {'id', 'name', 'target', 'joinedAt'}),
  );

  final String id;
  final String name;
  final SyncTarget target;

  /// Epoch ms this device joined or made the space.
  final int joinedAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'id': id, 'name': name, 'target': target.toJson(), 'joinedAt': joinedAt, ...extra};

  @override
  bool operator ==(Object other) => other is Space && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(id, name);

  @override
  String toString() => 'Space($id, $name, $target)';
}

/// The open vault's sync settings.
class SyncSettings {
  const SyncSettings({this.personal, this.spaces = const [], this.vaultwarden, this.kemlock, this.extra = const {}});

  /// Reads stored settings; anything that isn't an object reads as sync off.
  factory SyncSettings.fromJson(Object? json) {
    if (json is! Map<String, Object?>) return const SyncSettings();
    return SyncSettings(
      personal: json['personal'] is Map<String, Object?> ? SyncTarget.fromJson(json['personal']! as Map<String, Object?>) : null,
      spaces: [
        if (json['spaces'] case final List<Object?> spaces)
          for (final space in spaces.whereType<Map<String, Object?>>()) Space.fromJson(space),
      ],
      vaultwarden: json['vaultwarden'] is Map<String, Object?>
          ? VaultwardenTarget.fromJson(json['vaultwarden']! as Map<String, Object?>)
          : null,
      kemlock: json['kemlock'] is Map<String, Object?> ? KemlockTarget.fromJson(json['kemlock']! as Map<String, Object?>) : null,
      extra: extraKeys(json, const {'personal', 'spaces', 'vaultwarden', 'kemlock'}),
    );
  }

  /// Where the vault's own entries sync through WebDAV, or null.
  final SyncTarget? personal;
  final List<Space> spaces;

  /// Where the vault's own entries sync in Vaultwarden, or null. At most one
  /// of [personal] and this is set. Builds from before Vaultwarden sync keep
  /// it among the keys they don't know, and see sync as off.
  final VaultwardenTarget? vaultwarden;

  /// Where the vault's own entries sync in Kemlock Server, or null. At most one of [personal] and
  /// this holds them ([ownEntriesClash]); [vaultwarden] may sit beside it only as the Bitwarden copy
  /// `move-off-vaultwarden-sync` keeps, which its scope state marks [copyOfKey]. Builds from before
  /// Kemlock Server sync keep it among the keys they don't know, and see sync as off.
  final KemlockTarget? kemlock;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  /// Whether the vault's own entries sync anywhere.
  bool get syncsOwnEntries => personal != null || vaultwarden != null || kemlock != null;

  /// Both WebDAV and Kemlock Server hold the vault's own entries, which an older build that saw sync
  /// as off can leave behind by turning WebDAV on beside Kemlock Server. Neither syncs, and the
  /// sheet asks which keeps the vault's own entries, until one of them is turned off.
  bool get ownEntriesClash => personal != null && kemlock != null;

  Map<String, Object?> toJson() => {
    'personal': personal?.toJson(),
    'spaces': [for (final space in spaces) space.toJson()],
    'vaultwarden': ?vaultwarden?.toJson(),
    'kemlock': ?kemlock?.toJson(),
    ...extra,
  };

  /// A copy with the given settings changed; pass null as [personal],
  /// [vaultwarden] or [kemlock] to turn that sync off.
  SyncSettings copyWith({Object? personal = keep, List<Space>? spaces, Object? vaultwarden = keep, Object? kemlock = keep}) => SyncSettings(
    personal: pick(personal, this.personal),
    spaces: spaces ?? this.spaces,
    vaultwarden: pick(vaultwarden, this.vaultwarden),
    kemlock: pick(kemlock, this.kemlock),
    extra: extra,
  );

  @override
  bool operator ==(Object other) => other is SyncSettings && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(personal, spaces.length, vaultwarden, kemlock);

  @override
  String toString() => 'SyncSettings($personal, $spaces, $vaultwarden, $kemlock)';
}

/// What a scope held after its last sync on this device.
class ScopeState {
  const ScopeState({required this.known, this.lastSyncAt, this.extra = const {}});

  factory ScopeState.fromJson(Map<String, Object?> json) => ScopeState(
    known: [if (json['known'] case final List<Object?> known) ...known.whereType<String>()],
    lastSyncAt: asInt(json['lastSyncAt']),
    extra: extraKeys(json, const {'known', 'lastSyncAt'}),
  );

  /// The ids the scope held; one missing here since was deleted here.
  final List<String> known;

  /// Epoch ms of the last sync that went through, or null.
  final int? lastSyncAt;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {'known': known, 'lastSyncAt': lastSyncAt, ...extra};

  @override
  bool operator ==(Object other) => other is ScopeState && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(known.length, lastSyncAt);

  @override
  String toString() => 'ScopeState(${toJson()})';
}

/// Why a sync didn't go through. The names are the ends of the
/// `sync.problem.*` message ids.
enum SyncProblem {
  /// The folder isn't https.
  insecure,

  /// The server refused the username or password.
  auth,

  /// The folder isn't a URL, or isn't on the server.
  folder,

  /// Another device kept writing the file at the same time.
  conflict,

  /// The server couldn't be reached.
  network,

  /// Any other failure.
  server,

  /// The passphrase or key doesn't open the file.
  key,

  /// The file isn't a Kemlock sync file.
  format,

  /// Vaultwarden: no Bitwarden-compatible server answers at the address.
  address,

  /// Vaultwarden: the session ended; sign in again.
  signedOut,

  /// Vaultwarden: the account uses something this app can't do yet.
  unsupported,

  /// Vaultwarden: the home note is gone from the vault.
  homeMissing,

  /// Vaultwarden: another phone changed how the home keeps its entries.
  modeChanged,

  /// Vaultwarden: the sync would remove many entries, and waits for the user.
  removals,

  /// The server handed back a sync file older than one this device already
  /// synced, which would bring back entries deleted since.
  older,

  /// Kemlock Server: no Kemlock Server answers at the address.
  kemlockAddress,

  /// Kemlock Server: the server ended this device's session (signed out from
  /// another device, or it expired); sign in again. The entries are kept.
  sessionEnded,

  /// Kemlock Server: the server ended the session for safety, because a refresh
  /// token was used twice, which can mean it was copied.
  sessionReused,

  /// Kemlock Server: the server handed back an older copy of the vault than
  /// this device saw, or one its signed manifest doesn't match: a rolled-back,
  /// missing or resurrected item, a manifest that fails, or an item no manifest
  /// listed for over a day. Nothing was stored.
  kemlockOlder,

  /// A server space: its chain of changes can't be checked (it goes back, forks, is malformed or carries a signature it
  /// shouldn't). Nothing of the space was stored; the vault's other scopes synced.
  spaceCantBeChecked,

  /// A server space: it waits for its keys to be replaced, and nothing is written under a replaced key. Not a failure;
  /// the next run after the replacement goes through.
  spaceKeysPending,
}

/// Scope id of the vault's own entries; spaces use their own ids.
const personalScope = 'personal';

/// Scope id of the vault's own entries when they sync with Vaultwarden.
const vaultwardenScope = 'vaultwarden';

/// Scope id of the vault's own entries when they sync with Kemlock Server.
const kemlockScope = 'kemlock';

/// The scope the list of the account's server spaces reports under: its problem (the server couldn't be reached, the
/// session ended) shows beside the ones of each space, whose scope id is the space's UUID.
const kemlockSpacesScope = 'kemlock-spaces';

/// The key of a scope state that marks the Vaultwarden scope as the Bitwarden copy of a vault whose
/// own entries sync with Kemlock Server (`move-off-vaultwarden-sync`).
const copyOfKey = 'copyOf';

/// The vault's own sync file.
const syncFile = 'backmycodes-sync.json';

/// A shared space's file.
String spaceFile(String id) => 'backmycodes-space-$id.json';

/// The problem to show for an error a sync step threw.
SyncProblem problemOf(Object? error) => switch (error) {
  DavError(:final problem) => switch (problem) {
    DavProblem.insecure => SyncProblem.insecure,
    DavProblem.auth => SyncProblem.auth,
    DavProblem.folder => SyncProblem.folder,
    DavProblem.conflict => SyncProblem.conflict,
    DavProblem.network => SyncProblem.network,
    DavProblem.server => SyncProblem.server,
  },
  SyncFileError(:final problem) => switch (problem) {
    SyncFileProblem.format => SyncProblem.format,
    SyncFileProblem.key => SyncProblem.key,
    SyncFileProblem.older => SyncProblem.older,
  },
  VwError(:final problem) => switch (problem) {
    VwProblem.insecure => SyncProblem.insecure,
    VwProblem.address => SyncProblem.address,
    VwProblem.auth || VwProblem.code => SyncProblem.auth,
    VwProblem.signedOut => SyncProblem.signedOut,
    VwProblem.outOfDate => SyncProblem.conflict,
    VwProblem.network => SyncProblem.network,
    VwProblem.unsupported => SyncProblem.unsupported,
    VwProblem.server => SyncProblem.server,
  },
  VwSyncError(:final issue) => switch (issue) {
    VwSyncIssue.homeMissing => SyncProblem.homeMissing,
    VwSyncIssue.modeChanged => SyncProblem.modeChanged,
    VwSyncIssue.removals => SyncProblem.removals,
  },
  KmError(:final problem, :final reason) => switch (problem) {
    KmProblem.insecure => SyncProblem.insecure,
    KmProblem.address => SyncProblem.kemlockAddress,
    KmProblem.auth => SyncProblem.sessionEnded,
    KmProblem.sessionEnded => reason == 'refresh-reuse' ? SyncProblem.sessionReused : SyncProblem.sessionEnded,
    // A run meets it only when it signs in again, on a replica: the person signs in again, with SSO
    KmProblem.ssoRequired => SyncProblem.sessionEnded,
    KmProblem.stale => SyncProblem.conflict,
    KmProblem.network => SyncProblem.network,
    KmProblem.fullSync || KmProblem.rateLimited || KmProblem.tooLarge || KmProblem.unsupported || KmProblem.server => SyncProblem.server,
  },
  KmSyncError(:final issue) => switch (issue) {
    KmSyncIssue.older => SyncProblem.kemlockOlder,
    KmSyncIssue.removals => SyncProblem.removals,
  },
  // A run that failed after its chain closed the WebDAV copy: the failure is what the person is shown
  ClosedRunError(:final cause) => problemOf(cause),
  SpaceSyncError(:final issue) => switch (issue) {
    SpaceSyncIssue.cantBeChecked => SyncProblem.spaceCantBeChecked,
    SpaceSyncIssue.older => SyncProblem.kemlockOlder,
    SpaceSyncIssue.keysPending => SyncProblem.spaceKeysPending,
    SpaceSyncIssue.removals => SyncProblem.removals,
  },
  _ => SyncProblem.server,
};

/// How many times a write that lost a race is tried, merging again each time.
const _attempts = 3;

/// The scope state's key for the count ([SyncDoc.seq]) of the newest sync
/// file this device read or wrote in the scope, for [syncScope]'s `seen`.
/// Kept with the rest of the scope's state, which only this device reads.
const seenSeqKey = 'seq';

/// The count of the newest sync file [state] says this device saw, or null.
int? seenSeq(Map<String, Object?> state) => syncSeq(state[seenSeqKey]);

/// [state] remembering [seq] as the newest count seen, or as it was when
/// [seq] is null.
Map<String, Object?> withSeenSeq(Map<String, Object?> state, int? seq) => seq == null ? state : {...state, seenSeqKey: seq};

/// Syncs one scope and returns the merged document (to take locally), the
/// ids it now holds and the count of the file it read or wrote (both to
/// remember for next time).
///
/// [local] is this device's entries in the scope and [known] the ids the
/// scope held after this device's last sync. [seen] is the count of the
/// newest file this device saw in the scope ([seenSeq]), null before any.
/// [now] is epoch ms, the current time by default. [anchors] is this device's
/// anchors of the account's server spaces, for the vault's own file only; the
/// file's `extra` then carries their union with its own (see [mergeScope]), and is
/// written again when that changed. Throws what [WebDav] and
/// [decryptSyncFile] throw; see [problemOf].
///
/// A file that counts less than [seen] is older than one this device saw,
/// as a server hands back when it means to bring back entries deleted
/// since: it is read again, as when a write loses a race, and if it is
/// still older, the sync stops with an `older` [SyncFileError] and writes
/// nothing. A file without a count, as the TypeScript app and older
/// versions write, is merged as before, since this can't tell it from
/// theirs; the file this writes then counts on from [seen]. Two devices of
/// this version can't stop each other: each counts on from the file it
/// read, and a write that raced another fails on its ETag.
Future<({SyncDoc doc, List<String> known, int? seq})> syncScope(
  WebDav webDav,
  SyncTarget target,
  Lists local,
  List<String> known, {
  int? now,
  int? seen,
  Object? anchors,
}) async {
  final at = now ?? DateTime.now().millisecondsSinceEpoch;
  final key = unb64(target.key);
  for (var attempt = 1; ; attempt++) {
    final remote = await webDav.readFile(target.dav, target.file);
    final remoteDoc = remote == null ? null : await decryptSyncFile(remote.text, key);
    final count = remoteDoc?.seq;
    if (count != null && seen != null && count < seen) {
      // Perhaps a copy the server hasn't caught up on yet: read it again
      if (attempt < _attempts) continue;
      throw const SyncFileError(SyncFileProblem.older);
    }
    final merged = mergeScope(await combineKeyCopies(local, remoteDoc), known, remoteDoc, now: at, anchors: anchors);
    if (remoteDoc != null && sameDoc(merged.doc, remoteDoc) && _sameAnchors(merged.doc, remoteDoc)) {
      return (doc: merged.doc, known: merged.known, seq: count ?? seen);
    }
    final next = max(count ?? 0, seen ?? 0) + 1;
    try {
      final text = await encryptSyncFile(_counted(merged.doc, next), key, kdf: target.kdf);
      await webDav.writeFile(target.dav, target.file, text, etag: remote?.etag, mustNotExist: remote == null);
      return (doc: merged.doc, known: merged.known, seq: next);
    } on DavError catch (e) {
      // Another device wrote first: read its version and merge again
      if (e.problem == DavProblem.conflict && attempt < _attempts) continue;
      rethrow;
    }
  }
}

/// Whether [a] and [b] carry the same anchors ([syncAnchorsKey]), so a file whose only difference is the anchors a device
/// brought is still written.
bool _sameAnchors(SyncDoc a, SyncDoc b) => canonical(a.extra[syncAnchorsKey]) == canonical(b.extra[syncAnchorsKey]);

/// [doc] counting [seq].
SyncDoc _counted(SyncDoc doc, int seq) => SyncDoc(
  accounts: doc.accounts,
  backupServices: doc.backupServices,
  keys: doc.keys,
  notes: doc.notes,
  passkeys: doc.passkeys,
  keyAccounts: doc.keyAccounts,
  contacts: doc.contacts,
  logins: doc.logins,
  cards: doc.cards,
  identities: doc.identities,
  files: doc.files,
  deleted: doc.deleted,
  seq: seq,
  extra: doc.extra,
);

Map<String, Object?> _object(Object? value) => value is Map<String, Object?> ? value : const {};
