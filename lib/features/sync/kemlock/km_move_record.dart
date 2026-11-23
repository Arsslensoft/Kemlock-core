/// The progress of a move off Vaultwarden or WebDAV sync, one sealed record of the vault,
/// `backmycodes_kemlock_move` (move-off-vaultwarden-sync, design 5). It is sealed with
/// `saveEncryptedValue` like the sync settings, and deleted with its vault by suffix
/// (`VaultRegistry.removeVaultData`), as the Kemlock session, account and cache are:
///
/// ```json
/// {"v":1,"source":"vaultwarden","server":"https://vault.example.com","home":"<home id>","mode":"sealed",
///  "step":"copy","sent":{"<entry id>":"<sha256 b64url>"},"files":{"<attachment id>":"<sha256 b64url>"},
///  "checked":false,"closed":false,"startedAt":1795300000000}
/// ```
///
/// The steps are [KmMoveStep.sync], `copy`, `files`, `check`, `oldStore` and `done`. Each is idempotent,
/// so a resume restarts the recorded step. [sent] is by the app's entry id, not the item's UUID, so it
/// stays true whichever owner the ids are mapped under. [redo] names entries a check found wrong, which
/// the next copy sends again even though they are in [sent], and [redoFiles] the attachments whose file a
/// check found wrong, which the next files step uploads again; each is written only when there are some.
///
/// After `done` the record stays for the window "Go back to Vaultwarden" is offered (design 9), then is
/// trimmed to `{v, source, done, finishedAt}` ([KmMoveRecord.trimmed]).
///
/// Like the other settings classes, it keeps the keys it doesn't know and writes them back.
///
/// Pure Dart, no Flutter.
library;

import '../../../models/json.dart';
import 'km_host.dart' show KmVaultValues;

/// Where the progress of a move is kept, per vault and encrypted with it.
const keyKemlockMove = 'backmycodes_kemlock_move';

/// The record's format version this build reads and writes.
const kmMoveVersion = 1;

/// How long "Go back to Vaultwarden" is offered after a sealed home is closed, and so how long the record
/// is kept whole after `done`.
const kmGoBackWindow = Duration(days: 30);

/// How far a move has got. The names are what the record stores.
enum KmMoveStep {
  /// The old store's ordinary run, with files, merged into the vault.
  sync,

  /// Every own entry written as a `kem1` item.
  copy,

  /// Every moved note's `KMA1` file uploaded, and the note written again naming it.
  files,

  /// The manifest signed, and the vault read back and compared.
  check,

  /// The old store closed (a sealed home) or left as it is.
  oldStore,

  /// Finished.
  done;

  static KmMoveStep? parse(Object? name) {
    for (final step in values) {
      if (step.name == name) return step;
    }
    return null;
  }
}

/// What a move stands at, as stored.
class KmMoveRecord {
  const KmMoveRecord({
    required this.source,
    required this.server,
    required this.startedAt,
    this.home,
    this.mode,
    this.step = KmMoveStep.sync,
    this.sent = const {},
    this.files = const {},
    this.redo = const [],
    this.redoFiles = const [],
    this.checked = false,
    this.closed = false,
    this.finishedAt,
    this.result,
    this.isTrimmed = false,
    this.extra = const {},
  });

  /// Reads a stored record. Anything that isn't a record of this version reads as null, which a caller
  /// treats as "no move started": a newer build's record is told apart by [KmMoveRecord.newer].
  static KmMoveRecord? tryParse(Object? json) {
    if (json is! Map<String, Object?> || json['v'] != kmMoveVersion) return null;
    final source = json['source'];
    if (source is! String || source.isEmpty) return null;
    final trimmed = json['done'] == true && json['step'] == null;
    return KmMoveRecord(
      source: source,
      server: asString(json['server']),
      home: asOptionalString(json['home']),
      mode: asOptionalString(json['mode']),
      step: trimmed ? KmMoveStep.done : (KmMoveStep.parse(json['step']) ?? KmMoveStep.sync),
      sent: _strings(json['sent']),
      files: _strings(json['files']),
      redo: [if (json['redo'] case final List<Object?> redo) ...redo.whereType<String>()],
      redoFiles: [if (json['redoFiles'] case final List<Object?> redoFiles) ...redoFiles.whereType<String>()],
      checked: json['checked'] == true,
      closed: json['closed'] == true,
      startedAt: asInt(json['startedAt']) ?? 0,
      finishedAt: asInt(json['finishedAt']),
      result: json['result'] is Map<String, Object?> ? json['result']! as Map<String, Object?> : null,
      isTrimmed: trimmed,
      extra: extraKeys(json, const {
        'v',
        'source',
        'server',
        'home',
        'mode',
        'step',
        'sent',
        'files',
        'redo',
        'redoFiles',
        'checked',
        'closed',
        'startedAt',
        'finishedAt',
        'result',
        'done',
      }),
    );
  }

  /// Whether [json] is a record of a version after this one: its move is left alone.
  static bool newer(Object? json) => json is Map<String, Object?> && json['v'] is int && (json['v']! as int) > kmMoveVersion;

  /// `vaultwarden` or `webdav`: the old store the vault came from.
  final String source;

  /// The old store's server: the Vaultwarden address, or the WebDAV folder.
  final String server;

  /// The Vaultwarden home's id and how it keeps entries (`sealed` or `plain`); null for WebDAV.
  final String? home;
  final String? mode;
  final KmMoveStep step;

  /// By entry id, the SHA-256 (base64url) of the canonical JSON sent for each entry once the server
  /// confirmed it.
  final Map<String, String> sent;

  /// By attachment id, the SHA-256 (base64url) of the `KMA1` bytes uploaded.
  final Map<String, String> files;

  /// Entries a check found different or missing: the next copy sends them again.
  final List<String> redo;

  /// Attachments whose file a check found wrong: the next files step uploads them again.
  final List<String> redoFiles;

  /// Whether the vault was read back and matched what was sent.
  final bool checked;

  /// Whether the sealed home was closed.
  final bool closed;

  /// Epoch ms the move began.
  final int startedAt;

  /// Epoch ms the move finished, once it has.
  final int? finishedAt;

  /// What the move left for the screen to say: counts by kind and what happened to the old store.
  final Map<String, Object?>? result;

  /// Whether this is the trimmed form kept after the window.
  final bool isTrimmed;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  bool get isDone => step == KmMoveStep.done;

  /// Whether the move began as a sealed home's.
  bool get sealedHome => source == vaultwardenSource && mode == 'sealed';

  /// Whether "Go back to Vaultwarden" is still offered at [now]: a sealed home was closed less than
  /// [kmGoBackWindow] ago.
  bool goBackOpen(DateTime now) {
    final at = finishedAt;
    return closed && !isTrimmed && at != null && now.millisecondsSinceEpoch - at < kmGoBackWindow.inMilliseconds;
  }

  KmMoveRecord copyWith({
    KmMoveStep? step,
    Map<String, String>? sent,
    Map<String, String>? files,
    List<String>? redo,
    List<String>? redoFiles,
    bool? checked,
    bool? closed,
    int? finishedAt,
    Object? result = keep,
  }) => KmMoveRecord(
    source: source,
    server: server,
    startedAt: startedAt,
    home: home,
    mode: mode,
    step: step ?? this.step,
    sent: sent ?? this.sent,
    files: files ?? this.files,
    redo: redo ?? this.redo,
    redoFiles: redoFiles ?? this.redoFiles,
    checked: checked ?? this.checked,
    closed: closed ?? this.closed,
    finishedAt: finishedAt ?? this.finishedAt,
    result: pick(result, this.result),
    isTrimmed: isTrimmed,
    extra: extra,
  );

  /// The record as it is kept once the window is over: `{v, source, done, finishedAt}`.
  KmMoveRecord trimmed() => KmMoveRecord(
    source: source,
    server: '',
    startedAt: startedAt,
    step: KmMoveStep.done,
    finishedAt: finishedAt,
    isTrimmed: true,
    extra: {
      for (final MapEntry(:key, :value) in extra.entries)
        if (key != kmGoBackTargetKey) key: value,
    },
  );

  Map<String, Object?> toJson() {
    if (isTrimmed) {
      return {'v': kmMoveVersion, 'source': source, 'done': true, 'finishedAt': finishedAt, ...extra};
    }
    return {
      'v': kmMoveVersion,
      'source': source,
      'server': server,
      'home': ?home,
      'mode': ?mode,
      'step': step.name,
      'sent': sent,
      'files': files,
      if (redo.isNotEmpty) 'redo': redo,
      if (redoFiles.isNotEmpty) 'redoFiles': redoFiles,
      'checked': checked,
      'closed': closed,
      'startedAt': startedAt,
      'finishedAt': ?finishedAt,
      'result': ?result,
      ...extra,
    };
  }

  @override
  bool operator ==(Object other) => other is KmMoveRecord && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(source, step, sent.length, files.length);

  /// Names no secret, only counts.
  @override
  String toString() => 'KmMoveRecord($source, ${step.name}, ${sent.length} sent, ${files.length} files)';
}

/// The source of a move from a Vaultwarden home.
const vaultwardenSource = 'vaultwarden';

/// The source of a move from a WebDAV personal vault.
const webdavSource = 'webdav';

Map<String, String> _strings(Object? json) => {
  if (json is Map<String, Object?>)
    for (final MapEntry(:key, :value) in json.entries)
      if (value is String) key: value,
};

/// Keeps the progress of a move in the vault's sealed values.
class KmMoveStore {
  const KmMoveStore(this.values);

  final KmVaultValues values;

  /// The record, or null when no move was started (or a newer build's record, which [loadsNewer] tells).
  Future<KmMoveRecord?> load() async => KmMoveRecord.tryParse(await values.load(keyKemlockMove));

  /// Whether the stored record is a newer build's, which this build leaves alone.
  Future<bool> loadsNewer() async => KmMoveRecord.newer(await values.load(keyKemlockMove));

  Future<void> save(KmMoveRecord record) => values.save(keyKemlockMove, record.toJson());

  void remove() => values.remove(keyKemlockMove);
}

/// The record's own key, among the keys it keeps beyond the format, where a move from a Vaultwarden home
/// keeps that home's target (`VaultwardenTarget.toJson`), so "Go back to Vaultwarden" can restore the
/// home once the sync settings dropped it. [KmMoveRecord.trimmed] drops it with the rest of the move.
const kmGoBackTargetKey = 'vaultwardenTarget';
