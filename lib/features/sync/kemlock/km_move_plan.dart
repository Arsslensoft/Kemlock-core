/// What a move writes (move-off-vaultwarden-sync, design 2): every own entry of every kind the
/// Kemlock API carries, from the vault's own lists after the old store's last sync, not from the home's
/// items. Logins, accounts on a security key, cards, identities, entries a plain home held back
/// (`paused`) and entries too long for an item's notes all move. The kind list is
/// `km_kinds.dart`'s (`kmEntriesOf`), so a kind added there moves with no code here.
///
/// The entries go in batches of at most 500, in kind order: accounts, backup codes, keys, accounts on a
/// key, notes, passkeys, contacts, cards, identities, logins. A login's `accountId` then never points at
/// an item a stopped move hasn't sent. Each item has its UUID (the entry's id when it is a UUID, else
/// its legacy-id UUID under the owner; the mapping is fixed, so a resent batch and a second phone moving
/// the same vault send the same UUIDs) and the hash `sha256(canonical(toJson()))` the check compares
/// with.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../models/secure_note.dart';
import '../sync_merge.dart';
import 'km_api.dart';
import 'km_kinds.dart';

/// The base64url SHA-256 of [json]'s canonical form: how an entry is told from another, whatever the
/// order of its keys.
String kmEntryHash(Map<String, Object?> json) => b64urlEncode(hash.sha256.convert(utf8.encode(canonical(json))).bytes);

/// One entry to move.
class KmMoveItem {
  const KmMoveItem({required this.itemId, required this.entryId, required this.kind, required this.json, required this.hash});

  /// The item's UUID on the server.
  final String itemId;

  /// The entry's own id, which stays inside the item.
  final String entryId;
  final String kind;

  /// The entry's `toJson()`.
  final Map<String, Object?> json;

  /// [kmEntryHash] of [json].
  final String hash;

  KmEntry get entry => (kind: kind, json: json);

  @override
  String toString() => 'KmMoveItem($kind, $entryId -> $itemId)';
}

/// A file a moved note or File item names.
class KmMoveFile {
  const KmMoveFile({required this.itemId, required this.noteId, required this.file, this.kind = KmKind.note});

  final String itemId;

  /// The id of the entry that names the file: a note's, or a File item's (the name says note for the notes it began with).
  final String noteId;

  /// [KmKind.note] or [KmKind.file].
  final String kind;
  final NoteAttachment file;
}

/// What a move writes: the items in the order they are sent, cut into batches, and the files.
class KmMovePlan {
  const KmMovePlan({required this.batches, required this.files});

  /// At most [KmApi.batchSize] items each, in kind order.
  final List<List<KmMoveItem>> batches;

  /// Every file the moved notes and File items name.
  final List<KmMoveFile> files;

  /// Every item, in order.
  List<KmMoveItem> get items => [for (final batch in batches) ...batch];

  /// How many items there are of each kind, for the screen that says what moves.
  Map<String, int> get byKind {
    final counts = <String, int>{};
    for (final item in items) {
      counts.update(item.kind, (n) => n + 1, ifAbsent: () => 1);
    }
    return counts;
  }

  int get count => batches.fold(0, (n, batch) => n + batch.length);
}

/// Where a kind stands in the order a move sends: what other kinds point at goes first.
int _rank(String kind) => switch (kind) {
  KmKind.otp => 0,
  KmKind.backupCodes => 1,
  KmKind.pgpKey || KmKind.sshKey || KmKind.certificate || KmKind.key => 2,
  KmKind.keyOtp => 3,
  KmKind.note => 4,
  KmKind.passkey => 5,
  KmKind.contact => 6,
  KmKind.card => 7,
  KmKind.identity => 8,
  KmKind.login => 9,
  _ => 10,
};

/// The plan for [own], the vault's own entries, as items of [owner]'s. An entry with no id is left out.
/// [batchSize] is the server's limit, except in a test.
KmMovePlan planKmMove(Lists own, Owner owner, {int batchSize = KmApi.batchSize}) {
  final ranked = <int, List<KmMoveItem>>{};
  final seen = <String>{};
  final files = <KmMoveFile>[];
  for (final entry in kmEntriesOf(own)) {
    final entryId = kmEntryId(entry);
    if (entryId.isEmpty || !seen.add(entryId)) continue;
    final itemId = kmItemId(entryId, owner);
    (ranked[_rank(entry.kind)] ??= []).add(
      KmMoveItem(itemId: itemId, entryId: entryId, kind: entry.kind, json: entry.json, hash: kmEntryHash(entry.json)),
    );
  }
  for (final note in own.notes) {
    if (note.id.isEmpty) continue;
    for (final file in note.files) {
      files.add(KmMoveFile(itemId: kmItemId(note.id, owner), noteId: note.id, file: file));
    }
  }
  for (final item in own.files) {
    if (item.id.isEmpty) continue;
    files.add(KmMoveFile(itemId: kmItemId(item.id, owner), noteId: item.id, file: item.file, kind: KmKind.file));
  }
  final ordered = [for (final rank in ranked.keys.toList()..sort()) ...ranked[rank]!];
  return KmMovePlan(
    batches: [
      for (var start = 0; start < ordered.length; start += batchSize)
        ordered.sublist(start, start + batchSize < ordered.length ? start + batchSize : ordered.length),
    ],
    files: files,
  );
}
