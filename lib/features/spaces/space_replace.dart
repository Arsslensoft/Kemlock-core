// The `keys` record of a key replacement (docs/plans/add-server-spaces.md, design 4 and task 6.1; the space chain
// section of docs/crypto.md, `keys` and "Removal and replacement"). After a removal marks keys, an Owner's or Admin's
// app (or, for a collection, any member entitled to it while it is marked) makes a new version of each marked key,
// seals it to the members still entitled to it, and publishes the record that commits to the seals. For the space key it
// also commits every name again, sealed under the new space key. The run that re-writes the items under the new
// collection keys is `KmSpaceSync.replaceKeys` (server_spaces.dart); this file is the record and what travels with it.
//
// Whoever makes a key version learns the key, so the record is signed only by a member entitled to it: the state's
// authority rules decide that, on the record built here, before it is sent.
//
// The append route that carries the record is the server's, pinned in the space chain section of docs/crypto.md:
// `POST /kem/v1/spaces/{id}/chain` with `{records, seals, names, held?}`, which [KeysReplacement.request] builds. It
// answers `201 {link, seq}`, `409 {head}` when the head moved and `422 {reason, seq}` (`space_chain_client.dart`).
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/bundle.dart';
import '../../crypto/account/encoding.dart';
import 'chain_body.dart' show SealCommitment;
import 'space_chain.dart';
import 'space_keys.dart';
import 'space_seals.dart';
import 'space_state.dart';

/// Makes the 32 bytes of a new key. The secure random source by default; a test gives fixed ones.
typedef KeyMaker = Uint8List Function(KeyRef key, int version);

Uint8List randomKeyMaker(KeyRef key, int version) => newSpaceKey();

/// Why a key replacement can't go on.
enum KeyReplacementProblem {
  /// No key of the space waits for replacement, or the account isn't a confirmed member.
  nothingToReplace,

  /// The chain doesn't let this account replace the keys, or the record makes no sense where it lands.
  notAllowed,

  /// A name of the space, a collection or a group wasn't given, so the space key's names can't be committed again.
  missingName,

  /// The server's answer, read back, isn't what was written: an item's revision, key version or hash, or the manifest.
  readBack,

  /// Items kept changing under the run, and it gave up for now; running it again resumes where it stopped.
  busy,
}

/// A key replacement that stopped, and why. Running it again carries on from what is still under an old key.
class KeyReplacementError implements Exception {
  const KeyReplacementError(this.problem, [this.detail]);

  final KeyReplacementProblem problem;
  final String? detail;

  @override
  String toString() => 'KeyReplacementError(${problem.name}${detail != null ? ': $detail' : ''})';
}

/// The packed names of a `keys` record that replaces the space key: `n × (u8(type) ‖ id (16) ‖ SHA-256(sealed name)
/// (32))` in ascending order of `type ‖ id`, one entry for the space and for every collection and group.
Uint8List packNames(Map<NameTarget, Uint8List> sealed, String space) {
  final rows = <(int, Uint8List, Uint8List)>[
    for (final MapEntry(:key, :value) in sealed.entries) (key.type.code, uuidBytes(key.id ?? space), nameHash(value)),
  ];
  rows.sort((a, b) {
    if (a.$1 != b.$1) {
      return a.$1 - b.$1;
    }
    for (var i = 0; i < 16; i++) {
      if (a.$2[i] != b.$2[i]) {
        return a.$2[i] - b.$2[i];
      }
    }
    return 0;
  });
  return Uint8List.fromList([
    for (final row in rows) ...[row.$1, ...row.$2, ...row.$3],
  ]);
}

/// A `keys` record, the new keys and what travels with it.
final class KeysReplacement {
  KeysReplacement({required this.entry, required this.newKeys, required this.boxes, required this.names});

  /// The record to sign.
  final SpaceChainEntry entry;

  /// The new key of each key replaced, at the version the record gives it. The caller wipes them.
  final Map<KeyRef, Uint8List> newKeys;

  /// The box of each new key, by key and recipient account.
  final Map<KeyRef, Map<String, Uint8List>> boxes;

  /// The sealed names, by target, when the space key is replaced.
  final Map<NameTarget, Uint8List> names;

  /// The new version of [key].
  int versionOf(KeyRef key) =>
      (entry.body['rotate']! as List<Object?>).cast<Map<String, Object?>>().firstWhere((c) => c['key'] == key.wire)['version']! as int;

  /// The body of `POST /kem/v1/spaces/{id}/chain` for [signed], the entry signed: the record, the boxes its commitments
  /// cover, the sealed names its hashes cover, and the live items the replacer didn't accept, named [held].
  Map<String, Object?> request(SignedChainEntry signed, {List<String> held = const []}) => {
    'records': [signed.toJson()],
    'seals': [
      for (final MapEntry(key: key, value: recipients) in boxes.entries)
        for (final MapEntry(key: member, value: box) in recipients.entries)
          {'box': b64urlEncode(box), 'key': key.wire, 'member': member, 'seq': entry.seq, 'version': versionOf(key)},
    ],
    'names': [
      for (final MapEntry(key: target, value: sealed) in names.entries)
        {'name': b64urlEncode(sealed), 'seq': entry.seq, 'target': target.wire},
    ],
    if (held.isNotEmpty) 'held': held,
  };
}

/// Builds the `keys` record by [signer] that replaces [rotate] (the keys the state marks) with their next versions.
///
/// Each new key is made by [makeKey], sealed to the members entitled to it, to the `kx1` key of the bundle the chain
/// recorded for them, and committed with its check. When the space key is among them, [names] gives the text of the
/// space, of every collection and of every group, which are sealed again under the new space key and committed as
/// `names`. A [KeyReplacementError] when a name is missing; the record is not checked against the state here, which the
/// caller does with `apply` and `chainAuthorityProblem`.
Future<KeysReplacement> buildKeysRecord({
  required SpaceState state,
  required String signer,
  required Set<KeyRef> rotate,
  required int at,
  KeyMaker makeKey = randomKeyMaker,
  Map<NameTarget, String> names = const {},
}) async {
  if (rotate.isEmpty) {
    throw const KeyReplacementError(KeyReplacementProblem.nothingToReplace);
  }
  final ordered = rotate.toList()..sort((a, b) => a.wire.compareTo(b.wire));
  final newKeys = <KeyRef, Uint8List>{};
  final boxes = <KeyRef, Map<String, Uint8List>>{};
  final commitments = <SealCommitment>[];
  for (final key in ordered) {
    final version = (state.keyVersionOf(key) ?? 0) + 1;
    final bytes = makeKey(key, version);
    newKeys[key] = bytes;
    final recipients = <String, KeyBundle>{for (final account in state.entitled(key)) account: state.member(account)!.bundle!};
    final sealed = await sealKeyTo(space: state.space, key: key, version: version, keyBytes: bytes, recipients: recipients, makes: true);
    commitments.add(sealed.commitment);
    boxes[key] = sealed.boxes;
  }
  final sealedNames = <NameTarget, Uint8List>{};
  if (newKeys.containsKey(const KeyRef.space())) {
    final version = state.spaceKeyVersion + 1;
    final targets = <NameTarget>[
      const NameTarget.space(),
      for (final id in state.collections.keys) NameTarget.collection(id),
      for (final id in state.groups.keys) NameTarget.group(id),
    ];
    for (final target in targets) {
      final text = names[target];
      if (text == null) {
        throw KeyReplacementError(KeyReplacementProblem.missingName, target.wire);
      }
      sealedNames[target] = await sealName(
        spaceKey: newKeys[const KeyRef.space()]!,
        space: state.space,
        keyVersion: version,
        kind: switch (target.type) {
          NameType.space => NameKind.space,
          NameType.collection => NameKind.collection,
          NameType.group => NameKind.group,
        },
        id: target.id ?? state.space,
        name: text,
      );
    }
  }
  final entry = SpaceChainEntry(
    space: state.space,
    seq: state.nextSeq,
    prev: state.headHash ?? chainGenesisLink,
    epoch: state.epoch,
    at: at,
    by: signer,
    kind: ChainKind.keys,
    body: {
      if (sealedNames.isNotEmpty) 'names': b64urlEncode(packNames(sealedNames, state.space)),
      'rotate': [for (final commitment in commitments) commitment.toJson()],
    },
  );
  return KeysReplacement(entry: entry, newKeys: newKeys, boxes: boxes, names: sealedNames);
}
