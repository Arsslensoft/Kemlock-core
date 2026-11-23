// Builders of the records an app makes by hand (the space chain section of docs/crypto.md, "Kinds"): a record that
// follows the state's head, in its epoch, by the member who will sign it, with the body of its kind in the exact shape
// `chain_body.dart` reads (sets sorted, no `null`). `buildRekey` (space_rekey.dart) and `buildSealRecord`
// (space_seals.dart) are the two that carry keys; these are the ones that change who is in the space and what they
// may do, and the pending changes of space_pending.dart are made through them.
//
// A builder never decides whether the record is allowed: the state's `apply` and `chainAuthorityProblem` do, on the
// record it returns. A `remove`, an `ungrant` and a `group-members` that takes someone out name in `replace` the keys the
// state loses by them (`SpaceState.keysLostBy`), which is the one thing a builder works out.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import 'space_chain.dart';
import 'space_state.dart';

SpaceChainEntry _entry(SpaceState state, String by, ChainKind kind, Map<String, Object?> body, int at) => SpaceChainEntry(
  space: state.space,
  seq: state.nextSeq,
  prev: state.headHash ?? chainGenesisLink,
  epoch: state.epoch,
  at: at,
  by: by,
  kind: kind,
  body: body,
);

List<String> _sorted(Iterable<String> texts) => texts.toList()..sort();

Map<String, Object?> _custom(Iterable<CustomPermission> custom) => {
  'custom': _sorted([for (final permission in custom) permission.wire]),
};

/// An `invite` of [member] as [role] (with the [custom] permissions of a Custom member), granting [grants] by collection.
SpaceChainEntry buildInvite({
  required SpaceState state,
  required String by,
  required String member,
  required SpaceRole role,
  Set<CustomPermission> custom = const {},
  Map<String, CollectionPermission> grants = const {},
  required int at,
}) => _entry(state, by, ChainKind.invite, {
  ..._custom(custom),
  'grants': [
    for (final collection in _sorted(grants.keys)) {'collection': collection, 'permission': grants[collection]!.wire},
  ],
  'member': member,
  'role': role.wire,
}, at);

/// A `role` record that makes [member] [role], with the [custom] permissions of a Custom member.
SpaceChainEntry buildRole({
  required SpaceState state,
  required String by,
  required String member,
  required SpaceRole role,
  Set<CustomPermission> custom = const {},
  required int at,
}) => _entry(state, by, ChainKind.role, {..._custom(custom), 'member': member, 'role': role.wire}, at);

/// A `grant` of [permission] on [collection] to [grantee].
SpaceChainEntry buildGrant({
  required SpaceState state,
  required String by,
  required String collection,
  required Grantee grantee,
  required CollectionPermission permission,
  required int at,
}) => _entry(state, by, ChainKind.grant, {'collection': collection, 'grantee': grantee.wire, 'permission': permission.wire}, at);

List<String> _refs(Iterable<KeyRef> refs) => _sorted([for (final ref in refs) ref.wire]);

/// A `remove` of [member], naming in `replace` every key the state loses by it. A record that makes no sense in
/// [state] is a `ChainRefusal` of `SpaceState.keysLostBy`.
SpaceChainEntry buildRemove({required SpaceState state, required String by, required String member, required int at}) {
  final probe = _entry(state, by, ChainKind.remove, {'member': member, 'replace': <String>[]}, at);
  return _entry(state, by, ChainKind.remove, {'member': member, 'replace': _refs(state.keysLostBy(probe))}, at);
}

/// An `ungrant` of [grantee]'s grant on [collection], naming in `replace` the keys the state loses by it.
SpaceChainEntry buildUngrant({
  required SpaceState state,
  required String by,
  required String collection,
  required Grantee grantee,
  required int at,
}) {
  final probe = _entry(state, by, ChainKind.ungrant, {'collection': collection, 'grantee': grantee.wire, 'replace': <String>[]}, at);
  return _entry(state, by, ChainKind.ungrant, {
    'collection': collection,
    'grantee': grantee.wire,
    'replace': _refs(state.keysLostBy(probe)),
  }, at);
}

/// A `group-members` record that adds [add] to [group] and takes [remove] out, naming in `replace` the keys the state
/// loses by it.
SpaceChainEntry buildGroupMembers({
  required SpaceState state,
  required String by,
  required String group,
  Set<String> add = const {},
  Set<String> remove = const {},
  required int at,
}) {
  Map<String, Object?> body(Iterable<KeyRef> replace) => {
    'add': _sorted(add),
    'group': group,
    'remove': _sorted(remove),
    'replace': _refs(replace),
  };
  final probe = _entry(state, by, ChainKind.groupMembers, body(const []), at);
  return _entry(state, by, ChainKind.groupMembers, body(state.keysLostBy(probe)), at);
}

/// The `sig1` signing of a record by the account's private key, which a screen passes where a record is to be signed
/// (a test passes a cheap signature instead).
Future<SignedChainEntry> Function(SpaceChainEntry) signerWith(Uint8List sig1PrivateKey) =>
    (entry) => signChainEntry(entry, sig1PrivateKey);
