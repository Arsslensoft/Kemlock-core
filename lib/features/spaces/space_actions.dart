// What a member does in a server space (docs/plans/add-server-spaces.md, tasks 5.2 to 5.6, 6.2 and 6.3): make a space,
// invite, confirm, change a role or a grant, remove, leave, and share the keys the chain says await a member. Each is a
// record the space chain section of docs/crypto.md defines, built here, checked against the state the verified chain
// gives and the authority table (`SpaceState.apply`, `chainAuthorityProblem`), signed with the account's `sig1` key and
// appended to the space's home (`POST /kem/v1/spaces/{id}/chain`, `space_chain_client.dart`) with the boxes and sealed
// names its commitments cover.
//
// - **Make.** `create` is the first record: the maker as Owner, one collection ("Everyone", granted `manage` to its
//   maker), the space key and that collection's key at version 1, sealed to the maker, and the names sealed under the space
//   key. Other members get "Everyone" through the invitation's grants.
// - **Invite.** An `invite` grants and seals nothing: the member is entitled to no key until a `confirm`.
// - **Confirm.** A `confirm` carries the member's bundle and its self-signature, and the 134-byte statement the confirmer
//   signs under the `"confirm"` context after comparing the fingerprint (`crypto/account/confirm.dart`). The screen
//   makes the comparison; this builds what follows it. The keys then go to the member in a `seal` record ([shareKeys]).
// - **Remove, leave, revoke.** A `remove` names in `replace` every key the member held and may no longer have. Revoking
//   an invitation is a `remove` of a member who never held a key, so `replace` is empty; leaving is a `remove` of
//   oneself. The keys it marks are replaced by `KmSpaceSync.replaceKeys`.
// - **Roles and grants.** `role`, `grant` and `ungrant`, as `space_records.dart` builds them. A grant to a confirmed
//   member is followed by a `seal` of that collection's key to them.
// - **Rekeyed members (task 6.3).** After a member's `rekey` the chain entitles their new bundle: the old key vouched for
//   it (the spec's `rekey`), and the keys are sealed to the new bundle by the next [shareKeys], never before the record
//   is on the chain, and never to a key the chain doesn't record. A member the chain doesn't confirm gets nothing.
//
// A record that no longer fits the chain, because the head moved, is made again from the new state, up to three times.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/bundle.dart';
import '../../crypto/account/confirm.dart';
import '../../crypto/account/encoding.dart';
import 'chain_body.dart' show SealCommitment;
import 'space_chain.dart';
import 'space_chain_client.dart';
import 'space_keys.dart';
import 'space_records.dart';
import 'space_replace.dart' show KeyMaker, randomKeyMaker;
import 'space_seals.dart';
import 'space_state.dart';
import 'space_verify.dart' show chainAuthorityProblem;

/// How many times a record is made again when the head moved under it.
const _attempts = 3;

/// A record to sign, with the boxes and the sealed names its commitments cover.
final class ChainAction {
  const ChainAction({required this.entry, this.boxes = const {}, this.names = const {}});

  final SpaceChainEntry entry;

  /// The box of each key the record commits, by key and recipient account.
  final Map<KeyRef, Map<String, Uint8List>> boxes;

  /// The sealed names of a `create`, by target.
  final Map<NameTarget, Uint8List> names;

  /// The version the record gives [key]: of the `seals` it commits, or its `rotate`.
  int _versionOf(KeyRef key) {
    for (final field in const ['seals', 'rotate']) {
      final list = entry.body[field];
      if (list is List<Object?>) {
        for (final commitment in list.whereType<Map<String, Object?>>()) {
          if (commitment['key'] == key.wire) {
            return commitment['version']! as int;
          }
        }
      }
    }
    throw StateError('the record commits no ${key.wire}');
  }

  /// The body of `POST /kem/v1/spaces/{id}/chain` for [signed], this action's entry signed.
  Map<String, Object?> request(SignedChainEntry signed) => {
    'records': [signed.toJson()],
    'seals': [
      for (final MapEntry(key: key, value: recipients) in boxes.entries)
        for (final MapEntry(key: member, value: box) in recipients.entries)
          {'box': b64urlEncode(box), 'key': key.wire, 'member': member, 'seq': entry.seq, 'version': _versionOf(key)},
    ],
    'names': [
      for (final MapEntry(key: target, value: sealed) in names.entries)
        {'name': b64urlEncode(sealed), 'seq': entry.seq, 'target': target.wire},
    ],
  };
}

/// What checking a record against a state found.
typedef ActionCheck = ({SpaceState? after, SpaceActionProblem? problem, String? detail});

/// Why a record can't be appended.
enum SpaceActionProblem {
  /// It makes no sense in the space as the chain has it now: the member left, the grant is gone, a key is marked.
  cantApply,

  /// The chain doesn't allow this member to make it.
  notAllowed,

  /// The server's verification refused it.
  refused,

  /// The head kept moving, and the record could not be placed.
  busy,

  /// The home server is away: every chain record and sealed key goes to it alone, so the change waits for it and is never queued.
  homeAway,
}

/// A record that can't be appended, and why.
class SpaceActionError implements Exception {
  const SpaceActionError(this.problem, [this.detail]);

  final SpaceActionProblem problem;
  final String? detail;

  @override
  String toString() => 'SpaceActionError(${problem.name}${detail != null ? ': $detail' : ''})';
}

/// Runs [entry] against [state]: what it makes sense as, and whether its signer may make it. Never throws.
ActionCheck checkAction(SpaceState state, SpaceChainEntry entry) {
  final SpaceState after;
  try {
    after = state.apply(entry);
  } on ChainRefusal catch (e) {
    return (after: null, problem: SpaceActionProblem.cantApply, detail: e.detail);
  }
  final problem = chainAuthorityProblem(state, after, entry);
  if (problem != null) {
    return (after: null, problem: SpaceActionProblem.notAllowed, detail: problem);
  }
  return (after: after, problem: null, detail: null);
}

/// The `create` of a new space by [account] with [bundle] and its self-signature [bundleSignature], named [name], with
/// one collection, [collectionName] ("Everyone"), under the ids [space] and [collection]. The keys are made by [makeKey]
/// and returned for the caller to keep and wipe.
Future<({ChainAction action, Uint8List spaceKey, Uint8List collectionKey})> buildCreateSpace({
  required String account,
  required KeyBundle bundle,
  required Uint8List bundleSignature,
  required String space,
  required String collection,
  required String name,
  required String collectionName,
  required int at,
  KeyMaker makeKey = randomKeyMaker,
}) async {
  const spaceRef = KeyRef.space();
  final collectionRef = KeyRef.collection(collection);
  final spaceKey = makeKey(spaceRef, 1);
  final collectionKey = makeKey(collectionRef, 1);
  final recipients = {account: bundle};
  final forCollection = await sealKeyTo(
    space: space,
    key: collectionRef,
    version: 1,
    keyBytes: collectionKey,
    recipients: recipients,
    makes: true,
  );
  final forSpace = await sealKeyTo(space: space, key: spaceRef, version: 1, keyBytes: spaceKey, recipients: recipients, makes: true);
  final sealedSpaceName = await sealName(spaceKey: spaceKey, space: space, keyVersion: 1, kind: NameKind.space, id: space, name: name);
  final sealedCollectionName = await sealName(
    spaceKey: spaceKey,
    space: space,
    keyVersion: 1,
    kind: NameKind.collection,
    id: collection,
    name: collectionName,
  );
  final entry = SpaceChainEntry(
    space: space,
    seq: 0,
    prev: chainGenesisLink,
    epoch: 1,
    at: at,
    by: account,
    kind: ChainKind.create,
    body: {
      'bundle': b64urlEncode(bundle.bytes),
      'bundleSignature': b64urlEncode(bundleSignature),
      'collection': {'id': collection, 'nameHash': b64urlEncode(nameHash(sealedCollectionName))},
      'member': account,
      'nameHash': b64urlEncode(nameHash(sealedSpaceName)),
      // The collection's commitment first, then the space's, as the chain reads them
      'seals': [
        for (final SealCommitment commitment in [forCollection.commitment, forSpace.commitment]) commitment.toJson(),
      ],
    },
  );
  return (
    action: ChainAction(
      entry: entry,
      boxes: {collectionRef: forCollection.boxes, spaceRef: forSpace.boxes},
      names: {const NameTarget.space(): sealedSpaceName, NameTarget.collection(collection): sealedCollectionName},
    ),
    spaceKey: spaceKey,
    collectionKey: collectionKey,
  );
}

/// An invitation of [member] as [role] with [grants], by [by]. It grants access and seals no key: the member is entitled
/// to a key only once confirmed.
ChainAction buildInviteAction({
  required SpaceState state,
  required String by,
  required String member,
  required SpaceRole role,
  Set<CustomPermission> custom = const {},
  Map<String, CollectionPermission> grants = const {},
  required int at,
}) => ChainAction(
  entry: buildInvite(state: state, by: by, member: member, role: role, custom: custom, grants: grants, at: at),
);

/// Revokes the invitation of [member], or removes the member: a `remove` that names the keys they held. For an
/// invitation that was never confirmed, `replace` is empty and nothing needs replacing.
ChainAction buildRemoveAction({required SpaceState state, required String by, required String member, required int at}) => ChainAction(
  entry: buildRemove(state: state, by: by, member: member, at: at),
);

/// [by] leaves: a `remove` of themselves, naming the keys they held.
ChainAction buildLeaveAction({required SpaceState state, required String by, required int at}) =>
    buildRemoveAction(state: state, by: by, member: by, at: at);

/// The `confirm` of [member] by [by], after [by] compared the fingerprint of [bundle], the bundle the server gave for the
/// member, with the member's own screen. [bundleSignature] is the bundle's self-signature, and [confirmerSig1PrivateKey]
/// signs the statement under `"confirm"`. A [StateError] when [bundle] isn't the member's.
Future<ChainAction> buildConfirmAction({
  required SpaceState state,
  required String by,
  required String member,
  required KeyBundle bundle,
  required Uint8List bundleSignature,
  required Uint8List confirmerSig1PrivateKey,
  required int at,
}) async {
  if (uuidText(bundle.accountId) != member) {
    throw StateError('the bundle is not $member\'s');
  }
  final statement = ConfirmStatement.forBundle(space: uuidBytes(state.space), bundle: bundle, confirmer: uuidBytes(by));
  final signature = await signConfirmation(statement, confirmerSig1PrivateKey);
  return ChainAction(
    entry: SpaceChainEntry(
      space: state.space,
      seq: state.nextSeq,
      prev: state.headHash ?? chainGenesisLink,
      epoch: state.epoch,
      at: at,
      by: by,
      kind: ChainKind.confirm,
      body: {
        'bundle': b64urlEncode(bundle.bytes),
        'bundleSignature': b64urlEncode(bundleSignature),
        'member': member,
        'statement': b64urlEncode(statement.bytes),
        'statementSignature': b64urlEncode(signature),
      },
    ),
  );
}

/// The keys [keyring] holds at the chain's current version, by key, for a `seal` of them to the members who await them.
Map<KeyRef, Uint8List> heldKeys(SpaceState state, SpaceKeyring keyring) {
  final keys = <KeyRef, Uint8List>{};
  final spaceKey = keyring.spaceKey;
  if (spaceKey != null && keyring.spaceKeyVersion == state.spaceKeyVersion) {
    keys[const KeyRef.space()] = spaceKey;
  }
  for (final collection in state.collections.keys) {
    final version = state.collections[collection]!.keyVersion;
    final key = keyring.collectionKey(collection, version);
    if (key != null) {
      keys[KeyRef.collection(collection)] = key;
    }
  }
  return keys;
}

/// What a member of the sheet does on one space: it reads the verified chain, makes a record from the state it got,
/// checks it, signs it and appends it, and answers the chain read again.
class SpaceActions {
  SpaceActions({
    required this.account,
    required this.readChain,
    required this.openKeyring,
    required this.append,
    required this.sign,
    required this.now,
  });

  /// The account whose app this is.
  final String account;

  /// Reads and verifies the space's chain (`KmSpaceSync.chainState`).
  final Future<SpaceState> Function() readChain;

  /// Opens the keys the chain lets this account hold, for [shareKeys]. The actions dispose it.
  final Future<SpaceKeyring> Function(SpaceState state) openKeyring;

  /// Appends a request (`ChainAction.request`) at the home; throws a [ChainAppendError] for a 409 and a 422.
  final Future<void> Function(Map<String, Object?> request) append;

  /// Signs with the account's `sig1` key (`signerWith`).
  final Future<SignedChainEntry> Function(SpaceChainEntry entry) sign;

  /// Unix seconds, for a record's time.
  final int Function() now;

  /// Makes a record with [build] from the verified chain and appends it, and answers the chain read again. [build] is
  /// called again from a fresh state when the head moved; it returns null when there is nothing to append, and the state
  /// is answered as it is. A [SpaceActionError] when the record makes no sense (a [ChainRefusal] while [build] prepares it
  /// included, with its reason), isn't allowed or is refused.
  Future<SpaceState> run(Future<ChainAction?> Function(SpaceState state) build) async {
    for (var attempt = 1; ; attempt++) {
      final state = await readChain();
      final ChainAction? action;
      try {
        action = await build(state);
      } on ChainRefusal catch (e) {
        // A builder that works out the keys a record loses (`SpaceState.keysLostBy`) refuses one that makes no sense
        throw SpaceActionError(SpaceActionProblem.cantApply, e.detail);
      }
      if (action == null) {
        return state;
      }
      final check = checkAction(state, action.entry);
      if (check.problem != null) {
        throw SpaceActionError(check.problem!, check.detail);
      }
      final signed = await sign(action.entry);
      try {
        await append(action.request(signed));
        return await readChain();
      } on ChainAppendError catch (e) {
        if (e.failure == ChainAppendFailure.refused) {
          throw SpaceActionError(SpaceActionProblem.refused, e.reason);
        }
        if (attempt >= _attempts) {
          throw const SpaceActionError(SpaceActionProblem.busy, 'the chain kept moving');
        }
      }
    }
  }

  /// Invites [member] as [role], granting [grants]. Seals nothing.
  Future<SpaceState> invite(
    String member,
    SpaceRole role, {
    Set<CustomPermission> custom = const {},
    Map<String, CollectionPermission> grants = const {},
  }) => run(
    (state) async => buildInviteAction(state: state, by: account, member: member, role: role, custom: custom, grants: grants, at: now()),
  );

  /// Revokes an invitation, or removes a member. The keys it marks are replaced by `KmSpaceSync.replaceKeys`.
  Future<SpaceState> remove(String member) => run((state) async => buildRemoveAction(state: state, by: account, member: member, at: now()));

  /// Leaves the space.
  Future<SpaceState> leave() => remove(account);

  /// Changes [member]'s role.
  Future<SpaceState> setRole(String member, SpaceRole role, {Set<CustomPermission> custom = const {}}) => run(
    (state) async => ChainAction(
      entry: buildRole(state: state, by: account, member: member, role: role, custom: custom, at: now()),
    ),
  );

  /// Gives [grantee] [permission] on [collection], then shares the collection's key with them if they are confirmed.
  Future<SpaceState> grant(String collection, Grantee grantee, CollectionPermission permission) async {
    await run(
      (state) async => ChainAction(
        entry: buildGrant(state: state, by: account, collection: collection, grantee: grantee, permission: permission, at: now()),
      ),
    );
    return shareKeys();
  }

  /// Takes away [grantee]'s grant on [collection]. The keys it marks are replaced by `KmSpaceSync.replaceKeys`.
  Future<SpaceState> ungrant(String collection, Grantee grantee) => run(
    (state) async => ChainAction(
      entry: buildUngrant(state: state, by: account, collection: collection, grantee: grantee, at: now()),
    ),
  );

  /// Confirms [member], whose [bundle] the confirmer compared, then seals the keys they are entitled to.
  Future<SpaceState> confirm({
    required String member,
    required KeyBundle bundle,
    required Uint8List bundleSignature,
    required Uint8List confirmerSig1PrivateKey,
  }) async {
    await run(
      (state) => buildConfirmAction(
        state: state,
        by: account,
        member: member,
        bundle: bundle,
        bundleSignature: bundleSignature,
        confirmerSig1PrivateKey: confirmerSig1PrivateKey,
        at: now(),
      ),
    );
    return shareKeys();
  }

  /// Seals the keys this account holds to the members the chain says await them: a confirmed member who isn't covered
  /// for a key they are entitled to, a member who replaced their key pair included (the chain records the new bundle).
  /// Only to the `kx1` key of the bundle the chain recorded, never to one the server lists, and nothing when no key is
  /// awaited or a key is marked (`buildSealRecord`).
  Future<SpaceState> shareKeys() => run((state) async {
    final awaited =
        state.awaiting(const KeyRef.space()).isNotEmpty ||
        state.collections.keys.any((id) => state.awaiting(KeyRef.collection(id)).isNotEmpty);
    if (!awaited) {
      return null;
    }
    final keyring = await openKeyring(state);
    try {
      final built = await buildSealRecord(state: state, signer: account, keys: heldKeys(state, keyring), at: now());
      return built == null ? null : ChainAction(entry: built.entry, boxes: built.boxes);
    } finally {
      keyring.dispose();
    }
  });
}
