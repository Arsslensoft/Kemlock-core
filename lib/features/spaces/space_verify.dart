// Checking a space's chain (the space chain section of docs/crypto.md, "Verification" and "Authority";
// docs/plans/add-server-spaces.md, design 2): each record's position, signer and signatures, the kind's rules,
// WHO may make it, and that the chain neither goes back nor forks from what this device already accepted.
//
// - **Order.** Per record: anchor, position (space, sequence, link, epoch), signer, signatures, the kind's rules
//   (`SpaceState.apply`), authority. The first check that fails gives the reason, so a record that breaks several
//   rules always gets the same one: a bad link and a bad signature is a bad link, a signature by a key the chain
//   doesn't record for `by` and a broken authority row is a bad signature.
// - **Signature.** A record is signed by `by` with the `sig1` key of the bundle the chain recorded for them in the
//   state before (the maker's own, for `create`); a `rekey` is cosigned by the bundle it installs.
// - **Who may sign what** is the spec's table, taken against the state before and the state after: Manage, Assign,
//   MayGrant and GroupAdmin, and four rules for every kind: Owners change Owners, nobody widens themselves, access
//   changes need MayGrant, a confirmed Owner remains.
// - **Anchor, fork and rollback.** A device keeps, for each space, the epoch and the link of every record it accepted.
//   A chain that ends before its anchor is a rollback; one with another record at a `seq` it accepted is a fork,
//   unless that record is a verifying `fence` of a higher epoch, which drops the device's own records from there
//   (the Owner moved the home, and the old home's later records never become part of the chain). Both refusals leave
//   the device its anchor and its last state, and seal nothing new.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/bundle.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart' show constantTimeEquals;
import 'chain_body.dart';
import 'space_chain.dart';
import 'space_state.dart';

/// The most bytes of links an anchor holds: 65,536 links of 32 bytes.
const maxAnchorBytes = 2 * 1024 * 1024;

/// What a device keeps of the chain of a space it accepted, its **anchor**: the epoch of the last record it accepted
/// and the link of every record it accepted, from `seq` 0 to that one (32 bytes each). It never goes back, except by
/// a fence. A device that lost its anchor can't rebuild it from the server: it starts again from "First contact".
final class ChainAnchor {
  ChainAnchor({required this.epoch, required List<Uint8List> links})
    : links = List.unmodifiable([for (final link in links) copyBytes(requireLength(link, 32, 'a chain link'))]) {
    if (epoch < 1 || epoch > 0xffffffff) {
      throw MalformedException('an epoch is from 1 to 2^32 - 1: $epoch');
    }
    if (links.isEmpty || links.length > maxChainRecords) {
      throw MalformedException('an anchor holds 1 to $maxChainRecords links, not ${links.length}');
    }
  }

  /// The anchor of the chain [state] derives from [accepted], null for an empty chain.
  static ChainAnchor? of(SpaceState state, List<SignedChainEntry> accepted) =>
      accepted.isEmpty ? null : ChainAnchor(epoch: state.epoch, links: [for (final signed in accepted) signed.entry.hashed]);

  /// Reads `{"epoch": n, "links": <base64url of the links, 32 bytes each>}`.
  factory ChainAnchor.fromJson(Object? json) {
    final fields = strictObject(json, required: {'epoch', 'links'});
    final epoch = fields['epoch'];
    final links = fields['links'];
    if (epoch is! int || links is! String) {
      throw const MalformedException('an anchor is an epoch and its links');
    }
    final bytes = b64urlDecode(links);
    if (bytes.length % 32 != 0 || bytes.length > maxAnchorBytes) {
      throw const MalformedException('the links of an anchor are whole 32-byte links, at most 2 MiB');
    }
    return ChainAnchor(epoch: epoch, links: [for (var at = 0; at < bytes.length; at += 32) Uint8List.sublistView(bytes, at, at + 32)]);
  }

  final int epoch;

  /// The link of the record at each `seq`, from 0.
  final List<Uint8List> links;

  /// The `seq` of the last record accepted.
  int get seq => links.length - 1;

  /// The link of the last record accepted.
  Uint8List get head => links.last;

  Map<String, Object?> toJson() => {
    'epoch': epoch,
    'links': b64urlEncode([for (final link in links) ...link]),
  };

  @override
  bool operator ==(Object other) =>
      other is ChainAnchor &&
      other.epoch == epoch &&
      other.links.length == links.length &&
      [for (var i = 0; i < links.length; i++) i].every((i) => constantTimeEquals(other.links[i], links[i]));

  @override
  int get hashCode => Object.hash(epoch, links.length, Object.hashAll(links.last));
}

/// What verifying a chain found.
final class ChainResult {
  const ChainResult({
    required this.state,
    required this.accepted,
    this.droppedFrom,
    this.droppedTo,
    this.problem,
    this.problemSeq,
    this.detail,
  });

  /// The state after the last entry accepted. When [problem] is set it is the last valid state of this chain, which
  /// a device that already holds a newer one keeps instead of it.
  final SpaceState state;

  /// The entries that verified, in order.
  final List<SignedChainEntry> accepted;

  /// The records this device had accepted from [droppedFrom] to [droppedTo] that a fence left out of the chain: they
  /// were made under the old home's epoch after the promotion, and the app lists them for the space's Admins to redo or
  /// drop, and says so plainly when one of them was a `remove`. Null when there is no fence in the way.
  final int? droppedFrom;
  final int? droppedTo;

  /// Why the chain stopped being accepted, or null when all of it was. The space then shows as "Can't be checked".
  final ChainProblem? problem;

  /// The sequence number of the entry that was refused, when there is one. For a chain that is rolled back, which
  /// has no entry to refuse, it is the `seq` of the chain's last entry (null when the chain is empty).
  final int? problemSeq;
  final String? detail;

  bool get ok => problem == null;

  /// The anchor to store: the links of every entry accepted, null for an empty chain.
  ChainAnchor? get anchor => ChainAnchor.of(state, accepted);
}

/// Whether the federation promotion record for a fence's epoch, which a client may hold through the sync plan, has the
/// hash [promotion] and the new home [home]. A client that doesn't hold it passes none and accepts the Owner's fence.
typedef FenceCheck = bool Function(int epoch, String home, Uint8List promotion);

/// Verifies [entries], the chain the server served for the space [space], from `seq` 0, in the order of the spec's
/// "Verification": for each record the anchor, its position (space, sequence, link, epoch), its signer, its signatures,
/// the kind's rules against the state, then the authority the chain gave its signer.
///
/// [anchor] is what this device accepted before. A record whose link differs from the anchor's at its `seq` is a
/// **divergence**, allowed only at a `fence` (then the device's own records from there are dropped, and the anchor's
/// epoch must be below the fence's) and otherwise [ChainProblem.forked]; a chain that ends before the anchor's last
/// record, with no divergence, is [ChainProblem.rolledBack]. [fenceCheck] holds a fence to its promotion record. [crypto]
/// checks the signatures; production code uses the default.
///
/// It stops at the first entry that isn't accepted: the result holds the state before it and the reason.
///
/// owner: to decide
/// A chain past 65,536 records or 64 MiB is refused as too large, as the spec's limits say, and a space that reaches
/// them takes no more records. The options (a checkpoint record, a new space and a move, a higher limit with
/// incremental verification) are the owner's; none is built.
///
/// Changes made outside Kemlock clients (the server's Bitwarden-compatible routes, SSO group sync) are not a record:
/// this verifies the chain and accepts nothing unsigned, so a member or group change the server makes alone never
/// shows in the state. The owner decided they are queued for an Admin's app to sign (space_pending.dart): it lists them,
/// shows what each would do, and appends the matching record, or drops the change.
Future<ChainResult> verifyChain({
  required String space,
  required List<SignedChainEntry> entries,
  ChainAnchor? anchor,
  FenceCheck? fenceCheck,
  ChainCrypto crypto = const RealChainCrypto(),
}) async {
  var state = SpaceState.empty(space);
  final accepted = <SignedChainEntry>[];
  int? divergence;
  int? divergenceEpoch;
  ChainResult stop(ChainProblem problem, int? seq, String detail) =>
      ChainResult(state: state, accepted: accepted, problem: problem, problemSeq: seq, detail: detail);

  for (final signed in entries) {
    final entry = signed.entry;
    try {
      // Step 1: the anchor
      final held = anchor != null && entry.seq <= anchor.seq ? anchor.links[entry.seq] : null;
      if (divergence == null && held != null && !constantTimeEquals(held, entry.hashed)) {
        if (entry.kind != ChainKind.fence) {
          throw ChainRefusal(ChainProblem.forked, 'the server has another entry ${entry.seq} than the one this device accepted');
        }
        divergence = entry.seq;
        divergenceEpoch = entry.epoch;
      }
      state.checkPosition(entry);
      final signer = _signerBundle(state, entry);
      await _checkSignatures(signed, signer, crypto);
      if (entry.kind == ChainKind.recoveryKey && !await _guard(() => crypto.checkRecoveryKey(readRecoveryKey(entry.body)))) {
        throw const ChainRefusal(ChainProblem.invalid, 'a recovery key is a usable kx1 key');
      }
      final next = state.apply(entry);
      final why = chainAuthorityProblem(state, next, entry);
      if (why != null) {
        throw ChainRefusal(ChainProblem.notAllowed, why);
      }
      if (entry.kind == ChainKind.fence && fenceCheck != null) {
        final fence = readFence(entry.body);
        if (!fenceCheck(entry.epoch, fence.home, fence.promotion)) {
          throw const ChainRefusal(ChainProblem.badEpoch, 'the fence is not the promotion record\'s');
        }
      }
      state = next;
      accepted.add(signed);
    } on ChainRefusal catch (e) {
      return stop(e.problem, entry.seq, e.detail);
    } on MalformedException catch (e) {
      return stop(ChainProblem.malformed, entry.seq, e.message);
    }
  }

  // Step 2: after the last record
  final headSeq = state.headSeq ?? -1;
  if (divergence != null) {
    if (anchor!.epoch >= divergenceEpoch!) {
      return stop(ChainProblem.forked, divergence, 'the fence at $divergence is not above the epoch ${anchor.epoch} this device accepted');
    }
    return ChainResult(state: state, accepted: accepted, droppedFrom: divergence, droppedTo: anchor.seq);
  }
  if (anchor != null && anchor.seq > headSeq) {
    return stop(
      ChainProblem.rolledBack,
      headSeq < 0 ? null : headSeq,
      'the server\'s chain ends at $headSeq, and this device accepted ${anchor.seq}',
    );
  }
  return ChainResult(state: state, accepted: accepted);
}

Future<bool> _guard(Future<bool> Function() check) async {
  try {
    return await check();
  } on MalformedException {
    return false;
  }
}

/// Step 3: the bundle that verifies [entry]. A `create` is verified with the bundle it carries, which must be its
/// signer's; any other kind with the bundle the chain recorded for `by`, who must be confirmed in [state].
KeyBundle _signerBundle(SpaceState state, SpaceChainEntry entry) {
  if (entry.kind == ChainKind.create) {
    final bundle = _parseBundle(readCreate(entry.body).bundle);
    if (bundle == null || !constantTimeEquals(bundle.accountId, uuidBytes(entry.by))) {
      throw const ChainRefusal(ChainProblem.badBundle, 'the first record carries the bundle of its signer');
    }
    return bundle;
  }
  final signer = state.member(entry.by);
  final bundle = signer?.bundle;
  if (signer == null || !signer.isConfirmed || bundle == null) {
    throw ChainRefusal(ChainProblem.unknownSigner, '${entry.by} is not a confirmed member whose key the chain records');
  }
  return bundle;
}

KeyBundle? _parseBundle(Uint8List bytes) {
  try {
    return KeyBundle.parse(bytes);
  } on MalformedException {
    return null;
  }
}

/// Step 4: the record's signature by [signer]'s key, a `rekey`'s cosignature by the new bundle's key, a carried bundle's
/// self-signature and a `confirm`'s statement signature by the confirmer's recorded key. A bundle that doesn't parse
/// is left to the kind's rules (step 5), which refuse it as a bad bundle.
Future<void> _checkSignatures(SignedChainEntry signed, KeyBundle signer, ChainCrypto crypto) async {
  final entry = signed.entry;
  if (!await _guard(() => crypto.checkEntry(signer.sig1PublicKey, entry.bytes, signed.signature))) {
    throw ChainRefusal(ChainProblem.badSignature, 'entry ${entry.seq} is not signed by ${entry.by} under "space-chain"');
  }
  final body = entry.body;
  Uint8List? carried;
  Uint8List? carriedSignature;
  switch (entry.kind) {
    case ChainKind.create:
      final create = readCreate(body);
      carried = create.bundle;
      carriedSignature = create.bundleSignature;
    case ChainKind.confirm:
      final confirm = readConfirm(body);
      carried = confirm.bundle;
      carriedSignature = confirm.bundleSignature;
    case ChainKind.rekey:
      final rekey = readRekey(body);
      carried = rekey.bundle;
      carriedSignature = rekey.bundleSignature;
    default:
      break;
  }
  final bundle = carried == null ? null : _parseBundle(carried);
  if (entry.kind == ChainKind.rekey) {
    final cosignature = signed.cosignature;
    if (cosignature == null || (bundle != null && !await _guard(() => crypto.checkEntry(bundle.sig1PublicKey, entry.bytes, cosignature)))) {
      throw ChainRefusal(ChainProblem.badSignature, 'entry ${entry.seq} is not cosigned by the key of the bundle it installs');
    }
  }
  if (bundle != null && !await _guard(() => crypto.checkBundle(bundle, carriedSignature!))) {
    throw ChainRefusal(ChainProblem.badBundle, 'the bundle of entry ${entry.seq} is not signed by its own key');
  }
  if (entry.kind == ChainKind.confirm) {
    final confirm = readConfirm(body);
    if (!await _guard(() => crypto.checkConfirmation(confirm.statement, confirm.statementSignature, signer.sig1PublicKey))) {
      throw ChainRefusal(ChainProblem.badConfirmation, 'the confirmation is not signed by ${entry.by} under "confirm"');
    }
  }
}

// ─── Who may sign ────────────────────────────────────────────────────────

/// Why the signer of [entry] may not make it, or null when they may (step 6 of verification). [before] is the state
/// before the record and [after] the state it gives. `create` is the maker's, who becomes the Owner.
///
/// Four rules hold for every kind but `create`, and then the kind's own row (the spec's "Authority"):
///
/// 1. **Owners change Owners.** A record that touches an Owner, in [before] or [after], by their role, permissions,
///    status, bundle, group memberships or access to a collection that exists in both, is an Owner's.
/// 2. **Nobody widens themselves**: not their role or permissions, nor their access to a collection of [before].
/// 3. **Access changes need MayGrant** of each collection that exists in both and where any member's access differs;
///    the member a `remove` removes is left out, Manage covers them.
/// 4. **A confirmed Owner remains**, which `SpaceState.apply` checks.
String? chainAuthorityProblem(SpaceState before, SpaceState after, SpaceChainEntry entry) {
  if (entry.kind == ChainKind.create) {
    return null;
  }
  final actor = before.member(entry.by);
  if (actor == null || !actor.isConfirmed) {
    return '${entry.by} is not a confirmed member';
  }
  final changes = before.accessChangesTo(after);
  final removed = entry.kind == ChainKind.remove ? readRemove(entry.body).member : null;

  // Rule 1
  if (actor.role != SpaceRole.owner) {
    final owners = {
      for (final member in [...before.members.values, ...after.members.values])
        if (member.inSpace && member.role == SpaceRole.owner) member.id,
    };
    for (final owner in owners) {
      if (_ownerTouched(before, after, owner, changes)) {
        return 'only an owner changes an owner: $owner';
      }
    }
  }

  // Rule 2
  final self = after.member(actor.id);
  if (self != null && self.inSpace) {
    final widerRole =
        roleRank(self.role) > roleRank(actor.role) ||
        (self.role == SpaceRole.custom && actor.role == SpaceRole.custom && !self.custom.every(actor.custom.contains));
    if (widerRole) {
      return '${entry.by} may not widen their own role or permissions';
    }
  }
  if (changes.any((change) => change.member == actor.id && accessWidens(change.before, change.after))) {
    return '${entry.by} may not widen their own access';
  }

  // Rule 3
  for (final change in changes) {
    if (change.member != removed && !_mayGrant(before, actor, change.collection)) {
      return 'a ${actor.role.wire} may not change the access to ${change.collection}';
    }
  }

  return _kindProblem(before, after, actor, entry);
}

/// Whether the record from [before] to [after] changes the Owner [owner]: their role, permissions, status, bundle, group
/// memberships, or access to a collection that exists in both ([changes]).
bool _ownerTouched(SpaceState before, SpaceState after, String owner, List<AccessChange> changes) {
  final was = before.member(owner);
  final now = after.member(owner);
  if (was == null || now == null) {
    return was != now;
  }
  final sameBundle = constantTimeEquals(was.bundle?.bytes ?? Uint8List(0), now.bundle?.bytes ?? Uint8List(0));
  final samePermissions = was.custom.length == now.custom.length && was.custom.every(now.custom.contains);
  if (was.role != now.role || was.status != now.status || !samePermissions || !sameBundle) {
    return true;
  }
  if (changes.any((change) => change.member == owner)) {
    return true;
  }
  final groups = {...before.groups.keys, ...after.groups.keys};
  return groups.any((id) => (before.groups[id]?.members.contains(owner) ?? false) != (after.groups[id]?.members.contains(owner) ?? false));
}

String? _kindProblem(SpaceState before, SpaceState after, SpaceMember actor, SpaceChainEntry entry) {
  final body = entry.body;
  final isOwner = actor.role == SpaceRole.owner;
  final isAdmin = actor.role == SpaceRole.admin;
  final role = actor.role.wire;
  switch (entry.kind) {
    case ChainKind.create:
      return null;
    case ChainKind.invite:
      final invite = readInvite(body);
      return _canAssign(actor, invite.role, invite.custom.toSet()) ? null : 'a $role may not invite a ${invite.role.wire}';
    case ChainKind.confirm:
      final target = before.member(readConfirm(body).member);
      return target != null && _canManage(actor, target) ? null : 'a $role may not confirm ${body['member']}';
    case ChainKind.rekey:
      return null;
    case ChainKind.role:
      final change = readRole(body);
      if (change.member == actor.id) {
        final narrower =
            roleRank(change.role) < roleRank(actor.role) ||
            (change.role == SpaceRole.custom &&
                actor.role == SpaceRole.custom &&
                change.custom.every(actor.custom.contains) &&
                change.custom.length < actor.custom.length);
        return narrower ? null : 'a member may only narrow their own role';
      }
      final target = before.member(change.member);
      return target != null && _canManage(actor, target) && _canAssign(actor, change.role, change.custom.toSet())
          ? null
          : 'a $role may not give ${change.member} the role ${change.role.wire}';
    case ChainKind.remove:
      final id = readRemove(body).member;
      // Leaving is anyone's own
      if (id == actor.id) {
        return null;
      }
      final target = before.member(id);
      return target != null && _canManage(actor, target) ? null : 'a $role may not remove $id';
    case ChainKind.grant:
    case ChainKind.ungrant:
      final collection = body['collection']! as String;
      return _mayGrant(before, actor, collection) ? null : 'a $role may not grant $collection';
    case ChainKind.collection:
      return isOwner || isAdmin || actor.custom.contains(CustomPermission.createCollections) ? null : 'a $role may not make collections';
    case ChainKind.move:
    case ChainKind.collectionDelete:
      final collection = body['collection']! as String;
      return _mayGrant(before, actor, collection) ? null : 'a $role may not change $collection';
    case ChainKind.group:
    case ChainKind.groupMembers:
    case ChainKind.groupDelete:
      return _groupAdmin(actor) ? null : 'a $role may not manage groups';
    case ChainKind.rename:
      final target = readRename(body).target;
      return switch (target.type) {
        NameType.space => isOwner || isAdmin ? null : 'only an owner or an admin renames the space',
        NameType.collection => _mayGrant(before, actor, target.id!) ? null : 'a $role may not rename ${target.id}',
        NameType.group => _groupAdmin(actor) ? null : 'a $role may not rename a group',
      };
    case ChainKind.seal:
      for (final commitment in readSeal(body).seals) {
        if (!before.holds(commitment.key, actor.id)) {
          return '${actor.id} does not hold ${commitment.key.wire}, so can not share it';
        }
      }
      return null;
    case ChainKind.keys:
      for (final commitment in readKeys(body).rotate) {
        final key = commitment.key;
        if (key.isSpace) {
          if (!isOwner && !isAdmin) {
            return 'only an owner or an admin replaces the space key';
          }
          continue;
        }
        if (!before.entitled(key).contains(actor.id)) {
          return '${actor.id} is not entitled to ${key.wire}, so can not replace it';
        }
        final allowed = isOwner || isAdmin || (before.accessOf(actor.id, key.collection!)?.manage ?? false) || before.isMarked(key);
        if (!allowed) {
          return 'a $role may replace ${key.wire} only while it is marked';
        }
      }
      return null;
    case ChainKind.policies:
      if (!isOwner && !isAdmin) {
        return 'only an owner or an admin sets the policies';
      }
      return before.policies['accountRecovery'] != after.policies['accountRecovery'] && !isOwner
          ? 'only an owner changes account recovery'
          : null;
    case ChainKind.recoveryKey:
    case ChainKind.recoveryKeyClear:
      return isOwner ? null : 'only an owner sets or clears the recovery key';
    case ChainKind.fence:
      return isOwner ? null : 'only an owner signs a fence';
  }
}

/// Whether [actor] may manage [target]: confirm or change them. An Owner may manage anyone, an Admin anyone but an Owner,
/// and a Custom member with Manage users a Custom member or Member whose permissions are all among its own.
bool _canManage(SpaceMember actor, SpaceMember target) => switch (actor.role) {
  SpaceRole.owner => true,
  SpaceRole.admin => target.role != SpaceRole.owner,
  SpaceRole.custom =>
    actor.custom.contains(CustomPermission.manageUsers) &&
        (target.role == SpaceRole.custom || target.role == SpaceRole.member) &&
        target.custom.every(actor.custom.contains),
  SpaceRole.member => false,
};

/// Whether [actor] may give someone [role] with [custom] permissions: an Owner any, an Admin any but Owner, a Custom
/// member with Manage users Member, or Custom with permissions all among its own.
bool _canAssign(SpaceMember actor, SpaceRole role, Set<CustomPermission> custom) => switch (actor.role) {
  SpaceRole.owner => true,
  SpaceRole.admin => role != SpaceRole.owner,
  SpaceRole.custom =>
    actor.custom.contains(CustomPermission.manageUsers) &&
        (role == SpaceRole.member || (role == SpaceRole.custom && custom.every(actor.custom.contains))),
  SpaceRole.member => false,
};

/// Whether [actor] may grant [collection]: an Owner or Admin, or a member whose own access gives them Manage on it.
bool _mayGrant(SpaceState state, SpaceMember actor, String collection) =>
    actor.role == SpaceRole.owner || actor.role == SpaceRole.admin || (state.accessOf(actor.id, collection)?.manage ?? false);

bool _groupAdmin(SpaceMember actor) =>
    actor.role == SpaceRole.owner ||
    actor.role == SpaceRole.admin ||
    (actor.role == SpaceRole.custom && actor.custom.contains(CustomPermission.manageGroups));
