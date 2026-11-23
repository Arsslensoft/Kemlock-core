// The state a space's chain derives (the space chain section of docs/crypto.md, "State" and
// "Kinds"; docs/plans/add-server-spaces.md, design 2): its members with their confirmed bundles,
// roles and Custom permissions, its collections, groups and grants, its key versions with their
// seal commitments, key checks and marks, its name hashes, its policies, its home epoch and its
// recovery key. The app opens and seals keys only from this state, and uses the server's own member
// list for display and invitations only.
//
// `SpaceState.apply` takes one record and gives the next state, or refuses it with a [ChainRefusal].
// It is step 5 of verification: the kind's rules, "Removal and replacement", the rule that a
// confirmed Owner remains and the limits on counts. Position (`checkPosition`, step 2) is the
// verifier's first look and `apply` repeats it. WHO may make a record, and its signatures, are
// `space_verify.dart`'s.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/bundle.dart';
import '../../crypto/account/confirm.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/account/jcs.dart';
import '../../crypto/bytes.dart' show constantTimeEquals;
import 'chain_body.dart';
import 'space_chain.dart';
import 'space_types.dart';

export 'space_types.dart';

/// Where a member is: invited, confirmed (holds keys) or removed (kept so their history reads).
enum MemberStatus { invited, confirmed, removed }

/// What a confirmer signed: that they compared this member's fingerprint.
final class MemberConfirmation {
  MemberConfirmation({required this.by, required List<int> statement, required List<int> signature, required this.seq})
    : statement = copyBytes(statement),
      signature = copyBytes(signature);

  /// The confirmer's account id.
  final String by;

  /// The 134 bytes (`confirm.dart`) and the confirmer's signature of them.
  final Uint8List statement;
  final Uint8List signature;

  /// The sequence number of the `confirm` record.
  final int seq;
}

/// One account's place in a space, as the chain has it.
final class SpaceMember {
  const SpaceMember({
    required this.id,
    required this.role,
    required this.status,
    required this.invitedBy,
    this.custom = const {},
    this.bundle,
    this.bundleSignature,
    this.confirmation,
    this.rekeySeq,
  });

  /// The account id.
  final String id;
  final SpaceRole role;
  final Set<CustomPermission> custom;
  final MemberStatus status;
  final String invitedBy;

  /// The bundle the chain records, set while confirmed: the `kx1` key keys are sealed to and the `sig1` key the
  /// member's records verify with. It is the creator's own for the first Owner.
  final KeyBundle? bundle;

  /// The bundle's signature by its own `sig1` key.
  final Uint8List? bundleSignature;

  /// The confirmation, null for the first Owner, who made the space, and after a `rekey`.
  final MemberConfirmation? confirmation;

  /// The `seq` of the member's last `rekey`, which stands in place of a confirmation: nobody compared the new
  /// fingerprint, the old key vouched for it.
  final int? rekeySeq;

  bool get isConfirmed => status == MemberStatus.confirmed;

  /// Invited or confirmed.
  bool get inSpace => status != MemberStatus.removed;

  SpaceMember withRole(SpaceRole role, Set<CustomPermission> custom) => SpaceMember(
    id: id,
    role: role,
    status: status,
    invitedBy: invitedBy,
    custom: custom,
    bundle: bundle,
    bundleSignature: bundleSignature,
    confirmation: confirmation,
    rekeySeq: rekeySeq,
  );
}

/// A collection: a set of a space's items that share one key and one set of grants.
final class CollectionInfo {
  CollectionInfo({
    required this.id,
    required List<int> nameHash,
    required this.nameVersion,
    required this.keyVersion,
    this.parent,
    this.marked = false,
  }) : nameHash = copyBytes(nameHash);

  final String id;
  final String? parent;

  /// `SHA-256` of the sealed name the chain committed, and the space key version it is sealed under.
  final Uint8List nameHash;
  final int nameVersion;

  /// The version of the collection's current key, from 1.
  final int keyVersion;

  /// Whether the key must be replaced before it is used again.
  final bool marked;

  CollectionInfo copyWith({Uint8List? nameHash, int? nameVersion, int? keyVersion, bool? marked, String? parent, bool noParent = false}) =>
      CollectionInfo(
        id: id,
        nameHash: nameHash ?? this.nameHash,
        nameVersion: nameVersion ?? this.nameVersion,
        keyVersion: keyVersion ?? this.keyVersion,
        marked: marked ?? this.marked,
        parent: noParent ? null : (parent ?? this.parent),
      );
}

/// A named set of members, granted collections as one.
final class SpaceGroup {
  SpaceGroup({required this.id, required List<int> nameHash, required this.nameVersion, required Set<String> members})
    : nameHash = copyBytes(nameHash),
      members = Set.unmodifiable(members);

  final String id;
  final Uint8List nameHash;
  final int nameVersion;
  final Set<String> members;
}

/// The seal of one key version to one member the chain committed: the bundle key version it is to, and the `seq` of
/// the record that committed it.
final class SealEntry {
  const SealEntry({required this.bundleVersion, required this.seq});

  final int bundleVersion;
  final int seq;
}

/// What one record committed about the seals of a key version: how many recipients, the digest of their boxes and who
/// the recipients were, each with the bundle key version the seal is to. The recipients stay as the record made them,
/// whatever happened to the members since, because the digest is of them.
final class CommitRecord {
  CommitRecord({required this.seq, required this.count, required List<int> digest, required Map<String, int> recipients})
    : digest = copyBytes(digest),
      recipients = Map.unmodifiable(recipients);

  final int seq;
  final int count;
  final Uint8List digest;
  final Map<String, int> recipients;
}

/// One member's access to one collection that differs between two states.
typedef AccessChange = ({String collection, String member, Access? before, Access? after});

/// The most levels collections nest, as the server has it.
const maxCollectionDepth = 16;

/// The most members (invited or confirmed), collections and groups of a space, and grants on one collection.
const maxSpaceMembers = 10000;
const maxSpaceCollections = 1000;
const maxSpaceGroups = 1000;
const maxCollectionGrants = 1000;

Never _invalid(String why) => throw ChainRefusal(ChainProblem.invalid, why);

/// What a space's chain says, up to its last accepted record.
final class SpaceState {
  /// A space with no record yet.
  SpaceState.empty(this.space)
    : _members = const {},
      _collections = const {},
      _groups = const {},
      _grants = const {},
      _checks = const {},
      _seals = const {},
      _commitments = const {},
      _retired = const {},
      _policies = const {},
      _flagSince = const {};

  SpaceState._copy(SpaceState other)
    : space = other.space,
      _headSeq = other._headSeq,
      _headHash = other._headHash,
      _epoch = other._epoch,
      _home = other._home,
      _promotion = other._promotion,
      _nameHash = other._nameHash,
      _nameVersion = other._nameVersion,
      _spaceKeyVersion = other._spaceKeyVersion,
      _spaceKeyMarked = other._spaceKeyMarked,
      _members = other._members,
      _collections = other._collections,
      _groups = other._groups,
      _grants = other._grants,
      _checks = other._checks,
      _seals = other._seals,
      _commitments = other._commitments,
      _retired = other._retired,
      _policies = other._policies,
      _flagSince = other._flagSince,
      _recoveryKey = other._recoveryKey,
      _recoveryKeySeq = other._recoveryKeySeq;

  /// The space's UUID.
  final String space;

  // Every map is replaced whole when it changes, never changed in place, so a state shares what it didn't change.
  int? _headSeq;
  Uint8List? _headHash;
  int _epoch = 1;
  String? _home;
  Uint8List? _promotion;
  Uint8List? _nameHash;
  int _nameVersion = 1;
  int _spaceKeyVersion = 1;
  bool _spaceKeyMarked = false;
  Map<String, SpaceMember> _members;
  Map<String, CollectionInfo> _collections;
  Map<String, SpaceGroup> _groups;
  Map<String, Map<String, CollectionPermission>> _grants;
  // By key (`space` or `collection:<uuid>`), for the key's current version only
  Map<String, Uint8List> _checks;
  Map<String, Map<String, SealEntry>> _seals;
  Map<String, List<CommitRecord>> _commitments;
  Set<String> _retired;
  Map<String, Object?> _policies;
  // The `seq` of the `policies` record that turned each policy flag on, for the flags that are on
  Map<String, int> _flagSince;
  Uint8List? _recoveryKey;
  // The `seq` of the `recovery-key` record that set [_recoveryKey], which an enrolment box is bound to
  int? _recoveryKeySeq;

  bool get isEmpty => _headHash == null;

  /// The sequence number the next record must have.
  int get nextSeq => _headSeq == null ? 0 : _headSeq! + 1;

  /// The sequence number and link of the last record applied, which the anchor keeps.
  int? get headSeq => _headSeq;
  Uint8List? get headHash => _headHash == null ? null : copyBytes(_headHash!);

  /// The epoch of the last record applied.
  int get epoch => _epoch;

  /// The server id and promotion hash of the last `fence`, or null.
  String? get home => _home;
  Uint8List? get promotion => _promotion == null ? null : copyBytes(_promotion!);

  /// The version of the current space key, and whether it must be replaced before it is used again.
  int get spaceKeyVersion => _spaceKeyVersion;
  bool get spaceKeyMarked => _spaceKeyMarked;

  Map<String, SpaceMember> get members => Map.unmodifiable(_members);
  Map<String, CollectionInfo> get collections => Map.unmodifiable(_collections);
  Map<String, SpaceGroup> get groups => Map.unmodifiable(_groups);

  /// The grants of each collection by grantee (`user:<uuid>` or `group:<uuid>`).
  Map<String, Map<String, CollectionPermission>> get grants => {
    for (final entry in _grants.entries) entry.key: Map<String, CollectionPermission>.unmodifiable(entry.value),
  };

  /// The ids of deleted collections and groups, which can't be used again.
  Set<String> get retired => Set.unmodifiable(_retired);

  /// The policy set, in the shape of a `policies` record's body.
  Map<String, Object?> get policies => Map.unmodifiable(_policies.isEmpty ? defaultPolicies() : _policies);

  /// The `seq` of the `policies` record that turned [flag] on, or null while it is off. A notice that is shown once
  /// remembers this number: turning the flag off and on again makes a new notice.
  int? flagSince(String flag) => _flagSince[flag];

  /// The recovery public key an Owner recorded, 1,600 bytes of a `kx1` key, or null.
  Uint8List? get recoveryKey => _recoveryKey == null ? null : copyBytes(_recoveryKey!);

  /// The `seq` of the chain record that set [recoveryKey], or null when there is none.
  int? get recoveryKeySeq => _recoveryKeySeq;

  /// The keys that must be replaced before they are used again, each as [KeyRef].
  Set<KeyRef> get markedKeys => {
    if (_spaceKeyMarked) const KeyRef.space(),
    for (final collection in _collections.values)
      if (collection.marked) KeyRef.collection(collection.id),
  };

  /// Whether any key waits for a replacement: the space shows "Keys need replacing" to its admins.
  bool get keysNeedReplacing => _spaceKeyMarked || _collections.values.any((collection) => collection.marked);

  /// The collections whose key is marked.
  Set<String> get markedCollections => {
    for (final collection in _collections.values)
      if (collection.marked) collection.id,
  };

  SpaceMember? member(String id) => _members[id];

  Iterable<SpaceMember> get confirmedMembers => _members.values.where((member) => member.isConfirmed);

  /// How many confirmed Owners the space has.
  int get confirmedOwners => confirmedMembers.where((member) => member.role == SpaceRole.owner).length;

  /// The hash of the sealed name of [target] and the space key version it is sealed under, or null when the target
  /// isn't in the space.
  ({Uint8List hash, int version})? nameOf(NameTarget target) {
    switch (target.type) {
      case NameType.space:
        final hash = _nameHash;
        return hash == null ? null : (hash: copyBytes(hash), version: _nameVersion);
      case NameType.collection:
        final collection = _collections[target.id];
        return collection == null ? null : (hash: copyBytes(collection.nameHash), version: collection.nameVersion);
      case NameType.group:
        final group = _groups[target.id];
        return group == null ? null : (hash: copyBytes(group.nameHash), version: group.nameVersion);
    }
  }

  // ─── Access, keys and seals ────────────────────────────────────────────

  /// The rights [memberId] has on [collection] through grants, directly or by a group. Null when they have none. The
  /// member's status isn't looked at: callers check it where it matters.
  Access? accessOf(String memberId, String collection) {
    Access? found;
    for (final entry in (_grants[collection] ?? const <String, CollectionPermission>{}).entries) {
      final grantee = Grantee.parse(entry.key);
      final applies = grantee.isGroup ? (_groups[grantee.id]?.members.contains(memberId) ?? false) : grantee.id == memberId;
      if (applies) {
        final rights = Access.of(entry.value);
        found = found == null ? rights : found.combine(rights);
      }
    }
    return found;
  }

  /// The confirmed members entitled to [collection]'s key: the ones with access to it.
  Set<String> recipients(String collection) => entitled(KeyRef.collection(collection));

  /// The collections [memberId] has access to through grants.
  Set<String> collectionsOf(String memberId) => {
    for (final collection in _collections.keys)
      if (accessOf(memberId, collection) != null) collection,
  };

  /// Whether the key [key] exists in the space.
  bool hasKey(KeyRef key) => key.isSpace ? _members.isNotEmpty : _collections.containsKey(key.collection);

  /// The current version of [key], or null when it doesn't exist.
  int? keyVersionOf(KeyRef key) => key.isSpace ? (isEmpty ? null : _spaceKeyVersion) : _collections[key.collection]?.keyVersion;

  /// Whether [key] must be replaced before it is used again.
  bool isMarked(KeyRef key) => key.isSpace ? _spaceKeyMarked : (_collections[key.collection]?.marked ?? false);

  /// The members entitled to [key]: for the space key every confirmed member, for a collection's key every confirmed
  /// member with access to it.
  Set<String> entitled(KeyRef key) => key.isSpace
      ? {for (final member in confirmedMembers) member.id}
      : {
          for (final member in confirmedMembers)
            if (accessOf(member.id, key.collection!) != null) member.id,
        };

  /// The seal of [key]'s current version to [account] the chain committed, or null.
  SealEntry? sealOf(KeyRef key, String account) => _seals[key.wire]?[account];

  /// Whether [account] holds [key]: has a seal of its current version, to any bundle version.
  bool holds(KeyRef key, String account) => sealOf(key, account) != null;

  /// Whether [account] is covered for [key]: its seal is to its current bundle version.
  bool covered(KeyRef key, String account) {
    final seal = sealOf(key, account);
    final bundle = _members[account]?.bundle;
    return seal != null && bundle != null && seal.bundleVersion == bundle.keyVersion;
  }

  /// The members entitled to [key] who aren't covered for it, by account id, ascending.
  List<String> awaiting(KeyRef key) => (entitled(key).where((account) => !covered(key, account)).toList())..sort();

  /// The records that committed seals of [key]'s current version, oldest first.
  List<CommitRecord> commitmentsOf(KeyRef key) => List.unmodifiable(_commitments[key.wire] ?? const <CommitRecord>[]);

  /// The check of [key]'s current version, or null.
  Uint8List? keyCheck(KeyRef key) => _checks[key.wire] == null ? null : copyBytes(_checks[key.wire]!);

  /// The accounts whose access to a collection existing in both this state and [after] differs, with the access
  /// before and after. Status isn't looked at. It looks only where a grant or a group in a grant changed.
  List<AccessChange> accessChangesTo(SpaceState after) {
    final changes = <AccessChange>[];
    for (final collection in _collections.keys) {
      if (!after._collections.containsKey(collection)) {
        continue;
      }
      final was = _grants[collection] ?? const <String, CollectionPermission>{};
      final now = after._grants[collection] ?? const <String, CollectionPermission>{};
      final groups = <String>{
        for (final wire in [...was.keys, ...now.keys])
          if (wire.startsWith('group:')) wire.substring(6),
      };
      final same = _sameGrants(was, now) && groups.every((id) => _sameSet(_groups[id]?.members, after._groups[id]?.members));
      if (same) {
        continue;
      }
      final accounts = <String>{};
      for (final state in [this, after]) {
        for (final wire in [...was.keys, ...now.keys]) {
          final grantee = Grantee.parse(wire);
          if (grantee.isGroup) {
            accounts.addAll(state._groups[grantee.id]?.members ?? const <String>{});
          } else {
            accounts.add(grantee.id);
          }
        }
      }
      for (final account in accounts) {
        final before = accessOf(account, collection);
        final later = after.accessOf(account, collection);
        if (before != later) {
          changes.add((collection: collection, member: account, before: before, after: later));
        }
      }
    }
    return changes;
  }

  /// The keys some member held, was entitled to and isn't any more in [after]: what a `remove`, `ungrant`,
  /// `group-members` or `group-delete` has to name in `replace`.
  Set<KeyRef> lostIn(SpaceState after) {
    final lost = <KeyRef>{};
    bool lostOf(KeyRef key) {
      final now = after.entitled(key);
      return entitled(key).any((account) => holds(key, account) && !now.contains(account));
    }

    if (lostOf(const KeyRef.space())) {
      lost.add(const KeyRef.space());
    }
    for (final collection in _collections.keys) {
      if (after._collections.containsKey(collection) && lostOf(KeyRef.collection(collection))) {
        lost.add(KeyRef.collection(collection));
      }
    }
    return lost;
  }

  // ─── Applying a record ─────────────────────────────────────────────────

  /// Step 2 of verification: that [entry] is of this space and follows this state's head, in its epoch, and is a `create`
  /// exactly when the state is empty. Throws a [ChainRefusal] of wrong space, bad sequence, bad link, bad epoch or invalid.
  void checkPosition(SpaceChainEntry entry) {
    if (entry.space != space) {
      throw ChainRefusal(ChainProblem.wrongSpace, 'an entry of ${entry.space}, not $space');
    }
    if (entry.seq != nextSeq) {
      throw ChainRefusal(ChainProblem.badSequence, 'entry ${entry.seq} where $nextSeq is next');
    }
    final expectedLink = _headHash ?? chainGenesisLink;
    if (!constantTimeEquals(entry.prev, expectedLink)) {
      throw ChainRefusal(ChainProblem.badLink, 'entry ${entry.seq} does not follow the entry before');
    }
    // The epoch is the state's, or the next one on a fence and only on a fence; the first record's is 1
    final expectedEpoch = isEmpty ? 1 : (entry.kind == ChainKind.fence ? _epoch + 1 : _epoch);
    if (entry.epoch != expectedEpoch) {
      throw ChainRefusal(ChainProblem.badEpoch, 'entry ${entry.seq} is of epoch ${entry.epoch}, where $expectedEpoch is the one');
    }
    if (isEmpty != (entry.kind == ChainKind.create)) {
      throw const ChainRefusal(ChainProblem.invalid, 'a chain starts with create, and only starts with it');
    }
  }

  /// Applies [entry] and gives the next state, or throws a [ChainRefusal]. Who may make the entry and its signatures are
  /// not checked here (space_verify.dart does that); what the entry says must make sense where it lands.
  SpaceState apply(SpaceChainEntry entry) {
    try {
      return _applied(entry);
    } on MalformedException catch (e) {
      throw ChainRefusal(ChainProblem.malformed, e.message);
    }
  }

  /// The keys the record [entry], a `remove`, `ungrant`, `group-members` or `group-delete` made by whoever is making
  /// it, has to name in `replace`: what the state loses by it (the spec's Lost). The entry's own `replace` is not looked
  /// at, so a builder can ask before it writes the record. Throws a [ChainRefusal] when the record makes no sense here.
  Set<KeyRef> keysLostBy(SpaceChainEntry entry) {
    try {
      return lostIn(_applied(entry, probe: true));
    } on MalformedException catch (e) {
      throw ChainRefusal(ChainProblem.malformed, e.message);
    }
  }

  SpaceState _applied(SpaceChainEntry entry, {bool probe = false}) {
    checkPosition(entry);
    final next = SpaceState._copy(this);
    final body = entry.body;
    switch (entry.kind) {
      case ChainKind.create:
        next._create(entry, readCreate(body));
      case ChainKind.invite:
        next._invite(entry, readInvite(body));
      case ChainKind.confirm:
        next._confirm(entry, readConfirm(body));
      case ChainKind.rekey:
        next._rekey(entry, readRekey(body));
      case ChainKind.role:
        next._role(readRole(body));
      case ChainKind.remove:
        next._remove(readRemove(body));
      case ChainKind.grant:
        next._grant(readGrant(body));
      case ChainKind.ungrant:
        next._ungrant(readUngrant(body));
      case ChainKind.collection:
        next._collection(entry, readCollection(body));
      case ChainKind.move:
        next._move(readMove(body));
      case ChainKind.collectionDelete:
        next._collectionDelete(readCollectionDelete(body));
      case ChainKind.group:
        next._group(readGroup(body));
      case ChainKind.groupMembers:
        next._groupMembers(readGroupMembers(body));
      case ChainKind.groupDelete:
        next._groupDelete(readGroupDelete(body));
      case ChainKind.rename:
        next._rename(readRename(body));
      case ChainKind.seal:
        next._seal(entry, readSeal(body));
      case ChainKind.keys:
        next._keys(entry, readKeys(body));
      case ChainKind.policies:
        next._policiesRecord(entry, readPolicies(body));
      case ChainKind.recoveryKey:
        next._recoveryKeyRecord(entry, readRecoveryKey(body));
      case ChainKind.recoveryKeyClear:
        next._recoveryKeyClear();
      case ChainKind.fence:
        next._fence(readFence(body));
    }
    next._afterKind(this, entry, probe: probe);
    next._headSeq = entry.seq;
    next._headHash = entry.hashed;
    next._epoch = entry.epoch;
    return next;
  }

  /// Removal and replacement, the rule that a confirmed Owner remains, and the limits on counts: what is checked in
  /// step 5 once the kind's own rules passed. [before] is the state this one came from.
  void _afterKind(SpaceState before, SpaceChainEntry entry, {bool probe = false}) {
    final body = entry.body;
    final List<KeyRef>? replace = switch (entry.kind) {
      ChainKind.remove => readRemove(body).replace,
      ChainKind.ungrant => readUngrant(body).replace,
      ChainKind.groupMembers => readGroupMembers(body).replace,
      ChainKind.groupDelete => readGroupDelete(body).replace,
      _ => null,
    };
    if (replace != null && !probe) {
      final lost = before.lostIn(this);
      if (lost.length != replace.length || !replace.every(lost.contains)) {
        _invalid(
          'replace names ${replace.map((key) => key.wire).join(', ')}, and the keys lost are ${lost.map((key) => key.wire).join(', ')}',
        );
      }
      for (final key in replace) {
        _mark(key);
      }
    }
    if (before._spaceKeyMarked) {
      switch (entry.kind) {
        case ChainKind.confirm || ChainKind.collection || ChainKind.group || ChainKind.rename || ChainKind.seal:
          _invalid('the space key is marked, so a ${entry.kind.wire} waits for its replacement');
        default:
          break;
      }
    }
    if (before.keysNeedReplacing) {
      for (final change in before.accessChangesTo(this)) {
        final marked = before._spaceKeyMarked || (before._collections[change.collection]?.marked ?? false);
        if (marked && accessWidens(change.before, change.after)) {
          _invalid('${change.member} gains access to ${change.collection}, whose key, or the space key, is marked');
        }
      }
    }
    if (confirmedOwners < 1) {
      _invalid('a space needs at least one confirmed owner');
    }
    if (_members.values.where((member) => member.inSpace).length > maxSpaceMembers) {
      _invalid('a space has at most $maxSpaceMembers members');
    }
    if (_collections.length > maxSpaceCollections) {
      _invalid('a space has at most $maxSpaceCollections collections');
    }
    if (_groups.length > maxSpaceGroups) {
      _invalid('a space has at most $maxSpaceGroups groups');
    }
    if (_grants.values.any((granted) => granted.length > maxCollectionGrants)) {
      _invalid('a collection has at most $maxCollectionGrants grants');
    }
  }

  void _mark(KeyRef key) {
    if (key.isSpace) {
      _spaceKeyMarked = true;
    } else {
      _collections = {..._collections, key.collection!: _collections[key.collection]!.copyWith(marked: true)};
    }
  }

  // ─── The kinds ─────────────────────────────────────────────────────────

  void _create(SpaceChainEntry entry, CreateBody body) {
    if (body.member != entry.by) {
      _invalid('the first record is signed by the account that made the space');
    }
    final bundle = _bundleOf(body.bundle, body.member);
    final collectionKey = KeyRef.collection(body.collection);
    if (body.seals.length != 2 ||
        body.seals[0].key != collectionKey ||
        !body.seals[1].key.isSpace ||
        body.seals.any((commitment) => commitment.version != 1)) {
      _invalid('create commits the first version of the collection key and of the space key');
    }
    _members = {
      body.member: SpaceMember(
        id: body.member,
        role: SpaceRole.owner,
        status: MemberStatus.confirmed,
        invitedBy: body.member,
        bundle: bundle,
        bundleSignature: body.bundleSignature,
      ),
    };
    _spaceKeyVersion = 1;
    _nameHash = body.nameHash;
    _nameVersion = 1;
    _collections = {body.collection: CollectionInfo(id: body.collection, nameHash: body.collectionNameHash, nameVersion: 1, keyVersion: 1)};
    _grants = {
      body.collection: {Grantee.user(body.member).wire: CollectionPermission.manage},
    };
    for (final commitment in body.seals) {
      _makeKey(entry, commitment, [body.member]);
    }
  }

  void _invite(SpaceChainEntry entry, InviteBody body) {
    final existing = _members[body.member];
    if (existing != null && existing.inSpace) {
      _invalid('${body.member} is already a member or has an invitation');
    }
    if (body.role == SpaceRole.owner) {
      _invalid('an owner is made by a role record from a confirmed member, not by an invitation');
    }
    if (body.role != SpaceRole.custom && body.custom.isNotEmpty) {
      _invalid('only a Custom member has custom permissions');
    }
    for (final grant in body.grants) {
      if (!_collections.containsKey(grant.collection)) {
        _invalid('an invitation grants ${grant.collection}, which is not in the space');
      }
    }
    _members = {
      ..._members,
      body.member: SpaceMember(
        id: body.member,
        role: body.role,
        status: MemberStatus.invited,
        invitedBy: entry.by,
        custom: Set.unmodifiable(body.custom),
      ),
    };
    for (final grant in body.grants) {
      _setGrant(grant.collection, Grantee.user(body.member), grant.permission);
    }
  }

  void _confirm(SpaceChainEntry entry, ConfirmBody body) {
    final target = _members[body.member];
    if (target == null || !target.inSpace) {
      _invalid('${body.member} is not in the space');
    }
    if (body.member == entry.by) {
      _invalid('nobody confirms themselves');
    }
    final bundle = _bundleOf(body.bundle, body.member);
    final known = target.bundle;
    // A confirmed member confirmed again after a new key pair: only a newer key version replaces their bundle
    if (target.isConfirmed && (known == null || bundle.keyVersion <= known.keyVersion)) {
      _invalid('${body.member} is confirmed already, and this bundle is not of a newer key version');
    }
    final ConfirmStatement statement;
    try {
      statement = ConfirmStatement.parse(body.statement);
    } on MalformedException catch (e) {
      throw ChainRefusal(ChainProblem.badConfirmation, e.message);
    }
    if (!statement.covers(bundle) ||
        !constantTimeEquals(statement.space, uuidBytes(space)) ||
        !constantTimeEquals(statement.confirmer, uuidBytes(entry.by))) {
      throw const ChainRefusal(ChainProblem.badConfirmation, 'the statement is not about this member, this space and this confirmer');
    }
    _members = {
      ..._members,
      body.member: SpaceMember(
        id: target.id,
        role: target.role,
        status: MemberStatus.confirmed,
        invitedBy: target.invitedBy,
        custom: target.custom,
        bundle: bundle,
        bundleSignature: body.bundleSignature,
        confirmation: MemberConfirmation(by: entry.by, statement: body.statement, signature: body.statementSignature, seq: entry.seq),
      ),
    };
  }

  void _rekey(SpaceChainEntry entry, RekeyBody body) {
    final me = _members[entry.by];
    final bundle = _bundleOf(body.bundle, entry.by);
    final known = me?.bundle;
    if (me == null || known == null) {
      _invalid('${entry.by} has no recorded bundle to replace');
    }
    if (bundle.keyVersion <= known.keyVersion) {
      _invalid('a rekey is of a newer key version than ${known.keyVersion}');
    }
    _members = {
      ..._members,
      entry.by: SpaceMember(
        id: me.id,
        role: me.role,
        status: me.status,
        invitedBy: me.invitedBy,
        custom: me.custom,
        bundle: bundle,
        bundleSignature: body.bundleSignature,
        rekeySeq: entry.seq,
      ),
    };
  }

  void _role(RoleBody body) {
    final target = _members[body.member];
    if (target == null || !target.inSpace) {
      _invalid('${body.member} is not in the space');
    }
    if (body.role != SpaceRole.custom && body.custom.isNotEmpty) {
      _invalid('only a Custom member has custom permissions');
    }
    if (body.role == SpaceRole.owner && !target.isConfirmed) {
      _invalid('an owner is made from a confirmed member: ${body.member} is not');
    }
    final custom = Set<CustomPermission>.unmodifiable(body.custom);
    if (body.role == target.role && custom.length == target.custom.length && custom.every(target.custom.contains)) {
      _invalid('${body.member} has this role and these permissions already');
    }
    _members = {..._members, body.member: target.withRole(body.role, custom)};
  }

  void _remove(RemoveBody body) {
    final target = _members[body.member];
    if (target == null || !target.inSpace) {
      _invalid('${body.member} is not in the space');
    }
    // The record keeps nothing else of them: no role, no bundle, no grant and no group
    _members = {
      ..._members,
      body.member: SpaceMember(id: target.id, role: SpaceRole.member, status: MemberStatus.removed, invitedBy: target.invitedBy),
    };
    final user = Grantee.user(body.member).wire;
    _grants = {
      for (final entry in _grants.entries)
        entry.key: {
          for (final granted in entry.value.entries)
            if (granted.key != user) granted.key: granted.value,
        },
    };
    _groups = {
      for (final entry in _groups.entries)
        entry.key: entry.value.members.contains(body.member)
            ? SpaceGroup(
                id: entry.key,
                nameHash: entry.value.nameHash,
                nameVersion: entry.value.nameVersion,
                members: {...entry.value.members}..remove(body.member),
              )
            : entry.value,
    };
    _seals = {
      for (final entry in _seals.entries)
        entry.key: {
          for (final seal in entry.value.entries)
            if (seal.key != body.member) seal.key: seal.value,
        },
    };
  }

  void _grant(GrantBody body) {
    _checkGrantable(body.collection, body.grantee);
    if (_grants[body.collection]?[body.grantee.wire] == body.permission) {
      _invalid('${body.grantee.wire} has this grant on ${body.collection} already');
    }
    _setGrant(body.collection, body.grantee, body.permission);
  }

  void _ungrant(UngrantBody body) {
    if (!_collections.containsKey(body.collection)) {
      _invalid('the collection ${body.collection} is not in the space');
    }
    if (_grants[body.collection]?.containsKey(body.grantee.wire) != true) {
      _invalid('${body.grantee.wire} has no grant on ${body.collection}');
    }
    _grants = {
      ..._grants,
      body.collection: {
        for (final entry in _grants[body.collection]!.entries)
          if (entry.key != body.grantee.wire) entry.key: entry.value,
      },
    };
  }

  void _collection(SpaceChainEntry entry, CollectionBody body) {
    if (_collections.containsKey(body.collection) || _retired.contains(body.collection)) {
      _invalid('the id ${body.collection} is taken');
    }
    final parent = body.parent;
    if (parent != null) {
      if (!_collections.containsKey(parent)) {
        _invalid('the parent collection $parent is not in the space');
      }
      if (1 + _pathLength(parent) > maxCollectionDepth) {
        _invalid('collections nest at most $maxCollectionDepth deep');
      }
    }
    if (!body.grants.any((grant) => grant.grantee == Grantee.user(entry.by))) {
      _invalid('a new collection lists its maker, ${entry.by}, among its grants');
    }
    for (final grant in body.grants) {
      _checkGrantee(grant.grantee);
    }
    _collections = {
      ..._collections,
      body.collection: CollectionInfo(
        id: body.collection,
        nameHash: body.nameHash,
        nameVersion: _spaceKeyVersion,
        keyVersion: 1,
        parent: parent,
      ),
    };
    _grants = {
      ..._grants,
      body.collection: {for (final grant in body.grants) grant.grantee.wire: grant.permission},
    };
    final key = KeyRef.collection(body.collection);
    if (body.seals.length != 1 || body.seals.single.key != key || body.seals.single.version != 1) {
      _invalid('a collection commits the first version of its own key');
    }
    _makeKey(entry, body.seals.single, entitled(key));
  }

  void _move(MoveBody body) {
    final collection = _collections[body.collection];
    if (collection == null) {
      _invalid('the collection ${body.collection} is not in the space');
    }
    final parent = body.parent;
    if (parent != null) {
      if (!_collections.containsKey(parent) || parent == body.collection) {
        _invalid('the parent $parent is not a collection of the space other than the one moved');
      }
      // Not below the collection itself
      for (String? cursor = parent; cursor != null; cursor = _collections[cursor]?.parent) {
        if (cursor == body.collection) {
          _invalid('a collection is not moved below itself');
        }
      }
    }
    if (parent == collection.parent) {
      _invalid('the collection ${body.collection} has this parent already');
    }
    _collections = {..._collections, body.collection: collection.copyWith(parent: parent, noParent: parent == null)};
    if (_collections.keys.any((id) => _pathLength(id) > maxCollectionDepth)) {
      _invalid('collections nest at most $maxCollectionDepth deep');
    }
  }

  void _collectionDelete(String id) {
    if (!_collections.containsKey(id)) {
      _invalid('the collection $id is not in the space');
    }
    if (_collections.values.any((collection) => collection.parent == id)) {
      _invalid('the collection $id has children');
    }
    final key = KeyRef.collection(id).wire;
    _collections = {
      for (final entry in _collections.entries)
        if (entry.key != id) entry.key: entry.value,
    };
    _grants = {
      for (final entry in _grants.entries)
        if (entry.key != id) entry.key: entry.value,
    };
    _checks = {
      for (final entry in _checks.entries)
        if (entry.key != key) entry.key: entry.value,
    };
    _seals = {
      for (final entry in _seals.entries)
        if (entry.key != key) entry.key: entry.value,
    };
    _commitments = {
      for (final entry in _commitments.entries)
        if (entry.key != key) entry.key: entry.value,
    };
    _retired = {..._retired, id};
  }

  void _group(GroupBody body) {
    if (_groups.containsKey(body.group) || _retired.contains(body.group)) {
      _invalid('the id ${body.group} is taken');
    }
    _groups = {
      ..._groups,
      body.group: SpaceGroup(id: body.group, nameHash: body.nameHash, nameVersion: _spaceKeyVersion, members: const {}),
    };
  }

  void _groupMembers(GroupMembersBody body) {
    final group = _groups[body.group];
    if (group == null) {
      _invalid('the group ${body.group} is not in the space');
    }
    for (final id in body.add) {
      if (_members[id]?.inSpace != true || group.members.contains(id)) {
        _invalid('$id is not in the space, or is in the group already');
      }
    }
    for (final id in body.remove) {
      if (!group.members.contains(id)) {
        _invalid('$id is not in the group');
      }
    }
    _groups = {
      ..._groups,
      body.group: SpaceGroup(
        id: group.id,
        nameHash: group.nameHash,
        nameVersion: group.nameVersion,
        members: {...group.members, ...body.add}..removeAll(body.remove),
      ),
    };
  }

  void _groupDelete(GroupDeleteBody body) {
    if (!_groups.containsKey(body.group)) {
      _invalid('the group ${body.group} is not in the space');
    }
    final grantee = Grantee.group(body.group).wire;
    _groups = {
      for (final entry in _groups.entries)
        if (entry.key != body.group) entry.key: entry.value,
    };
    _grants = {
      for (final entry in _grants.entries)
        entry.key: {
          for (final granted in entry.value.entries)
            if (granted.key != grantee) granted.key: granted.value,
        },
    };
    _retired = {..._retired, body.group};
  }

  void _rename(RenameBody body) {
    final current = nameOf(body.target);
    if (current == null) {
      _invalid('${body.target.wire} is not in the space');
    }
    if (constantTimeEquals(current.hash, body.nameHash)) {
      _invalid('${body.target.wire} has this name hash already');
    }
    switch (body.target.type) {
      case NameType.space:
        _nameHash = body.nameHash;
        _nameVersion = _spaceKeyVersion;
      case NameType.collection:
        _collections = {
          ..._collections,
          body.target.id!: _collections[body.target.id]!.copyWith(nameHash: body.nameHash, nameVersion: _spaceKeyVersion),
        };
      case NameType.group:
        final group = _groups[body.target.id]!;
        _groups = {
          ..._groups,
          group.id: SpaceGroup(id: group.id, nameHash: body.nameHash, nameVersion: _spaceKeyVersion, members: group.members),
        };
    }
  }

  void _seal(SpaceChainEntry entry, SealBody body) {
    for (final commitment in body.seals) {
      final key = commitment.key;
      if (!hasKey(key) || commitment.version != keyVersionOf(key)) {
        _invalid('${key.wire} has no version ${commitment.version} to share');
      }
      if (isMarked(key)) {
        _invalid('${key.wire} is marked: it is replaced before it is shared');
      }
      final recipients = awaiting(key);
      if (recipients.isEmpty) {
        _invalid('nobody awaits ${key.wire}');
      }
      _share(entry, commitment, recipients);
    }
  }

  void _keys(SpaceChainEntry entry, KeysBody body) {
    final replacesSpace = body.rotate.any((commitment) => commitment.key.isSpace);
    if (replacesSpace != (body.names != null)) {
      _invalid('names are present exactly when the space key is replaced');
    }
    for (final commitment in body.rotate) {
      final key = commitment.key;
      final current = keyVersionOf(key);
      if (current == null || !hasKey(key) || commitment.version != current + 1 || commitment.version > 0xffffffff) {
        _invalid('${key.wire} has no version ${commitment.version} to follow its current one');
      }
    }
    final names = body.names;
    if (names != null) {
      _checkNames(names);
    }
    for (final commitment in body.rotate) {
      final key = commitment.key;
      _makeKey(entry, commitment, entitled(key));
      if (key.isSpace) {
        _spaceKeyVersion = commitment.version;
        _spaceKeyMarked = false;
      } else {
        _collections = {
          ..._collections,
          key.collection!: _collections[key.collection]!.copyWith(keyVersion: commitment.version, marked: false),
        };
      }
    }
    if (names != null) {
      _applyNames(names);
    }
  }

  /// Whether [names] is a whole number of 49-byte entries, sorted, with one for the space and for each collection and
  /// group of this state, and no other.
  void _checkNames(Uint8List names) {
    if (names.length % packedNameLength != 0) {
      _invalid('names are a whole number of $packedNameLength-byte entries');
    }
    final expected = <String>{'1', for (final id in _collections.keys) '2$id', for (final id in _groups.keys) '3$id'};
    final seen = <String>{};
    Uint8List? last;
    for (var at = 0; at < names.length; at += packedNameLength) {
      final head = Uint8List.sublistView(names, at, at + 17);
      if (last != null && _compare(head, last) <= 0) {
        _invalid('names are sorted by type and id, each once');
      }
      last = head;
      final type = head[0];
      if (type < 1 || type > 3) {
        _invalid('a name of type $type');
      }
      if (type == 1 && !constantTimeEquals(Uint8List.sublistView(head, 1), uuidBytes(space))) {
        _invalid('the name of the space is under the space\'s own id');
      }
      seen.add(type == 1 ? '1' : '$type${uuidText(Uint8List.sublistView(head, 1))}');
    }
    if (seen.length != expected.length || !seen.containsAll(expected)) {
      _invalid('names hold one entry for the space and for each collection and group, and no other');
    }
  }

  void _applyNames(Uint8List names) {
    final version = _spaceKeyVersion;
    final collections = {..._collections};
    final groups = {..._groups};
    for (var at = 0; at < names.length; at += packedNameLength) {
      final type = names[at];
      final id = type == 1 ? '' : uuidText(Uint8List.sublistView(names, at + 1, at + 17));
      final hash = Uint8List.sublistView(names, at + 17, at + packedNameLength);
      if (type == 1) {
        _nameHash = copyBytes(hash);
        _nameVersion = version;
      } else if (type == 2) {
        collections[id] = collections[id]!.copyWith(nameHash: copyBytes(hash), nameVersion: version);
      } else {
        final group = groups[id]!;
        groups[id] = SpaceGroup(id: id, nameHash: copyBytes(hash), nameVersion: version, members: group.members);
      }
    }
    _collections = collections;
    _groups = groups;
  }

  void _policiesRecord(SpaceChainEntry entry, Map<String, Object?> policies) {
    final timeout = policies['sessionTimeout']! as Map<String, Object?>;
    if ((timeout['action'] == 'none') != (timeout['minutes'] == 0)) {
      _invalid('a session timeout has the action none exactly when its minutes are 0');
    }
    if (policies['accountRecovery'] == true && _recoveryKey == null) {
      _invalid('account recovery is on only while the space has a recovery key');
    }
    if (jcs(policies) == jcs(this.policies)) {
      _invalid('these policies are the current ones');
    }
    final since = <String, int>{};
    for (final flag in policyFlags) {
      if (policies[flag] == true) {
        // A flag that was on and stays on keeps its number
        since[flag] = _flagSince[flag] ?? entry.seq;
      }
    }
    _policies = policies;
    _flagSince = since;
  }

  void _recoveryKeyRecord(SpaceChainEntry entry, Uint8List key) {
    if (_recoveryKey != null && constantTimeEquals(_recoveryKey!, key)) {
      _invalid('this is the recovery key already');
    }
    _recoveryKey = copyBytes(key);
    _recoveryKeySeq = entry.seq;
  }

  void _recoveryKeyClear() {
    if (_recoveryKey == null) {
      _invalid('there is no recovery key to clear');
    }
    if (policies['accountRecovery'] == true) {
      _invalid('the recovery key stays while account recovery is on');
    }
    _recoveryKey = null;
    _recoveryKeySeq = null;
  }

  void _fence(FenceBody body) {
    _home = body.home;
    _promotion = copyBytes(body.promotion);
  }

  // ─── Helpers ───────────────────────────────────────────────────────────

  /// Records the new version of [commitment]'s key: its check, and a seal to each of [recipients] at their current
  /// bundle version, replacing the seals of the version before.
  void _makeKey(SpaceChainEntry entry, SealCommitment commitment, Iterable<String> recipients) {
    final ids = recipients.toList()..sort();
    if (commitment.count != ids.length) {
      _invalid('${commitment.key.wire} commits ${commitment.count} seals for ${ids.length} recipients');
    }
    final wire = commitment.key.wire;
    _checks = {..._checks, wire: commitment.check!};
    _seals = {
      ..._seals,
      wire: {for (final id in ids) id: SealEntry(bundleVersion: _members[id]!.bundle!.keyVersion, seq: entry.seq)},
    };
    _commitments = {
      ..._commitments,
      wire: [CommitRecord(seq: entry.seq, count: commitment.count, digest: commitment.digest, recipients: _bundleVersions(ids))],
    };
  }

  Map<String, int> _bundleVersions(Iterable<String> ids) => {for (final id in ids) id: _members[id]!.bundle!.keyVersion};

  /// Records seals of the key version already in place to [recipients], beside the ones it has.
  void _share(SpaceChainEntry entry, SealCommitment commitment, List<String> recipients) {
    if (commitment.count != recipients.length) {
      _invalid('${commitment.key.wire} commits ${commitment.count} seals for ${recipients.length} recipients');
    }
    final wire = commitment.key.wire;
    _seals = {
      ..._seals,
      wire: {...?_seals[wire], for (final id in recipients) id: SealEntry(bundleVersion: _members[id]!.bundle!.keyVersion, seq: entry.seq)},
    };
    _commitments = {
      ..._commitments,
      wire: [
        ...?_commitments[wire],
        CommitRecord(seq: entry.seq, count: commitment.count, digest: commitment.digest, recipients: _bundleVersions(recipients)),
      ],
    };
  }

  void _setGrant(String collection, Grantee grantee, CollectionPermission permission) {
    _grants = {
      ..._grants,
      collection: {...?_grants[collection], grantee.wire: permission},
    };
  }

  /// A grant needs a collection that exists, and a grantee that is in the space (a user) or exists (a group).
  void _checkGrantable(String collection, Grantee grantee) {
    if (!_collections.containsKey(collection)) {
      _invalid('the collection $collection is not in the space');
    }
    _checkGrantee(grantee);
  }

  void _checkGrantee(Grantee grantee) {
    if (grantee.isGroup) {
      if (!_groups.containsKey(grantee.id)) {
        _invalid('the group ${grantee.id} is not in the space');
      }
    } else if (_members[grantee.id]?.inSpace != true) {
      _invalid('${grantee.id} is not in the space');
    }
  }

  /// The number of collections on the path from [id] to the top, [id] included.
  int _pathLength(String id) {
    var length = 0;
    for (String? cursor = id; cursor != null; cursor = _collections[cursor]?.parent) {
      length++;
      if (length > maxCollectionDepth + _collections.length) {
        break;
      }
    }
    return length;
  }

  KeyBundle _bundleOf(Uint8List bytes, String member) {
    final KeyBundle bundle;
    try {
      bundle = KeyBundle.parse(bytes);
    } on MalformedException catch (e) {
      throw ChainRefusal(ChainProblem.badBundle, e.message);
    }
    if (!constantTimeEquals(bundle.accountId, uuidBytes(member))) {
      throw ChainRefusal(ChainProblem.badBundle, 'the bundle is of another account than $member');
    }
    return bundle;
  }
}

bool _sameGrants(Map<String, CollectionPermission> a, Map<String, CollectionPermission> b) =>
    a.length == b.length && a.entries.every((entry) => b[entry.key] == entry.value);

bool _sameSet(Set<String>? a, Set<String>? b) {
  final left = a ?? const <String>{};
  final right = b ?? const <String>{};
  return left.length == right.length && left.containsAll(right);
}

/// Byte order of [a] against [b].
int _compare(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}
