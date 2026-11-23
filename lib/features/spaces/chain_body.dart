// The bodies of the 21 kinds of a record (the space chain section of docs/crypto.md, "Kinds"): each
// reader takes the body object of a record and gives it typed, or refuses it as malformed when it
// isn't exactly its kind's shape, or as too large when a list is past its limit. Arrays are sets:
// each is in strictly ascending byte order of the text of its elements (its `key`, `grantee`,
// `collection` or id), so a duplicate and a disorder are the same refusal and nothing is collapsed.
// An optional member is absent, never `null` (the strict reader of `chain_json.dart` has no `null`).
//
// What these readers can't know, a state's rules, is `space_state.dart`'s: a reader checks lengths
// and sorting, never whether a collection exists or a key version follows.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/encoding.dart';
import '../../crypto/account/kx1.dart' show Kx1;
import '../../crypto/account/sig1.dart' show Sig1;
import 'chain_json.dart';
import 'chain_kind.dart';
import 'space_types.dart';

/// The length of a public-key bundle, 3621 bytes.
const chainBundleLength = 3621;

/// The length of a member confirmation statement, 134 bytes.
const chainStatementLength = 134;

/// The length of one packed name: `u8(type) || id (16) || SHA-256 (32)`.
const packedNameLength = 49;

/// The most grants in `invite` and `collection`, ids in `group-members`, and members, collections and groups of a space.
const maxChainList = 1000;
const maxSealRecipients = 10000;
const maxSealCommitments = 1001;
const maxRotatedKeys = 257;

/// One commitment to the sealed boxes of a key: how many, their digest, and for a new key version its check.
final class SealCommitment {
  SealCommitment({required this.key, required this.version, required this.count, required List<int> digest, List<int>? check})
    : digest = copyBytes(requireLength(digest, 32, 'a seal digest')),
      check = check == null ? null : copyBytes(requireLength(check, 32, 'a key check'));

  final KeyRef key;
  final int version;
  final int count;
  final Uint8List digest;

  /// Set when the commitment makes a key version, absent when it shares an existing one.
  final Uint8List? check;

  bool get makes => check != null;

  Map<String, Object?> toJson() => {
    if (check != null) 'check': b64urlEncode(check!),
    'count': count,
    'digest': b64urlEncode(digest),
    'key': key.wire,
    'version': version,
  };
}

typedef GrantSpec = ({String collection, CollectionPermission permission});
typedef GranteeSpec = ({Grantee grantee, CollectionPermission permission});

typedef CreateBody = ({
  Uint8List bundle,
  Uint8List bundleSignature,
  String collection,
  Uint8List collectionNameHash,
  String member,
  Uint8List nameHash,
  List<SealCommitment> seals,
});
typedef InviteBody = ({List<CustomPermission> custom, List<GrantSpec> grants, String member, SpaceRole role});
typedef ConfirmBody = ({Uint8List bundle, Uint8List bundleSignature, String member, Uint8List statement, Uint8List statementSignature});
typedef RekeyBody = ({Uint8List bundle, Uint8List bundleSignature});
typedef RoleBody = ({List<CustomPermission> custom, String member, SpaceRole role});
typedef RemoveBody = ({String member, List<KeyRef> replace});
typedef GrantBody = ({String collection, Grantee grantee, CollectionPermission permission});
typedef UngrantBody = ({String collection, Grantee grantee, List<KeyRef> replace});
typedef CollectionBody = ({String collection, List<GranteeSpec> grants, Uint8List nameHash, String? parent, List<SealCommitment> seals});
typedef MoveBody = ({String collection, String? parent});
typedef GroupBody = ({String group, Uint8List nameHash});
typedef GroupMembersBody = ({List<String> add, String group, List<String> remove, List<KeyRef> replace});
typedef GroupDeleteBody = ({String group, List<KeyRef> replace});
typedef RenameBody = ({Uint8List nameHash, NameTarget target});
typedef SealBody = ({List<SealCommitment> seals});
typedef KeysBody = ({Uint8List? names, List<SealCommitment> rotate});
typedef FenceBody = ({String home, Uint8List promotion});

/// Reads [body] as the body of a [kind], or throws a [MalformedException] or a [ChainRefusal] of [ChainProblem.tooLarge].
void validateBody(ChainKind kind, Map<String, Object?> body) {
  switch (kind) {
    case ChainKind.create:
      readCreate(body);
    case ChainKind.invite:
      readInvite(body);
    case ChainKind.confirm:
      readConfirm(body);
    case ChainKind.rekey:
      readRekey(body);
    case ChainKind.role:
      readRole(body);
    case ChainKind.remove:
      readRemove(body);
    case ChainKind.grant:
      readGrant(body);
    case ChainKind.ungrant:
      readUngrant(body);
    case ChainKind.collection:
      readCollection(body);
    case ChainKind.move:
      readMove(body);
    case ChainKind.collectionDelete:
      readCollectionDelete(body);
    case ChainKind.group:
      readGroup(body);
    case ChainKind.groupMembers:
      readGroupMembers(body);
    case ChainKind.groupDelete:
      readGroupDelete(body);
    case ChainKind.rename:
      readRename(body);
    case ChainKind.seal:
      readSeal(body);
    case ChainKind.keys:
      readKeys(body);
    case ChainKind.policies:
      readPolicies(body);
    case ChainKind.recoveryKey:
      readRecoveryKey(body);
    case ChainKind.recoveryKeyClear:
      strictObject(body, required: const {});
    case ChainKind.fence:
      readFence(body);
  }
}

// ─── The kinds ───────────────────────────────────────────────────────────

CreateBody readCreate(Map<String, Object?> body) {
  final f = _Fields(body, required: {'bundle', 'bundleSignature', 'collection', 'member', 'nameHash', 'seals'});
  final first = _Fields(f.map['collection'], required: {'id', 'nameHash'});
  return (
    bundle: f.bytes('bundle', chainBundleLength),
    bundleSignature: f.bytes('bundleSignature', Sig1.signatureLength),
    collection: first.uuid('id'),
    collectionNameHash: first.bytes('nameHash', 32),
    member: f.uuid('member'),
    nameHash: f.bytes('nameHash', 32),
    seals: f.commitments('seals', makes: true, max: maxRotatedKeys),
  );
}

InviteBody readInvite(Map<String, Object?> body) {
  final f = _Fields(body, required: {'custom', 'grants', 'member', 'role'});
  final grants = [
    for (final raw in f.list('grants', max: maxChainList))
      () {
        final g = _Fields(raw, required: {'collection', 'permission'});
        return (collection: g.uuid('collection'), permission: g.permission());
      }(),
  ];
  _ascending([for (final grant in grants) grant.collection], 'the grants of an invitation');
  return (custom: f.customPermissions(), grants: grants, member: f.uuid('member'), role: f.role());
}

ConfirmBody readConfirm(Map<String, Object?> body) {
  final f = _Fields(body, required: {'bundle', 'bundleSignature', 'member', 'statement', 'statementSignature'});
  return (
    bundle: f.bytes('bundle', chainBundleLength),
    bundleSignature: f.bytes('bundleSignature', Sig1.signatureLength),
    member: f.uuid('member'),
    statement: f.bytes('statement', chainStatementLength),
    statementSignature: f.bytes('statementSignature', Sig1.signatureLength),
  );
}

RekeyBody readRekey(Map<String, Object?> body) {
  final f = _Fields(body, required: {'bundle', 'bundleSignature'});
  return (bundle: f.bytes('bundle', chainBundleLength), bundleSignature: f.bytes('bundleSignature', Sig1.signatureLength));
}

RoleBody readRole(Map<String, Object?> body) {
  final f = _Fields(body, required: {'custom', 'member', 'role'});
  return (custom: f.customPermissions(), member: f.uuid('member'), role: f.role());
}

RemoveBody readRemove(Map<String, Object?> body) {
  final f = _Fields(body, required: {'member', 'replace'});
  return (member: f.uuid('member'), replace: f.keyRefs('replace'));
}

GrantBody readGrant(Map<String, Object?> body) {
  final f = _Fields(body, required: {'collection', 'grantee', 'permission'});
  return (collection: f.uuid('collection'), grantee: f.grantee('grantee'), permission: f.permission());
}

UngrantBody readUngrant(Map<String, Object?> body) {
  final f = _Fields(body, required: {'collection', 'grantee', 'replace'});
  return (collection: f.uuid('collection'), grantee: f.grantee('grantee'), replace: f.keyRefs('replace'));
}

CollectionBody readCollection(Map<String, Object?> body) {
  final f = _Fields(body, required: {'collection', 'grants', 'nameHash', 'seals'}, optional: {'parent'});
  final grants = [
    for (final raw in f.list('grants', min: 1, max: maxChainList))
      () {
        final g = _Fields(raw, required: {'grantee', 'permission'});
        return (grantee: g.grantee('grantee'), permission: g.permission());
      }(),
  ];
  _ascending([for (final grant in grants) grant.grantee.wire], 'the grants of a collection');
  return (
    collection: f.uuid('collection'),
    grants: grants,
    nameHash: f.bytes('nameHash', 32),
    parent: f.has('parent') ? f.uuid('parent') : null,
    seals: f.commitments('seals', makes: true, max: maxRotatedKeys),
  );
}

MoveBody readMove(Map<String, Object?> body) {
  final f = _Fields(body, required: {'collection'}, optional: {'parent'});
  return (collection: f.uuid('collection'), parent: f.has('parent') ? f.uuid('parent') : null);
}

String readCollectionDelete(Map<String, Object?> body) => _Fields(body, required: {'collection'}).uuid('collection');

GroupBody readGroup(Map<String, Object?> body) {
  final f = _Fields(body, required: {'group', 'nameHash'});
  return (group: f.uuid('group'), nameHash: f.bytes('nameHash', 32));
}

GroupMembersBody readGroupMembers(Map<String, Object?> body) {
  final f = _Fields(body, required: {'add', 'group', 'remove', 'replace'});
  final add = f.uuidSet('add', max: maxChainList + 1);
  final remove = f.uuidSet('remove', max: maxChainList + 1);
  if (add.length + remove.length > maxChainList) {
    throw ChainRefusal(ChainProblem.tooLarge, 'add and remove hold at most $maxChainList ids together');
  }
  if (add.isEmpty && remove.isEmpty) {
    throw const MalformedException('add and remove hold 1 to 1,000 ids between them');
  }
  if (add.toSet().intersection(remove.toSet()).isNotEmpty) {
    throw const MalformedException('add and remove share no id');
  }
  return (add: add, group: f.uuid('group'), remove: remove, replace: f.keyRefs('replace'));
}

GroupDeleteBody readGroupDelete(Map<String, Object?> body) {
  final f = _Fields(body, required: {'group', 'replace'});
  return (group: f.uuid('group'), replace: f.keyRefs('replace'));
}

RenameBody readRename(Map<String, Object?> body) {
  final f = _Fields(body, required: {'nameHash', 'target'});
  return (nameHash: f.bytes('nameHash', 32), target: NameTarget.parse(f.string('target')));
}

SealBody readSeal(Map<String, Object?> body) {
  final f = _Fields(body, required: {'seals'});
  return (seals: f.commitments('seals', makes: false, min: 1, max: maxSealCommitments));
}

KeysBody readKeys(Map<String, Object?> body) {
  final f = _Fields(body, required: {'rotate'}, optional: {'names'});
  final rotate = f.commitments('rotate', makes: true, min: 1, max: maxRotatedKeys);
  if (rotate.where((commitment) => commitment.key.isSpace).length > 1) {
    throw const MalformedException('rotate holds the space key at most once');
  }
  return (names: f.has('names') ? f.bytes('names') : null, rotate: rotate);
}

/// The policy set of a `policies` record, typed after the server's `SpacePolicies`. Every member is present, with
/// these types and ranges; there are no other policy names.
Map<String, Object?> readPolicies(Map<String, Object?> body) {
  final f = _Fields(body, required: {'policies'});
  final p = _Fields(f.map['policies'], required: {...policyFlags, 'masterPassword', 'sessionTimeout'});
  final master = _Fields(
    p.map['masterPassword'],
    required: {'enforceOnLogin', 'minComplexity', 'minLength', 'requireLower', 'requireNumbers', 'requireSpecial', 'requireUpper'},
  );
  final timeout = _Fields(p.map['sessionTimeout'], required: {'action', 'minutes'});
  final action = timeout.string('action');
  if (action != 'none' && action != 'lock' && action != 'log-out') {
    throw MalformedException('a session timeout action is none, lock or log-out: $action');
  }
  return {
    for (final flag in policyFlags) flag: p.boolean(flag),
    'masterPassword': {
      'enforceOnLogin': master.boolean('enforceOnLogin'),
      'minComplexity': master.integer('minComplexity', max: 4),
      'minLength': master.integer('minLength', max: 128),
      'requireLower': master.boolean('requireLower'),
      'requireNumbers': master.boolean('requireNumbers'),
      'requireSpecial': master.boolean('requireSpecial'),
      'requireUpper': master.boolean('requireUpper'),
    },
    'sessionTimeout': {'action': action, 'minutes': timeout.integer('minutes', max: 525600)},
  };
}

/// The boolean policies, in the order of the server's `SpacePolicies`.
const policyFlags = <String>{
  'accountRecovery',
  'alwaysShowEmail',
  'centralOwnership',
  'disableExport',
  'disableSend',
  'duplicateMatching',
  'noCardItems',
  'noPinUnlock',
  'requireSso',
  'singleSpace',
  'twoStep',
};

/// The policy set before any `policies` record: every setting off.
Map<String, Object?> defaultPolicies() => {
  for (final flag in policyFlags) flag: false,
  'masterPassword': {
    'enforceOnLogin': false,
    'minComplexity': 0,
    'minLength': 0,
    'requireLower': false,
    'requireNumbers': false,
    'requireSpecial': false,
    'requireUpper': false,
  },
  'sessionTimeout': {'action': 'none', 'minutes': 0},
};

Uint8List readRecoveryKey(Map<String, Object?> body) => _Fields(body, required: {'key'}).bytes('key', Kx1.publicKeyLength);

FenceBody readFence(Map<String, Object?> body) {
  final f = _Fields(body, required: {'home', 'promotion'});
  return (home: f.uuid('home'), promotion: f.bytes('promotion', 32));
}

// ─── Reading ─────────────────────────────────────────────────────────────

/// [keys] strictly ascending in byte order: each once, in order.
void _ascending(Iterable<String> keys, String what) {
  String? last;
  for (final key in keys) {
    if (last != null && key.compareTo(last) <= 0) {
      throw MalformedException('$what are each once and in ascending order');
    }
    last = key;
  }
}

final class _Fields {
  _Fields(Object? json, {required Set<String> required, Set<String> optional = const {}})
    : map = strictObject(json, required: required, optional: optional);

  final Map<String, Object?> map;

  bool has(String name) => map.containsKey(name);

  String string(String name) {
    final value = map[name];
    if (value is! String) {
      throw MalformedException('$name is a string');
    }
    return value;
  }

  int integer(String name, {int min = 0, int max = chainMaxInteger}) {
    final value = map[name];
    if (value is! int || value < min || value > max) {
      throw MalformedException('$name is a whole number from $min to $max');
    }
    return value;
  }

  bool boolean(String name) {
    final value = map[name];
    if (value is! bool) {
      throw MalformedException('$name is true or false');
    }
    return value;
  }

  String uuid(String name) {
    final value = string(name);
    if (!isUuidText(value)) {
      throw MalformedException('$name is a hyphenated lower-case UUID');
    }
    return value;
  }

  /// base64url bytes, [length] long when it is given.
  Uint8List bytes(String name, [int? length]) {
    final decoded = b64urlDecode(string(name));
    return length == null ? decoded : requireLength(decoded, length, name);
  }

  /// A list of at least [min] and at most [max] elements: fewer than [min] is malformed, more than [max] too large.
  List<Object?> list(String name, {int min = 0, required int max}) {
    final value = map[name];
    if (value is! List<Object?>) {
      throw MalformedException('$name is an array');
    }
    if (value.length < min) {
      throw MalformedException('$name holds at least $min elements');
    }
    if (value.length > max) {
      throw ChainRefusal(ChainProblem.tooLarge, '$name holds at most $max elements, not ${value.length}');
    }
    return value;
  }

  List<String> uuidSet(String name, {required int max}) {
    final ids = [
      for (final raw in list(name, max: max))
        if (raw is String && isUuidText(raw)) raw else throw MalformedException('$name holds UUIDs'),
    ];
    _ascending(ids, name);
    return ids;
  }

  SpaceRole role() {
    final role = SpaceRole.fromWire(string('role'));
    if (role == null) {
      throw MalformedException('unknown role ${map['role']}');
    }
    return role;
  }

  CollectionPermission permission() {
    final permission = CollectionPermission.fromWire(string('permission'));
    if (permission == null) {
      throw MalformedException('unknown permission ${map['permission']}');
    }
    return permission;
  }

  Grantee grantee(String name) => Grantee.parse(string(name));

  List<CustomPermission> customPermissions() {
    final custom = [
      for (final raw in list('custom', max: CustomPermission.values.length))
        if (raw is String && CustomPermission.fromWire(raw) != null)
          CustomPermission.fromWire(raw)!
        else
          throw MalformedException('unknown custom permission $raw'),
    ];
    _ascending([for (final permission in custom) permission.wire], 'custom permissions');
    return custom;
  }

  List<KeyRef> keyRefs(String name) {
    final refs = [
      for (final raw in list(name, max: maxRotatedKeys))
        if (raw is String) KeyRef.parse(raw) else throw MalformedException('$name holds keys'),
    ];
    _ascending([for (final ref in refs) ref.wire], name);
    return refs;
  }

  List<SealCommitment> commitments(String name, {required bool makes, int min = 0, required int max}) {
    final commitments = [
      for (final raw in list(name, min: min, max: max))
        () {
          final c = _Fields(raw, required: {'count', 'digest', 'key', 'version', if (makes) 'check'});
          return SealCommitment(
            key: KeyRef.parse(c.string('key')),
            version: c.integer('version', min: 1, max: 0xffffffff),
            count: c.integer('count', min: 1, max: maxSealRecipients),
            digest: c.bytes('digest', 32),
            check: makes ? c.bytes('check', 32) : null,
          );
        }(),
    ];
    _ascending([for (final commitment in commitments) commitment.key.wire], name);
    return commitments;
  }
}
