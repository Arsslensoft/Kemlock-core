// Builds the chains the space tests check, with cheap fake signatures in place of
// `sig1`'s (a MAC under the signer's public key, which is slow only in pure Dart
// as ML-DSA is), as `FakeKmCrypto` does for the sync tests. The tests of
// `space_chain_test.dart` that need the real signature use real keys instead.
//
// Nothing here is a vector shared with the server: the commitments hold filler digests and checks,
// because the state only counts a commitment's recipients, and every case is built in code from the
// space chain section of docs/crypto.md, version 2.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/confirm.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/crypto/bytes.dart' show constantTimeEquals;
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_keys.dart';
import 'package:kemlock_core/features/spaces/space_seals.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';

/// A UUID made of [n], for readable tests.
String uuid(int n) => '00000000-0000-4000-8000-${n.toRadixString(16).padLeft(12, '0')}';

Uint8List _fill(int length, int seed) => Uint8List.fromList(List.generate(length, (i) => (seed * 31 + i * 7) & 0xff));

/// 32 filler bytes, standing for a hash or a digest the state doesn't recompute.
Uint8List hash32([int seed = 7]) => _fill(32, seed);

String hash64([int seed = 7]) => b64urlEncode(hash32(seed));

/// A signature in the length of a `sig1` one: a MAC under [publicKey] of [label] and [message].
Uint8List fakeSignature(List<int> publicKey, String label, List<int> message) {
  final mac = Hmac(sha256, publicKey).convert([...utf8.encode(label), ...message]).bytes;
  return Uint8List.fromList([for (var i = 0; i < Sig1.signatureLength; i++) mac[i % mac.length]]);
}

/// [ChainCrypto] that checks [fakeSignature]s, and takes a key that isn't all zeros as a usable recovery key.
class FakeChainCrypto implements ChainCrypto {
  const FakeChainCrypto();

  @override
  Future<bool> checkEntry(Uint8List signerPublicKey, Uint8List entryBytes, Uint8List signature) async =>
      constantTimeEquals(signature, fakeSignature(signerPublicKey, 'space-chain', entryBytes));

  @override
  Future<bool> checkBundle(KeyBundle bundle, Uint8List signature) async =>
      constantTimeEquals(signature, fakeSignature(bundle.sig1PublicKey, 'bundle', bundle.bytes));

  @override
  Future<bool> checkConfirmation(Uint8List statement, Uint8List signature, Uint8List confirmerPublicKey) async =>
      constantTimeEquals(signature, fakeSignature(confirmerPublicKey, 'confirm', statement));

  @override
  Future<bool> checkRecoveryKey(Uint8List key) async => key.any((byte) => byte != 0);
}

/// An account with keys of its own at one key version.
class Person {
  /// [kx1PublicKey] is a real key when the test seals to the account; the chain tests don't open anything and use a
  /// filler of the right length.
  Person(int n, {this.keyVersion = 1, Uint8List? kx1PublicKey})
    : id = uuid(n),
      bundle = KeyBundle(
        accountId: uuidBytes(uuid(n)),
        keyVersion: keyVersion,
        kx1PublicKey: kx1PublicKey ?? _fill(Kx1.publicKeyLength, n * 10 + keyVersion),
        sig1PublicKey: _fill(Sig1.publicKeyLength, n * 10 + keyVersion + 5000),
      );

  final String id;
  final int keyVersion;
  final KeyBundle bundle;

  Uint8List get bundleSignature => fakeSignature(bundle.sig1PublicKey, 'bundle', bundle.bytes);

  /// The same account after it replaced its key pair.
  Person withNewKeys() => Person(int.parse(id.substring(id.length - 12), radix: 16), keyVersion: keyVersion + 1);
}

/// One commitment of a record's `seals` or `rotate`: filler digest, and a filler check when it [makes] a key version.
Map<String, Object?> commitment(KeyRef key, int version, int count, {bool makes = false}) => {
  if (makes) 'check': hash64(version + 1),
  'count': count,
  'digest': hash64(version),
  'key': key.wire,
  'version': version,
};

/// Real seals for a chain: the keys of a space at each version and the box of each sealed to each person, so the
/// commitments a [ChainBuilder] makes hold the real digest and check, and a phone can open a key through them
/// (`openCommittedKey`). The boxes are made once by [prepare], since sealing is slow in pure Dart, and a box is the same
/// whichever chain commits it.
class SealRegistry {
  SealRegistry(this.space, {required this.keyOf});

  final String space;

  /// The key bytes of a key at a version.
  final Uint8List Function(KeyRef key, int version) keyOf;

  final _boxes = <String, Uint8List>{};

  String _id(KeyRef key, int version, String account) => '${key.wire}/$version/$account';

  /// Seals every key in [keys] at every one of [versions] to each of [people].
  Future<void> prepare({required Iterable<KeyRef> keys, required Iterable<int> versions, required Iterable<Person> people}) async {
    for (final key in keys) {
      for (final version in versions) {
        for (final person in people) {
          _boxes[_id(key, version, person.id)] = key.isSpace
              ? await sealSpaceKey(to: person.bundle, key: keyOf(key, version), space: space, keyVersion: version)
              : await sealCollectionKey(
                  to: person.bundle,
                  key: keyOf(key, version),
                  space: space,
                  collection: key.collection!,
                  keyVersion: version,
                );
        }
      }
    }
  }

  /// The box of [key] at [version] sealed to [account].
  Uint8List box(KeyRef key, int version, String account) {
    final box = _boxes[_id(key, version, account)];
    if (box == null) {
      throw StateError('no box prepared for ${key.wire} at $version to $account');
    }
    return box;
  }

  /// The commitment of [key] at [version] sealed to [recipients] (account, and the bundle key version its box is to)
  /// with the check when it [makes] the key version. The server's hash list for it is added to [into].
  Map<String, Object?> commitment(
    KeyRef key,
    int version,
    Map<String, int> recipients, {
    required List<ChainSealHash> into,
    bool makes = false,
  }) {
    final listed = [
      for (final entry in recipients.entries)
        ChainSealHash(
          bundleVersion: entry.value,
          key: key,
          member: entry.key,
          sealHash: sealHashOf(box(key, version, entry.key)),
          version: version,
        ),
    ];
    into.addAll(listed);
    final digest = sealsDigest(
      space: space,
      key: key,
      version: version,
      recipients: [for (final item in listed) (account: item.member, bundleVersion: item.bundleVersion, sealHash: item.sealHash)],
    );
    return {
      if (makes) 'check': b64urlEncode(keyCheckOf(key: keyOf(key, version), space: space, ref: key, version: version)),
      'count': recipients.length,
      'digest': b64urlEncode(digest),
      'key': key.wire,
      'version': version,
    };
  }
}

/// Builds the entries of one space, each linked to the one before and signed. With [seals] its commitments are real,
/// and the boxes they cover are the registry's; without, they hold filler digests and checks.
class ChainBuilder {
  ChainBuilder(this.space, {this.epoch = 1, this.seals});

  final String space;
  final SealRegistry? seals;

  /// What each record committed, by `seq`: the server's seal hash list for it, when the chain has real seals.
  final sealLog = <int, List<ChainSealHash>>{};
  int epoch;
  var seq = 0;
  Uint8List prev = chainGenesisLink;
  var at = 1000;
  final entries = <SignedChainEntry>[];

  /// The state of the chain so far, applying every entry with no checks of who made it.
  SpaceState get state {
    var state = SpaceState.empty(space);
    for (final signed in entries) {
      state = state.apply(signed.entry);
    }
    return state;
  }

  /// A copy that goes on from here, for a chain that forks.
  ChainBuilder fork() => ChainBuilder(space, epoch: epoch, seals: seals)
    ..seq = seq
    ..prev = prev
    ..at = at
    ..entries.addAll(entries)
    ..sealLog.addAll({
      for (final entry in sealLog.entries) entry.key: [...entry.value],
    });

  /// Takes an entry made elsewhere, signed and linked to the head, as a server does when it appends a record.
  void append(SignedChainEntry signed) {
    entries.add(signed);
    seq = signed.entry.seq + 1;
    prev = signed.entry.hashed;
    epoch = signed.entry.epoch;
  }

  /// Adds an entry by [by]. [signer], [seqOverride], [prevOverride] and [epochOverride] make an entry that is wrong;
  /// [cosigner] makes a `rekey`'s cosignature, which another kind doesn't have.
  SignedChainEntry add(
    Person by,
    ChainKind kind,
    Map<String, Object?> body, {
    Person? signer,
    Person? cosigner,
    int? seqOverride,
    Uint8List? prevOverride,
    int? epochOverride,
    bool advance = true,
  }) {
    final entry = SpaceChainEntry(
      space: space,
      seq: seqOverride ?? seq,
      prev: prevOverride ?? prev,
      epoch: epochOverride ?? epoch,
      at: at++,
      by: by.id,
      kind: kind,
      body: body,
    );
    final signed = SignedChainEntry(
      entry,
      fakeSignature((signer ?? by).bundle.sig1PublicKey, 'space-chain', entry.bytes),
      cosignature: cosigner == null ? null : fakeSignature(cosigner.bundle.sig1PublicKey, 'space-chain', entry.bytes),
    );
    entries.add(signed);
    if (advance) {
      seq = entry.seq + 1;
      prev = entry.hashed;
    }
    return signed;
  }

  /// A commitment of the record about to be added: real with a registry, filler without. [recipients] are the accounts
  /// the key is sealed to, with the bundle key version the state records for them ([extra] gives it for a member the
  /// state doesn't have yet, as the maker of a `create`).
  Map<String, Object?> _commit(
    KeyRef key,
    int version,
    Iterable<String> recipients, {
    bool makes = false,
    Map<String, int> extra = const {},
  }) {
    final accounts = recipients.toList();
    final registry = seals;
    if (registry == null) {
      return commitment(key, version, accounts.length, makes: makes);
    }
    final now = state;
    return registry.commitment(
      key,
      version,
      {for (final account in accounts) account: extra[account] ?? now.member(account)!.bundle!.keyVersion},
      into: sealLog.putIfAbsent(seq, () => []),
      makes: makes,
    );
  }

  SignedChainEntry create(Person maker, {String? collection, int nameSeed = 7, Uint8List? spaceNameHash}) {
    final first = collection ?? uuid(0xe0);
    return add(maker, ChainKind.create, {
      'bundle': b64urlEncode(maker.bundle.bytes),
      'bundleSignature': b64urlEncode(maker.bundleSignature),
      'collection': {'id': first, 'nameHash': hash64(nameSeed + 1)},
      'member': maker.id,
      'nameHash': spaceNameHash == null ? hash64(nameSeed) : b64urlEncode(spaceNameHash),
      'seals': [
        _commit(KeyRef.collection(first), 1, [maker.id], makes: true, extra: {maker.id: maker.keyVersion}),
        _commit(const KeyRef.space(), 1, [maker.id], makes: true, extra: {maker.id: maker.keyVersion}),
      ],
    });
  }

  SignedChainEntry invite(
    Person by,
    Person member, {
    SpaceRole role = SpaceRole.member,
    List<CustomPermission> custom = const [],
    Map<String, CollectionPermission> grants = const {},
  }) => add(by, ChainKind.invite, {
    'custom': _customWires(custom),
    'grants': [
      for (final grant in (grants.entries.toList()..sort((a, b) => a.key.compareTo(b.key))))
        {'collection': grant.key, 'permission': grant.value.wire},
    ],
    'member': member.id,
    'role': role.wire,
  });

  /// [by] confirms [member] after comparing their fingerprint. [statementFor], [statementConfirmer] and
  /// [statementSigner] make a confirmation that is wrong; [bundleFrom] a bundle of another account and
  /// [bundleSigner] a bundle that isn't signed by its own key.
  SignedChainEntry confirm(
    Person by,
    Person member, {
    Person? statementFor,
    Person? statementConfirmer,
    Person? statementSigner,
    Person? bundleFrom,
    Person? bundleSigner,
  }) {
    final statement = ConfirmStatement.forBundle(
      space: uuidBytes(space),
      bundle: (statementFor ?? bundleFrom ?? member).bundle,
      confirmer: uuidBytes((statementConfirmer ?? by).id),
    );
    final bundle = (bundleFrom ?? member).bundle;
    return add(by, ChainKind.confirm, {
      'bundle': b64urlEncode(bundle.bytes),
      'bundleSignature': b64urlEncode(fakeSignature((bundleSigner ?? bundleFrom ?? member).bundle.sig1PublicKey, 'bundle', bundle.bytes)),
      'member': member.id,
      'statement': b64urlEncode(statement.bytes),
      'statementSignature': b64urlEncode(fakeSignature((statementSigner ?? by).bundle.sig1PublicKey, 'confirm', statement.bytes)),
    });
  }

  /// [by] replaces their own bundle with [next]'s, signed by the old key and cosigned by [cosigner] (the new key).
  SignedChainEntry rekey(Person by, Person next, {Person? cosigner, Person? signer}) => add(
    by,
    ChainKind.rekey,
    {'bundle': b64urlEncode(next.bundle.bytes), 'bundleSignature': b64urlEncode(next.bundleSignature)},
    signer: signer,
    cosigner: cosigner ?? next,
  );

  SignedChainEntry role(Person by, Person member, SpaceRole role, {List<CustomPermission> custom = const []}) =>
      add(by, ChainKind.role, {'custom': _customWires(custom), 'member': member.id, 'role': role.wire});

  SignedChainEntry remove(Person by, Person member, {List<KeyRef> replace = const []}) =>
      add(by, ChainKind.remove, {'member': member.id, 'replace': _refs(replace)});

  SignedChainEntry grant(Person by, String collection, String grantee, CollectionPermission permission) =>
      add(by, ChainKind.grant, {'collection': collection, 'grantee': grantee, 'permission': permission.wire});

  SignedChainEntry ungrant(Person by, String collection, String grantee, {List<KeyRef> replace = const []}) =>
      add(by, ChainKind.ungrant, {'collection': collection, 'grantee': grantee, 'replace': _refs(replace)});

  /// A collection with [grants] by grantee (`user:<by>` is added with Manage when it isn't listed). [recipients] is the
  /// count its seal commits, which is worked out from the state so far when it isn't given.
  SignedChainEntry collection(
    Person by,
    String id, {
    Map<String, CollectionPermission> grants = const {},
    String? parent,
    int? recipients,
  }) {
    final all = {'user:${by.id}': CollectionPermission.manage, ...grants};
    final ids = _recipientsOf(all);
    return add(by, ChainKind.collection, {
      'collection': id,
      'grants': [
        for (final grant in (all.entries.toList()..sort((a, b) => a.key.compareTo(b.key))))
          {'grantee': grant.key, 'permission': grant.value.wire},
      ],
      'nameHash': hash64(9),
      'parent': ?parent,
      'seals': [
        recipients != null && seals == null
            ? commitment(KeyRef.collection(id), 1, recipients, makes: true)
            : _commit(KeyRef.collection(id), 1, ids, makes: true),
      ],
    });
  }

  SignedChainEntry move(Person by, String collection, {String? parent}) =>
      add(by, ChainKind.move, {'collection': collection, 'parent': ?parent});

  SignedChainEntry collectionDelete(Person by, String collection) => add(by, ChainKind.collectionDelete, {'collection': collection});

  SignedChainEntry group(Person by, String id) => add(by, ChainKind.group, {'group': id, 'nameHash': hash64(11)});

  SignedChainEntry groupMembers(
    Person by,
    String group, {
    List<Person> add = const [],
    List<Person> remove = const [],
    List<KeyRef> replace = const [],
  }) => this.add(by, ChainKind.groupMembers, {
    'add': _sorted([for (final member in add) member.id]),
    'group': group,
    'remove': _sorted([for (final member in remove) member.id]),
    'replace': _refs(replace),
  });

  SignedChainEntry groupDelete(Person by, String group, {List<KeyRef> replace = const []}) =>
      add(by, ChainKind.groupDelete, {'group': group, 'replace': _refs(replace)});

  SignedChainEntry rename(Person by, NameTarget target, {int seed = 21}) =>
      add(by, ChainKind.rename, {'nameHash': hash64(seed), 'target': target.wire});

  /// Shares [keys] with the members awaiting them, as the state before this record has it.
  SignedChainEntry seal(Person by, List<KeyRef> keys) {
    final before = state;
    return add(by, ChainKind.seal, {
      'seals': [for (final key in _sortedRefs(keys)) _commit(key, before.keyVersionOf(key)!, before.awaiting(key))],
    });
  }

  /// Replaces [rotate]'s keys with their next versions. [names] is built for a replaced space key from every name of the
  /// state so far, unless it is given (or [noNames] leaves it out).
  SignedChainEntry keys(Person by, List<KeyRef> rotate, {Uint8List? names, bool noNames = false}) {
    final before = state;
    final ordered = _sortedRefs(rotate);
    final hasSpace = ordered.any((key) => key.isSpace);
    final packed = noNames ? null : (names ?? (hasSpace ? packedNames(before) : null));
    final body = <String, Object?>{
      if (packed != null) 'names': b64urlEncode(packed),
      'rotate': [for (final key in ordered) _commit(key, before.keyVersionOf(key)! + 1, before.entitled(key), makes: true)],
    };
    return add(by, ChainKind.keys, body);
  }

  /// A `policies` record: the defaults with [changes] over the top-level members.
  SignedChainEntry policies(Person by, Map<String, Object?> changes) => add(by, ChainKind.policies, {
    'policies': {...state.policies, ...changes},
  });

  SignedChainEntry recoveryKey(Person by) => add(by, ChainKind.recoveryKey, {'key': b64urlEncode(_fill(Kx1.publicKeyLength, 99))});

  SignedChainEntry recoveryKeyClear(Person by) => add(by, ChainKind.recoveryKeyClear, <String, Object?>{});

  /// An Owner's `fence` to the next epoch, after a promotion that moved the home to [home].
  SignedChainEntry fence(Person by, {String? home, int? epochOverride}) {
    final signed = add(by, ChainKind.fence, {
      'home': home ?? uuid(0xf2),
      'promotion': hash64(33),
    }, epochOverride: epochOverride ?? epoch + 1);
    epoch = epochOverride ?? epoch + 1;
    return signed;
  }

  Set<String> _recipientsOf(Map<String, CollectionPermission> grants) {
    final before = state;
    final ids = <String>{};
    for (final member in before.confirmedMembers) {
      final direct = grants.containsKey('user:${member.id}');
      final byGroup = before.groups.values.any((group) => group.members.contains(member.id) && grants.containsKey('group:${group.id}'));
      if (direct || byGroup) {
        ids.add(member.id);
      }
    }
    return ids;
  }
}

List<String> _sorted(List<String> ids) => ids.toList()..sort();

List<String> _customWires(List<CustomPermission> custom) => _sorted([for (final permission in custom) permission.wire]);

List<KeyRef> _sortedRefs(List<KeyRef> refs) => refs.toList()..sort((a, b) => a.wire.compareTo(b.wire));

List<String> _refs(List<KeyRef> refs) => [for (final ref in _sortedRefs(refs)) ref.wire];

/// The packed names of [state]: one entry for the space, each collection and each group, sorted by type and id, with
/// filler hashes.
Uint8List packedNames(SpaceState state, {int seed = 40}) {
  final entries = <(int, Uint8List)>[
    (1, uuidBytes(state.space)),
    for (final id in state.collections.keys) (2, uuidBytes(id)),
    for (final id in state.groups.keys) (3, uuidBytes(id)),
  ];
  int compare((int, Uint8List) a, (int, Uint8List) b) {
    if (a.$1 != b.$1) {
      return a.$1 - b.$1;
    }
    for (var i = 0; i < 16; i++) {
      if (a.$2[i] != b.$2[i]) {
        return a.$2[i] - b.$2[i];
      }
    }
    return 0;
  }

  entries.sort(compare);
  return Uint8List.fromList([
    for (final entry in entries) ...[entry.$1, ...entry.$2, ...hash32(seed + entry.$1)],
  ]);
}
