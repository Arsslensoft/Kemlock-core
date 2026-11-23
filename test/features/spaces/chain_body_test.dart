@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/spaces/chain_body.dart';
import 'package:kemlock_core/features/spaces/space_chain.dart';
import 'package:kemlock_core/features/spaces/space_state.dart';
import 'package:test/test.dart';

import 'chain_kit.dart';

// The exact shape of the body of each kind: what a reader refuses as malformed whatever the state, and as too
// large when a list is past its limit (the space chain section, "Kinds", "Encoding" and "Limits").
void main() {
  final malformed = throwsA(isA<MalformedException>());
  final tooLarge = throwsA(isA<ChainRefusal>().having((e) => e.problem, 'problem', ChainProblem.tooLarge));
  final bundle = b64urlEncode(Uint8List(chainBundleLength));
  final signature = b64urlEncode(Uint8List(Sig1.signatureLength));
  final collection = uuid(0xe0);
  final finance = uuid(0xf1);

  Map<String, Object?> commit(KeyRef key, {bool makes = false, int count = 1, int version = 1}) =>
      commitment(key, version, count, makes: makes);

  group('reads the body of every kind', () {
    final bodies = <ChainKind, Map<String, Object?>>{
      ChainKind.create: {
        'bundle': bundle,
        'bundleSignature': signature,
        'collection': {'id': collection, 'nameHash': hash64()},
        'member': uuid(1),
        'nameHash': hash64(),
        'seals': [commit(KeyRef.collection(collection), makes: true), commit(const KeyRef.space(), makes: true)],
      },
      ChainKind.invite: {
        'custom': ['create-collections', 'manage-users'],
        'grants': [
          {'collection': collection, 'permission': 'edit'},
          {'collection': finance, 'permission': 'view'},
        ],
        'member': uuid(2),
        'role': 'custom',
      },
      ChainKind.confirm: {
        'bundle': bundle,
        'bundleSignature': signature,
        'member': uuid(2),
        'statement': b64urlEncode(Uint8List(chainStatementLength)),
        'statementSignature': signature,
      },
      ChainKind.rekey: {'bundle': bundle, 'bundleSignature': signature},
      ChainKind.role: {'custom': <String>[], 'member': uuid(2), 'role': 'admin'},
      ChainKind.remove: {
        'member': uuid(2),
        'replace': ['collection:$finance', 'space'],
      },
      ChainKind.grant: {'collection': finance, 'grantee': 'group:${uuid(0x91)}', 'permission': 'manage'},
      ChainKind.ungrant: {'collection': finance, 'grantee': 'user:${uuid(2)}', 'replace': <String>[]},
      ChainKind.collection: {
        'collection': finance,
        'grants': [
          {'grantee': 'group:${uuid(0x91)}', 'permission': 'view'},
          {'grantee': 'user:${uuid(1)}', 'permission': 'manage'},
        ],
        'nameHash': hash64(),
        'parent': collection,
        'seals': [commit(KeyRef.collection(finance), makes: true)],
      },
      ChainKind.move: {'collection': finance},
      ChainKind.collectionDelete: {'collection': finance},
      ChainKind.group: {'group': uuid(0x91), 'nameHash': hash64()},
      ChainKind.groupMembers: {
        'add': [uuid(2), uuid(3)],
        'group': uuid(0x91),
        'remove': [uuid(4)],
        'replace': <String>[],
      },
      ChainKind.groupDelete: {
        'group': uuid(0x91),
        'replace': ['collection:$finance'],
      },
      ChainKind.rename: {'nameHash': hash64(), 'target': 'group:${uuid(0x91)}'},
      ChainKind.seal: {
        'seals': [commit(KeyRef.collection(finance)), commit(const KeyRef.space())],
      },
      ChainKind.keys: {
        'names': b64urlEncode(Uint8List(packedNameLength * 2)),
        'rotate': [commit(const KeyRef.space(), makes: true, version: 2)],
      },
      ChainKind.policies: {'policies': defaultPolicies()},
      ChainKind.recoveryKey: {'key': b64urlEncode(Uint8List(Kx1.publicKeyLength))},
      ChainKind.recoveryKeyClear: <String, Object?>{},
      ChainKind.fence: {'home': uuid(0xf2), 'promotion': hash64()},
    };

    test('all 21 kinds have a case', () {
      expect(bodies.keys.toSet(), ChainKind.values.toSet());
      expect(ChainKind.values, hasLength(21));
    });

    for (final MapEntry(:key, :value) in bodies.entries) {
      test('a ${key.wire}', () {
        validateBody(key, value);
      });
    }

    for (final MapEntry(:key, :value) in bodies.entries) {
      if (value.isEmpty) {
        continue;
      }
      test('a ${key.wire} with a member it doesn\'t have, or without one it has, is malformed', () {
        expect(() => validateBody(key, {...value, 'extra': 'x'}), malformed);
        // `names` is the one member that may be absent, so keys loses `rotate` instead
        expect(() => validateBody(key, {...value}..remove(key == ChainKind.keys ? 'rotate' : value.keys.first)), malformed);
      });
    }
  });

  group('refuses as malformed', () {
    Map<String, Object?> invite({Object? custom = const <String>[], Object? grants = const <Object?>[]}) => {
      'custom': custom,
      'grants': grants,
      'member': uuid(2),
      'role': 'custom',
    };

    test('null for an optional member, which is absent instead', () {
      expect(
        () => validateBody(ChainKind.collection, {
          'collection': finance,
          'grants': [
            {'grantee': 'user:${uuid(1)}', 'permission': 'manage'},
          ],
          'nameHash': hash64(),
          'parent': null,
          'seals': [commit(KeyRef.collection(finance), makes: true)],
        }),
        malformed,
      );
      expect(() => validateBody(ChainKind.move, {'collection': finance, 'parent': null}), malformed);
    });

    test('"custom": null, and a list that isn\'t a list', () {
      expect(() => validateBody(ChainKind.invite, invite(custom: null)), malformed);
      expect(() => validateBody(ChainKind.invite, invite(custom: 'manage-users')), malformed);
      expect(() => validateBody(ChainKind.invite, invite(grants: null)), malformed);
    });

    test('custom permissions out of order, twice, or unknown', () {
      expect(() => validateBody(ChainKind.invite, invite(custom: ['manage-users', 'create-collections'])), malformed);
      expect(() => validateBody(ChainKind.invite, invite(custom: ['manage-users', 'manage-users'])), malformed);
      expect(() => validateBody(ChainKind.invite, invite(custom: ['delete-everything'])), malformed);
    });

    test('grants out of order or for one collection twice, with a permission that is unknown', () {
      Map<String, Object?> grant(String c, [String permission = 'view']) => {'collection': c, 'permission': permission};
      expect(() => validateBody(ChainKind.invite, invite(grants: [grant(finance), grant(collection)])), malformed);
      expect(() => validateBody(ChainKind.invite, invite(grants: [grant(finance), grant(finance, 'edit')])), malformed);
      expect(() => validateBody(ChainKind.invite, invite(grants: [grant(finance, 'own')])), malformed);
    });

    test('an id twice in add, an id in both add and remove, and an empty change', () {
      Map<String, Object?> members(List<String> add, List<String> remove) => {
        'add': add,
        'group': uuid(0x91),
        'remove': remove,
        'replace': <String>[],
      };
      expect(() => validateBody(ChainKind.groupMembers, members([uuid(2), uuid(2)], [])), malformed);
      expect(() => validateBody(ChainKind.groupMembers, members([uuid(3), uuid(2)], [])), malformed);
      expect(() => validateBody(ChainKind.groupMembers, members([uuid(2)], [uuid(2)])), malformed);
      expect(() => validateBody(ChainKind.groupMembers, members([], [])), malformed);
    });

    test('a grantee, a key, a name target or an id that is not the form', () {
      expect(() => validateBody(ChainKind.grant, {'collection': finance, 'grantee': 'team:${uuid(2)}', 'permission': 'view'}), malformed);
      expect(() => validateBody(ChainKind.grant, {'collection': finance, 'grantee': 'user:x', 'permission': 'view'}), malformed);
      expect(
        () => validateBody(ChainKind.remove, {
          'member': uuid(2),
          'replace': ['collection:x'],
        }),
        malformed,
      );
      expect(
        () => validateBody(ChainKind.remove, {
          'member': uuid(2),
          'replace': ['space', 'space'],
        }),
        malformed,
      );
      expect(
        () => validateBody(ChainKind.remove, {
          'member': uuid(2),
          'replace': ['space', 'collection:$finance'],
        }),
        malformed,
      );
      expect(() => validateBody(ChainKind.rename, {'nameHash': hash64(), 'target': 'user:${uuid(2)}'}), malformed);
      expect(() => validateBody(ChainKind.remove, {'member': uuid(0xab).toUpperCase(), 'replace': <String>[]}), malformed);
    });

    test('a hash, a bundle, a signature or a key of the wrong length or not canonical base64url', () {
      expect(() => validateBody(ChainKind.group, {'group': uuid(0x91), 'nameHash': b64urlEncode(Uint8List(31))}), malformed);
      expect(() => validateBody(ChainKind.group, {'group': uuid(0x91), 'nameHash': '${hash64()}='}), malformed);
      expect(() => validateBody(ChainKind.rekey, {'bundle': b64urlEncode(Uint8List(3620)), 'bundleSignature': signature}), malformed);
      expect(() => validateBody(ChainKind.rekey, {'bundle': bundle, 'bundleSignature': b64urlEncode(Uint8List(3372))}), malformed);
      expect(() => validateBody(ChainKind.recoveryKey, {'key': b64urlEncode(Uint8List(1599))}), malformed);
    });

    test('a commitment with a count, a version, a digest or a check out of range', () {
      Map<String, Object?> seal(Map<String, Object?> commitment) => {
        'seals': [commitment],
      };
      final base = commit(KeyRef.collection(finance));
      expect(() => validateBody(ChainKind.seal, seal({...base, 'count': 0})), malformed);
      expect(() => validateBody(ChainKind.seal, seal({...base, 'count': 10001})), malformed);
      expect(() => validateBody(ChainKind.seal, seal({...base, 'version': 0})), malformed);
      expect(() => validateBody(ChainKind.seal, seal({...base, 'version': 0x100000000})), malformed);
      expect(() => validateBody(ChainKind.seal, seal({...base, 'digest': b64urlEncode(Uint8List(31))})), malformed);
      expect(() => validateBody(ChainKind.seal, seal({...base, 'check': hash64()})), malformed);
      expect(
        () => validateBody(ChainKind.keys, {
          'rotate': [commit(const KeyRef.space(), version: 2)],
        }),
        malformed,
      );
    });

    test('commitments out of order, and a keys record that rotates nothing', () {
      expect(
        () => validateBody(ChainKind.seal, {
          'seals': [commit(const KeyRef.space()), commit(KeyRef.collection(finance))],
        }),
        malformed,
      );
      expect(() => validateBody(ChainKind.seal, {'seals': <Object?>[]}), malformed);
      expect(() => validateBody(ChainKind.keys, {'rotate': <Object?>[]}), malformed);
    });

    test('a collection without a grant', () {
      expect(
        () => validateBody(ChainKind.collection, {
          'collection': finance,
          'grants': <Object?>[],
          'nameHash': hash64(),
          'seals': [commit(KeyRef.collection(finance), makes: true)],
        }),
        malformed,
      );
    });

    test('policies with a missing member, an unknown one, a wrong type or a value out of range', () {
      Map<String, Object?> policies(void Function(Map<String, Object?>) change) {
        final set = defaultPolicies();
        change(set);
        return {'policies': set};
      }

      Map<String, Object?> master(Map<String, Object?> set) => set['masterPassword']! as Map<String, Object?>;
      Map<String, Object?> timeout(Map<String, Object?> set) => set['sessionTimeout']! as Map<String, Object?>;

      expect(() => validateBody(ChainKind.policies, policies((p) => p.remove('twoStep'))), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => p['requireBiometrics'] = true)), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => p['twoStep'] = 1)), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => master(p)['minComplexity'] = 5)), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => master(p)['minLength'] = 129)), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => timeout(p)['minutes'] = 525601)), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => timeout(p)['action'] = 'sleep')), malformed);
      expect(() => validateBody(ChainKind.policies, policies((p) => master(p)['requireEmoji'] = true)), malformed);
      validateBody(ChainKind.policies, policies((p) => timeout(p)['action'] = 'log-out'));
      validateBody(ChainKind.policies, policies((p) => master(p)['minLength'] = 128));
    });
  });

  group('refuses as too large', () {
    test('a list past its limit, where an empty one is malformed', () {
      final ids = [for (var i = 0; i < 1001; i++) uuid(0x1000 + i)];
      expect(
        () => validateBody(ChainKind.groupMembers, {'add': ids, 'group': uuid(0x91), 'remove': <String>[], 'replace': <String>[]}),
        tooLarge,
      );
      final half = ids.sublist(0, 501);
      expect(
        () => validateBody(ChainKind.groupMembers, {
          'add': half,
          'group': uuid(0x91),
          'remove': ids.sublist(501, 1001),
          'replace': <String>[],
        }),
        tooLarge,
      );
      final grants = [
        for (var i = 0; i < 1001; i++) {'collection': uuid(0x1000 + i), 'permission': 'view'},
      ];
      expect(() => validateBody(ChainKind.invite, {'custom': <String>[], 'grants': grants, 'member': uuid(2), 'role': 'member'}), tooLarge);
      final seals = [for (var i = 0; i < 1002; i++) commit(KeyRef.collection(uuid(0x1000 + i)))];
      expect(() => validateBody(ChainKind.seal, {'seals': seals}), tooLarge);
      final rotate = [for (var i = 0; i < 258; i++) commit(KeyRef.collection(uuid(0x1000 + i)), makes: true, version: 2)];
      expect(() => validateBody(ChainKind.keys, {'rotate': rotate}), tooLarge);
    });

    test('1,000 ids and 1,001 commitments are the most that are read', () {
      final ids = [for (var i = 0; i < 1000; i++) uuid(0x1000 + i)];
      validateBody(ChainKind.groupMembers, {'add': ids, 'group': uuid(0x91), 'remove': <String>[], 'replace': <String>[]});
      final seals = [for (var i = 0; i < 1001; i++) commit(KeyRef.collection(uuid(0x1000 + i)))];
      validateBody(ChainKind.seal, {'seals': seals});
    });
  });
}
