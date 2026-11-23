@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart' show canonical;
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

const _json = <String, Object?>{
  'id': 'k1',
  'name': 'laptop',
  'kind': 'ssh',
  'algorithm': 'ed25519',
  'private': 'MC4CAQAwBQYDK2VwBCIEIA==',
  'public': 'MCowBQYDK2VwAyEA',
  'origin': 'generated',
  'note': 'The work laptop',
  'tags': ['work'],
  'pinned': true,
  'spaceId': 'space-1',
  'addedAt': 100,
  'updatedAt': 200,
  'agentHint': 'later',
};

void main() {
  group('VaultKey', () {
    test('reads every field and writes back what it read, unknown keys included', () {
      final key = VaultKey.fromJson(jsonDecode(jsonEncode(_json)) as Map<String, Object?>);

      expect(
        (key.name, key.kind, key.algorithm, key.origin, key.isPinned, key.spaceId),
        ('laptop', KeyKind.ssh, 'ed25519', KeyOrigin.generated, true, 'space-1'),
      );
      expect((key.privateKey, key.publicKey, key.changedAt), ('MC4CAQAwBQYDK2VwBCIEIA==', 'MCowBQYDK2VwAyEA', 200));
      expect(canonical(key.toJson()), canonical(_json));
      expect(key.extra, {'agentHint': 'later'});
    });

    test('keeps an RSA size, a protected PGP key, and a key without a public half', () {
      final rsa = VaultKey.fromJson(const {
        'id': 'k2',
        'name': 'r',
        'kind': 'signing',
        'algorithm': 'rsa',
        'bits': 4096,
        'private': 'AA==',
        'addedAt': 1,
      });
      final pgp = VaultKey.fromJson(const {
        'id': 'k3',
        'name': 'p',
        'kind': 'pgp',
        'algorithm': 'pgp',
        'protected': true,
        'private': 'AA==',
        'public': 'AQ==',
        'addedAt': 1,
      });
      final other = VaultKey.fromJson(const {
        'id': 'k4',
        'name': 'o',
        'kind': 'other',
        'algorithm': '1.3.101.999',
        'private': 'AA==',
        'addedAt': 1,
      });

      expect(rsa.bits, 4096);
      expect(pgp.protected, isTrue);
      expect((other.publicKey, other.algorithm), (null, '1.3.101.999'));
      expect(other.toJson().containsKey('public'), isFalse);
    });

    test('reads a key without a kind or origin as another imported key', () {
      final key = VaultKey.fromJson(const {'id': 'k5', 'private': 'AA=='});

      expect((key.kind, key.origin), (KeyKind.other, KeyOrigin.imported));
    });

    test('never changes its halves through copyWith', () {
      final key = VaultKey.fromJson(_json);

      final renamed = key.copyWith(name: 'desktop', note: unset, spaceId: unset);

      expect((renamed.name, renamed.note, renamed.spaceId), ('desktop', null, null));
      expect(
        (renamed.privateKey, renamed.publicKey, renamed.algorithm, renamed.kind),
        (key.privateKey, key.publicKey, key.algorithm, key.kind),
      );
    });

    group('withHalves', () {
      // As toJson writes it, so the text compares byte for byte
      const pgpJson = <String, Object?>{
        'id': 'k6',
        'name': 'Ada',
        'kind': 'pgp',
        'algorithm': 'pgp',
        'private': 'AAEC',
        'public': 'AQID',
        'origin': 'imported',
        'protected': true,
        'note': 'Signing key',
        'tags': ['work'],
        'pinned': true,
        'spaceId': 'space-1',
        'addedAt': 100,
        'updatedAt': 200,
        'cardSerial': 'later',
      };

      test('changes the halves of a PGP key and keeps every other field, extra ones too', () {
        final key = VaultKey.fromJson(pgpJson);
        final grown = key.withHalves(privateKey: 'AAECAw==', publicKey: 'AQIDBA==', protected: false);

        expect((grown.privateKey, grown.publicKey, grown.protected), ('AAECAw==', 'AQIDBA==', null));
        expect(
          grown.toJson()
            ..remove('private')
            ..remove('public'),
          {...pgpJson}
            ..remove('private')
            ..remove('public')
            ..remove('protected'),
        );
        expect(grown.extra, {'cardSerial': 'later'});
        expect(key.withHalves(privateKey: 'AA==', publicKey: 'AQ==', protected: true).protected, isTrue);
      });

      // Joined with add-openpgp-card: a key on a card that grows is still on its card
      test('keeps the card of a key whose private half is on a security key', () {
        const card = {
          'aid': 'D276000124010304FFFF123456780000',
          'slots': {'sig': '1FCDA135EE42400EC2B77CE677249ABE661CF8DB'},
        };
        final key = VaultKey.fromJson({...pgpJson, 'card': card});

        final grown = key.withHalves(privateKey: 'AAECAw==', publicKey: 'AQIDBA==', protected: true);

        expect(grown.card, card);
        expect(grown.isOnCard, isTrue);
        expect(grown.toJson()['card'], card);
        expect(grown.extra, {'cardSerial': 'later'});
        expect(
          VaultKey.fromJson(pgpJson).withHalves(privateKey: 'AA==', publicKey: 'AQ==', protected: true).toJson(),
          isNot(contains('card')),
        );
      });

      test('throws for a key of any other kind', () {
        for (final kind in [KeyKind.ssh, KeyKind.signing, KeyKind.exchange, KeyKind.other]) {
          final key = VaultKey.fromJson({..._json, 'kind': kind});
          expect(
            () => key.withHalves(privateKey: 'AA==', publicKey: 'AQ==', protected: false),
            throwsStateError,
            reason: kind,
          );
        }
      });

      test('a key that was not changed is written byte for byte as it was read', () {
        expect(jsonEncode(VaultKey.fromJson(jsonDecode(jsonEncode(pgpJson)) as Map<String, Object?>).toJson()), jsonEncode(pgpJson));
      });
    });

    test('is stamped and moved between scopes as other entries are', () {
      final key = VaultKey.fromJson(_json);

      expect(key.stamped(999).updatedAt, 999);
      expect(key.inSpace(null).spaceId, isNull);
      expect(key.inSpace('space-2').spaceId, 'space-2');
    });

    test('never prints its private half', () {
      expect(VaultKey.fromJson(_json).toString(), isNot(contains('MC4CAQAw')));
    });
  });
}
