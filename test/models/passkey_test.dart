@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/sync_merge.dart' show canonical;
import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:test/test.dart';

const _json = <String, Object?>{
  'id': 'p1',
  'credentialId': 'AAECAwQFBgcICQoLDA0ODw',
  'rpId': 'github.com',
  'rpName': 'GitHub',
  'userHandle': 'dXNlci0xMjM',
  'userName': 'octocat@example.com',
  'userDisplayName': 'Octo Cat',
  'privateKey': 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg',
  'algorithm': -7,
  'label': 'Work',
  'note': 'Made on my phone',
  'tags': ['dev'],
  'addedAt': 100,
  'updatedAt': 200,
  'counterSeen': 0,
};

void main() {
  group('Passkey', () {
    test('reads every field and writes back what it read, unknown keys included', () {
      final passkey = Passkey.fromJson(jsonDecode(jsonEncode(_json)) as Map<String, Object?>);

      expect(
        (passkey.credentialId, passkey.rpId, passkey.rpName, passkey.userHandle, passkey.userName),
        ('AAECAwQFBgcICQoLDA0ODw', 'github.com', 'GitHub', 'dXNlci0xMjM', 'octocat@example.com'),
      );
      expect((passkey.algorithm, passkey.label, passkey.changedAt), (-7, 'Work', 200));
      expect(canonical(passkey.toJson()), canonical(_json));
      expect(passkey.extra, {'counterSeen': 0});
    });

    test('is listed by its label, then the site name, then the domain', () {
      final passkey = Passkey.fromJson(_json);

      expect(passkey.displayName, 'Work');
      expect(passkey.copyWith(label: unset).displayName, 'GitHub');
      expect(passkey.copyWith(label: '  ', rpName: unset).displayName, 'github.com');
    });

    test('reads a passkey without an algorithm as ES256', () {
      expect(Passkey.fromJson(const {'id': 'p2', 'credentialId': 'AA', 'rpId': 'x.com'}).algorithm, coseEs256);
    });

    test('never belongs to a space', () {
      final passkey = Passkey.fromJson({..._json, 'spaceId': 'space-1'});

      expect(passkey.spaceId, isNull);
      expect(passkey.inSpace('space-2'), same(passkey));
      // A spaceId written by something else is kept as it was, not acted on
      expect(passkey.toJson()['spaceId'], 'space-1');
    });

    test('keeps its key and its ids through copyWith, and stamps a change', () {
      final passkey = Passkey.fromJson(_json);

      final changed = passkey.copyWith(note: 'changed', tags: unset).stamped(999);

      expect(
        (changed.privateKey, changed.credentialId, changed.userHandle),
        (passkey.privateKey, passkey.credentialId, passkey.userHandle),
      );
      expect((changed.note, changed.tags, changed.updatedAt), ('changed', null, 999));
    });

    test('never prints its key', () {
      expect(Passkey.fromJson(_json).toString(), isNot(contains(_json['privateKey'])));
    });
  });
}
