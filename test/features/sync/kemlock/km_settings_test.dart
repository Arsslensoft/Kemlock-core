@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:test/test.dart';

const _target = {
  'accountId': '00000000-0000-4000-8000-000000000001',
  'email': 'me@example.com',
  'servers': [
    {'url': 'https://kem.example.com', 'role': 'home', 'pin': 'AA:BB', 'identityKey': 'AAAA'},
    {'url': 'https://replica.example.com', 'role': 'replica'},
  ],
  'deviceId': '00000000-0000-4000-8000-0000000000d1',
  'homeEpoch': 2,
};

const _dav = {
  'dav': {'url': 'https://dav.example.com/', 'username': 'me', 'password': 'pw'},
  'file': 'backmycodes-sync.json',
  'key': 'AAAA',
};

// What the settings write for a Vaultwarden target, whatever members it holds
final _vaultwarden = VaultwardenTarget.fromJson({'server': 'https://vw.example', 'email': 'me@example.com'}).toJson();

void main() {
  test('a kemlock target round trips, with the keys this version does not know', () {
    final json = {..._target, 'later': 1};

    final target = KemlockTarget.fromJson(json);

    expect(target.servers, hasLength(2));
    expect(target.home.url, 'https://kem.example.com');
    expect(target.home.pin, 'AA:BB');
    expect(target.homeEpoch, 2);
    expect(target.toJson(), json);
  });

  test('a server keeps its own unknown keys', () {
    final server = KemlockServer.fromJson({'url': 'https://kem.example.com', 'role': 'replica', 'region': 'de'});

    expect(server.toJson(), {'url': 'https://kem.example.com', 'role': 'replica', 'region': 'de'});
  });

  test('settings with a kemlock target round trip, and it counts as syncing the vault’s own entries', () {
    final json = {'personal': null, 'spaces': <Object?>[], 'kemlock': _target};

    final settings = SyncSettings.fromJson(json);

    expect(settings.kemlock?.email, 'me@example.com');
    expect(settings.syncsOwnEntries, isTrue);
    expect(settings.ownEntriesClash, isFalse);
    expect(jsonEncode(settings.toJson()), jsonEncode(json));
  });

  test('settings from before write byte for byte what they were, with no kemlock member', () {
    for (final json in <Map<String, Object?>>[
      {'personal': null, 'spaces': <Object?>[]},
      {'personal': _dav, 'spaces': <Object?>[]},
      {
        'personal': null,
        'spaces': <Object?>[],
        'vaultwarden': _vaultwarden,
        'later': {'x': 1},
      },
    ]) {
      final settings = SyncSettings.fromJson(json);

      expect(settings.kemlock, isNull);
      expect(jsonEncode(settings.toJson()), jsonEncode(json));
    }
  });

  test('settings written by a build that does not know kemlock keep it among their extra keys', () {
    final json = {'personal': null, 'spaces': <Object?>[], 'kemlock': _target};
    final older = SyncSettings(extra: {'kemlock': _target});

    expect(jsonEncode(older.toJson()), jsonEncode(json));
    expect(older.syncsOwnEntries, isFalse);
    expect(SyncSettings.fromJson(older.toJson()).kemlock?.accountId, _target['accountId']);
  });

  test('WebDAV and Kemlock Server both holding the vault’s own entries read as "ask"', () {
    final settings = SyncSettings.fromJson({'personal': _dav, 'spaces': <Object?>[], 'kemlock': _target});

    expect(settings.ownEntriesClash, isTrue);
    expect(settings.copyWith(personal: null).ownEntriesClash, isFalse);
    expect(settings.copyWith(kemlock: null).ownEntriesClash, isFalse);
  });

  test('Vaultwarden beside Kemlock Server is not a clash: only the scope state says whether it is a copy', () {
    final settings = SyncSettings.fromJson({'personal': null, 'spaces': <Object?>[], 'vaultwarden': _vaultwarden, 'kemlock': _target});

    expect(settings.ownEntriesClash, isFalse);
    expect(copyOfKey, 'copyOf');
  });

  test('copyWith turns kemlock on and off and leaves the rest', () {
    const settings = SyncSettings();
    final on = settings.copyWith(kemlock: KemlockTarget.fromJson(_target));

    expect(on.kemlock, isNotNull);
    expect(on.copyWith(spaces: const []).kemlock, isNotNull);
    expect(on.copyWith(kemlock: null).kemlock, isNull);
    expect(on.copyWith(kemlock: null), settings);
  });
}
