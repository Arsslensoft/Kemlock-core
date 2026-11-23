@TestOn('vm')
library;

// The formats Vaultwarden sync writes, pinned by test/fixtures/vaultwarden/
// formats.json: phones running other versions read them, so a later version
// must keep reading these and keep writing the same. The fixture was written
// once by the last test here (WRITE_VAULTWARDEN_FORMATS=1); don't write it
// again.
import 'dart:convert';
import 'dart:io';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/accounts/otpauth.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

const _path = 'test/fixtures/vaultwarden/formats.json';

final _account = OtpAccount.fromJson({
  'id': '6f9e2c64-3c1d-4b7a-9a52-0d1f0c4e8b11',
  'type': 'totp',
  'issuer': 'GitHub',
  'label': 'me@example.com',
  'secret': 'JBSWY3DPEHPK3PXP',
  'algorithm': 'SHA256',
  'digits': 8,
  'period': 30,
  'pinned': true,
  'tags': ['Work'],
  'order': 2,
  'note': 'Main account',
  'addedAt': 1794038400000,
  'updatedAt': 1794042000000,
  'aFutureKey': {'kept': true},
});

final _steam = OtpAccount.fromJson({
  'id': '0b8d7a1e-5f3c-4e2d-8a6b-9c1d2e3f4a5b',
  'type': 'steam',
  'issuer': 'Steam',
  'label': 'gamer',
  'secret': 'GEZDGNBVGY3TQOJQ',
  'period': 30,
  'addedAt': 1794038400000,
});

final _hotp = OtpAccount.fromJson({
  'id': '3c2b1a09-8f7e-4d6c-9b5a-4e3d2c1b0a99',
  'type': 'hotp',
  'issuer': 'Bank',
  'label': '',
  'secret': 'KRSXG5CTMVRXEZLU',
  'counter': 7,
  'addedAt': 1794038400000,
});

final _service = BackupService.fromJson({
  'id': '9d8c7b6a-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
  'serviceName': 'GitHub',
  'codes': [
    {'code': 'aaaa-1111', 'used': false},
    {'code': 'bbbb-2222', 'used': true, 'usedAt': 1794040000000},
  ],
  'note': 'In the drawer',
  'addedAt': 1794038400000,
});

const _home = 'wJ2kX9c4Qm1zR7tB';

Map<String, Object?> get _fixture => jsonDecode(File(_path).readAsStringSync()) as Map<String, Object?>;

void main() {
  group('reads the fixture', () {
    test('home notes', () {
      final f = _fixture;
      final sealed = HomeNote.tryParse(f['homeSealed']! as String)!;
      expect((sealed.id, sealed.name, sealed.mode), (_home, 'Kemlock', VaultwardenMode.sealed));
      final plain = HomeNote.tryParse(f['homePlain']! as String)!;
      expect((plain.id, plain.mode, plain.seal), (_home, VaultwardenMode.plain, null));
      // The seal is a sync file whose kdf gives the salt, opened by the seal key
      final text = jsonEncode(sealed.seal);
      expect(readKdf(text), isNotNull);
      expect(decryptSyncFile(text, unb64(f['sealKey']! as String)), completion(isA<SyncDoc>()));
    });

    test('sealed entries', () async {
      final f = _fixture;
      final key = unb64(f['sealKey']! as String);
      for (final (name, entry) in [('sealedAccount', _account), ('sealedBackupService', _service)]) {
        final value = f[name]! as String;
        expect(value, startsWith('kemlock-sealed:1:$_home:'));
        expect(sealedHeader(value), (home: _home, id: _idOf(entry)));
        final opened = await openSealedEntry(value, key);
        expect(canonical(_jsonOf(opened)), canonical(_jsonOf(entry)));
      }
    });

    test('plain fields', () {
      final f = _fixture;
      for (final (name, entry, own) in [
        ('plainOwn', _account, true),
        ('plainLinked', _account, false),
        ('plainBackupService', _service, true),
      ]) {
        final field = PlainField.tryParse(f[name]! as String)!;
        expect((field.home, field.own, field.id), (_home, own, _idOf(entry)), reason: name);
        expect(canonical(_jsonOf(field.entry)), canonical(_jsonOf(entry)), reason: name);
      }
    });

    test('backup codes as text', () {
      final text = _fixture['codesText']! as String;
      final read = readBackupCodesText(text, _service.copyWith(codes: const []), at: 1);
      expect(read.codes.map((code) => (code.code, code.used)), [('aaaa-1111', false), ('bbbb-2222', true)]);
      expect(read.note, 'In the drawer');
    });

    test('the settings and the session', () {
      final f = _fixture;
      final settings = SyncSettings.fromJson(f['settings']);
      expect(settings.vaultwarden?.home, _home);
      expect(settings.vaultwarden?.seal, isNotNull);
      expect(settings.personal, isNull);
      expect(VwCredentials.fromJson(f['session']! as Map<String, Object?>).userId, '00000000-0000-4000-8000-000000000001');
    });
  });

  group('writes what the fixture holds', () {
    test('the values of plain items, and their sums', () {
      final f = _fixture;
      final values = f['values']! as Map<String, Object?>;
      for (final (name, entry, own) in [
        ('own', _account, true),
        ('linked', _account, false),
        ('steam', _steam, true),
        ('hotp', _hotp, true),
        ('backupService', _service, true),
      ]) {
        final written = plainValues(entry, own: own);
        expect(written, (values[name]! as Map<String, Object?>)['values'], reason: name);
        expect(valuesSum(written), (values[name]! as Map<String, Object?>)['sum'], reason: name);
      }
    });

    test("Bitwarden's totp values, backup codes text and home notes", () {
      final f = _fixture;
      expect(buildBitwardenTotp(_account), f['totpAccount']);
      expect(buildBitwardenTotp(_steam), f['totpSteam']);
      expect(backupCodesText(_service), f['codesText']);
      expect(HomeNote.tryParse(f['homePlain']! as String)!.toText(), f['homePlain']);
      expect(HomeNote.tryParse(f['homeSealed']! as String)!.toText(), f['homeSealed']);
      expect(PlainField.tryParse(f['plainOwn']! as String)!.toText(), f['plainOwn']);
    });
  });

  test('writes the fixture', () async {
    final key = randomBytes(32);
    final kdf = newKdf();
    final seal = jsonDecode(await encryptSyncFile(const SyncDoc(), key, kdf: kdf)) as Map<String, Object?>;
    final target = VaultwardenTarget(
      server: 'https://vault.example.com',
      email: 'me@example.com',
      home: _home,
      mode: VaultwardenMode.sealed,
      folderId: '00000000-0000-4000-8000-000000000002',
      seal: VwSeal(key: b64(key), kdf: kdf),
    );
    Map<String, Object?> values(Object entry, bool own) {
      final written = plainValues(entry, own: own);
      return {'values': written, 'sum': valuesSum(written)};
    }

    final fixture = {
      'about': 'Formats Vaultwarden sync writes, made by test/features/sync/vaultwarden/formats_test.dart on 2026-11-07. Never regenerate.',
      'sealKey': b64(key),
      'homeSealed': HomeNote(id: _home, name: 'Kemlock', mode: VaultwardenMode.sealed, seal: seal).toText(),
      'homePlain': const HomeNote(id: _home, name: 'Kemlock', mode: VaultwardenMode.plain).toText(),
      'sealedAccount': await sealEntry(_account, _home, key),
      'sealedBackupService': await sealEntry(_service, _home, key),
      'plainOwn': PlainField(home: _home, own: true, sum: valuesSum(plainValues(_account, own: true)), entry: _account).toText(),
      'plainLinked': PlainField(home: _home, own: false, sum: valuesSum(plainValues(_account, own: false)), entry: _account).toText(),
      'plainBackupService': PlainField(home: _home, own: true, sum: valuesSum(plainValues(_service, own: true)), entry: _service).toText(),
      'codesText': backupCodesText(_service),
      'totpAccount': buildBitwardenTotp(_account),
      'totpSteam': buildBitwardenTotp(_steam),
      'values': {
        'own': values(_account, true),
        'linked': values(_account, false),
        'steam': values(_steam, true),
        'hotp': values(_hotp, true),
        'backupService': values(_service, true),
      },
      'settings': SyncSettings(vaultwarden: target).toJson(),
      'session': const VwCredentials(
        deviceId: '00000000-0000-4000-8000-000000000003',
        userId: '00000000-0000-4000-8000-000000000001',
        userKey: 'AAAA',
        accessToken: 'a.b.c',
        refreshToken: 'r',
        expiresAt: 1794045600000,
      ).toJson(),
    };
    await File(_path).writeAsString('${const JsonEncoder.withIndent('  ').convert(fixture)}\n');
  }, skip: Platform.environment['WRITE_VAULTWARDEN_FORMATS'] == '1' ? null : 'Set WRITE_VAULTWARDEN_FORMATS=1 to write the fixture');
}

String _idOf(Object entry) => entry is OtpAccount ? entry.id : (entry as BackupService).id;

Map<String, Object?> _jsonOf(Object entry) => entry is OtpAccount ? entry.toJson() : (entry as BackupService).toJson();
