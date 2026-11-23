@TestOn('vm')
library;

// The formats Vaultwarden sync writes for keys, notes, passkeys and files
// attached to notes, pinned by test/fixtures/vaultwarden/vault-items.json:
// phones running other versions read them, so a later version must keep
// reading these and keep writing the same. The fixture was written once by
// the last test here (WRITE_VAULTWARDEN_ITEMS=1); don't write it again.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_attachments.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_items.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

const _path = 'test/fixtures/vaultwarden/vault-items.json';
const _home = 'wJ2kX9c4Qm1zR7tB';

final _sshKey = VaultKey.fromJson({
  'id': '2b7c9e0a-0d4f-4b8e-9a3c-5f1e2d3c4b5a',
  'name': 'laptop',
  'kind': 'ssh',
  'algorithm': 'ed25519',
  'private': 'MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC',
  'public': 'MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=',
  'origin': 'generated',
  'note': 'Work laptop',
  'pinned': true,
  'addedAt': 1794038400000,
});

final _note = SecureNote.fromJson({
  'id': '7d1e5c3a-9b2f-4e6d-8c0a-1f2e3d4c5b6a',
  'title': 'Passport',
  'text': 'Number 12AB34567\nIn the drawer',
  'pinned': true,
  'addedAt': 1794038400000,
  'attachments': [
    {
      'id': 'q8s3Lw0bVt9Yk2Rr4Xc1Zg',
      'name': 'scan.pdf',
      'size': 17,
      'type': 'application/pdf',
      'key': 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
      'addedAt': 1794038400000,
    },
  ],
});

final _passkey = Passkey.fromJson({
  'id': '5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d',
  'credentialId': 'AQIDBAUGBwgJCgsMDQ4PEA',
  'rpId': 'github.com',
  'rpName': 'GitHub',
  'userHandle': 'dXNlci0xMjM',
  'userName': 'octocat',
  'userDisplayName': 'The Octocat',
  'privateKey': 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg',
  'addedAt': 1794038400000,
});

Map<String, Object?> get _fixture => jsonDecode(File(_path).readAsStringSync()) as Map<String, Object?>;

final _entries = <String, VaultEntry>{'key': _sshKey, 'note': _note, 'passkey': _passkey};

void main() {
  group('reads the fixture', () {
    test('sealed values of each kind', () async {
      final f = _fixture;
      final key = unb64(f['sealKey']! as String);
      for (final MapEntry(key: name, value: entry) in _entries.entries) {
        final value = (f['sealed']! as Map<String, Object?>)[name]! as String;
        expect(sealedHeader(value), (home: _home, id: entry.id), reason: name);
        final opened = await openSealedEntry(value, key) as VaultEntry;
        expect(canonical(opened.toJson()), canonical(entry.toJson()), reason: name);
      }
    });

    test('plain fields of each kind', () {
      final plain = _fixture['plain']! as Map<String, Object?>;
      for (final MapEntry(key: name, value: entry) in _entries.entries) {
        final field = PlainField.tryParse(plain[name]! as String)!;
        expect((field.home, field.id, field.own, field.kind.name), (_home, entry.id, true, name), reason: name);
        expect(canonical((field.entry as VaultEntry).toJson()), canonical(entry.toJson()), reason: name);
      }
    });

    test("a file's attachment, sealed and plain", () async {
      final f = _fixture['attachment']! as Map<String, Object?>;
      final file = _note.files.single;
      final key = attachmentKey(file);
      expect(b64(key.bytes), f['key']);
      final sealed = await bwDecryptAttachment(unb64(f['sealed']! as String), key);
      expect(sealed.sublist(0, 4), kma1Magic);
      expect(utf8.decode(kma1DecryptSync(sealed, unb64(file.key))), '%PDF-1.7 passport');
      final plain = await bwDecryptAttachment(unb64(f['plain']! as String), key);
      expect(utf8.decode(plain), '%PDF-1.7 passport');
    });

    test('the settings with the kinds agreed to', () {
      final settings = SyncSettings.fromJson(_fixture['settings']);
      expect(settings.vaultwarden?.plainKinds, {'key', 'note', 'passkey'});
    });
  });

  group('writes what the fixture holds', () {
    test('the values of plain items, and their sums', () {
      final values = _fixture['values']! as Map<String, Object?>;
      for (final (name, entry, ssh) in [
        ('note', _note as Object, false),
        ('keyAsNote', _sshKey, false),
        ('keyAsSshItem', _sshKey, true),
        ('passkey', _passkey, false),
      ]) {
        final written = laterValues(entry, sshItem: ssh);
        expect(written, (values[name]! as Map<String, Object?>)['values'], reason: name);
        expect(valuesSum(written), (values[name]! as Map<String, Object?>)['sum'], reason: name);
      }
    });

    test('fields, credential ids and attachment keys', () {
      final f = _fixture;
      final plain = f['plain']! as Map<String, Object?>;
      for (final MapEntry(key: name, value: entry) in _entries.entries) {
        final values = laterValues(entry, sshItem: name == 'key');
        expect(
          PlainField(home: _home, own: true, sum: valuesSum(values), entry: entry).toText(),
          plain[name],
          reason: name,
        );
      }
      expect(bitwardenCredentialId(_passkey.credentialId), f['credentialId']);
      expect(b64(attachmentKey(_note.files.single).bytes), (f['attachment']! as Map<String, Object?>)['key']);
      final settings = SyncSettings.fromJson(f['settings']);
      expect(settings.toJson(), f['settings']);
    });
  });

  test('writes the fixture', () async {
    final key = randomBytes(32);
    final file = _note.files.single;
    final plainFile = Uint8List.fromList(utf8.encode('%PDF-1.7 passport'));
    Map<String, Object?> values(Object entry, {bool ssh = false}) {
      final written = laterValues(entry, sshItem: ssh);
      return {'values': written, 'sum': valuesSum(written)};
    }

    final fixture = {
      'about':
          'Formats Vaultwarden sync writes for keys, notes, passkeys and attached files, made by '
          'test/features/sync/vaultwarden/items_formats_test.dart on 2026-11-15. Never regenerate.',
      'sealKey': b64(key),
      'sealed': {for (final MapEntry(key: name, value: entry) in _entries.entries) name: await sealEntry(entry, _home, key)},
      'plain': {
        for (final MapEntry(key: name, value: entry) in _entries.entries)
          name: PlainField(
            home: _home,
            own: true,
            sum: valuesSum(laterValues(entry, sshItem: name == 'key')),
            entry: entry,
          ).toText(),
      },
      'values': {
        'note': values(_note),
        'keyAsNote': values(_sshKey),
        'keyAsSshItem': values(_sshKey, ssh: true),
        'passkey': values(_passkey),
      },
      'credentialId': bitwardenCredentialId(_passkey.credentialId),
      'attachment': {
        'key': b64(attachmentKey(file).bytes),
        'sealed': b64(await bwEncryptAttachment(kma1EncryptSync(plainFile, unb64(file.key)), attachmentKey(file))),
        'plain': b64(await bwEncryptAttachment(plainFile, attachmentKey(file))),
      },
      'settings': const SyncSettings(
        vaultwarden: VaultwardenTarget(
          server: 'https://vault.example.com',
          email: 'me@example.com',
          home: _home,
          mode: VaultwardenMode.plain,
          folderId: '00000000-0000-4000-8000-000000000002',
          plainKinds: {'key', 'note', 'passkey'},
        ),
      ).toJson(),
    };
    await File(_path).writeAsString('${const JsonEncoder.withIndent('  ').convert(fixture)}\n');
  }, skip: Platform.environment['WRITE_VAULTWARDEN_ITEMS'] == '1' ? null : 'Set WRITE_VAULTWARDEN_ITEMS=1 to write the fixture');
}
