@TestOn('vm')
library;

// File items in exports and imports, and the helper that seals a new attached file.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/import/import_merge.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:kemlock_core/vault/attachment_seal.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

const _lease = VaultFile(
  id: '3f2c9a71-e4b0-4856-8a00-0000000000f1',
  name: 'Lease.pdf',
  file: NoteAttachment(id: 'att-1', name: 'Lease.pdf', size: 10, key: 'AAAA', addedAt: 1, sha256: 'ab'),
  addedAt: 9,
);

void main() {
  group('a plain export', () {
    test('holds File items under `files` and reads them back, counted among the attached files', () {
      final text = exportVaultPlaintext(const [], const [], files: const [_lease], now: DateTime.utc(2026, 11, 25));

      expect((jsonDecode(text) as Map<String, Object?>)['files'], [_lease.toJson()]);
      final payload = importVaultPlaintext(text);
      expect(payload.files, [_lease]);
      expect(payload.fileCount, 1);
    });

    test('without File items has no `files` key, as it never had', () {
      final text = exportVaultPlaintext(const [], const [], now: DateTime.utc(2026, 11, 25));

      expect((jsonDecode(text) as Map<String, Object?>).keys, isNot(contains('files')));
      expect(importVaultPlaintext(text).files, isEmpty);
    });
  });

  group('an import', () {
    test('adds the File items the vault does not hold, by id, each once', () {
      final preview = ImportPreview.of(VaultExportPayload(accounts: const [], backupServices: const [], files: const [_lease, _lease]));

      expect(newFiles(preview, const []), [_lease]);
      expect(newFiles(preview, const [_lease]), isEmpty);
    });

    test('drops the server file an exported File item or note names: it is under another item', () {
      const named = NoteAttachment(id: 'att-1', name: 'Lease.pdf', size: 10, key: 'AAAA', addedAt: 1, extra: {'kemlockFile': 'file-1', 'x': 1});
      final preview = ImportPreview.of(
        VaultExportPayload(
          accounts: const [],
          backupServices: const [],
          files: [_lease.copyWith(file: named)],
          notes: const [
            SecureNote(id: 'n1', title: 'Papers', addedAt: 1, attachments: [named]),
          ],
        ),
      );

      final file = newFiles(preview, const []).single.file;
      final note = newNotes(preview, const []).single.files.single;

      expect(file.extra, {'x': 1});
      expect(note.extra, {'x': 1});
      expect(note.id, 'att-1');
    });
  });

  group('sealAttachment', () {
    test('seals the bytes under a new key and names them, with the hash of the plain bytes', () async {
      final plain = randomBytes(70 * 1024);

      final made = await sealAttachment(plain, name: 'scan.pdf', type: 'application/pdf', now: 123);

      final entry = made.entry;
      expect(entry.name, 'scan.pdf');
      expect(entry.type, 'application/pdf');
      expect(entry.size, plain.length);
      expect(entry.addedAt, 123);
      expect(entry.id, isNotEmpty);
      expect(entry.sha256, sha256Hex(plain));
      expect(entry.sha256, matches(RegExp(r'^[0-9a-f]{64}$')));
      expect(made.sealed, hasLength(kma1Length(plain.length)));
      expect(await kma1Decrypt(made.sealed, unb64(entry.key)), plain);
    });

    test('makes a new id and key each time, leaves out an empty type, and takes an empty file', () async {
      final one = await sealAttachment(Uint8List(0), name: 'empty.txt', type: '', now: 1);
      final two = await sealAttachment(Uint8List(0), name: 'empty.txt', now: 1);

      expect(one.entry.id, isNot(two.entry.id));
      expect(one.entry.key, isNot(two.entry.key));
      expect(one.entry.type, isNull);
      expect(one.entry.size, 0);
    });

    test('refuses a file with no name', () async {
      await expectLater(sealAttachment(Uint8List(1), name: '', now: 1), throwsArgumentError);
    });
  });
}
