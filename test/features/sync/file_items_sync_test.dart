@TestOn('vm')
library;

// File items in a sync document, its merge and its scopes: left out while there are none, read back whole, merged by id,
// and carried with the other kinds.
import 'dart:convert';

import 'package:kemlock_core/crypto/account/encoding.dart' show Owner;
import 'package:kemlock_core/features/export/credential_export_plan.dart';
import 'package:kemlock_core/features/export/export_scope.dart';
import 'package:kemlock_core/features/spaces/space_scope.dart';
import 'package:kemlock_core/features/sync/attachment_sync.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_file.dart';
import 'package:test/test.dart';

const _now = 1_800_000_000_000;

const _lease = VaultFile(
  id: '3f2c9a71-e4b0-4856-8a00-0000000000f1',
  name: 'Lease.pdf',
  file: NoteAttachment(id: 'att-1', name: 'Lease.pdf', size: 10, key: 'AAAA', addedAt: 1, sha256: 'ab'),
  addedAt: 9,
);

const _teamFile = VaultFile(
  id: '3f2c9a71-e4b0-4856-8a00-0000000000f3',
  name: 'Team lease',
  file: NoteAttachment(id: 'att-3', name: 'Team lease', size: 1, key: 'DDDD', addedAt: 1),
  spaceId: 'team',
  addedAt: 9,
);

OtpAccount _account(String id) => OtpAccount(id: id, issuer: 'Issuer $id', label: '', secret: 'SECRET${id.toUpperCase()}', addedAt: 100);

Map<String, Object?> _json(Object? value) => jsonDecode(jsonEncode(value)) as Map<String, Object?>;

void main() {
  group('a sync document', () {
    test('without File items is written as it always was', () {
      final doc = SyncDoc(accounts: [_account('a1')], deleted: [Tombstone(id: 'x', at: 5)]);

      expect(doc.toJson().keys, ['accounts', 'backupServices', 'deleted']);
      expect(SyncDoc.fromJson(_json(doc.toJson())), doc);
    });

    test('writes the `files` list after the others, only when it holds something, and reads it back with its ids', () {
      final doc = SyncDoc(files: const [_lease]);

      expect(doc.toJson().keys, ['accounts', 'backupServices', 'files', 'deleted']);
      final read = SyncDoc.fromJson(_json(doc.toJson()));
      expect(read.files, [_lease]);
      expect(read.extra, isEmpty);
      expect(read.ids, [_lease.id]);
    });
  });

  group('merging', () {
    test('takes File items from both sides, the later copy of one id winning, and records a deletion', () {
      final renamed = _lease.copyWith(name: 'Lease 2026.pdf').stamped(50);
      const other = VaultFile(
        id: '3f2c9a71-e4b0-4856-8a00-0000000000f2',
        name: 'Other',
        file: NoteAttachment(id: 'att-2', name: 'Other', size: 1, key: 'BBBB', addedAt: 1),
        addedAt: 9,
      );

      final merged = mergeScope(Lists(files: [renamed]), [_lease.id], SyncDoc(files: const [_lease, other]), now: _now);

      expect({for (final file in merged.doc.files) file.id: file.name}, {_lease.id: 'Lease 2026.pdf', other.id: 'Other'});
      expect(merged.known..sort(), [_lease.id, other.id]);

      final gone = mergeScope(const Lists(), merged.known, merged.doc, now: _now);
      expect(gone.doc.files, isEmpty);
      expect(gone.doc.deleted.map((tomb) => tomb.id), containsAll([_lease.id, other.id]));
    });

    test('keeps a File item in the scope it is in, and a space takes the File items of its own', () {
      const lists = Lists(files: [_lease, _teamFile]);

      expect(scopeLists(lists, 'team').files, [_teamFile]);
      expect(scopeLists(lists, null).files, [_lease]);
      expect(rescopedTo(Lists(files: [_lease]), 'team').files.single.spaceId, 'team');
      expect(applyScope(const Lists(), null, SyncDoc(files: const [_lease])).files, [_lease]);
    });
  });

  group('the other kinds of file', () {
    test('Kemlock Server sees a File item as an item of kind `file` and reads it back from a document', () {
      final entries = kmEntriesOf(const Lists(files: [_lease]));

      expect(entries.single.kind, KmKind.file);
      expect(KmKind.file, 'file');
      expect(kmKnowsKind('file'), isTrue);
      expect(kmDocOf(entries).files, [_lease]);
      expect(kmReadable('file', _lease.toJson(), _lease.id, Owner.user('00000000-0000-4000-8000-000000000001')), isTrue);
    });

    test('WebDAV lists a File item\'s file with the attachments of the notes', () {
      const note = SecureNote(
        id: 'n1',
        title: 'Photos',
        addedAt: 1,
        attachments: [NoteAttachment(id: 'att-n', name: 'p.jpg', size: 1, key: 'CCCC', addedAt: 1)],
      );

      expect(attachmentsOf(const Lists(notes: [note], files: [_lease])).map((file) => file.id), ['att-n', 'att-1']);
    });

    test('an export scope leaves the File items of spaces out, and counts them', () {
      final scope = exportScope(const Lists(files: [_lease, _teamFile]));

      expect(scope.lists.files.single.spaceId, isNull);
      expect(scope.spaceItems, 1);
      expect(exportScope(const Lists(files: [_lease]), codesOnly: true).lists.files, isEmpty);
    });

    test('a Credential Exchange export does not carry them, and says so', () {
      final plan = CredentialExportPlan.of(const Lists(files: [_lease]));

      expect(plan.notCarried[ExportNotCarried.files], 1);
    });
  });
}
