@TestOn('vm')
library;

import 'package:kemlock_core/features/export/credential_export_plan.dart';
import 'package:kemlock_core/features/export/export_scope.dart';
import 'package:kemlock_core/features/import/formats/cxf_writer.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart' show Lists;
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

OtpAccount _code(String id, {String? spaceId, OtpType type = OtpType.totp}) =>
    OtpAccount(id: id, type: type, issuer: 'Issuer $id', label: 'me', secret: 'JBSWY3DPEHPK3PXP', spaceId: spaceId, addedAt: 1);

Login _login(String id, {String? spaceId}) => Login(id: id, name: 'Login $id', username: 'me', password: 'pw', spaceId: spaceId, addedAt: 1);

SecureNote _note(String id, {String? spaceId}) => SecureNote(id: id, title: 'Note $id', spaceId: spaceId, addedAt: 1);

BackupService _service(String id, {String? spaceId}) => BackupService(id: id, serviceName: 'Service $id', codes: const [], spaceId: spaceId, addedAt: 1);

void main() {
  final vault = Lists(
    accounts: [_code('a'), _code('b', spaceId: 'family'), _code('s', type: OtpType.steam)],
    backupServices: [_service('x'), _service('y', spaceId: 'family')],
    notes: [_note('n'), _note('m', spaceId: 'family')],
    logins: [_login('l'), _login('k', spaceId: 'family'), _login('j', spaceId: '')],
  );

  group('exportScope', () {
    test('leaves out every item of a shared space, and counts them', () {
      final scope = exportScope(vault);

      expect(scope.lists.accounts.map((a) => a.id), ['a', 's']);
      expect(scope.lists.backupServices.map((s) => s.id), ['x']);
      expect(scope.lists.notes.map((n) => n.id), ['n']);
      // An empty space id is no space
      expect(scope.lists.logins.map((l) => l.id), ['l', 'j']);
      expect(scope.spaceItems, 4);
    });

    test('for the QR codes keeps only codes and backup services, and counts nothing else', () {
      final scope = exportScope(vault, codesOnly: true);

      expect(scope.lists.accounts, hasLength(2));
      expect(scope.lists.backupServices, hasLength(1));
      expect(scope.lists.notes, isEmpty);
      expect(scope.lists.logins, isEmpty);
      // The notes and logins of the space were not asked for, so they are not counted as left out
      expect(scope.spaceItems, 2);
    });
  });

  group('CredentialExportPlan', () {
    test('counts what may leave by kind, and what no type carries', () {
      final plan = CredentialExportPlan.of(vault);

      expect(plan.counts[ExportKind.logins], 2);
      expect(plan.counts[ExportKind.codes], 2);
      expect(plan.counts[ExportKind.notes], 1);
      expect(plan.spaceItems, 4);
      expect(plan.notCarried[ExportNotCarried.backupServices], 1);
    });

    test('says what the writer would leave out of the kinds picked, and how many go', () {
      final plan = CredentialExportPlan.of(vault);

      expect(plan.sendable(ExportKind.codes), 1);
      expect(plan.sending({ExportKind.logins, ExportKind.codes}), 3);
      expect(plan.leftOut({ExportKind.codes}), {CxfLeftOutReason.notTotp: 1});
      expect(plan.leftOut({ExportKind.logins}), isEmpty);
    });

    test('cuts the items to the kinds picked', () {
      final picked = CredentialExportPlan.of(vault).pick({ExportKind.notes});

      expect(picked.notes, hasLength(1));
      expect(picked.logins, isEmpty);
      expect(picked.codes, isEmpty);
    });
  });
}
