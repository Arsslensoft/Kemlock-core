@TestOn('vm')
library;

// What a move writes (move-off-vaultwarden-sync, task 2.2): every own entry of every kind, in batches of
// at most 500 in kind order, each under its item UUID with the hash of its canonical JSON.
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:kemlock_core/features/sync/kemlock/km_kinds.dart';
import 'package:kemlock_core/features/sync/kemlock/km_move_plan.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/identity.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/login.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:test/test.dart';

final _owner = Owner.user('11111111-1111-1111-1111-111111111111');

String _uuid(int n) => '3f2c9a71-e4b0-4856-8a00-${n.toRadixString(16).padLeft(12, '0')}';

OtpAccount _account(String id) => OtpAccount(id: id, issuer: id, label: '', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1);

void main() {
  test('1,201 entries give three batches of 500, 500 and 201', () {
    final lists = Lists(accounts: [for (var i = 0; i < 1201; i++) _account(_uuid(i))]);

    final plan = planKmMove(lists, _owner);

    expect([for (final batch in plan.batches) batch.length], [500, 500, 201]);
    expect(plan.count, 1201);
  });

  test('a login comes after its linked account, and the kinds go in the order the move sends them', () {
    final lists = Lists(
      logins: [Login(id: _uuid(9), name: 'Site', addedAt: 1, accountId: _uuid(1))],
      accounts: [_account(_uuid(1))],
      identities: [Identity(id: _uuid(8), name: 'Me', addedAt: 1)],
      cards: [PaymentCard(id: _uuid(7), name: 'Visa', addedAt: 1)],
      notes: [SecureNote(id: _uuid(5), title: 'Note', addedAt: 1)],
      keyAccounts: [KeyAccount(id: _uuid(4), device: 'yk', name: 'GitHub', label: 'me', addedAt: 1)],
      backupServices: [
        BackupService(
          id: _uuid(2),
          serviceName: 'GitHub',
          codes: const [BackupCode(code: 'abcd-1234')],
          addedAt: 1,
        ),
      ],
    );

    final kinds = [for (final item in planKmMove(lists, _owner).items) item.kind];

    expect(kinds, [KmKind.otp, KmKind.backupCodes, KmKind.keyOtp, KmKind.note, KmKind.card, KmKind.identity, KmKind.login]);
  });

  test('logins, accounts on a key, cards and identities are in the plan, and so are entries of every other list', () {
    final lists = Lists(
      logins: [Login(id: _uuid(1), name: 'Site', addedAt: 1)],
      keyAccounts: [KeyAccount(id: _uuid(2), device: 'yk', name: 'GitHub', label: 'me', addedAt: 1)],
      cards: [PaymentCard(id: _uuid(3), name: 'Visa', addedAt: 1)],
      identities: [Identity(id: _uuid(4), name: 'Me', addedAt: 1)],
      // One held back by a plain home, and one too long for an item's notes
      notes: [
        SecureNote(id: _uuid(5), title: 'Held back', addedAt: 1),
        SecureNote(id: _uuid(6), title: 'Long', text: 'x' * 20000, addedAt: 1),
      ],
    );

    final plan = planKmMove(lists, _owner);

    expect(plan.items.map((item) => item.entryId), unorderedEquals([for (var i = 1; i <= 6; i++) _uuid(i)]));
    expect(plan.byKind, {KmKind.keyOtp: 1, KmKind.note: 2, KmKind.card: 1, KmKind.identity: 1, KmKind.login: 1});
  });

  test('a UUID id stays the item id, and acc-1 gets the legacy-id UUID under the owner, its entry keeping its id', () {
    final plan = planKmMove(Lists(accounts: [_account(_uuid(1)), _account('acc-1'), _account('item-1')]), _owner);

    final byEntry = {for (final item in plan.items) item.entryId: item};
    expect(byEntry[_uuid(1)]!.itemId, _uuid(1));
    expect(byEntry['acc-1']!.itemId, itemUuid('acc-1', _owner));
    expect(byEntry['acc-1']!.itemId, isNot('acc-1'));
    expect(byEntry['acc-1']!.json['id'], 'acc-1');
    // The server's legacy-id vector for item-1 under a user owner of 0x11 bytes
    expect(byEntry['item-1']!.itemId, '23280d17-0c54-8f3a-8b1b-48ce55eb6f85');
  });

  test('each item carries the hash of its canonical JSON, whatever the order of its keys', () {
    final plan = planKmMove(Lists(accounts: [_account(_uuid(1))]), _owner);
    final item = plan.items.single;

    expect(item.hash, kmEntryHash(item.json));
    expect(kmEntryHash({'b': 1, 'a': 2}), kmEntryHash({'a': 2, 'b': 1}));
    expect(kmEntryHash({'a': 1}), isNot(kmEntryHash({'a': 2})));
  });

  test('names the files its notes hold, under the note’s item', () {
    final note = SecureNote(
      id: 'n-1',
      title: 'Scan',
      addedAt: 1,
      attachments: const [NoteAttachment(id: 'f1', name: 'a.pdf', size: 3, key: 'a2V5', addedAt: 1)],
    );

    final plan = planKmMove(Lists(notes: [note]), _owner);

    expect(plan.files.single.noteId, 'n-1');
    expect(plan.files.single.itemId, itemUuid('n-1', _owner));
    expect(plan.files.single.file.id, 'f1');
  });
}
