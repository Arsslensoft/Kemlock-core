@TestOn('vm')
library;

// Keys, notes and passkeys in what Kemlock writes inside Vaultwarden items:
// sealed values and plain fields hold every kind, and give each back as it
// went in, unknown keys included.
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/passkey.dart';
import 'package:kemlock_core/models/secure_note.dart';
import 'package:kemlock_core/models/vault_entry.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

final _key = VaultKey.fromJson({
  'id': '2b7c9e0a-0d4f-4b8e-9a3c-5f1e2d3c4b5a',
  'name': 'laptop',
  'kind': 'ssh',
  'algorithm': 'ed25519',
  'private': 'MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC',
  'public': 'MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=',
  'origin': 'generated',
  'note': 'Work laptop',
  'tags': ['Work'],
  'pinned': true,
  'addedAt': 1794038400000,
  'aFutureKey': {'kept': true},
});

final _note = SecureNote.fromJson({
  'id': '7d1e5c3a-9b2f-4e6d-8c0a-1f2e3d4c5b6a',
  'title': 'Passport',
  'text': 'Number 12AB34567\nIn the drawer',
  'tags': ['Travel'],
  'addedAt': 1794038400000,
  'updatedAt': 1794042000000,
  'attachments': [
    {
      'id': 'q8s3Lw0bVt9Yk2Rr4Xc1Zg',
      'name': 'scan.pdf',
      'size': 1234,
      'type': 'application/pdf',
      'key': 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=',
      'addedAt': 1794038400000,
      'aFutureKey': 1,
    },
  ],
  'aFutureKey': 'kept',
});

final _passkey = Passkey.fromJson({
  'id': '5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d',
  'credentialId': 'qHEeQnjhI7-M3gnvNbaBDA',
  'rpId': 'github.com',
  'rpName': 'GitHub',
  'userHandle': 'dXNlci0xMjM',
  'userName': 'octocat',
  'userDisplayName': 'The Octocat',
  'privateKey': 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg',
  'algorithm': -7,
  'label': 'Work',
  'addedAt': 1794038400000,
  'aFutureKey': [1, 2],
});

final _contact = Contact.fromJson({
  'id': '9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d',
  'name': 'Grace Hopper',
  'public': 'mDMEavvBvhYJKwYBBAHaRw8BAQdA5u9VJy0bk117b67pa3OynrS90v96RwuEYCascWUiiLk=',
  'source': 'qr',
  'checkedAt': 1794038400000,
  'checkedFingerprint': '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495',
  'note': 'Compared on a call',
  'addedAt': 1794038400000,
  'aFutureKey': {'kept': true},
});

const _home = 'wJ2kX9c4Qm1zR7tB';

void main() {
  final entries = <(EntryKind, VaultEntry)>[
    (EntryKind.key, _key),
    (EntryKind.note, _note),
    (EntryKind.passkey, _passkey),
    (EntryKind.contact, _contact),
  ];

  test('every kind has its name in the formats', () {
    for (final kind in EntryKind.values) {
      expect(EntryKind.parse(kind.name), kind);
    }
    expect(EntryKind.parse('hologram'), isNull);
    expect(EntryKind.of(_key), EntryKind.key);
    expect(EntryKind.of(_note), EntryKind.note);
    expect(EntryKind.of(_passkey), EntryKind.passkey);
    expect(EntryKind.of(OtpAccount(id: 'a', issuer: 'X', label: '', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1)), EntryKind.account);
    expect(EntryKind.of(const BackupService(id: 's', serviceName: 'X', codes: [], addedAt: 1)), EntryKind.backupService);
    expect(EntryKind.of(_contact), EntryKind.contact);
    expect([for (final kind in EntryKind.values) kind.isLater], [false, false, true, true, true, true]);
    expect(EntryKind.contact.name, 'contact');
  });

  for (final (kind, entry) in entries) {
    test('${kind.name}: sealed and opened again unchanged', () async {
      final key = randomBytes(32);

      final sealed = await sealEntry(entry, _home, key);

      expect(sealedHeader(sealed), (home: _home, id: entry.id));
      final opened = await openSealedEntry(sealed, key);
      expect(EntryKind.of(opened), kind);
      expect(canonical((opened as VaultEntry).toJson()), canonical(entry.toJson()));
      await expectLater(openSealedEntry(sealed, randomBytes(32)), throwsA(isA<SealedEntryError>()));
    });

    test('${kind.name}: a plain field written and read again unchanged', () {
      final field = PlainField(home: _home, own: true, sum: 'c3Vt', entry: entry, extra: const {'later': true});

      final read = PlainField.tryParse(field.toText())!;

      expect((read.home, read.id, read.own, read.sum, read.kind), (_home, entry.id, true, 'c3Vt', kind));
      expect(canonical((read.entry as VaultEntry).toJson()), canonical(entry.toJson()));
      expect(read.extra, {'later': true});
      expect(read.toText(), field.toText());
      expect(plainHeader(field.toText()), (home: _home, id: entry.id));
    });
  }

  test('a field naming another id than its entry is not one', () {
    final text = PlainField(home: _home, own: true, sum: '', entry: _note).toText().replaceFirst('"id":"${_note.id}"', '"id":"other"');
    expect(PlainField.tryParse(text), isNull);
  });
}
