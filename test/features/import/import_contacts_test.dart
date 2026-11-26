@TestOn('vm')
library;

import 'package:kemlock_core/features/import/import_merge.dart';
import 'package:kemlock_core/models/contact.dart';
import 'package:kemlock_core/vault/vault_export.dart';
import 'package:test/test.dart';

import '../contacts/contacts_kit.dart';

ImportPreview _preview(List<Contact> contacts) =>
    ImportPreview.of(VaultExportPayload(accounts: const [], backupServices: const [], contacts: contacts));

void main() {
  group('the contacts an import adds', () {
    test('are the ones whose key the vault lacks, each key once', () {
      final held = [contactOf(grace1, id: 'c1')];

      final added = newContacts(_preview([contactOf(grace1, id: 'x1'), contactOf(alan, id: 'a1', name: 'Alan'), contactOf(alan, id: 'a2')]), held);

      expect(added.map((contact) => contact.id), ['a1']);
    });

    test('are never given an id the vault holds, whatever their key', () {
      final held = [contactOf(grace1, id: 'c1'), const Contact(id: 'k0', name: 'No key', source: ContactSource.manual, addedAt: 1)];

      final added = newContacts(
        _preview([
          contactOf(alan, id: 'c1', name: 'Alan, same id as Grace'),
          const Contact(id: 'k0', name: 'Another keyless, same id', source: ContactSource.manual, addedAt: 2),
          const Contact(id: 'k1', name: 'Keyless', source: ContactSource.manual, addedAt: 2),
          contactOf(signOnly, id: 'k1', name: 'Keyed, same id as the one before'),
        ]),
        held,
      );

      expect(added.map((contact) => contact.id), ['k1']);
      expect(added.single.name, 'Keyless');
    });
  });
}
