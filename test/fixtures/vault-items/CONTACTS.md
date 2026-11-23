# Files holding other people's keys

Written once when contacts, other people's OpenPGP public keys, joined
exports and sync (openspec: `add-pgp-contacts`), by
`test/vault/contacts_fixtures_generator_test.dart` from the inputs in
`test/vault/contacts_fixture_inputs.dart`, and never regenerated: files on
people's phones and drives are in these forms, and every later version
must open them.

- `export-plain-before-contacts.json`: a plain export of a vault with one
  account, one backup-code list, one key, one note and one passkey, and no
  contact, written by the code from before `vault_export.dart` knew
  contacts. A vault without contacts must still export exactly this.
- `export-with-contacts.json`: a plain export of the same vault holding two
  contacts as well: Grace Hopper's key (`keys/contacts/grace-1`), checked
  on 3 November 2026 with a note, and Alan Turing's (`keys/contacts/alan`),
  never checked.
- `sync-with-contacts.json`: the decrypted sync file of that vault's own
  scope: the same entries, and the deletion of a contact among the
  tombstones.
