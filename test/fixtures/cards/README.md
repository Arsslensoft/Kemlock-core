# Cards and identities

Fixtures for the `add-cards-identities-and-websites` plan, written once by
`test/vault/cards_fixtures_generator_test.dart` from the inputs in
`test/vault/cards_fixture_inputs.dart`, and never regenerated: exports, sync
files and vaults on people's phones and drives will be in these forms, and
every later version must open them. `test/vault/cards_fixtures_test.dart`
opens each one.

The sealed and encrypted files can't be written by hand, so the plan's
coding session wrote the generator and the tests, not the files. The files
are generated once, in the single build-and-test pass after the plan merged:

```text
cd mobile
OUT=test/fixtures/cards flutter test test/vault/cards_fixtures_generator_test.dart
```

Until then a file is missing and its tests skip. Once they are written and
committed, this paragraph goes and the files are frozen.

The cards: one with every field and a key of a later version (`later`), one
with a name and a cardholder, and one in the shared space `fam`. The
identities: one with every field, two documents (the second a type of a
later version, `residencePermit`) and keys of a later version in it, in its
address and in a document, one with a name and an email, and one in `fam`.

- `vault-with-cards.json`: the storage of a vault, built by hand from fixed
  seeds in the formats the store reads, with the real scrypt parameters:
  `backmycodes_card_data` and `backmycodes_identity_data`. Its password is
  `fixture password`.
- `sync-with-cards.json` (task 3.3): two sync files, each with its 32-byte
  key. `own` is the vault's own file, `space` space `fam`'s.
- `export-with-cards.json` and `export-with-cards-plain.json` (task 3.5): an
  encrypted version 2 export, password `fixture password`, and the same as a
  plain export.
