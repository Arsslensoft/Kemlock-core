# Exports holding keys, notes and passkeys

Written once by `exportVault`, `exportVaultPlaintext` and
`writeExportArchive` when keys, notes and passkeys were added to exports,
and never regenerated: exports on people's phones and drives are in these
forms, and every later version must open them. `vault_items_fixtures_test.dart`
opens each one.

- `export-encrypted.json`: an encrypted version 2 export, password
  `fixture password`, with the real scrypt parameters. Its payload holds one
  account, one backup-code list, one SSH key (Ed25519, made by OpenSSL 3.6),
  one note with two attached files, and one passkey (P-256, made by
  OpenSSL 3.6).
- `export-plain.json`: the same items as a plain export.
- `export-archive.zip`: `export-encrypted.json` as `export.json`, and the
  note's two files as KMA1 files at `files/<attachment id>`: a 31-byte PDF
  and a two-chunk file whose byte `i` is `(i * 7 + 3) & 0xff`.
- `sync-every-kind.json`: two sync files, each with its 32-byte key, written
  by `encryptSyncFile` with fixed nonces when keys, notes and passkeys joined
  sync. `own` is a vault's own file: the items of `export-plain.json` (the
  key edited once since) and a deletion of an account, a key, a note and a
  passkey. `space` is space `fam`'s file: a key and a note with one attached
  file, a note's deletion, and no passkeys. `sync_every_kind_test.dart`
  opens both, and checks this version and the merge from before these items
  (`test/compat/before_vault_items`) keep every entry and deletion in them.
- `card-key-vault.json`: the storage of a vault holding one PGP key whose
  private half is on an OpenPGP card (openspec: add-openpgp-card), written
  once by `test/vault/card_key_fixture_generator_test.dart` from fixed
  seeds, with the real scrypt parameters. The key is the GnuPG Ed25519 key
  of `test/fixtures/keys/gnupg`, its private half the hand-made stub of
  `keys/gnupg/card`, with its `card` object. `card_key_vault_fixture_test.dart`
  opens it with the password and replaces its key.
- `export-with-key-accounts.json`: an encrypted version 2 export, password
  `fixture password`, with the real scrypt parameters, written by
  `key_accounts_fixtures_generator_test.dart` when accounts kept on a
  security key joined exports (add-security-key-codes). It holds one
  account and a `keyAccounts` list of three: a tagged one with a note, a
  60-second SHA-256 one that needs a touch, and a counter-based one. No
  secret of theirs is in it. `export-with-key-accounts-plain.json` is the
  same as a plain export. `vault_items_fixtures_test.dart` opens both.
