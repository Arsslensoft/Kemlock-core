# Logins

Written once by `test/vault/logins_fixtures_generator_test.dart` when logins
joined the vault, its exports and sync (openspec: add-passwords, task 7.7),
from the inputs in `test/vault/logins_fixture_inputs.dart`, and never
regenerated: exports, sync files and vaults on people's phones and drives are
in these forms, and every later version must open them.
`test/vault/logins_fixtures_test.dart` opens each one.

The logins: one with every field (two websites, a note, tags, pinned, linked
to the account, two previous passwords, saved by AutoFill, told not to warn
for its code, and a key of a later version, `later`, that must pass
through), one saved in an app with no website, and one in the shared space
`fam` whose first website is an exact host (`=10.0.0.20`).

- `export-with-logins.json`: an encrypted version 2 export, password
  `fixture password`, with the real scrypt parameters, holding the account
  and the three logins.
- `export-with-logins-plain.json`: the same as a plain export.
- `sync-with-logins.json`: two sync files, each with its 32-byte key,
  written by `encryptSyncFile` with fixed nonces. `own` is the vault's own
  file: the account, the first two logins and a deleted login's tombstone.
  `space` is space `fam`'s file: its login.
- `vault-with-logins.json`: the storage of a vault, built by hand from fixed
  seeds in the formats the store reads, with the real scrypt parameters:
  `backmycodes_login_data` holding the three logins, and
  `backmycodes_generated_data` a password AutoFill generated that no save
  followed. Its password is `fixture password`.
