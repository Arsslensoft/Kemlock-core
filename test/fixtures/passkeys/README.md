# Passkey fixtures

`passkeys.json` holds fixed inputs and the exact bytes a passkey provider
builds from them, written once by `lib/features/passkeys` and never
regenerated. The Dart tests (`test/features/passkeys/passkey_fixture_test.dart`),
the iOS `RunnerTests` and the Android JVM tests read it, and each must build
the same bytes.

Inputs: three P-256 keys made by OpenSSL 3.6 (`openssl genpkey -algorithm EC
-pkeyopt ec_paramgen_curve:P-256`, then `openssl pkcs8 -topk8 -nocrypt`): the
credential's, the vault's inbox key, and the ephemeral key of the inbox file.
The relying party is `webauthn.io` and the credential id the 16 bytes 0 to 15.

- `registration`: the COSE key of the credential's public point, the
  authenticator data (flags 0x5D: UP, UV, BE, BS, AT; counter 0; Kemlock's
  AAGUID), and the attestation object (`fmt` `none`).
- `assertion`: the client data, its SHA-256, the authenticator data (flags
  0x1D, counter 0), the bytes signed, and an ES256 signature of them made
  deterministically (RFC 6979). Platforms sign with fresh randomness, so
  their tests check that their own signature and this one verify with the
  credential's public key, not that they are equal.
- `inbox`: the inbox key, the ephemeral key, the nonce, the ECDH shared
  secret, the HKDF-SHA-256 key (salt: ephemeral point then inbox point;
  info: `kemlock-passkey-inbox-v1`), the record, and the sealed file.

When they were written, these were checked against other implementations:
`openssl dgst -sha256 -verify` accepted the signature; `openssl pkeyutl
-derive` gave the same shared secret and `openssl kdf … HKDF` the same file
key; Node 25's AES-256-GCM opened the inbox file to the record; and a CBOR
reader written separately in Python read the attestation object, the
authenticator data and the COSE key as described above.

## Logins in the inbox

`logins.json` holds login inbox files (openspec: add-passwords, design
decision 9), written once by `test/features/logins/login_inbox_test.dart`
with `WRITE_LOGIN_INBOX_FIXTURE=1` and never regenerated. Each case seals a
record (a login saved on a website with a generated password, a login saved
in an Android app, a generated password no save followed) to the inbox key
of `passkeys.json`, with that fixture's ephemeral key and the case's nonce.
The file's outer JSON is `v`, `kind` (`login`), `epk`, `nonce`, `ct`, in that
order; its key is HKDF-SHA-256 as above but with the info
`kemlock-login-inbox-v1`, and the record is written in the order the case
shows it. Dart, Kotlin and Swift must each seal every record to its file,
byte for byte, and open it.
