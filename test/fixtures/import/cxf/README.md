# Credential Exchange fixtures

Nothing in this folder is the output of a real exporter. Every file was
written from the specification. Real hand-offs from Apple Passwords on iOS 26
and from Google, 1Password, Bitwarden and Dashlane on Android are still to be
collected on devices with test accounts, one folder per app
(`cxf/<app>/`, with its own README naming the app, its version, the platform,
the date and what was set up). That is task 7.2 of
`docs/plans/add-credential-exchange.md`.

## fido-example.json

Appendix A, "Example Payload", of the FIDO Alliance's *Credential Exchange
Format 1.0* errata of 9 March 2026
(<https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html>). The
errata correct only this example. The text is the content of the page's
`<pre>` block, with its markup removed and nothing else changed; it ends with
one line feed. The folder is `-text` in `.gitattributes`, so the bytes stay as
they are in every checkout.

It holds one account, "jane_smith", with 14 items and 15 credential types
(one of each): `basic-auth` and `totp` (in the GitHub item), `passkey` (with
every `fido2Extensions` member), `credit-card`, `wifi`, `note`,
`drivers-license`, `address`, `ssh-key` (RSA), `file`, `identity-document`,
`passport`, `person-name`, `api-key` and `generated-password`. It has no
`custom-fields` or `item-reference` credential. It has one collection, "Work
Accounts", which is not nested. The plan's task 2.1 calls it a nested
collection; nesting is covered by cases of `cases.json`.

The example's passkey key is a P-256 key in PKCS#8, and its SSH key an RSA
key, so both are real keys the reader can open. The values are the
specification's, made up for implementers.

## cases.json

Cases written by hand from the specification, each a small payload (or a
directive for a large one) with what the reader must give: the version rule,
unknown fields, unknown field types in optional and required members, an
unknown credential type, shared collections, nested collections, a malformed
payload, two `basic-auth` credentials in one item, and every limit of design
decision 9. `test/features/import/cxf_reader_test.dart` runs every one.

A case with a `generate` name has its large part built by the test (40
credentials, 70 URLs, 12,000 items, a 5,000-character password, a payload of
40 MiB, collections 500 deep): a file of that size doesn't belong in the
repo.

## keys.json

Four private keys in PKCS#8 (base64url, as CXF carries them) with the public
line `ssh-keygen -y` printed for each: Ed25519, ECDSA P-256, ECDSA P-384 and
the RSA key of `fido-example.json`. The first three are throwaway keys made
for these tests with `openssl genpkey`, so they are not the specification's
and not a real exporter's. The SSH key tests check the public half Kemlock
derives against the recorded line, and the passkey tests use the same keys
to check that only P-256 is kept.
