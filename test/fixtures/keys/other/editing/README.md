# A PGP key that keeps its expiry in a direct-key signature

A test key for changing a PGP key in the vault (openspec:
`add-pgp-key-editing`), made on 2026-11-17 (UTC) by Sequoia `sq` 1.3.1
(sequoia-openpgp 2.3.0, OpenSSL 3.5.9; `versions.txt`), the `sequoia-sq`
package of Alpine Linux 3.24.4 in Docker. It is a test key, made for this
and nothing else, with no passphrase.

**Never regenerate these files.** A fresh run makes a different key.

`direct-key` is what `sq key generate` makes for the RFC 4880 profile: a
version 4 Ed25519 primary key that only certifies, with a direct-key
signature (0x1f) carrying its key flags and its expiry, 2029-12-31
23:59:59 UTC; two user IDs, `<direct@example.org>` and `Fixture Direct`
(marked primary), each certified with the expiry again; and an Ed25519
signing subkey (with its back-signature), an Ed25519 authentication
subkey and a Curve25519 encryption subkey. Every packet has the new header
format, the creation time, key expiry, key flags, primary user ID and
embedded signature subpackets are marked critical, and every self-signature
carries Sequoia's salt notation.

- `direct-key.secret.asc`: as `sq` wrote it (`--output`).
- `direct-key.public.asc`: `gpg --export` of it, after `gpg --import`, with
  GnuPG 2.4.9 in the same container.
- `direct-key.colons.txt`: what
  `gpg --list-keys --with-subkey-fingerprints --with-colons` printed.
- `direct-key.packets.txt`: `gpg --list-packets` of the secret key, then
  `sq inspect`.
- `direct-key.rev`: the revocation certificate `sq` wrote (`--rev-cert`):
  unlike GnuPG's, it is the primary key packet followed by the revocation
  signature (reason 0, unspecified).

## The commands

Run in `alpine:latest` (3.24.4) with `sh`, this folder mounted
at `/out`:

```sh
set -e
apk add --no-cache sequoia-sq gnupg >/dev/null 2>&1
export SEQUOIA_HOME=$(mktemp -d)
cd /out
sq version 2>&1 | head -2 > versions.txt
sq --home "$SEQUOIA_HOME" key generate --own-key --name 'Fixture Direct' --email direct@example.org \
  --expiration 2030-01-01 --without-password --profile rfc4880 --cipher-suite cv25519 \
  --output direct-key.secret.asc --rev-cert direct-key.rev
export GNUPGHOME=$(mktemp -d)
gpg --batch --import direct-key.secret.asc 2>/dev/null
f=$(gpg --list-keys --with-colons | awk -F: '/^fpr/ {print $10; exit}')
gpg --armor --export "$f" > direct-key.public.asc
gpg --list-keys --with-subkey-fingerprints --with-colons "$f" > direct-key.colons.txt
gpg --list-packets direct-key.secret.asc > direct-key.packets.txt 2>&1
sq --home "$SEQUOIA_HOME" inspect direct-key.secret.asc >> direct-key.packets.txt 2>&1
```

## What Sequoia made of Kemlock's changes

`sq-check.txt` is the output of `tool/keys/sq_check.sh` with sq 1.3.1 in
Alpine Linux 3.24.4 on 2026-11-17, over a run of
`tool/keys/write_edited_keys.dart` (a run of its own, so its new subkeys
are not those of `../../gnupg/editing/gnupg-check.txt`): the same changes
to the same four keys. sq imported each with no error, showed the new
dates, subkeys and user ID, linted no problem, and took each bare
revocation certificate Kemlock wrote ("imported revocation certificate"),
after which the key showed as revoked.
