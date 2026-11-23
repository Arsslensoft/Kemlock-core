# GnuPG's post-quantum keys

Keys and messages made by GnuPG 2.5.24 (libgcrypt 1.12.4,
`versions.txt`), which reads and makes LibrePGP's Kyber keys (algorithm 8
in a version 5 subkey under a version 4 primary key). No package had
2.5.24, so it was built from its release tarball in Docker:
`tool/keys/docker/gnupg-2.5.24.Dockerfile`, on the public image
`alpine:edge@sha256:020dfcbaaf4cc1078bf2d9c7ba31a8466e334061dcd2f248001d68f79e52c000`,
the tarball checked against SHA-256
`bf149d01a2b9fcc0e4589b8ae8697d3d5c557ea48ed95a3fa55dd3b1187e6039`.

`tool/keys/make_pqc_fixtures.sh` made every file in one run on 2026-11-17
and is the exact record of the commands:

    docker build -t kemlock-gnupg:2.5.24 -f tool/keys/docker/gnupg-2.5.24.Dockerfile tool/keys/docker
    docker run --rm -v "$PWD/test/fixtures/keys:/fixtures" -v "$PWD/tool/keys:/tool:ro" \
      kemlock-gnupg:2.5.24 sh /tool/make_pqc_fixtures.sh /fixtures/gnupg/pqc

**Never regenerate these files.** Add new ones beside them.

## Keys

| Name | Primary key | Subkey |
|---|---|---|
| `ky768-cv25519` | ed25519 | ky768_cv25519 (Kyber-768 with X25519) |
| `pqc` | brainpoolP384r1 (ECDSA) | ky768_bp256 (Kyber-768 with brainpoolP256r1) |
| `ky1024-bp384` | ed25519 | ky1024_bp384 (Kyber-1024 with brainpoolP384r1) |

`pqc` is what `gpg --quick-generate-key <uid> pqc` makes: still the
brainpool pairing of design decision 5. Each name has a twin
`<name>-protected` under the passphrase `fixture passphrase`. They are
different keys, not the same key twice: GnuPG 2.5.24 cannot change the
passphrase of a Kyber key (`gpg --change-passphrase` fails with "Invalid
S-expression"), so a protected key had to be made with its passphrase.

For each key:

- `<name>.public.asc` and `<name>.secret.asc`: `gpg --armor --export` and
  `--export-secret-keys`;
- `<name>.colons.txt`: `gpg --list-keys --with-subkey-fingerprints
  --with-colons`; `<name>.list.txt` the same listing as people read it;
- `<name>.public.packets.txt` and `<name>.secret.packets.txt`:
  `gpg --list-packets` of the two exports;
- `<name>.message.gpg`: `message.txt` encrypted to the key.

What GnuPG wrote:

- The Kyber secret is exported in GnuPG's own form, S2K usage 255 with
  the GNU extension's mode 1003 (`gnu-mode1003`): the secret part is the
  gpg-agent's S-expression, `(composite-key (private-key (ecc ...))
  (private-key (kyber768 (p ...) (s ...) (seed ...))))`.
- Under a passphrase only the ECC half is protected, as
  `(protected-private-key (ecc ... (protected openpgp-s2k3-ocb-aes ...)))`:
  the ML-KEM half stays a plain `private-key`, in the clear.
- The primary keys are exported as RFC 9580 says: S2K usage 254, AES-128
  in CFB under Iterated and Salted S2K with SHA-1, when protected.

## Messages

`message.txt` is two lines of ASCII ending in LF.

- `<name>.message.gpg`: `gpg --encrypt --recipient <key>`. GnuPG's
  default for a Kyber key is a version 3 PKESK of algorithm 8 and its OCB
  packet (tag 20), AES-256 with OCB, holding ZLIB-compressed literal data.
- `ky768-cv25519.force-ocb.gpg`: the same with `--force-ocb`, which
  changes nothing here.
- `ky768-cv25519.seipd1.gpg`: to the Kyber key and to Kemlock's Ed25519
  key `../../kemlock/pgp-ed25519.public.asc` together. That key does not
  advertise AEAD, so GnuPG writes SEIPD version 1 (tag 18) beside the
  Kyber session key.

`packets.txt` is `gpg --list-packets` of each file, and
`session-keys.txt` what `gpg --show-session-key` printed for each,
`<cipher>[.<AEAD mode>]:<session key in hex>`.

## Kemlock's keys in GnuPG

`kemlock-check.txt` is what `tool/keys/gnupg_check.sh` printed on
2026-11-17, run in the same image over keys `tool/keys/write_pgp_keys.dart`
had just made: GnuPG 2.5.24 imported Kemlock's Ed25519, RSA 4096 and
GnuPG-format post-quantum keys, public and protected secret, found every
signature good, listed the `ky768_cv25519` subkey as `[E]`, encrypted to it
with a version 3 PKESK of algorithm 8 (and SEIPD version 1, the key
advertising no AEAD), decrypted with the passphrase, and signed and
verified, with no warning. Of the standard key (version 6,
ML-DSA-65+Ed25519) it said, with and without `--allow-9980`, "can't check
signature with unsupported public-key algorithm (30)" and imported no user
ID: GnuPG 2.5.24 does not read it.

## A key with two encryption subkeys

`two-subkeys.*` is an Ed25519 key with a `ky768_cv25519` subkey and, made
two seconds later, a `cv25519` subkey, both unprotected, for the rule that
a post-quantum subkey is encrypted to before a newer classical one. It was
made on 2026-11-17 in the same image by hand, with
`gpg --quick-generate-key 'Fixture Two Subkeys <two@example.org>' ed25519
cert,sign 0`, then `gpg --quick-add-key <fpr> ky768_cv25519 encr 0`,
`sleep 2` and `gpg --quick-add-key <fpr> cv25519 encr 0`, exported and
listed as the others.

`kemlock-messages-check.txt` is the same check run again on 2026-11-17
over fresh keys and the messages `tool/keys/write_pq_messages.dart` wrote
with them: GnuPG decrypted, with the GnuPG-format key, a message Kemlock
encrypted to it and signed (a good signature) and a message to the
standard, the GnuPG-format and an RSA key at once (version 3 PKESKs of
algorithms 35, 8 and 1, then SEIPD version 1), which it decrypted with
the RSA key too; it verified a detached signature by the GnuPG-format
key. Its only warning, "Using untrusted key", is about trust in a fresh
keyring, not about what Kemlock wrote.

`kemlock-edit-check.txt` is `tool/keys/pq_edit_check.sh`, run on
2026-11-17 in the same image over the Ed25519 key to which Kemlock's key
editing had just added a Kyber-768 with X25519 subkey, protected with the
key's own passphrase (`tool/keys/write_pq_edited_keys.dart`,
add-post-quantum-pgp task 9.2): GnuPG imported it with no error, its
signatures good, listed the version 5 subkey with its fingerprint,
encrypted to it (a version 3 PKESK of algorithm 8) and decrypted with the
passphrase.
