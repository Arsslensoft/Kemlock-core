# PGP message fixtures

Messages and signatures made by the programs people use, for the message
code in `lib/crypto/keys/openpgp` and the tests in `test/crypto/pgp`. The
keys are the test keys of `../keys/gnupg` and `../keys/kemlock`, imported
and never regenerated.

**Never regenerate these files.** Session keys, salts and signing times are
random or of the day. Add new files beside them instead.

## `rfc9580/`

The sample messages of RFC 9580, appendices A.6 to A.11. See
`rfc9580/NOTES.md`.

## `gnupg/`: GnuPG 2.4.9 (libgcrypt 1.12.2), the `gpg` of Git for Windows

`tool/pgp/make_fixtures.sh` made every file in one run on 2026-11-16 (the
17th in UTC, which is the date in the signatures) and is the exact record
of the commands. The passphrase of the protected keys and of every
passphrase-encrypted message is `fixture passphrase`.

The plain inputs:

- `gnupg/message.txt`: seven lines of text, with a line starting with a
  dash, one starting with `From `, trailing spaces, a trailing tab, an
  empty line and text outside ASCII. Its lines end with LF.
- `gnupg/report.txt`: 216 000 bytes that compress well.
- The 5 MB input of `gnupg/large.gpg` is not kept: it is 5 242 880 bytes of a
  xorshift32 stream that `tool/pgp/sample_file.dart` writes and
  `sampleBytes` in `test/crypto/pgp/fixtures.dart` makes again.
  `gnupg/chunks.ocb.gpg` holds its first 1 048 576 bytes.

The records the tests read:

- `gnupg/session-keys.txt`: for each encrypted file, what
  `gpg --show-session-key` printed, `<cipher id>:<session key in hex>`
  (`9.2` is AES-256 with OCB).
- `gnupg/signatures.txt`: for each signature, GnuPG's `VALIDSIG` status
  line: the signing key's fingerprint, the date, the time in seconds, the
  expiry time, the version, the public-key and hash algorithms, the
  signature class, and the primary key's fingerprint. `ERRSIG` for
  `gnupg/message.txt.nistp256.sig` would mean GnuPG could not check it; it could.
- `gnupg/packets.txt`: the packets `gpg --list-packets` found in each.
- `gnupg/versions.txt`: `gpg --version`.

What this build chose with no option: `gnupg/default-to-ed25519.gpg`, to a
key that prefers OCB, is PKESK 3 and SEIPD version 1 (tag 18) with AES-256
and ZLIB, not the OCB packet upstream GnuPG documents for such a key; and
`gnupg/sym-default.gpg` is SKESK 4 (AES-256, Iterated and Salted S2K over
SHA-512, count octet 229), SEIPD 1 and ZIP. Every other file forces its
form.

### New keys, made by the same run

- `gnupg/signing-subkey.secret.asc`, `gnupg/signing-subkey.public.asc`,
  `gnupg/signing-subkey.colons.txt`: an Ed25519 primary key that only
  certifies (`F6BF7047…08DA2D2D` in this run; see the colons file), with an
  Ed25519 signing subkey, whose binding signature carries the 0x19
  back-signature in its unhashed part, and a Curve25519 encryption subkey.
- `gnupg/rsa1024.secret.asc`, `gnupg/rsa1024.public.asc`,
  `gnupg/rsa1024.colons.txt`: RSA 1024 for both keys.
- `gnupg/nistp256.secret.asc`, `gnupg/nistp256.public.asc`,
  `gnupg/nistp256.colons.txt`: ECDSA and ECDH on NIST P-256.
- `gnupg/ed25519.stub.secret.gpg`: `--export-secret-subkeys` of the
  Ed25519 fixture key: its primary key's secret is a GnuPG stub (S2K 101),
  its subkey's secret is there.

### Encrypted to keys (`--encrypt gnupg/message.txt`)

`--rfc4880` forces SEIPD version 1 (tag 18); `--force-ocb` forces GnuPG's
OCB packet (tag 20, chunk size octet 16, 4 MiB).

- `gnupg/to-ed25519.seipd.gpg`, `gnupg/to-ed25519.ocb.gpg`: to the Ed25519
  fixture key (ECDH on Curve25519, PKESK 3).
- `gnupg/to-rsa3072.seipd.gpg`, `gnupg/to-rsa3072.ocb.gpg`: to the RSA 3072
  key.
- `gnupg/to-two.gpg`: to both.
- `gnupg/hidden.gpg`: `--throw-keyids`, to the Ed25519 key; the key ID in
  its PKESK is zero.
- `gnupg/to-kemlock-ed25519.gpg`, `gnupg/to-kemlock-rsa4096.gpg`: to the
  keys Kemlock generated, with no option: both are SEIPD 1, as those keys
  advertise.
- `gnupg/to-protected-ed25519.gpg`, `gnupg/to-protected-rsa3072.gpg`: to
  the two keys that keep a passphrase.
- `gnupg/to-signing-subkey.gpg`, `gnupg/to-rsa1024.gpg`,
  `gnupg/to-nistp256.gpg`: to the new keys.
- `gnupg/aes128.gpg`, `gnupg/aes192.gpg`: `--cipher-algo AES` and `AES192`.
- `gnupg/armored.asc`: `--armor`. `gnupg/armored-headers.asc`: with
  `--emit-version --comment 'a comment header'`.
- `gnupg/cast5.gpg`: `--cipher-algo CAST5 --allow-old-cipher-algos`, SEIPD
  1 with CAST5, which Kemlock refuses by name.

### Compressed, large, signed

- `gnupg/zip.gpg`, `gnupg/zlib.gpg`, `gnupg/bzip2.gpg`,
  `gnupg/uncompressed.gpg`: `gnupg/report.txt` with `--compress-algo` `zip`,
  `zlib`, `bzip2` and `none`.
- `gnupg/signed-bzip2.ocb.gpg`: `gnupg/report.txt`, `--sign --encrypt` by the RSA
  3072 key to the Ed25519 key, BZip2, in the OCB packet.
- `gnupg/large.gpg`: the 5 MB input from a pipe, uncompressed, SEIPD 1: the
  encrypted data and the literal data inside are both in partial body
  lengths. The literal data has no file name.
- `gnupg/chunks.ocb.gpg`: the first 1 MB of it from a pipe, in the OCB
  packet with `--chunk-size 16`: sixteen chunks of 64 KiB.
- `gnupg/signed-encrypted.gpg`: signed by and encrypted to the Ed25519 key.
  `gnupg/signed-encrypted-rsa.gpg`: the same with the RSA 3072 key.
- `gnupg/two-signers-encrypted.gpg`: signed by both, to the Ed25519 key.
- `gnupg/two-signers.gpg`: `--sign` by both, not encrypted.
- `gnupg/inline-signed.gpg`, `gnupg/inline-signed.asc`: `--sign` by the
  Ed25519 key, binary and armored.

### With a passphrase (`--symmetric gnupg/message.txt`)

- `gnupg/sym-default.gpg`: no option.
- `gnupg/sym-ocb.gpg`: `--force-ocb`: SKESK version 5 and the OCB packet.
- `gnupg/sym-s2k0.gpg`, `gnupg/sym-s2k1.gpg`: `--s2k-mode 0` (Simple) and
  `1` (Salted), over SHA-1, AES-256.
- `gnupg/sym-s2k3-SHA1.gpg`, `gnupg/sym-s2k3-SHA224.gpg`,
  `gnupg/sym-s2k3-SHA256.gpg`, `gnupg/sym-s2k3-SHA384.gpg`,
  `gnupg/sym-s2k3-SHA512.gpg`: Iterated and Salted with
  `--s2k-digest-algo`, AES-256. In each of these the S2K key is the
  session key, so `gnupg/session-keys.txt` holds what the S2K must derive.
- `gnupg/sym-aes128.gpg`: AES-128.
- `gnupg/sym-and-key.gpg`: `--symmetric --encrypt` to the Ed25519 key: a
  PKESK and an SKESK that holds the encrypted session key.
- `gnupg/sym-cast5.gpg`: CAST5, refused by name.
- `gnupg/no-mdc.gpg`: the old form with no integrity protection (tag 9).
  GnuPG 2.4 does not write it, so it is hand-built: the SKESK of
  `gnupg/sym-aes128.gpg` and a tag 9 packet of 40 random bytes. It decrypts to
  nothing; a reader must refuse it at the tag.

### Signatures

- `gnupg/clearsigned.asc`, `gnupg/clearsigned-rsa.asc`: `--clearsign` of
  `gnupg/message.txt` by the Ed25519 and the RSA 3072 key (`Hash: SHA512`).
- `gnupg/message.txt.ed25519.sig`, `gnupg/message.txt.rsa3072.sig`,
  `gnupg/message.txt.ed25519-protected.sig`,
  `gnupg/message.txt.rsa3072-protected.sig`: `--detach-sign` by each key;
  and `gnupg/message.txt.ed25519.asc`, `gnupg/message.txt.rsa3072.asc`,
  `gnupg/message.txt.ed25519-protected.asc`,
  `gnupg/message.txt.rsa3072-protected.asc` with `--armor`.
- `gnupg/report.txt.sig`: `gnupg/report.txt` by the Ed25519 key.
- `gnupg/message.txt.text.sig`: `--textmode`, signature type 0x01.
- `gnupg/message.txt.signing-subkey.sig`: by the signing subkey, with
  `--default-sig-expire 10y`: a critical signature expiration subpacket.
- `gnupg/message.txt.rsa1024.sig`, `gnupg/message.txt.nistp256.sig`: by
  the new keys.
- `gnupg/message.txt.sha1.sig`: `--digest-algo SHA1
  --allow-weak-digest-algos`, by the RSA 3072 key.

## `kemlock/`: written by Kemlock

`tool/pgp/write_samples.dart` wrote these on 2026-11-16 from the samples in
`test/crypto/pgp/samples.dart`: `gnupg/message.txt` and `gnupg/report.txt`,
with fixed randomness (SHA-256 of a label, in counter mode) and the fixed
time 2026-11-20T09:30:00Z. `test/crypto/pgp/encrypt_test.dart` checks that
the writers still give these bytes, so a change in what Kemlock writes
shows as a failing test. `kemlock/manifest.txt` lists each file, what it
is, the plain file it was made from and the fingerprints of its signers.

- `kemlock/to-ed25519.asc`: `gnupg/message.txt` as a typed message (armored,
  literal data of format `u`, definite lengths) to the Ed25519 fixture key.
- `kemlock/to-rsa3072.signed.asc`: to the RSA 3072 key, signed by it.
- `kemlock/to-two.signed.asc`: to both, signed by the Ed25519 key.
- `kemlock/to-kemlock.signed.asc`: to the two keys Kemlock generated,
  signed by the RSA 4096 one.
- `kemlock/report.txt.gpg`: `gnupg/report.txt` as a file (binary, format `b`,
  partial lengths of 64 KiB) to both GnuPG keys, signed by the Ed25519 key
  Kemlock generated. `kemlock/report.txt.unsigned.gpg`: to the RSA key,
  unsigned.
- `kemlock/passphrase.asc`: `gnupg/message.txt` with the passphrase
  `fixture passphrase`. `kemlock/passphrase.signed.gpg`: `gnupg/report.txt` with
  it, signed by the Ed25519 key.
- `kemlock/clearsigned.asc`, `kemlock/clearsigned-rsa.asc`: `gnupg/message.txt`
  clear-signed by the Ed25519 and the RSA 3072 key. Their text part is
  byte for byte what GnuPG wrote in `gnupg/clearsigned.asc`.
- `kemlock/report.txt.ed25519.sig`, `kemlock/report.txt.rsa3072.sig`,
  `kemlock/message.txt.kemlock-ed25519.sig`: detached signatures, binary.
  `kemlock/report.txt.kemlock-rsa4096.sig.asc`: armored.

### What GnuPG says of them

`tool/pgp/gnupg_check.sh` imports the four unprotected fixture keys into a
throwaway `GNUPGHOME`, marks them as the person's own, and for every line
of the manifest runs `gpg --decrypt` or `gpg --verify` with `--status-fd`.
It fails unless gpg reports `DECRYPTION_OKAY` and `GOODMDC` for a message
and a `VALIDSIG` from each signer listed, gives back the plain file byte
for byte, and prints no `WARNING`.

Run on 2026-11-16 with gpg (GnuPG) 2.4.9, libgcrypt 1.12.2, the `gpg` of
Git for Windows:

```text
ok  to-ed25519.asc
ok  to-rsa3072.signed.asc
ok  to-two.signed.asc
ok  to-kemlock.signed.asc
ok  report.txt.gpg
ok  report.txt.unsigned.gpg
ok  passphrase.asc
ok  passphrase.signed.gpg
ok  clearsigned.asc
ok  clearsigned-rsa.asc
ok  report.txt.ed25519.sig
ok  report.txt.rsa3072.sig
ok  report.txt.kemlock-rsa4096.sig.asc
ok  message.txt.kemlock-ed25519.sig
PASS: GnuPG decrypted and verified all 14 files Kemlock wrote, with no warning
```

From a clear-signed text gpg gives the text back without the trailing
spaces and tabs of its lines, which such a signature does not cover; the
script compares with `gnupg/message.txt` treated the same way.

Not checked with GnuPG 2.5: this machine has 2.4.9 only. The key fixtures
came from 2.5.24 on a Mac, where the script should be run once more.

## Added by add-openpgp-card

- `gnupg/brainpoolP256r1.secret.asc`, `gnupg/brainpoolP256r1.public.asc`,
  `gnupg/brainpoolP256r1.colons.txt`: ECDSA and ECDH on brainpoolP256r1,
  made on 2026-11-17 with GnuPG 2.4.9 as `make_fixtures.sh` made the NIST
  P-256 key (`--quick-generate-key ... brainpoolP256r1 cert,sign 0`, then
  `--quick-add-key ... brainpoolP256r1 encr 0`, exported unprotected).
  Once Kemlock checked and wrote to NIST P-256 keys (an OpenPGP card's
  key may be on that curve), the tests that a curve Kemlock does not use
  is refused by name use this one.
- `gnupg/message.txt.brainpoolP256r1.sig`: `--detach-sign` of
  `gnupg/message.txt` by the brainpoolP256r1 key, with GnuPG 2.4.9 on
  2026-11-17, its defaults (SHA-256); `gpg --verify` called it good. The
  test that a signature by a key of a curve Kemlock does not check names
  the curve uses it, since `gnupg/message.txt.nistp256.sig` now checks.
