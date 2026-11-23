# Mail fixtures

What a mail app hands Kemlock's OpenPGP provider, and what a correspondent's
GnuPG wrote, for `test/features/mail` (openspec: add-pgp-mail-provider,
task 1.5). The keys are the test keys of `../keys/gnupg`, imported and never
regenerated: Fixture Ed25519 (`1FCDA135…661CF8DB`) and Fixture RSA
(`EA29C79D…8EFC2F98`).

**Never regenerate these files.** Session keys and signing times are random
or of the day. Add new files beside them instead.

- `body.eml`: a MIME part as a mail app signs or encrypts it for PGP/MIME:
  headers, an empty line and a quoted-printable body, every line ending
  with CRLF.
- `note.txt`: four lines of text ending with LF, for clear-signing.
- `signed-encrypted.asc`: `body.eml` signed by Fixture RSA and encrypted
  to Fixture Ed25519 (SEIPD version 1, forced by `--rfc4880`).
- `signed-encrypted-rsa.asc`: the same, encrypted to Fixture RSA.
- `body.eml.sig.asc`: Fixture RSA's detached signature over `body.eml`
  (signature class 0x00).
- `note.clearsigned.asc`: `note.txt` clear-signed by Fixture RSA.
- `note.clearsigned-changed.asc`: the same with one byte of the text
  changed ("all night" became "all might"); its signature no longer
  matches.
- `versions.txt`: `gpg --version`.

## How they were made

With the GnuPG 2.4.9 of Git for Windows, in Git Bash, on 2026-11-17, from
`mobile/`, with `TZ=UTC`:

```sh
OUT=test/fixtures/mail
KEYS=test/fixtures/keys/gnupg
mkdir "$OUT" && cd "$OUT"
GNUPGHOME=$(mktemp -d); export GNUPGHOME
q() { gpg --batch --no-tty --pinentry-mode loopback --trust-model always "$@"; }
q --import "$KEYS/ed25519.secret.asc" "$KEYS/rsa3072.secret.asc"
ED=1FCDA135EE42400EC2B77CE677249ABE661CF8DB
RSA=EA29C79D1C6570277907BB485D49D28C8EFC2F98
gpg --version | head -2 > versions.txt
printf 'Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nDear Ada,\r\n\r\nThe engine has run all night. Caf=C3=A9 at nine?\r\n\r\nCharles\r\n' > body.eml
printf 'Dear Ada,\n\nThe engine has run all night.\n- Charles\n' > note.txt
q --armor --rfc4880 --sign --encrypt -u "$RSA" -r "$ED" -o signed-encrypted.asc body.eml
q --armor --rfc4880 --sign --encrypt -u "$RSA" -r "$RSA" -o signed-encrypted-rsa.asc body.eml
q --armor --detach-sign -u "$RSA" -o body.eml.sig.asc body.eml
q --clearsign -u "$RSA" -o note.clearsigned.asc note.txt
sed 's/all night/all might/' note.clearsigned.asc > note.clearsigned-changed.asc
```

## What GnuPG says of them

`q --status-fd 1 --decrypt` or `--verify` of each, in the same
`GNUPGHOME`; the status lines about key lookups and trust are left out.

```text
## gpg --decrypt signed-encrypted.asc
[GNUPG:] ENC_TO 841A40E3B199EA67 18 0
gpg: encrypted with cv25519 key, ID 841A40E3B199EA67, created 2026-11-15
      "Fixture Ed25519 <ed25519@example.org>"
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Dear Ada,

The engine has run all night. Caf=C3=A9 at nine?

Charles
gpg: Signature made Tue Nov 17 05:49:29 2026 GMT
gpg:                using RSA key EA29C79D1C6570277907BB485D49D28C8EFC2F98
[GNUPG:] GOODSIG 5D49D28C8EFC2F98 Fixture RSA <rsa@example.org>
gpg: Good signature from "Fixture RSA <rsa@example.org>" [unknown]
[GNUPG:] VALIDSIG EA29C79D1C6570277907BB485D49D28C8EFC2F98 2026-11-17 1794894569 0 4 0 1 10 00 EA29C79D1C6570277907BB485D49D28C8EFC2F98
gpg: WARNING: Using untrusted key!
[GNUPG:] DECRYPTION_OKAY
[GNUPG:] GOODMDC
## gpg --decrypt signed-encrypted-rsa.asc
[GNUPG:] ENC_TO B8A3CCC781F74F29 1 0
gpg: encrypted with rsa3072 key, ID B8A3CCC781F74F29, created 2026-11-15
      "Fixture RSA <rsa@example.org>"
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Dear Ada,

The engine has run all night. Caf=C3=A9 at nine?

Charles
gpg: Signature made Tue Nov 17 05:49:29 2026 GMT
gpg:                using RSA key EA29C79D1C6570277907BB485D49D28C8EFC2F98
[GNUPG:] GOODSIG 5D49D28C8EFC2F98 Fixture RSA <rsa@example.org>
gpg: Good signature from "Fixture RSA <rsa@example.org>" [unknown]
[GNUPG:] VALIDSIG EA29C79D1C6570277907BB485D49D28C8EFC2F98 2026-11-17 1794894569 0 4 0 1 10 00 EA29C79D1C6570277907BB485D49D28C8EFC2F98
gpg: WARNING: Using untrusted key!
[GNUPG:] DECRYPTION_OKAY
[GNUPG:] GOODMDC
## gpg --verify body.eml.sig.asc body.eml
gpg: Signature made Tue Nov 17 05:49:30 2026 GMT
gpg:                using RSA key EA29C79D1C6570277907BB485D49D28C8EFC2F98
[GNUPG:] GOODSIG 5D49D28C8EFC2F98 Fixture RSA <rsa@example.org>
gpg: Good signature from "Fixture RSA <rsa@example.org>" [unknown]
[GNUPG:] VALIDSIG EA29C79D1C6570277907BB485D49D28C8EFC2F98 2026-11-17 1794894570 0 4 0 1 10 00 EA29C79D1C6570277907BB485D49D28C8EFC2F98
gpg: WARNING: Using untrusted key!
## gpg --verify note.clearsigned.asc
gpg: Signature made Tue Nov 17 05:49:30 2026 GMT
gpg:                using RSA key EA29C79D1C6570277907BB485D49D28C8EFC2F98
[GNUPG:] GOODSIG 5D49D28C8EFC2F98 Fixture RSA <rsa@example.org>
gpg: Good signature from "Fixture RSA <rsa@example.org>" [unknown]
[GNUPG:] VALIDSIG EA29C79D1C6570277907BB485D49D28C8EFC2F98 2026-11-17 1794894570 0 4 0 1 10 01 EA29C79D1C6570277907BB485D49D28C8EFC2F98
gpg: WARNING: Using untrusted key!
## gpg --verify note.clearsigned-changed.asc
gpg: Signature made Tue Nov 17 05:49:30 2026 GMT
gpg:                using RSA key EA29C79D1C6570277907BB485D49D28C8EFC2F98
[GNUPG:] BADSIG 5D49D28C8EFC2F98 Fixture RSA <rsa@example.org>
gpg: BAD signature from "Fixture RSA <rsa@example.org>" [unknown]
[GNUPG:] FAILURE gpg-exit 33554433
```
