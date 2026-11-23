# Answers to a key lookup

What a domain's Web Key Directory and keys.openpgp.org might answer when
asked for a key by email address (openspec: `add-key-lookup`), made on
2026-11-17 (UTC) by GnuPG 2.4.9 (libgcrypt 1.12.2, the `gpg` of Git for
Windows; `versions.txt`) from the test keys of `../contacts`. The tests
hand them to a `MockClient`; nothing here was fetched from a server.

**Never regenerate these files.** `wkd-grace-two-addresses.bin` holds a
self-signature made when it was written, so a fresh run gives other bytes.
Add new files beside them instead.

A directory answers binary keys, one after another; the key server
answers one armored key.

- `wkd-grace.bin`: `grace-1`, Grace Hopper's key
  (`894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495`), as one binary key, with
  its one user ID `Grace Hopper <grace@example.org>`.
- `wkd-grace-revoked-then-other.bin`: `grace-3` (the same key, revoked)
  and then `grace-other` (`877C60B601AFE3B57806CC99A828765639DB3D98`, a
  different key that also says `Grace Hopper <grace@example.org>`), binary,
  concatenated: two keys for one address, the first revoked.
- `wkd-alan.bin`: `alan` (`C677F2C26A5E4C4E78CD6003A8CFF189E65E4BDC`),
  binary: a key whose only user ID, `Alan Turing <alan@example.org>`,
  names another address than Grace's.
- `wkd-grace-two-addresses.bin`: `grace-1` with a second user ID, the bare
  address `hopper@lab.example.org`, at another domain, added with the
  secret key of `grace-1`. `wkd-grace-two-addresses.colons.txt` is what
  `gpg --list-keys --with-subkey-fingerprints --with-colons` printed for
  it.
- `vks-alan.asc`: a key-server answer, armored, with a single user ID: a
  copy of `../contacts/alan.public.asc`, byte for byte.

## The commands

Run in Git Bash, in this folder, with a throwaway `GNUPGHOME`:

```sh
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
q() { gpg --batch --pinentry-mode loopback --passphrase '' "$@"; }
gpg --version | head -2 > versions.txt
gpg --dearmor < ../contacts/grace-1.public.asc > wkd-grace.bin
gpg --dearmor < ../contacts/grace-3.public.asc > grace-3.tmp
gpg --dearmor < ../contacts/grace-other.public.asc > grace-other.tmp
cat grace-3.tmp grace-other.tmp > wkd-grace-revoked-then-other.bin && rm grace-3.tmp grace-other.tmp
gpg --dearmor < ../contacts/alan.public.asc > wkd-alan.bin
cp ../contacts/alan.public.asc vks-alan.asc
q --import ../contacts/grace-1.secret.asc
q --quick-add-uid 894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495 'hopper@lab.example.org'
gpg --export 894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495 > wkd-grace-two-addresses.bin
gpg --list-keys --with-subkey-fingerprints --with-colons 894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495 \
  > wkd-grace-two-addresses.colons.txt
gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"
```
