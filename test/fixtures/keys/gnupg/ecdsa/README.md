# ECDSA keys and signatures

Made on 2026-11-17 with GnuPG 2.4.9 (Git for Windows) in a throwaway
home, for the ECDSA checks of add-openpgp-card (task 6.2). Never
regenerate them; add new ones beside them.

For each of `nistp256` and `nistp384`:

```sh
gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-gen-key "Fixture nistp256 <nistp256@example.org>" nistp256 sign never
gpg --export <fingerprint> > nistp256.public.gpg
gpg --local-user <fingerprint> --detach-sign -o nistp256.data.sig data.txt
gpg --list-keys --with-colons <fingerprint> > nistp256.colons.txt
```

- `<curve>.public.gpg`: the public key, an ECDSA primary key that certifies
  and signs, with its user ID's self-certification.
- `<curve>.data.sig`: a detached signature of `data.txt`. GnuPG chose
  SHA-256 for P-256 (digest algo 8) and SHA-384 for P-384 (digest algo 9).
- `<curve>.colons.txt`: what GnuPG listed for the key.
