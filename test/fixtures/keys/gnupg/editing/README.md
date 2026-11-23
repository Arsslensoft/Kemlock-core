# PGP keys to change

Test keys for changing a PGP key in the vault (openspec:
`add-pgp-key-editing`), made on 2026-11-17 (UTC) by GnuPG 2.4.9 (libgcrypt
1.12.2, the `gpg` of Git for Windows; `versions.txt`). The task asked for
GnuPG 2.5.24, the version of `../versions.txt`, which made the older
fixtures on another machine; 2.4.9 is the one this machine has. They are
test keys, made for this and nothing else.

**Never regenerate these files.** A fresh run makes different keys with
other fingerprints and dates. Add new files beside them instead.

- `signing-subkey`: an Ed25519 primary key that only certifies, with an
  Ed25519 signing subkey and a Curve25519 encryption subkey, all expiring
  on 2030-01-01. No passphrase.
- `signing-subkey.after`: the same key after GnuPG changed it: the primary
  key and every subkey extended to 2035-01-01, a second user ID
  `Fixture Signing <signing@work.example.org>`, and a second Curve25519
  encryption subkey. It is the "after" of `signing-subkey`, which is its
  "before".
- `rsa3072-expiring`: an RSA 3072 primary key (certify and sign) with an
  RSA 3072 encryption subkey, both expiring on 2027-01-01. No passphrase.
- `protected`: an Ed25519 primary key (certify and sign) with a Curve25519
  encryption subkey, protected by the passphrase `fixture passphrase`
  (GnuPG's export: S2K usage 254, AES-128, Iterated and Salted S2K over
  SHA-1).
- `protected.stub.secret.asc`: the same key exported with
  `--export-secret-subkeys`: its primary key is GnuPG's stub (S2K type 101,
  `gnu-dummy`), with no secret in it; the subkey keeps its protected secret.

For each key: `<name>.secret.asc` (`--export-secret-keys`),
`<name>.public.asc` (`--export`) and `<name>.colons.txt`, what
`gpg --list-keys --with-subkey-fingerprints --with-colons` printed. GnuPG
lists the dates of a subkey and the end of an expiry day in its own way;
the tests read the fingerprints and dates from these listings.

`<name>.rev` is the revocation certificate GnuPG wrote into
`openpgp-revocs.d` when it made each key, as it wrote it: a text, then the
armored signature with a colon before its first line, so that it is not
imported by accident. It is a bare key revocation signature (0x20) with
reason 0 (no reason) and no note. `signing-subkey.rev` is the certificate
of `signing-subkey.after` too: the change kept the key's fingerprint.

## The commands

Run in Git Bash, in this folder. GnuPG would not take `--faked-system-time`
for the protected key ("key has been created 1 second in future"), so the
keys were made in real time, a pause between steps so that every new
self-signature is newer than the one it replaces:

```sh
set -e
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
gpg --version | head -2 > versions.txt
q() { gpg --batch --pinentry-mode loopback --passphrase '' "$@"; }
p() { gpg --batch --pinentry-mode loopback --passphrase 'fixture passphrase' "$@"; }
fpr_of() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/ {print $10; exit}'; }
out() { # fingerprint file [passphrase function]
  ${3:-q} --armor --export-secret-keys "$1" > "$2.secret.asc"
  gpg --armor --export "$1" > "$2.public.asc"
  gpg --list-keys --with-subkey-fingerprints --with-colons "$1" > "$2.colons.txt"
}

# An Ed25519 key that only certifies, with a signing and an encryption subkey
q --quick-generate-key 'Fixture Signing <signing@example.org>' ed25519 cert 2030-01-01
s=$(fpr_of signing@example.org)
sleep 2; q --quick-add-key "$s" ed25519 sign 2030-01-01
sleep 2; q --quick-add-key "$s" cv25519 encr 2030-01-01
out "$s" signing-subkey
cp "$GNUPGHOME/openpgp-revocs.d/$s.rev" signing-subkey.rev

# An RSA 3072 key that expires
q --quick-generate-key 'Fixture RSA <rsa@example.org>' rsa3072 cert,sign 2027-01-01
r=$(fpr_of rsa@example.org)
sleep 2; q --quick-add-key "$r" rsa3072 encr 2027-01-01
out "$r" rsa3072-expiring
cp "$GNUPGHOME/openpgp-revocs.d/$r.rev" rsa3072-expiring.rev

# A protected Ed25519 key, and the same exported without its primary secret
p --quick-generate-key 'Fixture Protected <protected@example.org>' ed25519 cert,sign 0
k=$(fpr_of protected@example.org)
sleep 2; p --quick-add-key "$k" cv25519 encr 0
out "$k" protected p
p --armor --export-secret-subkeys "$k" > protected.stub.secret.asc
cp "$GNUPGHOME/openpgp-revocs.d/$k.rev" protected.rev

# The first key after GnuPG changed it: extended, a second user ID, a second encryption subkey
sleep 2; q --quick-set-expire "$s" 2035-01-01
sleep 2; q --quick-set-expire "$s" 2035-01-01 '*'
sleep 2; q --quick-add-uid "$s" 'Fixture Signing <signing@work.example.org>'
sleep 2; q --quick-add-key "$s" cv25519 encr 2035-01-01
out "$s" signing-subkey.after

gpgconf --kill gpg-agent
rm -rf "${GNUPGHOME:?}"
```

## What GnuPG made of Kemlock's changes

`gnupg-check.txt` is the output of one run of `tool/keys/gnupg_check.sh`
(run as `bash -o igncr tool/keys/gnupg_check.sh` in Git Bash, which
checks the scripts out with CR LF), on 2026-11-17 with GnuPG 2.4.9. Its
second part imports each change Kemlock made to the keys here and to
`../../other/editing/direct-key`, one at a time, into a fresh home: a new
expiry for the key and its subkeys, never, a new expiry for one subkey, a
new user ID made the main one, a new encryption subkey, a new signing
subkey (and on the RSA key an RSA 4096 one), and a revocation; then each
revocation certificate Kemlock made over the key's original public key.
GnuPG took every one with no error and no warning, every signature was
good, it listed the new subkeys with their usage, the new user ID first
and valid, the new dates, and each revocation with its reason and
comment; and the protected key's new subkeys opened with its passphrase.
