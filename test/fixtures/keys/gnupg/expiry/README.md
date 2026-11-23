# PGP keys that expire or were revoked

Test keys for the expiry warnings (openspec: `add-key-expiry-warnings`),
made on 2026-11-16 by GnuPG 2.4.9 (libgcrypt 1.12.2, the `gpg` of Git for
Windows; `versions.txt`). They are test keys, made for this and nothing
else, with no passphrase.

**Never regenerate these files.** A fresh run makes different keys with
other fingerprints and dates. Add new files beside them instead.

Each is an Ed25519 primary key (certify and sign) with a Curve25519
encryption subkey:

- `never`: neither the primary nor the subkey expires.
- `expired`: made with the clock at 2020-01-01 12:00 UTC, both expiring
  after a year, on 2020-12-31.
- `future`: both expire on 2095-01-01.
- `revoked`: never expires; the primary revoked itself.
- `revoked-expired`: as `expired`, and the primary revoked itself.
- `subkey-expired`: made with the clock at 2020-01-01; the primary never
  expires, the subkey expired on 2020-12-31.

For each: `<name>.secret.asc` (`--export-secret-keys`), `<name>.public.asc`
(`--export`) and `<name>.colons.txt`, what
`gpg --list-keys --with-subkey-fingerprints --with-colons` printed, which
the tests read the fingerprints and dates from. GnuPG revokes a key with a
key revocation signature on the primary alone, so the subkey of a revoked
key carries no revocation of its own. It also lists a subkey as expiring no
later than its primary key: the subkey of `expired` was made a second after
its primary, so its own self-signature says 12:00:01 where the listing says
12:00:00.

## The commands

Run in Git Bash, in this folder, with a throwaway `GNUPGHOME`:

```sh
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
gpg --version | head -2 > versions.txt
q() { gpg --batch --pinentry-mode loopback --passphrase '' "$@"; }
PAST='--faked-system-time 20200101T120000'
fpr_of() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/ {print $10; exit}'; }
out() { # fingerprint file
  q --armor --export-secret-keys "$1" > "$2.secret.asc"
  gpg --armor --export "$1" > "$2.public.asc"
  gpg --list-keys --with-subkey-fingerprints --with-colons "$1" > "$2.colons.txt"
}
# The revocation certificate GnuPG writes with every new key, imported
revoke() { sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$1.rev" | gpg --batch --import; }

q --quick-generate-key 'Fixture Never <never@example.org>' ed25519 cert,sign 0
f=$(fpr_of never@example.org); q --quick-add-key "$f" cv25519 encr 0; out "$f" never

q $PAST --quick-generate-key 'Fixture Expired <expired@example.org>' ed25519 cert,sign 1y
f=$(fpr_of expired@example.org); q $PAST --quick-add-key "$f" cv25519 encr 1y; out "$f" expired

q --quick-generate-key 'Fixture Future <future@example.org>' ed25519 cert,sign 2095-01-01
f=$(fpr_of future@example.org); q --quick-add-key "$f" cv25519 encr 2095-01-01; out "$f" future

q --quick-generate-key 'Fixture Revoked <revoked@example.org>' ed25519 cert,sign 0
f=$(fpr_of revoked@example.org); q --quick-add-key "$f" cv25519 encr 0; revoke "$f"; out "$f" revoked

q $PAST --quick-generate-key 'Fixture Revoked Expired <revoked-expired@example.org>' ed25519 cert,sign 1y
f=$(fpr_of revoked-expired@example.org); q $PAST --quick-add-key "$f" cv25519 encr 1y; revoke "$f"; out "$f" revoked-expired

q $PAST --quick-generate-key 'Fixture Subkey Expired <subkey-expired@example.org>' ed25519 cert,sign 0
f=$(fpr_of subkey-expired@example.org); q $PAST --quick-add-key "$f" cv25519 encr 1y; out "$f" subkey-expired

gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"
```
