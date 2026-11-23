# Other people's public keys

Test keys for other people's keys in the vault (openspec:
`add-pgp-contacts`), made on 2026-11-17 (UTC) by GnuPG 2.4.9 (libgcrypt
1.12.2, the `gpg` of Git for Windows; `versions.txt`). They are test keys,
made for this and nothing else, with no passphrase.

**Never regenerate these files.** A fresh run makes different keys with
other fingerprints and dates. Add new files beside them instead.

- `grace-1`: an Ed25519 primary key (certify and sign) with a Curve25519
  encryption subkey, both expiring a year on, 2027-11-17.
  `grace-1.secret.asc` is its secret key, for a test that needs the
  person to hold a key themselves.
- `grace-2`: the same key a few seconds later: both now expire on
  2030-01-01, and it gained an Ed25519 signing subkey. GnuPG replaced the
  earlier self-signatures, so this copy holds the later ones only.
- `grace-3`: the same key later still: the primary revoked itself.
- `grace-other`: a different Ed25519 key, made later in a throwaway home of
  its own, that also says it is `Grace Hopper <grace@example.org>`: the
  key someone else might hand over in her name.
- `alan`: an Ed25519 key with a Curve25519 subkey, never expiring.
- `rsa3072-certified-photo`: an RSA 3072 key with an RSA 3072 encryption
  subkey, a certification of its user ID by another key (an Ed25519 key,
  `Fixture Certifier`, not kept) and a photo, a 1 by 1 pixel JPEG, with
  its self-signature.
- `sign-only`: an Ed25519 key (certify and sign) with no subkey, so
  nothing can be encrypted to it.
- `ecdsa-p256`: an ECDSA P-256 primary key with an ECDH P-256 subkey.
- `two-keys.public.gpg` and `two-keys.public.asc`: `alan` and `sign-only`
  exported together, binary and armored.

For each: `<name>.public.asc` (`--export`) and `<name>.colons.txt`, what
`gpg --list-keys --with-subkey-fingerprints --with-colons` printed, which
the tests read the fingerprints, user IDs and dates from.

`rsa3072-certified-photo.trimmed.public.asc` is the key Kemlock keeps of
`rsa3072-certified-photo` (`trimPublicKey`: without the other key's
certification and the photo), written once by
`test/crypto/keys/pgp_public_trimmed_generator_test.dart`, and
`rsa3072-certified-photo.trimmed.colons.txt` what GnuPG 2.4.9 printed for
that file with `gpg --show-keys --with-subkey-fingerprints --with-colons`.
`gpg --import` took it as one new public key.

## Altered by hand

Three files GnuPG did not write.
`test/crypto/keys/pgp_public_altered_generator_test.dart` made them from
`grace-1.public.asc`, once:

- `grace-1.foreign-subkey.public.asc`: Alan's encryption subkey and the
  binding Alan's key made for it, appended. The fingerprint is still
  Grace's.
- `grace-1.flipped-certification.public.asc`: the last byte of the user
  ID's certification flipped.
- `grace-1.cut.public.asc`: the armored block as far as its fifth line.

## The commands

Run in Git Bash, in this folder, with a throwaway `GNUPGHOME`:

```sh
GNUPGHOME=$(mktemp -d) && export GNUPGHOME
gpg --version | head -2 > versions.txt
q() { gpg --batch --pinentry-mode loopback --passphrase '' "$@"; }
fpr_of() { gpg --list-keys --with-colons "$1" | awk -F: '/^fpr/ {print $10; exit}'; }
out() { # fingerprint file
  gpg --armor --export "$1" > "$2.public.asc"
  gpg --list-keys --with-subkey-fingerprints --with-colons "$1" > "$2.colons.txt"
}
# The revocation certificate GnuPG writes with every new key, imported
revoke() { sed 's/^:-----BEGIN/-----BEGIN/' "$GNUPGHOME/openpgp-revocs.d/$1.rev" | gpg --batch --import; }

q --quick-generate-key 'Grace Hopper <grace@example.org>' ed25519 cert,sign 1y
f=$(fpr_of grace@example.org); q --quick-add-key "$f" cv25519 encr 1y; out "$f" grace-1
q --armor --export-secret-keys "$f" > grace-1.secret.asc
sleep 2
q --quick-set-expire "$f" 2030-01-01; q --quick-set-expire "$f" 2030-01-01 '*'
q --quick-add-key "$f" ed25519 sign 2030-01-01; out "$f" grace-2
sleep 2
revoke "$f"; out "$f" grace-3

q --quick-generate-key 'Alan Turing <alan@example.org>' ed25519 cert,sign 0
a=$(fpr_of alan@example.org); q --quick-add-key "$a" cv25519 encr 0; out "$a" alan

q --quick-generate-key 'Fixture Sign Only <sign-only@example.org>' ed25519 cert,sign 0
s=$(fpr_of sign-only@example.org); out "$s" sign-only

q --quick-generate-key 'Fixture Ecdsa <ecdsa@example.org>' nistp256 cert,sign 0
e=$(fpr_of ecdsa@example.org); q --quick-add-key "$e" nistp256 encr 0; out "$e" ecdsa-p256

gpg --export "$a" "$s" > two-keys.public.gpg
gpg --armor --export "$a" "$s" > two-keys.public.asc
gpg --list-keys --with-subkey-fingerprints --with-colons "$a" "$s" > two-keys.colons.txt

# The certified key with a photo was made in a second throwaway home
q --quick-generate-key 'Fixture Certifier <certifier@example.org>' ed25519 cert,sign 0
k=$(fpr_of certifier@example.org)
q --quick-generate-key 'Fixture Certified <certified@example.org>' rsa3072 cert,sign 0
c=$(fpr_of certified@example.org); q --quick-add-key "$c" rsa3072 encr 0
q --default-key "$k" --quick-sign-key "$c"
printf 'ffd8ffdb00430003020202020302020203030303040604040404040806060506090808090a0c0f0c0a0b0e0b09090d110d0e0f101011100a0c12131210130f101010ffc9000b080001000101011100ffcc000600101005ffda0008010100003f00d2cf20ffd9' \
  | xxd -r -p > "$GNUPGHOME/photo.jpg"
printf 'addphoto\n%s\nsave\n' "$(cygpath -w "$GNUPGHOME/photo.jpg")" \
  | gpg --no-tty --command-fd 0 --status-fd 2 --pinentry-mode loopback --passphrase '' --edit-key "$c"
out "$c" rsa3072-certified-photo

gpgconf --kill gpg-agent; rm -rf "$GNUPGHOME"
```
