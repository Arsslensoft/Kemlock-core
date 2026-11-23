# Key fixtures

Key files made by the tools people use, for the readers in `lib/crypto/keys`
and the tests in `test/crypto/keys`. They are test keys, made for this and
nothing else.

**Never regenerate these files.** The tests pin Kemlock to what each tool
wrote on the day it wrote it; a fresh run makes different random keys and
would hide a change in behaviour. Add new files beside them instead.

`tool/keys/make_fixtures.sh` made `openssl/`, `openssh/` and `gnupg/` in one
run on 2026-11-15, and is the exact record of the commands. Its passphrase
for every protected key is `fixture passphrase`.

## `openssl/`: OpenSSL 3.6.1 (27 Jan 2026)

For each of `rsa2048`, `p256`, `p384`, `p521`, `ed25519`, `x25519` and
`ed448`:

- `<name>.pkcs8.pem`: the private key, PKCS#8, as `openssl genpkey` wrote it
  (`p256` came from `openssl ecparam -genkey`, kept as
  `p256.sec1-with-params.pem`, an `EC PARAMETERS` block and a SEC1 key, and
  converted with `openssl pkey`).
- `<name>.pkcs8.der`: `openssl pkey -outform DER`, the bytes Kemlock keeps
  as the private half.
- `<name>.spki.pem` and `<name>.spki.der`: `openssl pkey -pubout`, the public
  half Kemlock must derive.
- For `rsa2048`, `p256`, `p384` and `p521`, `<name>.traditional.pem` and
  `.der`: `openssl pkey -traditional`, PKCS#1 for RSA and SEC1 for EC.

Also:

- `p256.cert.pem`: a self-signed certificate of the P-256 key
  (`openssl req -new -x509`), refused as a public key alone.
- `rsa2048.legacy-aes128.pem`: `openssl rsa -aes128 -traditional`, a PEM key
  with `Proc-Type: 4,ENCRYPTED` and `DEK-Info: AES-128-CBC,...` headers,
  refused as a legacy encrypted PEM.
- `ed448` and `p521` are keys of an algorithm and a curve Kemlock doesn't
  know, kept as given under their identifiers (`1.3.101.113` and
  `1.3.132.0.35`).

Encrypted with `openssl pkcs8 -topk8` from the plain files above:

- `rsa2048.pbes2-sha1-aes128.pem`: `-v2 aes-128-cbc -v2prf hmacWithSHA1`
- `p256.pbes2-sha256-aes256.pem`: `-v2 aes-256-cbc -v2prf hmacWithSHA256`
- `ed25519.pbes2-sha512-aes256.pem`: `-v2 aes-256-cbc -v2prf hmacWithSHA512`
- `x25519.pbes2-sha256-aes128.pem`: `-v2 aes-128-cbc -v2prf hmacWithSHA256`
- `p384.pbes2-default.der`: `-v2 aes-256-cbc`, OpenSSL's default PRF, DER
- `p256.pbes2-sha256-aes192-100000.pem`: `-v2 aes-192-cbc -iter 100000`
- refused by name: `p256.pbes2-scrypt.pem` (`-scrypt`),
  `p256.pbes2-des3.pem` (`-v2 des3`) and `rsa2048.pbes1-sha1-3des.pem`
  (`-v1 PBE-SHA1-3DES`)

`encrypted-asn1.txt` has the start of `openssl asn1parse` for each: OpenSSL
3.6 writes a 16-byte salt, 2048 rounds, no key length, and the PRF with a
NULL parameter.

Post-quantum keys, each made from a seed `openssl rand -hex` wrote to
`<name>.seed.hex`, so a test can make the same key
(`openssl genpkey -algorithm <NAME> -pkeyopt hexseed:<seed>`):

- `ml-dsa-65.both.pem` and `.both.der`: as `genpkey` wrote it, OpenSSL's
  default form (`seed-priv`: the 32-byte seed and the 4032-byte expanded
  key). The seed is `d15986216c11af602450982a941804f8e6e099f6025a52141e373a273b48265c`.
- `ml-dsa-65.seed.pem` and `ml-dsa-65.expanded.pem`: the same key rewritten
  with `openssl pkey -provparam ml-dsa.output_formats=seed-only` and
  `=priv-only`.
- `ml-dsa-65.spki.pem` and `.spki.der`: `openssl pkey -pubout`.
- `ml-kem-768.*` and `ml-kem-1024.*`: the same five files for an ML-KEM-768
  and an ML-KEM-1024 key, each made from a 64-byte seed `d || z`
  (`ml-kem.output_formats` for the forms). The seeds are
  `cc1c793ee8bda03a4b87a10144b293db10edb1f5a87ee1445dd2ce0962af2136`
  `b5f8f75bf98075e7dbe74839c42813b87b6973e556afd33e26f7d85b37b266bd` and
  `1f87857039af04fd5201d37a086bef8f83c62db53877ced0151c02afa1633d1b`
  `c8db97a6a4442100e7bec98ce4661e83a0643b3ce59f5c031f6a74c33242df78`.
- `ml-kem-512.both.pem`: an ML-KEM-512 key, which the vault doesn't offer;
  it is kept as a key of an unknown algorithm.

`pkey-text.txt` has the first lines `openssl pkey -noout -text` printed for
each file, which show how OpenSSL read it (for example
`Private-Key: (2048 bit, 2 primes)` for `rsa2048.pkcs8.pem` and
`ED448 Private-Key:` for `ed448.pkcs8.pem`); `versions.txt` has
`openssl version`.

## `openssh/`: OpenSSH 10.2p1 (`ssh-keygen`)

- `ed25519`, `ecdsa256`, `ecdsa384`, `ecdsa521`, `rsa3072`: `ssh-keygen -t
  <type> -N ''`, no passphrase; each comment is `fixture <type>`.
- `<name>.protected`: `-N 'fixture passphrase'` with `ssh-keygen`'s
  defaults (`aes256-ctr`, 16 rounds of bcrypt).
- `ed25519.<cipher>`: protected with `-Z <cipher>`, for `aes128-ctr`,
  `aes192-ctr`, `aes128-cbc`, `aes192-cbc`, `aes256-cbc`, and the refused
  `chacha20-poly1305@openssh.com` and `aes256-gcm@openssh.com`.
- `ed25519.rounds4`: `-a 4`.
- `ed25519-cert.pub`: `ed25519.pub` signed by a throwaway CA
  (`ssh-keygen -s ca -I fixture -n fixture`), refused as a public key alone.
- `ecdsa521` is refused: OpenSSH has the key type, the vault doesn't.
- `ed25519.protected.y.txt`: `ssh-keygen -y -P 'fixture passphrase'`.

`fingerprints.txt` is `ssh-keygen -l -f` on each `.pub` file:

```text
256 SHA256:3+c2hXfaRng7wEk1ZtVzlpPJgSyUq7Lfcc1S5OuxDnI fixture ecdsa p256 protected (ECDSA)
256 SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg fixture ecdsa p256 (ECDSA)
384 SHA256:U/3Mm3PbmLUgvyJsRYI4DO0siotTMO5b5YXOhx+kVH4 fixture ecdsa p384 protected (ECDSA)
384 SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw fixture ecdsa p384 (ECDSA)
521 SHA256:2Zkkw/B6LrkdE2VFIbEVtPKk9IejguYDxi0yg2+xtS4 fixture ecdsa p521 (ECDSA)
256 SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4 fixture ed25519 (ED25519-CERT)
256 SHA256:Nymrm2gC9TMzS4BKF+JgnKFl2q4PXGCb4vJWFOIAQCY fixture ed25519 aes128-cbc (ED25519)
256 SHA256:Bh9R4ep+bojBUgsBnjyOomJYpbZOBLvcI61qYWyUZgI fixture ed25519 aes128-ctr (ED25519)
256 SHA256:CC5+f6wYCaX2UFpLetCb86/XEF5kDG6IkeXFol9Zzo4 fixture ed25519 aes192-cbc (ED25519)
256 SHA256:izy1Mx2x5woBI8OPn1xenlQRT44OZwsc3YvQQqbHxG0 fixture ed25519 aes192-ctr (ED25519)
256 SHA256:FfxBUdFotgoo/QdVOw8pVYW8FOxpXpaZFhF6TbOsUKY fixture ed25519 aes256-cbc (ED25519)
256 SHA256:RkAGYfuAw61UUGgQYKU+KTUNh54lT6tneYNK0M6+PyA fixture ed25519 aes256-gcm@openssh.com (ED25519)
256 SHA256:X7XEKsVh2POU7JYGgh51pd3ujwsMOhDFkuY6jk8aikQ fixture ed25519 chacha20-poly1305@openssh.com (ED25519)
256 SHA256:vsbOCtY7PSc1SWvXM/w1Rl36BGXbwJkyXbU6ZJaLT+0 fixture ed25519 protected (ED25519)
256 SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4 fixture ed25519 (ED25519)
256 SHA256:RqYGsHzf0fHXFb011AbG/JcBZ7Zno9b94m0Kt6Fu2o8 fixture ed25519 4 rounds (ED25519)
3072 SHA256:dRlWClTvUkCP6ZEuv0uEcnlBge2dFg99U7zOsHb2F8A fixture rsa 3072 protected (RSA)
3072 SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM fixture rsa 3072 (RSA)
```

## `openssh/sshsig/`: OpenSSH 10.3p1 and git 2.55.0 (SSH signatures)

Signatures in the SSHSIG format (OpenSSH's `PROTOCOL.sshsig`), made on
2026-11-16 by `tool/keys/make_sshsig_fixtures.sh` with the unprotected keys
of `openssh/`, which it only reads (it copies them to a temporary folder,
because `ssh-keygen` refuses a key file others can read). The same rule
holds: these files are never regenerated. The ECDSA signatures are random,
so a second run would write other bytes; the Ed25519 and RSA ones would
come out the same, and Kemlock must write exactly those.

- `empty` (no bytes), `hello.txt` (`hello`, no line ending) and `bytes.bin`
  (the 256 byte values in order): the messages.
- `<key>-file-<message>.sig`, for `ed25519`, `rsa3072`, `ecdsa256`,
  `ecdsa384` and `ecdsa521`: `ssh-keygen -Y sign -f <key> -n file <message>`.
  `ecdsa521` is a key type Kemlock names and refuses.
- `ed25519-git-<message>.sig`: `-n git`.
- `ed25519-custom-<message>.sig`: `-n kemlock-test@example.org`.
- `ed25519-sha256-<message>.sig`: `-n file -O hashalg=sha256`; every other
  signature has `ssh-keygen`'s default hash, SHA-512.
- `git-commit.txt` and `git-tag.txt`: `git cat-file commit HEAD` and
  `git cat-file tag v1` in a throwaway repository, the commit made with
  `git -c gpg.format=ssh -c user.signingkey=<ed25519> commit -S` and the
  tag with `tag -s`, with fixed names, addresses and dates and none of the
  machine's git configuration. `git-commit.id.txt` and `git-tag.id.txt` are
  their object ids.
- `versions.txt`: `ssh -V` and `git --version`.

The armor is base64 in lines of 70 characters, not the 76
`PROTOCOL.sshsig` suggests.

The script checks each signature it wrote with
`ssh-keygen -Y check-novalidate -n <namespace> -s <file>.sig < <message>`,
and the commit and tag with `git verify-commit` and `git verify-tag`
against an allowed-signers file. What it printed:

```text
ed25519-file-empty.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
rsa3072-file-empty.sig: Good "file" signature with RSA key SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
ecdsa256-file-empty.sig: Good "file" signature with ECDSA key SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
ecdsa384-file-empty.sig: Good "file" signature with ECDSA key SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
ecdsa521-file-empty.sig: Good "file" signature with ECDSA key SHA256:2Zkkw/B6LrkdE2VFIbEVtPKk9IejguYDxi0yg2+xtS4
ed25519-git-empty.sig: Good "git" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-custom-empty.sig: Good "kemlock-test@example.org" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-sha256-empty.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-file-hello.txt.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
rsa3072-file-hello.txt.sig: Good "file" signature with RSA key SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
ecdsa256-file-hello.txt.sig: Good "file" signature with ECDSA key SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
ecdsa384-file-hello.txt.sig: Good "file" signature with ECDSA key SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
ecdsa521-file-hello.txt.sig: Good "file" signature with ECDSA key SHA256:2Zkkw/B6LrkdE2VFIbEVtPKk9IejguYDxi0yg2+xtS4
ed25519-git-hello.txt.sig: Good "git" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-custom-hello.txt.sig: Good "kemlock-test@example.org" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-sha256-hello.txt.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-file-bytes.bin.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
rsa3072-file-bytes.bin.sig: Good "file" signature with RSA key SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
ecdsa256-file-bytes.bin.sig: Good "file" signature with ECDSA key SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
ecdsa384-file-bytes.bin.sig: Good "file" signature with ECDSA key SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
ecdsa521-file-bytes.bin.sig: Good "file" signature with ECDSA key SHA256:2Zkkw/B6LrkdE2VFIbEVtPKk9IejguYDxi0yg2+xtS4
ed25519-git-bytes.bin.sig: Good "git" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-custom-bytes.bin.sig: Good "kemlock-test@example.org" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ed25519-sha256-bytes.bin.sig: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
git-commit.txt: Good "git" signature for committer@example.org with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
git-tag.txt: Good "git" signature for committer@example.org with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
```

## `gnupg/`: GnuPG 2.5.24 (libgcrypt 1.12.4)

Made in a throwaway `GNUPGHOME` with `gpg --batch --pinentry-mode loopback`:
`--quick-generate-key '<name> <email>' <algo> cert,sign <expiry>`, then
`--quick-add-key <fpr> <subalgo> encr <expiry>`. GnuPG 2.5 still makes
version 4 keys this way, as 2.4 does.

- `ed25519`: Ed25519 primary, no expiry, and a Curve25519 encryption subkey
  expiring in 2 years; no passphrase.
- `ed25519-protected`: the same kinds, the primary expiring in 5 years,
  protected with `fixture passphrase`.
- `rsa3072`: RSA 3072 primary and RSA 3072 encryption subkey, no passphrase.
- `rsa3072-protected`: the same, the subkey expiring in 3 years, protected.
- `ed25519-two-uids`: `ed25519` after `--quick-add-uid` added
  `Fixture Second <second@example.org>`.

For each: `<name>.secret.asc` and `.secret.gpg` (`--export-secret-keys`,
armored and binary), `<name>.public.asc` and `.public.gpg` (`--export`, the
public key Kemlock must derive from the secret one, byte for byte), and
what `gpg --list-keys --with-subkey-fingerprints` printed, as people read it
(`<name>.list.txt`) and with `--with-colons` (`<name>.colons.txt`, which the
tests read). The listings:

`ed25519`:

```text
pub   ed25519 2026-11-15 [SC]
      1FCDA135EE42400EC2B77CE677249ABE661CF8DB
uid           [ultimate] Fixture Ed25519 <ed25519@example.org>
sub   cv25519 2026-11-15 [E] [expires: 2028-11-14]
      4BA83174FC8CE762A23BF0A4841A40E3B199EA67
```

`ed25519-two-uids`:

```text
pub   ed25519 2026-11-15 [SC]
      1FCDA135EE42400EC2B77CE677249ABE661CF8DB
uid           [ unknown] Fixture Second <second@example.org>
uid           [ultimate] Fixture Ed25519 <ed25519@example.org>
sub   cv25519 2026-11-15 [E] [expires: 2028-11-14]
      4BA83174FC8CE762A23BF0A4841A40E3B199EA67
```

`ed25519-protected`:

```text
pub   ed25519 2026-11-15 [SC] [expires: 2031-11-14]
      1BB5EC3961E61EE44F919AB63FCD57EBA0308CA9
uid           [ultimate] Fixture Ed25519 Protected <ed25519p@example.org>
sub   cv25519 2026-11-15 [E]
      528798657C87EF17FE445512E12DD2D2A5D8334C
```

`rsa3072`:

```text
pub   rsa3072 2026-11-15 [SC]
      EA29C79D1C6570277907BB485D49D28C8EFC2F98
uid           [ultimate] Fixture RSA <rsa@example.org>
sub   rsa3072 2026-11-15 [E]
      6C37F218DD1709BF97071E1CB8A3CCC781F74F29
```

`rsa3072-protected`:

```text
pub   rsa3072 2026-11-15 [SC]
      40563A0693F24839F76000FE6D181E7A2C932FEA
uid           [ultimate] Fixture RSA Protected <rsap@example.org>
sub   rsa3072 2026-11-15 [E] [expires: 2029-11-14]
      3BE1CED86CA9D41259607C7BA0166FA099F1F980
```

GnuPG lists the newest self-signed user ID first; Kemlock keeps the order
of the packets.

## `rfc9580/`: the sample keys of RFC 9580

`tool/keys/rfc9580_keys.py` copied them out of the RFC's text
(https://www.rfc-editor.org/rfc/rfc9580.txt):

- `v6-public.asc`: appendix A.3, a version 6 Ed25519 certificate with an
  X25519 subkey; primary fingerprint
  `CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9`, subkey
  `12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885`.
- `v6-secret.asc`: appendix A.4, its unprotected secret key.
- `v6-locked-secret.asc`: appendix A.5, the same key locked with AEAD and
  Argon2 (passphrase `correct horse battery staple`, never used here).

## `acvp/`: NIST's ACVP vectors

From https://github.com/usnistgov/ACVP-Server, `gen-val/json-files`, the
`internalProjection.json` of `ML-KEM-keyGen-FIPS203`,
`ML-KEM-encapDecap-FIPS203` and `ML-DSA-keyGen-FIPS204` (vector set 42),
downloaded on 2026-11-15 and cut down by `tool/keys/trim_acvp.py` to a few
cases, with NIST's field names and test case ids:

- `ml-kem-768.json`: key generation from `d` and `z` (tcId 26 to 28),
  encapsulation with a fixed `m` (26 to 28), decapsulation of a good and two
  modified ciphertexts (86, 88, 91), and the decapsulation and
  encapsulation key checks, one passing and one failing each (126, 128, 136,
  137).
- `ml-dsa-65.json`: key generation from a seed (tcId 26 to 28).

The `internalProjection.json` of `ML-DSA-sigGen-FIPS204` and
`ML-DSA-sigVer-FIPS204` (vector set 42), at ACVP-Server commit
`975de31eb83d87039ec88934fdc47d8c312b892d` (master, "RELEASE/v1.1.0.43
including hotfix patches"), were downloaded on 2026-11-17 and cut down by
`tool/keys/trim_acvp_signatures.dart` to ML-DSA-65 cases of the external,
pure interface (FIPS 204 Algorithms 2 and 3), with NIST's field names and
test group and case ids. The script was run once and is never rerun over
them:

- `ml-dsa-65-sigGen.json`: signing with a given expanded secret key `sk`
  (and its `pk`), `message` and `context`: deterministic (tgId 3, tcId 35,
  39 to 42 and 44; `rnd` is 32 zero bytes) and hedged with the given `rnd`
  (tgId 15, tcId 211 to 216).
- `ml-dsa-65-sigVer.json`: verification (tgId 3), three good signatures
  (tcId 33, 43, 44) and two each with a changed z (31, 36), hint (32, 38),
  commitment (34, 42) or message (35, 39), with `testPassed` and NIST's
  `reason`.

## `kemlock/`: written by Kemlock

`tool/keys/write_samples.dart` wrote these with Kemlock's exporters, so the
tools above can be shown reading them. The passphrase is `fixture passphrase`.

- `p256.pbes2.pem`: `openssl/p256.pkcs8.pem` exported with a passphrase.
  `openssl asn1parse` shows PBES2, PBKDF2 with a 16-byte salt, 600,000
  rounds (`INTEGER :0927C0`), `hmacWithSHA256` and `aes-256-cbc`.
  `openssl pkey -in p256.pbes2.pem -passin 'pass:fixture passphrase' -pubout`
  printed the key's public half, the same as `openssl/p256.spki.pem`:

  ```text
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8XlFnN61stEDDbyCHHhf6SzIhvPN
  5jTJOLq8e3qWxxpjJcBu0hLoyYNO2uk/w7Vna1GWvu1vJqg2GYI396/Kow==
  -----END PUBLIC KEY-----
  ```

  and `-outform DER` gave the bytes of `openssl/p256.pkcs8.der`; with
  `-passin pass:wrong` it printed `Could not find private key` and
  `bad decrypt`.

- `<name>.openssh`, for `ed25519`, `ecdsa256`, `ecdsa384` and `rsa3072`: the
  `openssh/<name>` key exported in OpenSSH form with the passphrase
  (`aes256-ctr`, bcrypt with 16 rounds, 70-character lines).
  `ssh-keygen -y -P 'fixture passphrase' -f <name>.openssh` exited 0 for
  each and printed the key and type of `openssh/<name>.pub`; `ssh-keygen -l`
  on that output printed the fingerprints above:

  ```text
  256 SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4 fixture ed25519 (ED25519)
  256 SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg fixture ecdsa p256 (ECDSA)
  384 SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw fixture ecdsa p384 (ECDSA)
  3072 SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM fixture rsa 3072 (RSA)
  ```

  With `-P wrong` each printed `Load key "<name>.openssh": incorrect
  passphrase supplied to decrypt private key`.
- `<name>.from-openssh.pkcs8.pem`: the same keys exported as plain PKCS#8,
  which is how the vault keeps them. `openssl pkey -check -noout` printed
  `Key is valid` for each, and for `rsa3072` `openssl pkey -pubout` gave the
  same PEM as `ssh-keygen -e -m PKCS8 -f openssh/rsa3072.pub`. (This
  `ssh-keygen` is built on LibreSSL: it writes ECDSA public keys with
  explicit curve parameters and can't export Ed25519 ones this way.)
- `pgp-ed25519.*` and `pgp-rsa4096.*`: PGP keys Kemlock generated for
  `Ada Lovelace <ada@example.org>`, an EdDSA key with a Curve25519 subkey and
  an RSA 4096 key with an RSA 4096 subkey: `.public.asc` the public key,
  `.secret.asc` the secret key exported with the passphrase (S2K usage 254,
  AES-256, Iterated and Salted S2K over SHA-256, coded count 0xf0), and
  `.unprotected.asc` the secret key as the vault keeps it. Imported into a
  throwaway GnuPG 2.5.24 home (`gpg --import` of each `.public.asc`, then of
  each `.secret.asc` with `--pinentry-mode loopback --passphrase`, then
  `gpg --check-signatures` and `gpg --list-secret-keys`), GnuPG printed:

  ```text
  == pgp-ed25519
  gpg: key 8F02623305202D36: public key "Ada Lovelace <ada@example.org>" imported
  gpg: Total number processed: 1
  gpg:               imported: 1
  gpg: key 8F02623305202D36: "Ada Lovelace <ada@example.org>" not changed
  gpg: key 8F02623305202D36: secret key imported
  gpg: Total number processed: 1
  gpg:              unchanged: 1
  gpg:       secret keys read: 1
  gpg:   secret keys imported: 1
  pub   ed25519 2026-11-15 [SC]
        C594BB69FBE8671D507316868F02623305202D36
  uid           [ unknown] Ada Lovelace <ada@example.org>
  sig!3        8F02623305202D36 2026-11-15  [self-signature]
  sub   cv25519 2026-11-15 [E]
        DB259E7FFDCF98F9B7912F7E0D76404F1C786EC7
  sig!         8F02623305202D36 2026-11-15  [self-signature]
  gpg: 2 good signatures
  == pgp-rsa4096
  gpg: key A6B5D78AA13B9834: public key "Ada Lovelace <ada@example.org>" imported
  gpg: Total number processed: 1
  gpg:               imported: 1
  gpg: key A6B5D78AA13B9834: "Ada Lovelace <ada@example.org>" not changed
  gpg: key A6B5D78AA13B9834: secret key imported
  gpg: Total number processed: 1
  gpg:              unchanged: 1
  gpg:       secret keys read: 1
  gpg:   secret keys imported: 1
  pub   ed25519 2026-11-15 [SC]
        C594BB69FBE8671D507316868F02623305202D36
  uid           [ unknown] Ada Lovelace <ada@example.org>
  sig!3        8F02623305202D36 2026-11-15  [self-signature]
  sub   cv25519 2026-11-15 [E]
        DB259E7FFDCF98F9B7912F7E0D76404F1C786EC7
  sig!         8F02623305202D36 2026-11-15  [self-signature]
  pub   rsa4096 2026-11-15 [SC]
        97AE084444E06EC065C5DFBDA6B5D78AA13B9834
  uid           [ unknown] Ada Lovelace <ada@example.org>
  sig!3        A6B5D78AA13B9834 2026-11-15  [self-signature]
  sub   rsa4096 2026-11-15 [E]
        09DA00B22E2CB4D05F8180E9DF7DE80526301D73
  sig!         A6B5D78AA13B9834 2026-11-15  [self-signature]
  gpg: 4 good signatures
  sec   ed25519 2026-11-15 [SC]
        C594BB69FBE8671D507316868F02623305202D36
  uid           [ unknown] Ada Lovelace <ada@example.org>
  ssb   cv25519 2026-11-15 [E]
        DB259E7FFDCF98F9B7912F7E0D76404F1C786EC7
  sec   rsa4096 2026-11-15 [SC]
        97AE084444E06EC065C5DFBDA6B5D78AA13B9834
  uid           [ unknown] Ada Lovelace <ada@example.org>
  ssb   rsa4096 2026-11-15 [E]
        09DA00B22E2CB4D05F8180E9DF7DE80526301D73
  uid validity, sigs: 4 good, 0 not good
  ```
- `pgp-pq-standard.*` and `pgp-pq-gnupg.*`: the two post-quantum PGP keys
  Kemlock generates (`add-post-quantum-pgp`), for
  `Ada Lovelace <pq-standard@example.org>` and `<pq-gnupg@example.org>`,
  written once on 2026-11-17 by `tool/keys/write_pgp_keys.dart` with the
  passphrase `fixture passphrase`, the same three files each. `pq-standard`
  is RFC 9980's version 6 ML-DSA-65+Ed25519 key with an ML-KEM-768+X25519
  subkey, armored without the CRC-24 line; `pq-gnupg` the Ed25519 key with
  a LibrePGP version 5 Kyber-768 with X25519 subkey, whose secret is kept,
  and exported, in gpg-agent's form (GNU mode 1003), both halves protected
  in `.secret.asc`. `tool/keys/gnupg_check.sh` and `sequoia_check.sh`
  record what GnuPG 2.5.24 and sq 1.5.0 made of keys like these
  (`gnupg/pqc/kemlock-check.txt`, `sequoia/pqc/kemlock-check.txt`).

## `tool/keys/gnupg_check.sh`

The check of task 4.9: it generates a fresh Ed25519 and RSA 4096 PGP key
with `tool/keys/write_pgp_keys.dart`, and for each, in a throwaway
`GNUPGHOME`, imports the public key and the passphrase-protected secret key,
fails on any error, checks every signature is good, lists the key, encrypts
a message to it and decrypts it with the passphrase, and signs one and
verifies it. Its run on 2026-11-15, with GnuPG 2.5.24 (the home was under
`$TMPDIR`: GnuPG's sockets must fit in about 100 characters, so it can't sit
deep in a long path):

```text
gpg (GnuPG) 2.5.24
ed25519: 8D9D 513E 9C64 4212 AA35 3009 DCB9 392F 6A78 A8EA
rsa4096: 8FFA 99EB 0BCF 2AB3 96A4 831D D720 17AD 867F 8D0B
== ed25519
gpg: key DCB9392F6A78A8EA: "Ada Lovelace <ed25519@example.org>" not changed
gpg: key DCB9392F6A78A8EA: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
signatures: 2 good
sec   ed25519 2026-11-15 [SC]
      8D9D513E9C644212AA353009DCB9392F6A78A8EA
uid           [ unknown] Ada Lovelace <ed25519@example.org>
ssb   cv25519 2026-11-15 [E]
      AE6E76FFE7C08A653C2B2DAC5817A6C8ECA9EDDF
encrypt and decrypt: ok
sign and verify: ok
== rsa4096
gpg: key D72017AD867F8D0B: "Ada Lovelace <rsa4096@example.org>" not changed
gpg: key D72017AD867F8D0B: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
signatures: 2 good
sec   rsa4096 2026-11-15 [SC]
      8FFA99EB0BCF2AB396A4831DD72017AD867F8D0B
uid           [ unknown] Ada Lovelace <rsa4096@example.org>
ssb   rsa4096 2026-11-15 [E]
      A08619E70695345E5C2AC34C64C63C4884147EF2
encrypt and decrypt: ok
sign and verify: ok
PASS: GnuPG imported, checked and used both keys
```

## `tool/keys/sshsig_check.sh`

The check of task 2.4 of `add-ssh-signatures`, the other way round from the
`openssh/sshsig/` fixtures: `tool/keys/write_sshsigs.dart` signs
`sshsig/hello.txt` for the namespace `file` with Kemlock's code and each of
the `ed25519`, `ecdsa256`, `ecdsa384` and `rsa3072` keys, and `ssh-keygen`
must accept each signature, with `-Y check-novalidate` and with `-Y verify`
against an allowed-signers file naming the key, and must refuse it over a
changed file and for another namespace. This is the only check of the
ECDSA signatures against OpenSSH: their nonce is the deterministic one of
RFC 6979, so they are not the bytes `ssh-keygen` writes. Its run on
2026-11-16, with OpenSSH 10.3p1:

```text
OpenSSH_10.3p1, OpenSSL 3.5.7 9 Jun 2026
ed25519: SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
ecdsa256: SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
ecdsa384: SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
rsa3072: SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
== ed25519
check-novalidate: Good "file" signature with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
verify: Good "file" signature for signer@example.org with ED25519 key SHA256:41s5PBHoZEOR0cJ/tvgDufVKulMqGbNyELiLyECUAW4
a changed file and another namespace: refused
== ecdsa256
check-novalidate: Good "file" signature with ECDSA key SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
verify: Good "file" signature for signer@example.org with ECDSA key SHA256:1LkESzryE4MYynhd3exDCkyGDEpD12LpdfrG6nxFqWg
a changed file and another namespace: refused
== ecdsa384
check-novalidate: Good "file" signature with ECDSA key SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
verify: Good "file" signature for signer@example.org with ECDSA key SHA256:wMVbj/Jt6yy6Qt3JEuQ6XmpwC/kJSMIpk4DJwDPx5Gw
a changed file and another namespace: refused
== rsa3072
check-novalidate: Good "file" signature with RSA key SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
verify: Good "file" signature for signer@example.org with RSA key SHA256:mbgQkBCI/n6+2Z/EVBwEvUdGixwoFo5k7g+teZng2bM
a changed file and another namespace: refused
PASS: OpenSSH accepted the signature of each key
```
