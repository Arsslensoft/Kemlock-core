# Shared items

What another app might share to Kemlock (openspec: add-share-extension),
for the tests that tell PGP data from anything else by its content. Made
on 16 November 2026 with GnuPG 2.4.9 (Git for Windows) from the Ed25519
test key already in `../keys/gnupg/`, in a throwaway `GNUPGHOME`. Never
regenerate them: a new run gives other bytes.

| File | What it is |
|---|---|
| `message.txt` | The plain text the others were made from |
| `encrypted.asc` | An armored message encrypted to the key |
| `encrypted.gpg` | The same message, binary |
| `clearsigned.asc` | `message.txt`, clear-signed |
| `detached.sig.asc` | An armored detached signature of `message.txt` |
| `detached.sig` | The same signature, binary |
| `mentions-pgp.txt` | A plain text whose second paragraph holds the words "BEGIN PGP MESSAGE" |

## How they were made

Run from this directory in Git Bash. The home is made with `mktemp -d`
because the agent's socket needs a short path.

```sh
export GNUPGHOME=$(mktemp -d)
gpg --batch --quiet --import ../keys/gnupg/ed25519.secret.asc
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')

printf 'Meet me at the usual place at nine.\nBring the contract.\n' > message.txt

gpg --batch --yes --trust-model always --armor --recipient "$FPR" \
    --output encrypted.asc --encrypt message.txt
gpg --batch --yes --dearmor --output encrypted.gpg encrypted.asc
gpg --batch --yes --local-user "$FPR" --output clearsigned.asc --clearsign message.txt
gpg --batch --yes --local-user "$FPR" --armor --output detached.sig.asc --detach-sign message.txt
gpg --batch --yes --dearmor --output detached.sig detached.sig.asc

printf 'Notes from the meeting on mail encryption.\n\nAn armored message starts with the line BEGIN PGP MESSAGE between\ntwo rows of five dashes, and ends with END PGP MESSAGE.\n' > mentions-pgp.txt

gpgconf --kill gpg-agent
rm -rf "$GNUPGHOME"
```

`$FPR` is `1FCDA135EE42400EC2B77CE677249ABE661CF8DB`, "Fixture Ed25519
<ed25519@example.org>". `gpg --verify` accepts `clearsigned.asc`, and
`detached.sig` and `detached.sig.asc` against `message.txt`.

## What `gpg --list-packets` says

`encrypted.asc` and `encrypted.gpg` (the same packets):

```text
gpg: encrypted with cv25519 key, ID 841A40E3B199EA67, created 2026-11-15
      "Fixture Ed25519 <ed25519@example.org>"
# off=0 ctb=84 tag=1 hlen=2 plen=94
:pubkey enc packet: version 3, algo 18, keyid 841A40E3B199EA67
	data: [263 bits]
	data: [392 bits]
# off=96 ctb=d2 tag=18 hlen=2 plen=120 new-ctb
:encrypted data packet:
	length: 120
	mdc_method: 2
# off=117 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
:compressed packet: algo=2
# off=119 ctb=ac tag=11 hlen=2 plen=73
:literal data packet:
	mode b (62), created 1794889044, name="message.txt",
	raw data: 56 bytes
```

`clearsigned.asc`: GnuPG lists the text as a literal packet and stops,
so the signature block under it is listed on its own as well (`sed -n
'/^-----BEGIN PGP SIGNATURE-----$/,$p' clearsigned.asc | gpg
--list-packets`):

```text
# off=0 ctb=ff tag=63 hlen=2 plen=19 new-ctb
:packet 63: length 19 - gpg control packet# off=21 ctb=cb tag=11 hlen=2 plen=0 partial new-ctb
:literal data packet:
	mode t (74), created 0, name="",
	raw data: unknown length
```

```text
# off=0 ctb=88 tag=2 hlen=2 plen=117
:signature packet: algo 22, keyid 77249ABE661CF8DB
	version 4, created 1794889044, md5len 0, sigclass 0x01
	digest algo 10, begin of digest b7 93
	hashed subpkt 33 len 21 (issuer fpr v4 1FCDA135EE42400EC2B77CE677249ABE661CF8DB)
	hashed subpkt 2 len 4 (sig created 2026-11-17)
	subpkt 16 len 8 (issuer key ID 77249ABE661CF8DB)
	data: [256 bits]
	data: [256 bits]
```

`detached.sig.asc` and `detached.sig` (the same packet):

```text
# off=0 ctb=88 tag=2 hlen=2 plen=117
:signature packet: algo 22, keyid 77249ABE661CF8DB
	version 4, created 1794889045, md5len 0, sigclass 0x00
	digest algo 10, begin of digest ef 5e
	hashed subpkt 33 len 21 (issuer fpr v4 1FCDA135EE42400EC2B77CE677249ABE661CF8DB)
	hashed subpkt 2 len 4 (sig created 2026-11-17)
	subpkt 16 len 8 (issuer key ID 77249ABE661CF8DB)
	data: [256 bits]
	data: [254 bits]
```
