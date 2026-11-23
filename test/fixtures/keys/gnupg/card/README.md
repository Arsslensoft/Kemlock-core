# Card stubs

GnuPG's form of a key whose secret parts are on an OpenPGP card: each
secret key packet holds the public key, then, in place of the secret, the
GNU extension S2K that says "divert to card" and names the card by its
serial number. Kemlock stores a card key's private half in this form
(openspec: add-openpgp-card, design decision 4). Never regenerate these
files; add new ones beside them.

## `stub-ed25519.gpg`

Made by hand on 2026-11-16 from `../ed25519.public.gpg` (the Ed25519 key
with a Curve25519 subkey that GnuPG made), as if both keys were on one card
whose application identifier is the made-up
`D276000124010304FFFF123456780000`: version 3.4, manufacturer `FFFF` (the
test range), serial number `12345678`.

A throwaway Dart script, kept out of the repo, copied every packet and
turned the public key packet (tag 6) into a secret key packet (tag 5) and
the public subkey packet (tag 14) into a secret subkey packet (tag 7),
keeping the old-format headers, with these 25 bytes after each public
body:

```text
ff                                S2K usage 255
00                                cipher: none
65 00                             S2K type 101 (GNU extension), hash 0
47 4e 55                          "GNU"
02                                mode 2: divert to card
10                                serial number length: 16
d2 76 00 01 24 01 03 04 ff ff 12 34 56 78 00 00
```

That is what GnuPG's `build-packet.c` writes for a card key on export
(S2K mode 1002, the serial in the IV field, cipher and hash 0). The user
ID and the signatures are the public key's, byte for byte, so the
fingerprints are the same.

`gpg --list-packets stub-ed25519.gpg` with GnuPG 2.4.9 (Git for Windows):

```text
# off=0 ctb=94 tag=5 hlen=2 plen=76
:secret key packet:
	version 4, algo 22, created 1794769831, expires 0
	pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
	pkey[1]: [263 bits]
	gnu-divert-to-card, algo: 0, simple checksum, hash: 0
	serial-number:  d2 76 00 01 24 01 03 04 ff ff 12 34 56 78 00 00
	keyid: 77249ABE661CF8DB
# off=78 ctb=b4 tag=13 hlen=2 plen=37
:user ID packet: "Fixture Ed25519 <ed25519@example.org>"
# off=117 ctb=88 tag=2 hlen=2 plen=175
:signature packet: algo 22, keyid 77249ABE661CF8DB
	...
# off=294 ctb=9c tag=7 hlen=2 plen=81
:secret sub key packet:
	version 4, algo 18, created 1794769832, expires 0
	pkey[0]: [88 bits] cv25519 (1.3.6.1.4.1.3029.1.5.1)
	pkey[1]: [263 bits]
	pkey[2]: [32 bits]
	gnu-divert-to-card, algo: 0, simple checksum, hash: 0
	serial-number:  d2 76 00 01 24 01 03 04 ff ff 12 34 56 78 00 00
	keyid: 841A40E3B199EA67
# off=377 ctb=88 tag=2 hlen=2 plen=154
:signature packet: algo 22, keyid 77249ABE661CF8DB
	...
```

`gpg --batch --import stub-ed25519.gpg` into an empty home reads it as a
card key, and asks for the card before it lists the secret key:

```text
gpg: key 77249ABE661CF8DB: public key "Fixture Ed25519 <ed25519@example.org>" imported
gpg: To migrate 'secring.gpg', with each smartcard, run: gpg --card-status
gpg: key 77249ABE661CF8DB: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
```

## `stub-ed25519-subkey.gpg`

Written by Kemlock's `cardStubKey` (`lib/crypto/keys/openpgp/writer.dart`)
on 2026-11-17 from the same public key and card, with only the subkey on
the card: the primary key gets the stub that says it has no secret here
(mode 1, nothing after it), the subkey the "divert to card" stub. The
test pins the writer to these bytes, and to `stub-ed25519.gpg` for both
keys on the card.

`gpg --list-packets stub-ed25519-subkey.gpg` with GnuPG 2.4.9:

```text
# off=0 ctb=94 tag=5 hlen=2 plen=59
:secret key packet:
	version 4, algo 22, created 1794769831, expires 0
	pkey[0]: [80 bits] ed25519 (1.3.6.1.4.1.11591.15.1)
	pkey[1]: [263 bits]
	gnu-dummy, algo: 0, simple checksum, hash: 0
	protect IV: 
	keyid: 77249ABE661CF8DB
# off=61 ctb=b4 tag=13 hlen=2 plen=37
:user ID packet: "Fixture Ed25519 <ed25519@example.org>"
# off=100 ctb=88 tag=2 hlen=2 plen=175
:signature packet: algo 22, keyid 77249ABE661CF8DB
	...
# off=277 ctb=9c tag=7 hlen=2 plen=81
:secret sub key packet:
	version 4, algo 18, created 1794769832, expires 0
	pkey[0]: [88 bits] cv25519 (1.3.6.1.4.1.3029.1.5.1)
	pkey[1]: [263 bits]
	pkey[2]: [32 bits]
	gnu-divert-to-card, algo: 0, simple checksum, hash: 0
	serial-number:  d2 76 00 01 24 01 03 04 ff ff 12 34 56 78 00 00
	keyid: 841A40E3B199EA67
# off=360 ctb=88 tag=2 hlen=2 plen=154
:signature packet: algo 22, keyid 77249ABE661CF8DB
	...
```

`gpg --batch --import` reads it as `stub-ed25519.gpg`: "secret key
imported", and the card is asked for before the key is listed.

## `signed/`

Signatures made on the fake OpenPGP card through the whole message flow
(add-openpgp-card, task 6.5): a PGP job whose signer is a card key, its
private step through a card bridge, the card session and the fake card,
which held the secret parts of `../ed25519.secret.gpg`. Written once on
2026-11-17 by `test/features/keys/card_signature_fixtures_test.dart` with
`OUT` set, at 2026-11-17 12:00 UTC:

- `message.asc`: the clear-signed text "Signed on a security key." and a
  second line, as the Sign sheet makes it from a typed message.
- `data.bin` and `data.bin.sig`: a 1000-byte file (byte `i` is
  `(i * 31 + 7) & 0xff`) and its detached signature, as the Sign sheet
  makes it for a file.

Checked by hand with GnuPG 2.4.9 in a throwaway home holding only the
public half:

```text
$ gpg --import ed25519.public.gpg
gpg:               imported: 1
$ gpg --verify signed/message.asc
gpg: Signature made Tue Nov 17 07:00:00 2026 EST
gpg:                using EDDSA key 1FCDA135EE42400EC2B77CE677249ABE661CF8DB
gpg: Good signature from "Fixture Ed25519 <ed25519@example.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 1FCD A135 EE42 400E C2B7  7CE6 7724 9ABE 661C F8DB
$ gpg --verify signed/data.bin.sig signed/data.bin
gpg: Signature made Tue Nov 17 07:00:00 2026 EST
gpg:                using EDDSA key 1FCDA135EE42400EC2B77CE677249ABE661CF8DB
gpg: Good signature from "Fixture Ed25519 <ed25519@example.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: 1FCD A135 EE42 400E C2B7  7CE6 7724 9ABE 661C F8DB
```

The warning is GnuPG's about trust in a key just imported, not about the
signatures.

## `generated-ed25519.public.gpg`

The public half of keys generated on the fake OpenPGP card as the
Generate sheet makes them (add-openpgp-card, task 10.4): Ed25519 in the
signature and authentication places, Curve25519 in the decryption
place, made by the card's GENERATE, their fingerprints and times written,
the user ID "Card Fixture <card@example.org>" certified and the two
subkeys bound by the card's signature key. Written once on 2026-11-17 by
`test/security_key/openpgp_card/card_generated_fixture_test.dart` with
`OUT` set, dated 2026-11-16 12:00 UTC.

With GnuPG 2.4.9 in a throwaway home:

```text
$ gpg --import generated-ed25519.public.gpg
gpg: key 00AF23A3988E4922: public key "Card Fixture <card@example.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
$ gpg --check-signatures
pub   ed25519 2026-11-16 [SC]
      622A3C8620F8F06835E581A500AF23A3988E4922
uid           [ unknown] Card Fixture <card@example.org>
sig!3        00AF23A3988E4922 2026-11-16  [self-signature]
sub   cv25519 2026-11-16 [E]
sig!         00AF23A3988E4922 2026-11-16  [self-signature]
sub   ed25519 2026-11-16 [A]
sig!         00AF23A3988E4922 2026-11-16  [self-signature]
gpg: 3 good signatures
```

A first try dated a few hours after the machine's clock was refused by
GnuPG as made "in the future", its user ID skipped: a key generated on a
phone whose clock runs ahead would meet the same.

## `subkeys.secret.gpg`

A GnuPG key whose parts go to different places of a card, for the plan of
a move (add-openpgp-card, task 11.1): an Ed25519 primary key that only
certifies, an encryption subkey made at a faked time in 2020 that expired
the next day, then a signing, a newer encryption and an authentication
subkey. Made on 2026-11-17 with GnuPG 2.4.9, unprotected:

```sh
gpg --faked-system-time 20200101T000000 --quick-generate-key 'Fixture Subkeys <subkeys@example.org>' ed25519 cert 0
gpg --faked-system-time 20200101T000001 --quick-add-key <fingerprint> cv25519 encr 2020-01-02
gpg --quick-add-key <fingerprint> ed25519 sign 0
gpg --quick-add-key <fingerprint> cv25519 encr 0
gpg --quick-add-key <fingerprint> ed25519 auth 0
gpg --export-secret-keys <fingerprint> > subkeys.secret.gpg
```

`subkeys.list.txt` is what `gpg --list-keys --list-options
show-unusable-subkeys --with-subkey-fingerprints` printed for it.
