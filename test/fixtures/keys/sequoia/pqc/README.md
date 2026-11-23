# Sequoia's post-quantum keys

A version 6 key and messages made by `sq` 1.5.0, using sequoia-openpgp
2.4.1 with the OpenSSL 4.0.3 backend (`versions.txt`, what `sq version`
printed), which makes and reads RFC 9980's ML-DSA-65+Ed25519 and
ML-KEM-768+X25519. It is Fedora 45's package `sequoia-sq-1.5.0-2.fc45`,
in the Docker image of `tool/keys/docker/sq-1.5.0.Dockerfile`, on the
public image
`registry.fedoraproject.org/fedora@sha256:e203b4174f6a2ce6c160ddc4917d85e6bfce32dfc610d953b355d63ec4c17909`.

`tool/keys/make_sequoia_pqc_fixtures.sh` made every file in one run on
2026-11-17 and is the exact record of the commands:

    docker build -t kemlock-sq:1.5.0 -f tool/keys/docker/sq-1.5.0.Dockerfile tool/keys/docker
    docker run --rm -v "$PWD/test/fixtures/keys:/fixtures" -v "$PWD/tool/keys:/tool:ro" \
      kemlock-sq:1.5.0 sh /tool/make_sequoia_pqc_fixtures.sh /fixtures/sequoia/pqc

**Never regenerate these files.** Add new ones beside them.

## The key

`sq key generate --cipher-suite mldsa65-ed25519 --profile rfc9580
--can-sign --cannot-authenticate --can-encrypt universal --expiration
never`, for `Fixture Sequoia <sq@example.org>`: a version 6 primary key
of algorithm 30 that only certifies, a signing subkey of algorithm 30,
and an encryption subkey of algorithm 35.

- `standard.secret.asc`: the key as generated, unprotected;
- `standard.public.asc`: `sq key delete`, its certificate;
- `standard-protected.secret.asc`: `sq key password`, the same key under
  `fixture passphrase` (S2K usage 254, AES-128, Iterated and Salted S2K
  over SHA-256);
- `<file>.inspect.txt` and `<file>.packets.txt`: `sq inspect` and
  `sq packet dump` of each.

## Messages and signatures

Over `message.txt`, two lines of ASCII ending in LF:

- `message.pgp`: `sq encrypt --for-file standard.public.asc
  --signer-file standard.secret.asc`, a version 6 PKESK and SEIPD
  version 2, AES-256 with OCB, signed inside. `message.decrypt.txt` is
  what `sq decrypt --dump-session-key` printed, the session key included;
- `message.txt.sig`: `sq sign --signature-file`, a detached signature;
- `message.signed.pgp`: `sq sign --message`, an inline-signed message;
- `message.cleartext.asc`: `sq sign --cleartext`;
- `<file>.packets.txt`: `sq packet dump` of each, and `verify.txt` what
  `sq verify` said of the three signatures and the one inside
  `message.pgp`.

## Kemlock's key in Sequoia

`kemlock-check.txt` is what `tool/keys/sequoia_check.sh` printed on
2026-11-17, run in the same image over a standard key
`tool/keys/write_pgp_keys.dart` had just made: sq inspected and linted it
with no issue, listed a signing ML-DSA-65+Ed25519 primary key and an
ML-KEM-768+X25519 subkey that encrypts, encrypted to it (PKESK version 6,
SEIPD version 2 with AES-256 and OCB), decrypted with Kemlock's
passphrase-protected export, and signed with that export and verified the
signature.

`kemlock-messages-check.txt` is the same check run again on 2026-11-17
over fresh keys and the messages `tool/keys/write_pq_messages.dart` wrote
with them: sq decrypted a message Kemlock encrypted to the standard key
and signed (PKESK 6, SEIPD version 2, a good signature inside) and the
message to the standard, the GnuPG-format and an RSA key at once (SEIPD
version 1), and verified a detached and a clear-text signature by the
standard key.

`kemlock-edit-check.txt` is `tool/keys/pq_edit_check.sh`, run on
2026-11-17 in the same image over the keys
`tool/keys/write_pq_edited_keys.dart` had just changed with Kemlock's key
editing (add-post-quantum-pgp, tasks 9.1 and 9.2): sq inspected and
linted with no issue the standard key with a new expiry on it and its
subkey, with a second user ID, with a new ML-KEM-768+X25519 subkey and
with a new ML-DSA-65+Ed25519 signing subkey, and revoked; the revocation
certificate Kemlock made, the primary key then the signature, revoked the
original key; sq encrypted to the new encryption subkey and to the
ML-KEM-768+X25519 subkey Kemlock added to a version 4 Ed25519 key, and
decrypted both; and verified a signature by the key with two keys that
sign.
