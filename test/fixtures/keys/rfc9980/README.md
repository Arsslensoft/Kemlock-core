# RFC 9980 test vectors

The sample keys, messages and signatures of appendix A of RFC 9980,
"Post-Quantum Cryptography in OpenPGP" (June 2026), copied out of
https://www.rfc-editor.org/rfc/rfc9980.txt (SHA-256
`3d2b30bdaecaf28bfde85545bd24e661a97f1e7b371a963778d4314a678c93ac`) on
2026-11-17 by `tool/keys/rfc9980_vectors.dart`, which was run once and is
never rerun over them:

    dart run tool/keys/rfc9980_vectors.dart rfc9980.txt test/fixtures/keys/rfc9980

`a<n>-<what>.asc` is the armored block of subsection A.n, without the
RFC's indentation:

| Section | Keys | Files |
|---|---|---|
| A.1 | v6 Ed25519, v6 ML-KEM-768+X25519 subkey | secret, public, message (PKESK v6, SEIPD v2) |
| A.2 | v4 Ed25519, v4 ML-KEM-768+X25519 subkey | secret, public, message-seipd1 (PKESK v3, SEIPD v1), message-seipd2 (PKESK v6, SEIPD v2) |
| A.3 | v6 ML-DSA-65+Ed25519, ML-KEM-768+X25519 subkey | secret, public, message, signature |
| A.4 | v6 ML-DSA-87+Ed448, ML-KEM-1024+X448 subkey | secret, public, message, signature |
| A.5 | v6 SLH-DSA-SHAKE-128s, ML-KEM-768+X25519 subkey | secret, public, message, signature |
| A.6 | v6 SLH-DSA-SHAKE-128f, ML-KEM-768+X25519 subkey | secret, public, signature |
| A.7 | v6 SLH-DSA-SHAKE-256s, ML-KEM-1024+X448 subkey | secret, public, signature |

Every message and signature is over "Testing\n", and every message is
signed inside by the section's secret key.

`values.json` holds what the RFC prints beside them, in lower-case hex:
for each section (`a1` ...) the fingerprints of the primary key and the
subkey, and for each message (`a1-message` ...) the `mlkemKeyShare` and
`ecdhKeyShare` that go into the key combiner, its output
`multiKeyCombine` (the key-wrapping key) and the session key.
