# Key unlock fixtures

Written once by test/vault/key_unlock_fixtures_generator_test.dart, from fixed seeds and with the real scrypt parameters, when add-security-key-unlock was built, and never regenerated.

Each file holds one vault config (`config`), as `backmycodes_vault_config` stores it, in one way of
opening of add-security-key-unlock, and the secrets that open it. The four configs hold the same
ML-KEM-1024 key pair, whose private key has the SHA-256 `39e655682c73034dfe7db9626e653e7e4b0b19758604281d91e6f6cbe8b21206`.

| File | Mode | Keys enrolled |
|---|---|---|
| `password-with-key.json` | `password` | first |
| `key.json` | `key` | first |
| `both.json` | `both` | first |
| `both-two-keys.json` | `both` | first, second |

The secrets, the same in every file:

- the password: `fixture password` (scrypt N=131072, r=8, p=1, with the config's `salt`);
- the key secret, base64: `TEkaCouVscMaaE9tnialA25lfdyWncnGv1khJqU/q3w=`;
- the `hmac-secret` output of the first key, base64: `bgYIijLjL1233KEgLbOdf8m7ZSQIYPTQupwrlfJWq6U=`;
- the `hmac-secret` output of the second key, base64: `imaCLoeHKaAPwyUHa055ot3k3CXby25//Nur5VrgrJs=`.

These are test values made from fixed seeds. No real key gave them.
