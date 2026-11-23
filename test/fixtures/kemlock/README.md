# Kemlock Server fixtures

What the client in `lib/features/sync/kemlock/` holds itself to, read from the server's code
(`kemlock-server`, branch `build/vertical-slice`, `docs/crypto.md` and `crates/kemlock-api-kem/src`).
`test/features/sync/kemlock/fake_kemlock_server.dart` serves the same shapes.

Binary values are base64url without padding. Bodies are camelCase and the server refuses unknown fields.
Errors are `application/problem+json` with `type` `urn:kemlock:problem:<slug>`.

## Routes the server has

| Route | Shape |
| --- | --- |
| `GET /kem/v1/config` | `{server: "kemlock-server", apiVersions, version, serverId, domain, setup, signupsAllowed, features}` |
| `POST /kem/v1/auth/prelogin` | `{email}` to `{kdf: {memoryKib, iterations, parallelism, salt}}` |
| `POST /kem/v1/auth/methods` | `{email}` to `{methods: ["password"]}` |
| `POST /kem/v1/accounts/register/start`, `/finish` | OPAQUE registration |
| `POST /kem/v1/auth/opaque/start` | `{email, request}` to `{response, loginState}` |
| `POST /kem/v1/auth/opaque/finish` | `{email, loginState, finalization, device: {id?, name, kind?}}` with a DPoP proof, to `{status: "signed_in" or "two_factor_required", tokens?, challenge?, methods?}` |
| `POST /kem/v1/auth/two-factor` | `{challenge, method: "totp", code}` to the tokens |
| `POST /kem/v1/auth/token` | `{grantType: "refresh_token", refreshToken}` with a DPoP proof, to the tokens |
| `PUT /kem/v1/items/{id}` | one item; `If-Match: <revision>` or `If-None-Match: *` |
| `POST /kem/v1/items:batch` | `{writes: [{expectedRevision, item}]}` to `{items}`; all or none; a stale write is 409 with `itemId` and `currentRevision` |
| `GET /kem/v1/sync?since=&limit=` | `{items, cursor, more}`, 304 when nothing changed, 410 when the cursor is too old |
| `GET /kem/v1/live` | WebSocket, `{"type":"sync"}` frames |
| `POST /kem/v1/items/{id}/files` | `{size}` to `{fileId, itemId, size, maxSize, uploadUrl, presigned, expiresIn}`; the item must exist |
| `PUT/GET/DELETE /kem/v1/items/{id}/files/{fileId}` | the `KMA1` bytes; `POST .../finish` after a pre-signed upload |
| `GET /kem/v1/devices/approvals`, `POST .../{id}` | the pending requests, and `{decision, sealedKey}` |
| `PUT/GET/DELETE /kem/v1/devices/key-copy` | `{wrappedKey, protection}`, protection one of `secure-enclave`, `keystore`, `web-crypto`, `software` |
| `POST /kem/v1/devices/sign-out` | `{deviceId}` |

A token response is `{tokenType: "DPoP", accessToken, expiresIn, refreshToken, refreshExpiresIn, userId, deviceId, admin}`.
A request with a token sends `Authorization: DPoP <token>` and a `DPoP` proof; the proof must carry the server's
`nonce` (a 401 `use-dpop-nonce` with `DPoP-Nonce` hands it out), `ath`, `htm`, `htu`, `iat` within 60 seconds and
a `jti` it has not seen. A session that ended is 401 `session-ended` with `reason`.

An item on the wire is `{id, owner, kind, format: "kem1", revision, keyVersion, ciphertext, itemKey, deleted}`.
**A tombstone carries no time.** The phone dates a deletion by its last sync before it saw it, never after now, so an edit made since then outlives it.

## Kind names

`crypto.md` lists `login`, `otp`, `note`, `backup-codes`, `passkey`, `pgp-key`, `ssh-key`, `certificate`, `card`
and `identity`. `items.json` holds only those. The plan's `key` (a signing, exchange or other key), `key-otp` (a code
whose secret lives on a security key) and `contact` are not in `crypto.md` yet; the server takes any kind of 1 to 64
characters of `[a-z0-9_-]`, so the client uses them and their fixtures wait for the server session to confirm them.

## Routes added since, and what is still open

Read from the server's `build/vertical-slice` (`docs/federation.md` too), and in the client and its fake:

| Route | Shape |
| --- | --- |
| `GET /kem/v1/config?vault=user:<uuid>` (repeatable, public) | adds `vaults: [{vault, epoch, servers: [{serverId, address, identityKey, role}], promotion}]`; the home first; `promotion` is a base64url CBOR envelope `{0: body, 1: sig1("federation-promotion", body)}` signed by the new home, `null` at epoch 1 |
| `POST /kem/v1/auth/device-key/challenge`, `/verify` | `{deviceId}` and `{challenge}`, each with a DPoP proof of the device key, to `{challenge}` and the tokens; for an account copied to a replica |
| `GET /kem/v1/sync` | adds `siblings: [{itemId, versions: [item]}]` on every page that is not a 304; `POST /kem/v1/items/{id}/siblings/resolve` answers `{resolved}`, or a 409 `siblings-already-sent` |
| `POST /kem/v1/auth/passkey/options` | no body, a DPoP proof; `{options: {challenge, rpId, allowCredentials: [], userVerification: "required"}, challenge}` |
| `POST /kem/v1/auth/passkey/verify` | `{challenge, credential: PublicKeyCredential.toJSON(), device}` to `{tokens, passkeyId, prf: {wrappedKey, keyVersion} or null, keyVersion}` |
| `GET /kem/v1/account/passkeys`, `PUT .../{id}/prf` | `{passkeys: [{id, name, prf, prfKeyVersion, ...}]}`; `{wrappedKey (92 bytes), keyVersion}` |
| `GET /kem/v1/account/keys` | `{keyVersion, kdf, wrappedRootKey, publicBundle, bundleSignature, sealedPrivateKeys}`, no PRF wraps |
| `GET /kem/v1/auth/device/request/{id}` | an approved poll answers `{status, sealedKey, accountId}` |
| `POST /kem/v1/auth/sso/start` | `{challenge, state, redirect?}` with a DPoP proof, to `{authorizationUrl, providerName}`; `challenge` is the unpadded base64url SHA-256 (32 bytes), `state` 16 to 256 unreserved characters; 404 `sso-not-configured` |
| `GET /kem/v1/auth/sso/callback` | the provider's redirect; 303 to `kemlock://sso?code=<sealed>&state=<the phone's>`, or `?error=<oauth code>&state=`; the phone never calls it |
| `POST /kem/v1/auth/sso/finish` | `{code, verifier (43 to 128 unreserved characters), device}` with a DPoP proof of the same key, to `{status, tokens?, challenge?, methods?, newAccount, mfaViaSso}`; 400 `sso-state-invalid`, 401, 403 `sso-required`, `sso-no-account` and kin |
| `POST /kem/v1/auth/sso/backchannel-logout` | the provider's, form `logout_token`; no DPoP; the phone never calls it |
| `POST` and `DELETE /kem/v1/devices/push-token` | `{kind: "fcm" or "apns", token (1 to 512 characters, no whitespace)}`, 204; `DELETE` takes no body, 204. The device body has no push token: `DeviceDto` is `{id?, name, kind?, bitwardenDeviceIdentifier?}` and refuses any other member |
| `GET /api/config` (Bitwarden API) | adds `kemlock: {api: "<domain>/kem/v1", versions: ["v1"]}`, which the move offer reads |

The manifest, the device list, the Bitwarden enrolment and `deletedAt` on tombstones, which the app contract listed, are served too.

Not served, or not read against the client (the client does without each), by the server's OpenAPI document at 2f66a04
(`test/fixtures/server/openapi.json`, 106 paths, which every route of the tables above is in):

- `/kem/v1/auth/methods` answers `methods` and, with `sso` in them, `sso: {providerName}`. It has no "Require SSO"
  (`ssoRequired`, which the client reads and so never sees `true`) and no passkey (they are discoverable).
- The second steps other than `totp` (`email`, `duo`, `yubikey`, `recovery`, `webauthn`) are routes of the document that the
  client doesn't call; it answers `totp` and says where the person goes for the others.
- A file's size and SHA-256 are not in `FileDto`; only `size` and `status`.
- `key`, `key-otp` and `contact` are not in `crypto.md`; the server takes any kind of 1 to 64 characters.
- The document holds no examples, so the fake can't answer with them: `openapi_contract_test.dart` checks each answer the
  fakes give against the schema of its status instead.

## Where the client and the document differ

The contract test (`test/features/sync/kemlock/openapi_contract_test.dart`) lists every route the client calls and checks
each in the document. The client calls no route the document lacks. What the document lacks or gets wrong, where the
server's code (`build/vertical-slice`) does it, for the server session:

- `GET /kem/v1/config` takes repeated `?vault=user:<uuid>`; the document lists no query parameter.
- A write of `POST /kem/v1/items:batch` and `PUT /kem/v1/items/{id}` takes `tags` and `tagVersion` beside the item, and the
  answers carry `tags` and `tagsStored` (`duplicates.rs`); `ItemDto`, `BatchResponse` and the item's answer list none.
- Two structs are named `GroupDto`, the duplicate cleaner's `{items}` and the spaces' `{id, members, name}`; the document
  holds the second, so `DuplicatesResponse.groups` is wrong.
- `POST /kem/v1/send-access/{access_id}` and `.../file` take an optional body, and the document marks it required.
- A response that the document lists no status for (a 401 `use-dpop-nonce`, a 429, a 5xx) is let through by the test; the
  document might name them once for every route.
- The problems carry members besides `type`, `title`, `status` and `detail` (`itemId`, `currentRevision`, `reason`, `seq`,
  `head`, `maxSize`, `spaceId`, `currentCounter`, `currentTagVersion`, `retryAfter`) that `ProblemDoc` doesn't list.

The client's own mistake it found: it asked `/spaces/{id}/pending` for the pending changes; the server's route is
`/spaces/{id}/chain/pending` (fixed, with the fake).

## `items.json`

The plaintext JSON of each confirmed kind, written once and never regenerated. A kind confirmed later goes in a
new file beside it.

## Send routes

What `lib/features/sync/kemlock/km_sends_api.dart` holds itself to, read again from the server's `build/vertical-slice` at 4f763da:
`crates/kemlock-api-kem/src/routes/sends.rs`, the use cases in `crates/kemlock-app/src/sends/`, the checks in
`crates/kemlock-domain/src/sends.rs`, the problems in `crates/kemlock-api-kem/src/problem.rs`, and `docs/crypto.md` "Sends"
(`docs/plans/add-sends.md`, task 1.2). The fake serves the same shapes (`test/features/sync/kemlock/fake_sends.dart`). Times are
Unix seconds, binary values are base64url without padding, bodies are camelCase, and every request body is refused if it has a field
the server doesn't know (`deny_unknown_fields`). `/kem/v1/config` lists `sends` in `features`.

| Route | Auth | Body | Answer |
| --- | --- | --- | --- |
| `POST /kem/v1/sends` | DPoP | `CreateSendRequest` below | 201 `SendDto` and `Location: /kem/v1/sends/{id}`; a file Send adds `uploadUrl` and stays closed until its bytes land |
| `GET /kem/v1/sends` | DPoP | none | 200, a JSON array of `SendDto`, newest first |
| `GET /kem/v1/sends/{id}` | DPoP | none | 200 `SendDto`; 404 for a Send of another account |
| `PUT /kem/v1/sends/{id}` | DPoP | `UpdateSendRequest` below | 200 `SendDto` |
| `DELETE /kem/v1/sends/{id}` | DPoP | none | 204, the file's bytes included; a policy that removes Sends doesn't refuse it |
| `PUT /kem/v1/sends/{id}/file` | DPoP | the `KMA1` bytes, with `Content-Length` (not chunked) equal to `file.size` | 200 `SendDto` with `file.ready` true, and no `uploadUrl` |
| `POST /kem/v1/send-access/{accessId}` | none, no DPoP | empty, or `{password: <proof>}` | 200 `AccessDto`, `Cache-Control: private, no-store`; a text Send counts an open |
| `POST /kem/v1/send-access/{accessId}/file` | none, no DPoP | the same | 200 the `KMA1` bytes (`application/octet-stream`, `Content-Length`, `private, no-store`, `nosniff`); counts an open |

Every answer of these routes, the public ones too, carries the current `DPoP-Nonce`. A path id that isn't a UUID is a 400.

**`CreateSendRequest`**: `id` (a version 4 UUID the client chooses; a taken one is 409), `kind` (`text` or `file`), `meta` (28 bytes to 16 KiB),
`sealedKey` (exactly 64 bytes), `payload` (28 bytes to 256 KiB), `file?: {size}` (a file Send only, a note has none; `size` is a `KMA1`
length, above 0 and at most `max_file_size`, 100 MiB by default), `maxAccess?` (an integer from 1), `hideEmail` and `disabled` (both default
false), `expiresAt?`, `deletionAt` (required: in the future, at most 30 days and one hour of clock skew away), `password?` (exactly 32 bytes).
`expiresAt` may not come after `deletionAt`. The server checks lengths and shapes and never the seals.

**`UpdateSendRequest`**: `meta` (28 bytes to 16 KiB, required), `payload?` (a text Send only: a file Send's content can't change, 400),
`maxAccess?`, `hideEmail`, `disabled`, `expiresAt?`, `deletionAt` (all replaced, so all are sent again), `password?` (a new proof of exactly 32
bytes; absent keeps the password) and `removePassword` (default false; not together with `password`, 400). The key, the file and the open count
never change.

**`SendDto`**: `{id, accessId, kind, meta, sealedKey, payload, file?: {size, ready}, hasPassword, maxAccess?, accessCount, hideEmail, disabled,
expiresAt?, deletionAt, createdAt, revisedAt, uploadUrl?}`. `accessId` is the 16 bytes of `id` in unpadded base64url. `uploadUrl` is only in the
answer that makes a file Send, and the server builds it from its configured `domain` (`<domain>/kem/v1/sends/{id}/file`); the client sends the
bytes to its own `/sends/{id}/file` and only checks that the address is on the server's host.

**`AccessDto`**: `{id (the access id), kind, payload, fileSize?, expiresAt?, deletionAt, senderEmail?}`. `senderEmail` is absent when the sender
hid it.

**Opens.** A text Send counts one when `POST /send-access/{accessId}` answers, before the answer is sent, so an answer lost on the way spends it.
A file Send's access answer counts nothing and can be asked again; the download (`.../file`) counts. A Send that is off, expired (`expiresAt`),
past `deletionAt`, used up, or a file Send whose bytes haven't landed is a plain 404 whatever the password.

**Password.** The proof is the 32 bytes the client derives (`docs/crypto.md`). A Send with a password answers 401 `send-password-required` to a
request with no proof and 401 `send-wrong-password` to a wrong one; a proof sent on an access has no length check, so one of another length is a
wrong password.

**Rate limit.** Each access that carries a proof counts one try against the Send's access id, found or not, 10 a minute; a right proof clears the
count. The eleventh waits 1 second, and each further try over the limit doubles the wait (2, 4, ... up to an hour). A refused try is a 429
`rate-limited` with `retryAfter` (seconds) and a `Retry-After` header. A request with no proof isn't counted. The order of the checks is the body
(400), the rate limit (429), the Send (404), the password (401).

**Problems**, as `application/problem+json` with `type` `urn:kemlock:problem:<slug>`. The owner's routes also answer the usual 401 problems of any
DPoP route (`unauthorized`, `session-ended`, `invalid-dpop-proof`, `use-dpop-nonce`).

| Status | Slug | When |
| --- | --- | --- |
| 400 | `invalid-request` | a body or field the server refuses, with its words in `detail`: a field it doesn't know, a kind that isn't `text` or `file`, an id that isn't a version 4 UUID, a length, a time, a view limit under 1, a deletion date that is past or too far, an expiry after the deletion, `password` with `removePassword`, a note's upload ("a note has no file"), a file Send's new content |
| 400 | `length-mismatch` | the upload isn't `file.size` bytes long |
| 400 | `upload-interrupted` | the upload broke off before its end |
| 401 | `send-password-required`, `send-wrong-password` | the password, with `WWW-Authenticate: KemlockSend` |
| 403 | `send-policy` | a policy of one of the owner's spaces ("allows you only to delete an existing Send", or "requires Sends to show your email"); the title is fixed and the words are in `detail`. It refuses make and change, never delete |
| 403 | `storage-disabled` | the account's file Send quota is 0; the words are in `title`, Vaultwarden's |
| 404 | `not-found` | no such Send of this account, and on the public routes any Send that is closed, as above |
| 409 | `already-exists` | the id is taken |
| 409 | `already-uploaded` | the file's bytes landed already |
| 411 | `length-required` | an upload with no `Content-Length`, or a chunked one |
| 413 | `file-too-large` | with `maxSize`, the server's `max_file_size`; on make, and on an upload when the limit was lowered since |
| 413 | `storage-limit-reached`, `storage-limit-exceeded` | the file Send quota is used up, or this file would pass it; the words are in `title` |
| 413 | `payload-too-large` | a JSON body over 2 MiB |
| 415 | `not-kma1` | the bytes don't start like a `KMA1` file, with the reason in `detail` |
| 429 | `rate-limited` | too many password tries, as above |
| 500 | `internal` | the server's own failure; it names no cause |

**One table, two APIs.** The Bitwarden API keeps its Sends in the same table (`kemlock-server`, `bw_sends.rs`): `meta` holds Bitwarden's JSON,
`sealedKey` the UTF-8 of its encrypted key string, `payload` its data string. `GET /kem/v1/sends` returns them with the Kemlock ones, with a
`sealedKey` that is never 64 bytes, while a Kemlock Send is skipped in Bitwarden's lists. The client leaves a Send whose `sealedKey` isn't 64 bytes
out of its list. The access routes serve a Bitwarden Send as well, but a Kemlock link has a 43-character key and a Bitwarden one 22, which only
the client sees.

### Agreed with the server, settled

The points the plan asked the server to settle, answered by its code at 4f763da:

- **`test-vectors/send.json`** is published, and `test/fixtures/server/send.json` is the same file (SHA-256 7a9c3bfe...cecfd9).
- **The `meta` comment** of `CreateSendRequest` now says it is sealed under the meta key from the owner's item-wrap child key, never the link key.
- **The recipient page** exists in the web vault: `Root.tsx` shows `SendAccess` for a `#/send/<accessId>/<key>` hash, and
  `web/e2e/7-send-recipient.spec.ts` opens one.
- **`sends` in `features`** is listed. `max_file_size` is not offered there (the config has no such member); a client learns the limit from the
  413 `file-too-large` and its `maxSize`.
- **The 429** carries both `retryAfter` and `Retry-After`, as the other rate limits do (`rate_limited` in `problem.rs`).
- **Lost opens** are the server's rule: it counts a text Send's open before it answers, and says so in `sends/mod.rs` ("A note counts a view when
  it is opened"). There is no second step to confirm a delivery.
- **Bitwarden links.** The server never sees a key, so it can't promise a Kemlock Send never has a 16-byte one; `docs/crypto.md` gives a Kemlock
  link a 32-byte key (43 characters), and the Send tables are shared, as above. The app tells them apart by the key's length, and by `sealedKey`
  in the list.

Nothing from the Send routes is left open.
