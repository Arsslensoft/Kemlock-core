# Vaultwarden security key (WebAuthn) fixtures

What a real Vaultwarden sent and accepted for two-step login with a
security key (provider 7), recorded on 16 November 2026 for the change
`add-vaultwarden-security-key`.

The server was `vaultwarden/server:latest`, version 1.37.5, run in Docker
on the development machine at `https://localhost:18443` with a self-signed
certificate and `DOMAIN=https://localhost:18443`. The key was a software
P-256 credential made by the test itself, not a hardware key: it was
registered with a test account through the web vault's two-factor routes
and then used to sign in. Every value here is a test value; the account
and the server no longer exist.

- `providers2-7.json`: the exact `TwoFactorProviders2["7"]` value of the
  server's "two factor required" answer (HTTP 400) to
  `POST /identity/connect/token`.
- `token.json`: the exact `twoFactorToken` the server then accepted
  (HTTP 200) for that challenge, sent with `twoFactorProvider=7`. Its
  `clientDataJson` decodes to
  `{"type":"webauthn.get","challenge":"x8G1k0ZH-D-N9AZUasBulEHWFpbehFLDT5O2O-L0Qmk","origin":"https://localhost:18443","crossOrigin":false}`.
- `providers2-7-no-domain.json`: the same account's challenge from the
  same data on a server started without `DOMAIN`. It still gives one, for
  the name `localhost`, its built-in default.

## What the server did

Each line was seen on that server, with the token of `token.json`'s shape.

- The member `clientDataJson` is accepted, and so is `clientDataJSON`.
- An origin with another port (`https://localhost:9999`) is refused, and
  so is `http://localhost:18443`. The refusal is HTTP 400 with the message
  `Webauthn` and no `TwoFactorProviders`.
- An origin whose host is written in upper case
  (`https://LOCALHOST:18443`) is accepted: origins are compared as URLs,
  not as text.
- A refused answer uses the challenge up: the same challenge answered
  correctly afterwards gets `Can't recover login challenge`.
- An accepted token sent a second time gets `Can't recover login challenge`.
- An answer to an older challenge, after a newer one was asked for, is
  refused.
- A signature counter that did not grow past the last one is refused.
- With `twoFactorRemember=1` the answer carries a `TwoFactorToken`, and
  signing in with it as provider 5 skips the step.
- Without `DOMAIN` the server still lists provider 7 with a challenge, for
  `rpId` `localhost` and the `appid` `http://localhost/app-id.json`.

## Registering the test key

For whoever repeats this (`test/vaultwarden_server/api_test.dart` does):

1. `POST /api/two-factor/get-webauthn` with `{"masterPasswordHash": …}`
   answers `{"userVerificationToken": …, "webAuthn": {"enabled": false, "keys": []}}`.
2. `POST /api/two-factor/get-webauthn-challenge` with the hash and that
   `userVerificationToken` answers `{"options": {…}}`, the creation
   options. Without the token it answers 422.
3. `PUT /api/two-factor/webauthn` with `id` (a slot, 1 to 5), `name`, the
   hash, the `userVerificationToken` and a `deviceResponse` holding `id`,
   `rawId`, `type`, `extensions` and a `response` with `AttestationObject`
   (attestation `none`) and `clientDataJson`.
