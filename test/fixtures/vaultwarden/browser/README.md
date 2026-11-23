# Vaultwarden and a browser extension

What a real Vaultwarden accepted from Kemlock's browser extension, and what
the web vault's security key pages answered, recorded on 21 November 2026
for the change `add-browser-extension` (tasks 1.4 and 1.5).

The server was `vaultwarden/server:1.37.5` with its web vault, run in Docker
on the development machine at `http://localhost:8081` with
`DOMAIN=http://localhost:8081`. It was plain http on `localhost`, which
browsers count as a secure context, because Chrome refuses WebAuthn on a
page whose certificate it doesn't trust. The browsers were Chrome for
Testing 158 and 119, Edge 157 and Firefox 160, each running an unpacked
spike extension. Every value here is a test value; the accounts and the
server no longer exist.

## Signing in as a browser extension (task 1.4)

From Vaultwarden's source, `src/db/models/device.rs` and
`src/api/identity.rs` on its main branch that day:

- `client_id` is only checked not to be blank for the password grant. Its
  comment names `web, cli, desktop, browser, mobile`, and Bitwarden's
  extension sends `browser`. The server copies it into the access token's
  `client_id` claim and checks nothing else about it.
- The device types for extensions are 2 (Chrome Extension), 3 (Firefox
  Extension) and 5 (Edge Extension). A type the server doesn't know reads
  as 14 (Unknown Browser).

The extension uses `client_id=browser` and the type of the browser it runs
in. The app sends `client_id=mobile` and 0 or 1.

What the server did, from the extension's service worker in Chrome 158 and
Edge 157 and from its event page in Firefox 160:

- The password grant with `client_id=browser`, `deviceType` 2, 5 or 3 and
  `deviceName` "Kemlock · Chrome", "Kemlock · Edge" or "Kemlock · Firefox"
  got HTTP 200.
- The refresh grant with `client_id=browser` got 200.
- The access token's claims were `client_id: browser` and `devicetype`
  "Chrome Extension", "Edge Extension" or "Firefox Extension".
- `GET /api/devices` listed each sign-in with the name, type and
  `deviceIdentifier` sent. Signing in again with the same identifier kept
  one entry.
- `mobile`, `web` and `kemlock` as `client_id` got 200 too: the server
  doesn't hold an extension to `browser`.
- Its CORS preflight answers carry no `Access-Control-Allow-Origin`, for an
  extension's origin or any other, so the extension's requests rest on its
  host permission for the server.

In Firefox 160 a request to `http://localhost:8081` failed with a network
error although the host permission for it was granted, and the same
server at `http://127.0.0.1:8081` answered. It wasn't looked into further,
since setup accepts https servers only.

## The security key pages (task 1.5)

The web vault has three: `webauthn-connector.html` for an iframe,
`webauthn-fallback-connector.html` for a tab, and
`webauthn-mobile-connector.html`, which the phone apps open.

### The fallback connector, in a tab

    <server>/webauthn-fallback-connector.html?data=<data>&parent=<parent>&v=1&locale=<locale>

- `data`: with `v=1`, the base64 of the UTF-8 JSON of
  `TwoFactorProviders2["7"]`, URI-encoded. The page reads a `+` in the
  query as a space.
- `parent`: required (without it the page says "No parent."), but this page
  doesn't use it. Bitwarden's extension passes its page's address.
- `locale`: optional, `en` by default.

The person clicks "Read security key". The box "Don't ask again on this
device for 30 days" is `remember`. The page then posts
`{command: "webAuthnResult", data, remember}` to its own window
(`window.postMessage(…, "*")`), for a script of the extension in that tab
to pick up. Bitwarden's extension has a content script for it. The spike
injected one with `scripting.executeScript`, under its host permission for
the server, and passed the message on with `runtime.sendMessage`.

`data` is the JSON text of `{id, rawId, type, extensions, response:
{authenticatorData, clientDataJson, signature}}`, in base64url without
padding: `fallback-connector-answer.json`. It went to
`POST /identity/connect/token` unchanged as `twoFactorToken`, with
`twoFactorProvider=7` and `twoFactorRemember=1`. The answer was 200 with a
`TwoFactorToken`. Its client data has the server's origin and
`crossOrigin: false`.

### The iframe connector, in an extension page

    <server>/webauthn-connector.html?data=<data>&parent=<parent>&v=1&btnText=<label>

in an `<iframe allow="publickey-credentials-get *">`. `parent` is the
framing page's own address, URI-encoded; the connector posts its messages
to it. In Chrome (not Safari) it asks the key as soon as it loads, and
posts `info|ready`, then `success|<JSON text>` or `error|<message>`.

Vaultwarden 1.37.5 serves the connector pages without `X-Frame-Options` or
a CSP, so any page can frame them. The web vault's other pages send
`X-Frame-Options: SAMEORIGIN` and a `frame-ancestors` that names
Bitwarden's own extensions.

The answer has the fallback's shape, `iframe-connector-answer.json`. Its
client data has `crossOrigin: true` and `topOrigin` the extension's origin,
and Vaultwarden accepted it (200).

### The challenges

`fallback-providers2-7.json` and `iframe-providers2-7.json` are the
server's `TwoFactorProviders2["7"]` for the two answers. Both carry
`extensions.appid` `http://localhost:8081/app-id.json`. Chrome refuses the
`appid` extension on a plain-http page ("This is an invalid domain."), so
the connectors were handed each challenge without `appid`, and the answers
are to that. An https server's `appid` is on its own origin and needs no
such step.

### Repeating it

The key was Chrome DevTools' virtual authenticator (CTAP2 over USB, with
user verification). It was registered with a test account through the
routes `../webauthn/README.md` gives, from a page of the server's origin,
and copied into each later tab with `WebAuthn.addCredential`. Both pages
signed in, in Chrome 158, Chrome 119 and Edge 157.

In one of three runs on Chrome 158, the extension's service worker was
restarted while it waited for the key, and what it held in memory was lost.
The page that waits should be an extension page, the setup tab, or keep its
step in `storage.session`.
