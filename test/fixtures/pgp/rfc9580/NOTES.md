# The sample messages of RFC 9580

`tool/pgp/rfc9580_messages.dart` copied them out of the RFC's text
(https://www.rfc-editor.org/rfc/rfc9580.txt) on 2026-11-16, as
`tool/keys/rfc9580_keys.py` did for the keys in `../../keys/rfc9580`. Never
regenerate them.

The key is the RFC's version 6 sample key, `../../keys/rfc9580/v6-secret.asc`
(Ed25519 primary `CB186C4F…BAD9ACC9`, X25519 subkey `12C83F1E…A9930885`).

- `a6-cleartext-signed.asc`: appendix A.6, a clear-signed text with
  dash-escaped lines, signed by the sample key (version 6 signature,
  Ed25519, SHA-512, made 2022-12-13T16:08:03Z). The text is
  `What we need from the grocery store:`, an empty line, `- tofu`,
  `- vegetables`, `- noodles`. The SHA-512 the signature is over begins
  `69365bf4`.
- `a7-inline-signed.asc`: appendix A.7, the same text and signature as an
  inline-signed message: a version 6 one-pass signature packet, literal
  data (format `u`, no name, date 0) and the signature. Its literal data
  ends each line with LF.
- `a8-x25519-ocb.asc`: appendix A.8, `Hello, world!` encrypted to the
  sample key's X25519 subkey: a version 6 PKESK and a version 2 SEIPD with
  AES-128 and OCB, chunk size octet 6. Session key
  `dd708f6fa1ed65114d68d2343e7c2f1d`; the HKDF output that wraps it
  `f66dadcff64592239b254539b64ff607`; message key
  `4512f7149d863341527c6567d5bffc42`, IV `5faf3250212ff9`.
- `a9-skesk6-eax.asc`: appendix A.9, the same text with the passphrase
  `password`: a version 6 SKESK (Iterated and Salted S2K, SHA-256, count
  octet 0xff) and SEIPD 2 with AES-128 and EAX. S2K key
  `154967e590aa1f923e1c0ac64c88f23d`, session key
  `3881bafe985412459b86c36f98cb9a5e`, message key
  `b50422ac1c26be9ddd831d5bbb36b64f`, IV `78b833f2e94a60c0`.
- `a10-skesk6-ocb.asc`: appendix A.10, the same with OCB. S2K key
  `e80de243a362d93b9dc607ede96a7356`, session key
  `28e79ab82397d3c63de24ac217d7b791`, message key
  `71662a11ee5b4e08144e6de883a00999`.
- `a11-skesk6-gcm.asc`: appendix A.11, the same with GCM. S2K key
  `250281715bba7828ef71ef64c4784753`, session key
  `1936fc8568980274bb900d8319360c77`, message key
  `ea1438803cb8a47740ce9b54c338778d`, IV `4d2bdc2b`.

In A.8 to A.11 the decrypted data is a literal data packet (`Hello, world!`,
format `b`, no name) followed by a padding packet (tag 21).

Appendix A.12's messages use Argon2 with 2 GB of memory and are not here:
Kemlock refuses Argon2 by name.
