# Security key fixtures

Values the security key tests check the app's protocol code against.

- `pin_protocol_openssl.json`: the two PIN protocols of CTAP 2.1 worked
  out with OpenSSL, not with the app: two P-256 key pairs, their ECDH
  secret, each protocol's shared secret, and the encrypted new PIN, its
  authentication tag and the encrypted PIN hash for the PIN `123456`.
  Every key, PIN and IV in it is a test value made for this file. It was
  not recorded from a security key.

No exchange recorded from a real key is here yet: the machine these were
made on had no key and no phone. When the spike of
`add-security-key-management` (task 1.7) records some, they go beside this
file as new files, each named in this list with the key, firmware and link
it came from, and with no serial number in it.
