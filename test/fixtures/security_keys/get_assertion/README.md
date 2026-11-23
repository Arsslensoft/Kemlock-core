# authenticatorGetAssertion fixture

`ctap_spec_example.json` is the CTAP specification's own example of an
`authenticatorGetAssertion` request and its answer: section 10.3 of
"Client to Authenticator Protocol (CTAP)", Proposed Standard of 15 June
2021 (CTAP 2.1), "Sample CTAP2 authenticatorGetAssertion Request (CBOR)"
and "Mapped CTAP2 authenticatorGetAssertion response (CBOR)".

The specification prints the two maps in CBOR's diagnostic notation, not
as bytes. The values (`rpId`, `clientDataHash`, `credentialId`,
`authenticatorData`, `signature`) are copied from it. The `request` and
`response` bytes were encoded from those maps by hand, under the
specification's canonical encoding rules (section 8), and not with the
app's CBOR code:

```text
a4                      map of 4
  01 6b "example.com"   1: the rpId, a text of 11 bytes
  02 58 20 …            2: the client data hash, 32 bytes
  03 81                 3: a list of 1
     a2                    map of 2, "id" before "type" (shorter key first)
       62 "id"   58 40 …   the credential id, 64 bytes
       64 "type" 6a "public-key"
  05 a1 62 "up" f5      5: {"up": true}
```

It was not recorded from a security key.
