# OATH application fixtures

`exchanges.json` holds, for each instruction of Yubico's OATH application
(YKOATH), a command as bytes and the answer a YubiKey gives, with what the
app must read from it. The tests of `lib/security_key/oath/` build each
command and compare it byte for byte, and parse each answer.

Every value was **written from the protocol page**
(https://developers.yubico.com/OATH/YKOATH_Protocol.html, read on
16 November 2026) and worked out with Node's `crypto`, not with the app:
the HMACs, the truncation of RFC 4226 and the PBKDF2 of the password. The
secret is the test secret of RFC 4226 and RFC 6238 (`12345678901234567890`),
so the codes are the RFCs' own (`755224`, `287082`, `94287082`). The id,
challenges and password are test values made for this file.

**Nothing here was recorded from a real key**: the machine these were made
on had no key and no phone. When a key is at hand, exchanges recorded from
it go beside this file as new files, each named here with the key, its
firmware and the link it came from, and with no serial number in it.

`malformed` lists answers no key should give (a length that runs past the
end, a missing value, a tag out of place, an unknown type or algorithm).
Each must be refused whole, never read as a shorter list.
