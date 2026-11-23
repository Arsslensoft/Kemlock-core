# NFC message (NDEF) fixtures

NDEF messages as the message file of a key's NFC application holds them,
in hex, without the two length bytes the file starts with. They check
`lib/security_key/otp_message.dart`, which reads a YubiKey's one-time
password from the link the key offers over NFC.

They were written by hand from the NFC Forum's record layout (NDEF, and
the URI and Text record types) and from the shape of the link Yubico
documents for a YubiKey's NFC message,
`https://my.yubico.com/yk/#<one-time password>`. None was recorded from a
key: the machine these were made on had no key and no phone. The
one-time password in them, `ccccccbchvthlivuitriujjifivbvtrjkjfirllluurj`,
is a made-up string in the right alphabet, and opens nothing.

- `yubico-link.hex`: one URI record, `https://my.yubico.com/yk/#` and the
  44 characters.
- `other-host-link.hex`: the same password after another host and path,
  `https://otp.example.org/k/`.
- `text-record.hex`: a Text record ("en") holding the 44 characters, not
  a link.
- `outside-alphabet.hex`: a link whose last part has letters a one-time
  password never has.
- `too-short.hex`: a link whose last part is 20 characters.
- `empty-record.hex`: one empty record.

Each record starts `d1 01 <payload length> <type>`: one short record that
is both first and last, of a well-known type one byte long, `55` ("U")
for a link and `54` ("T") for text. A link's payload starts with `04`,
which stands for `https://`.
