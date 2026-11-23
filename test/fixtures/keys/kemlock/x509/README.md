# What Kemlock wrote, and OpenSSL's verdict

Two self-signed certificates and a certificate request written by
`buildSelfSigned` and `buildRequest` (`lib/crypto/keys/x509.dart`) on
2026-11-16, for the keys in `../../openssl`, signed in software as a slot's
key signs on a card. `test/crypto/keys/x509_test.dart` builds them again from
the same inputs and compares the bytes: RSA PKCS#1 v1.5 and RFC 6979 ECDSA
both give the same signature every time.

- `rsa2048.selfsigned`: "Ada Example", the signature slot's key usage, two years.
- `p256.selfsigned`: "Zoé Müller", the sign-in slot's key usage, until 2051
  (so its end date is a GeneralizedTime).
- `p384.request`: a PKCS#10 request for "Ada Example".

Checked by hand with OpenSSL 3.5.7 (the signature bytes are left out below):

```text
$ openssl verify -x509_strict -CAfile rsa2048.selfsigned.pem rsa2048.selfsigned.pem
rsa2048.selfsigned.pem: OK
$ openssl x509 -in rsa2048.selfsigned.der -noout -text -nameopt RFC2253,utf8,-esc_msb
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Ada Example
        Validity
            Not Before: Nov 16 09:00:00 2026 GMT
            Not After : Nov 16 09:00:00 2028 GMT
        Subject: CN=Ada Example
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature, Non Repudiation
            X509v3 Subject Key Identifier:
                4E:B0:46:5E:9D:2D:D3:13:37:EF:02:D4:75:64:89:8E:5A:90:0E:AC
    Signature Algorithm: sha256WithRSAEncryption

$ openssl verify -x509_strict -CAfile p256.selfsigned.pem p256.selfsigned.pem
p256.selfsigned.pem: OK
$ openssl x509 -in p256.selfsigned.der -noout -text -nameopt RFC2253,utf8,-esc_msb
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Zoé Müller
        Validity
            Not Before: Nov 16 09:00:00 2026 GMT
            Not After : Jan  1 00:00:00 2051 GMT
        Subject: CN=Zoé Müller
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Subject Key Identifier:
                54:89:5B:D8:A7:5B:C4:23:C9:32:F2:3D:37:E8:F9:E5:51:C4:DC:58
    Signature Algorithm: ecdsa-with-SHA256

$ openssl req -in p384.request.pem -noout -verify -subject -nameopt RFC2253
Certificate request self-signature verify OK
subject=CN=Ada Example
```

OpenSSL only. That macOS and Windows accept a certificate Kemlock wrote is
task 11.2 of `add-piv-management`, which needs a real key.
