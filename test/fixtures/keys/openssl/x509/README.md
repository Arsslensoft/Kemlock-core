# X.509 fixtures

Certificates and a certificate request made with OpenSSL 3.5.7 (Git Bash on
Windows, 2026-11-16) for the keys in the folder above, for
`test/crypto/keys/x509_test.dart`. Each certificate is there as `.pem` and
`.der`, with what OpenSSL reads in it as `.txt`. Never regenerate them: the
ECDSA signatures differ on every run, and the tests compare fingerprints.

`authority.pkcs8.pem` is the private key of a test authority, made here and
used for nothing else.

## How they were made

Run in this folder, with `MSYS_NO_PATHCONV=1` so Git Bash leaves `/CN=...`
alone, and `K=..`:

```sh
show() {
  openssl x509 -in $1.pem -noout -text -nameopt RFC2253,utf8,-esc_msb -dateopt iso_8601 \
    -serial -subject -issuer -dates -fingerprint -sha256 > $1.txt
  openssl x509 -in $1.pem -outform DER -out $1.der
}

# Self-signed, one per kind of key Kemlock generates in a slot
openssl req -x509 -new -key $K/rsa2048.pkcs8.pem -sha256 -subj "/CN=Ada Example" -not_before 20261101000000Z -not_after 20281101000000Z -set_serial 0x1a2b3c4d5e6f708192a3b4c5d6e7f801 -out rsa2048.selfsigned.pem && show rsa2048.selfsigned
openssl req -x509 -new -key $K/p256.pkcs8.pem -sha256 -subj "/CN=Ada Example" -not_before 20261101000000Z -not_after 20281101000000Z -set_serial 0x2a2b3c4d5e6f708192a3b4c5d6e7f802 -out p256.selfsigned.pem && show p256.selfsigned
openssl req -x509 -new -key $K/p384.pkcs8.pem -sha384 -subj "/CN=Ada Example" -not_before 20261101000000Z -not_after 20281101000000Z -set_serial 0x3a2b3c4d5e6f708192a3b4c5d6e7f803 -out p384.selfsigned.pem && show p384.selfsigned

# One that ended in the past, and one that ends in 2090 (a GeneralizedTime)
openssl req -x509 -new -key $K/p256.pkcs8.pem -sha256 -subj "/CN=Ended Example" -not_before 20200101000000Z -not_after 20210101000000Z -set_serial 0x04 -out p256.expired.pem && show p256.expired
openssl req -x509 -new -key $K/p256.pkcs8.pem -sha256 -subj "/CN=Far Example" -not_before 20261101000000Z -not_after 20900101000000Z -set_serial 0x05 -out p256.until-2090.pem && show p256.until-2090

# Several name parts and a common name that is not ASCII (names.cnf is UTF-8)
openssl req -x509 -new -key $K/p256.pkcs8.pem -sha256 -config names.cnf -not_before 20261101000000Z -not_after 20281101000000Z -set_serial 0x06 -out p256.names.pem && show p256.names

# A kind of key Kemlock does not generate in a slot but must still read
openssl req -x509 -new -key $K/ed25519.pkcs8.pem -subj "/CN=Ed Example" -not_before 20261101000000Z -not_after 20281101000000Z -set_serial 0x07 -out ed25519.selfsigned.pem && show ed25519.selfsigned

# A PKCS#10 request for the P-256 key
openssl req -new -key $K/p256.pkcs8.pem -sha256 -subj "/CN=Ada Example" -out p256.request.pem
openssl req -in p256.request.pem -outform DER -out p256.request.der
openssl req -in p256.request.pem -noout -text -verify -nameopt RFC2253,utf8,-esc_msb > p256.request.txt 2>&1

# A test authority, and the certificate it issues for that request
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out authority.pkcs8.pem
openssl req -x509 -new -key authority.pkcs8.pem -sha384 -subj "/O=Example Test Authority/CN=Example Test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -not_before 20261101000000Z -not_after 20361101000000Z -set_serial 0x08 -out authority.pem && show authority
openssl x509 -req -in p256.request.pem -CA authority.pem -CAkey authority.pkcs8.pem -sha384 -not_before 20261101000000Z -not_after 20271101000000Z -set_serial 0x09 -extfile issued.ext -out p256.issued.pem && show p256.issued

# A negative serial number, which some authorities have issued
openssl req -x509 -new -key $K/p256.pkcs8.pem -sha256 -subj "/CN=Negative Example" -not_before 20261101000000Z -not_after 20281101000000Z -set_serial -0x0a -out p256.negative-serial.pem && show p256.negative-serial
```

## Checked

```text
$ for f in rsa2048 p256 p384 ed25519; do openssl verify -CAfile $f.selfsigned.pem $f.selfsigned.pem; done
rsa2048.selfsigned.pem: OK
p256.selfsigned.pem: OK
p384.selfsigned.pem: OK
ed25519.selfsigned.pem: OK
$ openssl verify -CAfile authority.pem p256.issued.pem
p256.issued.pem: OK
```
