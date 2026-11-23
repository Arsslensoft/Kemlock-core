// Encrypted PKCS#8 (`ENCRYPTED PRIVATE KEY`) with PBES2 (RFC 8018): PBKDF2
// and AES-CBC. Read with HMAC-SHA-1, -224, -256, -384 or -512 and AES-128,
// -192 or -256; written with PBKDF2-HMAC-SHA-256 and AES-256-CBC, the
// shape `openssl pkcs8 -topk8` writes. Other schemes (scrypt, PBES1, DES)
// are refused by name.

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../bytes.dart';
import '../pbkdf2.dart';
import 'der.dart';
import 'key_error.dart';

const _oidPbes2 = '1.2.840.113549.1.5.13';
const _oidPbkdf2 = '1.2.840.113549.1.5.12';
const _oidHmacSha1 = '1.2.840.113549.2.7';
const _oidHmacSha256 = '1.2.840.113549.2.9';

/// The PRFs PBKDF2 is read with, and their digests and block sizes.
final _prfs = <String, (pc.Digest Function(), int)>{
  _oidHmacSha1: (pc.SHA1Digest.new, 64),
  '1.2.840.113549.2.8': (pc.SHA224Digest.new, 64),
  _oidHmacSha256: (pc.SHA256Digest.new, 64),
  '1.2.840.113549.2.10': (pc.SHA384Digest.new, 128),
  '1.2.840.113549.2.11': (pc.SHA512Digest.new, 128),
};

const _oidAes256Cbc = '2.16.840.1.101.3.4.1.42';

/// AES-CBC by object identifier, and its key length.
const _ciphers = {'2.16.840.1.101.3.4.1.2': 16, '2.16.840.1.101.3.4.1.22': 24, _oidAes256Cbc: 32};

/// Names of the schemes refused, for the message.
const _refusedNames = {
  '1.3.6.1.4.1.11591.4.11': 'scrypt',
  '1.2.840.113549.3.7': 'des-ede3-cbc',
  '1.3.14.3.2.7': 'des-cbc',
  '1.2.840.113549.3.2': 'rc2-cbc',
  '2.16.840.1.101.3.4.1.6': 'aes-128-gcm',
  '2.16.840.1.101.3.4.1.26': 'aes-192-gcm',
  '2.16.840.1.101.3.4.1.46': 'aes-256-gcm',
  '1.2.840.113549.1.5.1': 'pbeWithMD2AndDES-CBC',
  '1.2.840.113549.1.5.3': 'pbeWithMD5AndDES-CBC',
  '1.2.840.113549.1.5.4': 'pbeWithMD2AndRC2-CBC',
  '1.2.840.113549.1.5.6': 'pbeWithMD5AndRC2-CBC',
  '1.2.840.113549.1.5.10': 'pbeWithSHA1AndDES-CBC',
  '1.2.840.113549.1.5.11': 'pbeWithSHA1AndRC2-CBC',
  '1.2.840.113549.1.12.1.1': 'pbeWithSHAAnd128BitRC4',
  '1.2.840.113549.1.12.1.2': 'pbeWithSHAAnd40BitRC4',
  '1.2.840.113549.1.12.1.3': 'pbeWithSHAAnd3-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.4': 'pbeWithSHAAnd2-KeyTripleDES-CBC',
  '1.2.840.113549.1.12.1.5': 'pbeWithSHAAnd128BitRC2-CBC',
  '1.2.840.113549.1.12.1.6': 'pbeWithSHAAnd40BitRC2-CBC',
};

/// More rounds than this are refused rather than run: a file could ask for
/// billions and hang the import.
const maxPbkdf2Iterations = 10000000;

/// The rounds of PBKDF2-HMAC-SHA-256 [encryptPkcs8] uses unless told
/// otherwise: OWASP's figure for it in 2023.
const defaultPbkdf2Iterations = 600000;

Never _refuse(String oid) => throw KeyFormatException(KeyProblem.unsupportedCipher, _refusedNames[oid] ?? oid);

/// The PKCS#8 `PrivateKeyInfo` inside an `EncryptedPrivateKeyInfo`,
/// decrypted with [passphrase] (UTF-8, as OpenSSL takes it).
///
/// Throws [KeyFormatException]: [KeyProblem.passphraseNeeded] without a
/// passphrase, [KeyProblem.wrongPassphrase] when the padding or the
/// decrypted structure is wrong, [KeyProblem.unsupportedCipher] with the
/// scheme's name, or [KeyProblem.damaged].
Uint8List decryptPkcs8(Uint8List der, String? passphrase) {
  checkSize(der.length);
  final r = readSequence(der);
  final scheme = r.sequence();
  final schemeOid = scheme.oid();
  if (schemeOid != _oidPbes2) _refuse(schemeOid);
  final params = scheme.sequence();
  scheme.done();
  final encrypted = r.octetString();
  r.done();

  final kdf = params.sequence();
  final kdfOid = kdf.oid();
  if (kdfOid != _oidPbkdf2) _refuse(kdfOid);
  final pbkdf2 = kdf.sequence();
  kdf.done();
  final cipher = params.sequence();
  final cipherOid = cipher.oid();
  final keyLength = _ciphers[cipherOid];
  if (keyLength == null) _refuse(cipherOid);
  final iv = cipher.octetString();
  cipher.done();
  params.done();
  check(iv.length == 16, 'PBES2: IV length');

  final salt = pbkdf2.octetString();
  final iterations = pbkdf2.smallInteger();
  check(iterations >= 1, 'PBES2: no rounds');
  if (iterations > maxPbkdf2Iterations) throw KeyFormatException(KeyProblem.unsupportedCipher, 'PBKDF2 with $iterations rounds');
  if (pbkdf2.nextTag == tagInteger) check(pbkdf2.smallInteger() == keyLength, 'PBES2: key length');
  var prfOid = _oidHmacSha1;
  final prf = pbkdf2.isEmpty ? null : pbkdf2.sequence();
  if (prf != null) {
    prfOid = prf.oid();
    if (!prf.isEmpty) prf.readNull();
    prf.done();
  }
  pbkdf2.done();
  if (!_prfs.containsKey(prfOid)) _refuse(prfOid);
  check(encrypted.isNotEmpty && encrypted.length % 16 == 0, 'PBES2: data length');

  if (passphrase == null) throw const KeyFormatException(KeyProblem.passphraseNeeded);
  final key = _pbkdf2(prfOid, utf8.encode(passphrase), salt, iterations, keyLength);
  final plain = _cbc(false, key, iv, encrypted);
  final pad = plain.last;
  var padOk = pad >= 1 && pad <= 16;
  for (var i = 1; padOk && i <= pad; i++) {
    padOk = plain[plain.length - i] == pad;
  }
  if (!padOk) throw const KeyFormatException(KeyProblem.wrongPassphrase);
  final pkcs8 = Uint8List.sublistView(plain, 0, plain.length - pad);
  // A wrong key gives good padding one time in 256; the DER then fails.
  try {
    readSequence(pkcs8);
  } on KeyFormatException {
    throw const KeyFormatException(KeyProblem.wrongPassphrase);
  }
  return Uint8List.fromList(pkcs8);
}

/// [pkcs8] as an `EncryptedPrivateKeyInfo`: PBES2 with
/// PBKDF2-HMAC-SHA-256 over [passphrase], a random 16-byte salt and
/// [iterations] rounds, and AES-256-CBC with a random IV.
Uint8List encryptPkcs8(Uint8List pkcs8, String passphrase, {int iterations = defaultPbkdf2Iterations}) {
  final salt = randomBytes(16);
  final iv = randomBytes(16);
  final key = pbkdf2Sha256(utf8.encode(passphrase), salt, iterations, 32);
  final pad = 16 - pkcs8.length % 16;
  final padded = Uint8List(pkcs8.length + pad)
    ..setAll(0, pkcs8)
    ..fillRange(pkcs8.length, pkcs8.length + pad, pad);
  return derSequence([
    derSequence([
      derOid(_oidPbes2),
      derSequence([
        derSequence([
          derOid(_oidPbkdf2),
          derSequence([
            derOctetString(salt),
            derSmallInteger(iterations),
            derSequence([derOid(_oidHmacSha256), derNull()]),
          ]),
        ]),
        derSequence([derOid(_oidAes256Cbc), derOctetString(iv)]),
      ]),
    ]),
    derOctetString(_cbc(true, key, iv, padded)),
  ]);
}

Uint8List _pbkdf2(String prfOid, List<int> passphrase, Uint8List salt, int iterations, int length) {
  if (prfOid == _oidHmacSha256) return pbkdf2Sha256(passphrase, salt, iterations, length);
  final (digest, blockSize) = _prfs[prfOid]!;
  final derivator = pc.PBKDF2KeyDerivator(pc.HMac(digest(), blockSize))..init(pc.Pbkdf2Parameters(salt, iterations, length));
  return derivator.process(Uint8List.fromList(passphrase));
}

/// AES-CBC over whole blocks, no padding.
Uint8List _cbc(bool encrypt, Uint8List key, Uint8List iv, Uint8List data) {
  final cipher = pc.CBCBlockCipher(pc.AESEngine())..init(encrypt, pc.ParametersWithIV(pc.KeyParameter(key), iv));
  final out = Uint8List(data.length);
  for (var i = 0; i < data.length; i += 16) {
    cipher.processBlock(data, i, out, i);
  }
  return out;
}
