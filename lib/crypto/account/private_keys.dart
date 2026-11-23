// The account's private keys at rest, `docs/crypto.md` "The account's private
// keys". The `kx1` and `sig1` private keys are sealed together under the user
// key's `"kemlock/v1/private-keys"` child (`AccountKeys.privateKeysKey`):
//
//   plaintext = u8(1) || kx1 private key (96) || sig1 private key (64)     161 bytes
//   aad       = "kemlock/v1/private-keys" || account id (16) || u32be(key version)
//   sealed    = AES-256-GCM(private-keys child key, nonce, plaintext, aad)
//
// A sealed value is `nonce (12) || ciphertext || tag (16)`: 189 bytes. The key
// version is the bundle's (`KeyBundle.keyVersion`), so a key-pair replacement
// seals the new pair under a new version.

library;

import 'dart:typed_data';

import '../aes_gcm.dart';
import '../bytes.dart';
import 'encoding.dart';
import 'kx1.dart';
import 'sig1.dart';

/// The version byte at the start of the plaintext.
const privateKeysVersion = 1;

/// The plaintext's length: the version byte and both private keys.
const privateKeysPlaintextLength = 1 + Kx1.privateKeyLength + Sig1.privateKeyLength;

/// The length of a sealed pair: nonce, plaintext and tag.
const sealedPrivateKeysLength = 12 + privateKeysPlaintextLength + 16;

const _keyLength = 32;

/// The two private keys an account holds. The caller owns the buffers and
/// wipes them.
typedef PrivateKeys = ({Uint8List kx1PrivateKey, Uint8List sig1PrivateKey});

/// Seals the 96-byte [kx1PrivateKey] and the 64-byte [sig1PrivateKey] under
/// [privateKeysKey], the user key's `"kemlock/v1/private-keys"` child, bound
/// to [accountId] and the bundle's [keyVersion]. [nonce] is random unless
/// given, for known-answer tests only. Returns `nonce || ciphertext || tag`.
Future<Uint8List> sealPrivateKeys({
  required Uint8List privateKeysKey,
  required List<int> accountId,
  required int keyVersion,
  required List<int> kx1PrivateKey,
  required List<int> sig1PrivateKey,
  Uint8List? nonce,
}) async {
  requireLength(privateKeysKey, _keyLength, 'the private-keys key');
  requireLength(kx1PrivateKey, Kx1.privateKeyLength, 'a kx1 private key');
  requireLength(sig1PrivateKey, Sig1.privateKeyLength, 'a sig1 private key');
  final aad = _aad(accountId, keyVersion);
  final plaintext = concatBytes([u8(privateKeysVersion), kx1PrivateKey, sig1PrivateKey]);
  try {
    final sealed = await aesGcmEncrypt(privateKeysKey, plaintext, nonce: nonce, aad: aad);
    return concatBytes([sealed.nonce, sealed.ct]);
  } finally {
    wipe(plaintext);
  }
}

/// Opens a sealed pair. A value of another length, or a plaintext whose
/// version byte is not 1, is a [MalformedException]; another key, account id
/// or key version, or a changed byte, is a [CorruptedException]. The caller
/// wipes the keys it gets.
Future<PrivateKeys> openPrivateKeys({
  required Uint8List privateKeysKey,
  required List<int> accountId,
  required int keyVersion,
  required List<int> sealed,
}) async {
  requireLength(privateKeysKey, _keyLength, 'the private-keys key');
  requireLength(sealed, sealedPrivateKeysLength, 'sealed private keys');
  final aad = _aad(accountId, keyVersion);
  final Uint8List plaintext;
  try {
    plaintext = await aesGcmDecrypt(privateKeysKey, sealed.sublist(0, 12), sealed.sublist(12), aad: aad);
  } on AesGcmAuthError {
    throw const CorruptedException();
  }
  try {
    if (plaintext.length != privateKeysPlaintextLength) {
      throw MalformedException('private keys are $privateKeysPlaintextLength bytes, not ${plaintext.length}');
    }
    if (plaintext[0] != privateKeysVersion) throw MalformedException('unknown private keys version ${plaintext[0]}');
    return (
      kx1PrivateKey: Uint8List.fromList(plaintext.sublist(1, 1 + Kx1.privateKeyLength)),
      sig1PrivateKey: Uint8List.fromList(plaintext.sublist(1 + Kx1.privateKeyLength)),
    );
  } finally {
    wipe(plaintext);
  }
}

Uint8List _aad(List<int> accountId, int keyVersion) {
  requireLength(accountId, 16, 'an account id');
  return concatBytes([label('kemlock/v1/private-keys'), accountId, u32be(keyVersion)]);
}
