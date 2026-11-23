// AES-256-GCM, as WebCrypto does it in `crypto.ts`, `qrVault.ts` and
// `syncCrypto.ts`: a 12-byte nonce, no additional data, and the 16-byte tag
// after the ciphertext. The cipher is `package:cryptography`'s AesGcm.
//
// The Kemlock account formats (`docs/crypto.md`) bind every seal to its place
// with additional data, so both functions take an optional `aad`. Left out it
// is empty, which is what every existing caller seals and opens with, so the
// bytes the vault, exports and sync files hold do not change.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'bytes.dart';

/// The tag didn't verify: wrong key (a wrong password, mostly) or data that
/// was changed or cut short. WebCrypto throws an `OperationError` here.
class AesGcmAuthError implements Exception {
  const AesGcmAuthError();

  @override
  String toString() => 'AesGcmAuthError: wrong key or corrupted data';
}

const _tagLength = 16;

final _aesGcm = AesGcm.with256bits();

/// Encrypts [data] with the 32-byte [key] under [nonce], or a fresh random
/// 12-byte nonce. `ct` is the ciphertext followed by the tag, as WebCrypto's
/// `encrypt` returns it. [aad] is the additional data the tag covers and the
/// seal does not carry; it is empty unless given.
Future<({Uint8List nonce, Uint8List ct})> aesGcmEncrypt(List<int> key, List<int> data, {List<int>? nonce, List<int> aad = const []}) async {
  _checkKey(key);
  final iv = nonce == null ? randomBytes(12) : Uint8List.fromList(nonce);
  if (iv.isEmpty) throw ArgumentError.value(iv.length, 'nonce', 'must not be empty');
  final box = await _aesGcm.encrypt(data, secretKey: SecretKeyData(List<int>.of(key)), nonce: iv, aad: aad);
  return (nonce: iv, ct: concatBytes([box.cipherText, box.mac.bytes]));
}

/// Decrypts [ct] (ciphertext and tag) with the 32-byte [key] and its
/// [nonce]. Throws [AesGcmAuthError] when the tag doesn't verify or [ct] is
/// too short to hold one, or when [aad] is not what the seal was made with.
Future<Uint8List> aesGcmDecrypt(List<int> key, List<int> nonce, List<int> ct, {List<int> aad = const []}) async {
  _checkKey(key);
  if (nonce.isEmpty) throw ArgumentError.value(nonce.length, 'nonce', 'must not be empty');
  if (ct.length < _tagLength) throw const AesGcmAuthError();
  final split = ct.length - _tagLength;
  final box = SecretBox(ct.sublist(0, split), nonce: List<int>.of(nonce), mac: Mac(ct.sublist(split)));
  try {
    return Uint8List.fromList(await _aesGcm.decrypt(box, secretKey: SecretKeyData(List<int>.of(key)), aad: aad));
  } on SecretBoxAuthenticationError {
    throw const AesGcmAuthError();
  }
}

void _checkKey(List<int> key) {
  if (key.length != 32) throw ArgumentError.value(key.length, 'key', 'AES-256-GCM needs a 32-byte key');
}
