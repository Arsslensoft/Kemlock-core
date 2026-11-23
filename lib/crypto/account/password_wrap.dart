// The password wrap of the root key (Kemlock-only accounts), `docs/crypto.md`
// "The password wrap of the root key":
//
//   wrap key = HKDF(ikm = master key || OPAQUE export key, salt = absent,
//                   info = "kemlock/v1/password-wrap", L = 32)
//   aad      = "kemlock/v1/root-wrap" || account id (16) || u32be(key version)
//   wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
//
// The master key is the 32-byte Argon2id output (argon2id.dart) and the export
// key is OPAQUE's 64-byte export key. Neither alone opens the wrap, so a
// stolen database allows no offline guessing without the OPAQUE server secret.
// A sealed value is `nonce (12) || ciphertext || tag (16)`: 92 bytes for the
// 64-byte root.

library;

import 'dart:typed_data';

import '../aes_gcm.dart';
import '../bytes.dart';
import '../hkdf.dart';
import 'encoding.dart';
import 'keys.dart';

/// The length of a wrapped root key: nonce, 64-byte root and tag.
const wrappedRootLength = 12 + rootKeyLength + 16;

const _masterKeyLength = 32;
const _exportKeyLength = 64;

/// Wraps [rootKey] under the master key and the OPAQUE export key, bound to
/// the account and key version. [nonce] is random unless given, for
/// known-answer tests only. Returns `nonce || ciphertext || tag`.
Future<Uint8List> wrapRootWithPassword({
  required Uint8List masterKey,
  required Uint8List exportKey,
  required List<int> accountId,
  required int keyVersion,
  required List<int> rootKey,
  Uint8List? nonce,
}) async {
  requireLength(rootKey, rootKeyLength, 'the root key');
  final wrapKey = _passwordWrapKey(masterKey, exportKey);
  try {
    final sealed = await aesGcmEncrypt(wrapKey, rootKey, nonce: nonce, aad: _rootWrapAad(accountId, keyVersion));
    return concatBytes([sealed.nonce, sealed.ct]);
  } finally {
    wipe(wrapKey);
  }
}

/// Unwraps the root key. A wrapped value of another length is a
/// [MalformedException]; a wrong master key or export key (either one alone
/// is wrong), another account id or another key version is a
/// [CorruptedException]. The caller wipes the root it gets.
Future<Uint8List> unwrapRootWithPassword({
  required Uint8List masterKey,
  required Uint8List exportKey,
  required List<int> accountId,
  required int keyVersion,
  required List<int> wrapped,
}) async {
  requireLength(wrapped, wrappedRootLength, 'a wrapped root key');
  final wrapKey = _passwordWrapKey(masterKey, exportKey);
  try {
    return await aesGcmDecrypt(wrapKey, wrapped.sublist(0, 12), wrapped.sublist(12), aad: _rootWrapAad(accountId, keyVersion));
  } on AesGcmAuthError {
    throw const CorruptedException();
  } finally {
    wipe(wrapKey);
  }
}

Uint8List _passwordWrapKey(Uint8List masterKey, Uint8List exportKey) {
  requireLength(masterKey, _masterKeyLength, 'the master key');
  requireLength(exportKey, _exportKeyLength, 'the export key');
  final ikm = concatBytes([masterKey, exportKey]);
  try {
    return hkdfSha256(ikm, salt: const [], info: label('kemlock/v1/password-wrap'), length: 32);
  } finally {
    wipe(ikm);
  }
}

Uint8List _rootWrapAad(List<int> accountId, int keyVersion) {
  requireLength(accountId, 16, 'an account id');
  return concatBytes([label('kemlock/v1/root-wrap'), accountId, u32be(keyVersion)]);
}
