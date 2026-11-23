// The passkey PRF wrap of the root key, `docs/crypto.md` "The passkey PRF wrap
// of the root key". A passkey with the WebAuthn PRF extension wraps one more
// copy of the root key. The PRF is evaluated with
// `first = SHA-256("kemlock/v1/prf-salt")` ([prfEvalInput]).
//
//   wrap key = HKDF(ikm = PRF output (32), salt = absent,
//                   info = "kemlock/v1/prf-wrap" || lp(credential id), L = 32)
//   aad      = "kemlock/v1/root-wrap/prf" || account id (16) || u32be(key version)
//              || lp(credential id)
//   wrapped  = AES-256-GCM(wrap key, nonce, root key, aad)
//
// The credential id is the raw WebAuthn credential id bytes. A wrapped value
// is `nonce (12) || ciphertext || tag (16)`: 92 bytes for the 64-byte root.
// Only the PRF output of the credential that made the wrap opens it, and it
// opens only for the same account, key version and credential id.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../aes_gcm.dart';
import '../bytes.dart';
import '../hkdf.dart';
import 'encoding.dart';
import 'keys.dart';

/// The PRF's `first` input, `SHA-256("kemlock/v1/prf-salt")`, 32 bytes: what
/// the client passes as the extension's `eval.first`.
final Uint8List prfEvalInput = Uint8List.fromList(hash.sha256.convert(label('kemlock/v1/prf-salt')).bytes);

/// The length of a PRF output.
const prfOutputLength = 32;

/// The length of a wrapped root key: nonce, 64-byte root and tag.
const prfWrappedRootLength = 12 + rootKeyLength + 16;

/// Wraps [rootKey] under the PRF output of the credential [credentialId],
/// bound to the account and key version. [nonce] is random unless given, for
/// known-answer tests only. Returns `nonce || ciphertext || tag`.
Future<Uint8List> wrapRootWithPrf({
  required Uint8List prfOutput,
  required List<int> credentialId,
  required List<int> accountId,
  required int keyVersion,
  required List<int> rootKey,
  Uint8List? nonce,
}) async {
  requireLength(rootKey, rootKeyLength, 'the root key');
  final aad = _aad(accountId, keyVersion, credentialId);
  final wrapKey = _wrapKey(prfOutput, credentialId);
  try {
    final sealed = await aesGcmEncrypt(wrapKey, rootKey, nonce: nonce, aad: aad);
    return concatBytes([sealed.nonce, sealed.ct]);
  } finally {
    wipe(wrapKey);
  }
}

/// Unwraps the root key. A wrapped value of another length is a
/// [MalformedException]; another PRF output, credential id, account id or key
/// version, or a changed byte, is a [CorruptedException]. The caller wipes
/// the root it gets.
Future<Uint8List> unwrapRootWithPrf({
  required Uint8List prfOutput,
  required List<int> credentialId,
  required List<int> accountId,
  required int keyVersion,
  required List<int> wrapped,
}) async {
  requireLength(wrapped, prfWrappedRootLength, 'a wrapped root key');
  final aad = _aad(accountId, keyVersion, credentialId);
  final wrapKey = _wrapKey(prfOutput, credentialId);
  try {
    return await aesGcmDecrypt(wrapKey, wrapped.sublist(0, 12), wrapped.sublist(12), aad: aad);
  } on AesGcmAuthError {
    throw const CorruptedException();
  } finally {
    wipe(wrapKey);
  }
}

Uint8List _wrapKey(Uint8List prfOutput, List<int> credentialId) {
  requireLength(prfOutput, prfOutputLength, 'the PRF output');
  _checkCredentialId(credentialId);
  return hkdfSha256(prfOutput, salt: const [], info: concatBytes([label('kemlock/v1/prf-wrap'), lp(credentialId)]), length: 32);
}

Uint8List _aad(List<int> accountId, int keyVersion, List<int> credentialId) {
  requireLength(accountId, 16, 'an account id');
  _checkCredentialId(credentialId);
  return concatBytes([label('kemlock/v1/root-wrap/prf'), accountId, u32be(keyVersion), lp(credentialId)]);
}

void _checkCredentialId(List<int> credentialId) {
  if (credentialId.isEmpty) throw const MalformedException('a credential id is not empty');
}
