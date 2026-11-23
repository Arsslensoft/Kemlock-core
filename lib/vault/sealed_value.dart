/// A value sealed to an ML-KEM-1024 key pair, as a vault stores each of its
/// values and an export its payload: `{"kemCT", "nonce", "ct"}`, a KEM
/// ciphertext and the value under AES-256-GCM with the shared secret it
/// carries.
///
/// Sealing takes the public key alone, and the public key is no secret: a
/// vault's config and an export hold it in the clear. So a seal by itself
/// says nothing about who made it. Whoever could write a vault's storage
/// could seal values of their own, and the vault would read them as its own.
///
/// An authenticated seal has the same shape, byte for byte, and older
/// versions and the TypeScript app read it as they read any other. What
/// differs is the message the KEM ciphertext is made from, which is random
/// otherwise:
///
/// ```
/// authKey = HKDF-SHA256(the secret key, info "Kemlock sealed value v1")
/// m       = HMAC-SHA256(authKey, storage key ‖ 0x00 ‖ nonce ‖ SHA-256(value))
/// ```
///
/// Opening a seal finds `m` again (`MlKem1024.decapsulateWithMessage`), so
/// the holder of the secret key can tell a value sealed by someone who held
/// it too, for this storage key, from one anyone could have made. The
/// storage key is in the message, so a value doesn't pass for the value of
/// another slot or another vault.
///
/// When a value has to pass that check is not said here but by the wraps
/// of the private key ([authenticatedWrapNonce]): those are the one thing
/// that someone without the password, the Recovery Kit or the phone's
/// hardware key cannot make.
///
/// What none of this stops: an older value of the same slot put back in
/// its place, since it was sealed by the right hands for that slot; and an
/// older copy of a vault's config, from before its wraps said its values
/// are authenticated, put back with values to go with it. Nothing kept in
/// the same storage can.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../crypto/aes_gcm.dart';
import '../crypto/bytes.dart';
import '../crypto/hkdf.dart';
import '../crypto/ml_kem.dart';

const _authInfo = 'Kemlock sealed value v1';

/// The key that ties sealed values to whoever holds [secretKey], an
/// ML-KEM-1024 secret key. It opens nothing; with it, a value can be sealed
/// that passes for one the key's holder sealed.
Uint8List sealAuthKey(Uint8List secretKey) => hkdfSha256(secretKey, salt: const [], info: utf8.encode(_authInfo));

/// The KEM message of the authenticated seal of [plain] under [nonce], stored as [storageKey].
Uint8List _sealMessage(Uint8List authKey, String storageKey, List<int> nonce, List<int> plain) => Uint8List.fromList(
  hash.Hmac(hash.sha256, authKey).convert([...utf8.encode(storageKey), 0, ...nonce, ...hash.sha256.convert(plain).bytes]).bytes,
);

/// [plain] sealed to [publicKey]. With [authKey], [sealAuthKey] of the
/// secret key, the seal is authenticated for [storageKey], the full key
/// the value is stored under. Without it the seal is one anyone could
/// make, which is all that can be made with the public key alone.
///
/// Each seal has its own encapsulation, so its own data key.
Future<Map<String, String>> sealValue(Uint8List plain, Uint8List publicKey, {required String storageKey, Uint8List? authKey}) async {
  final nonce = randomBytes(12);
  final kem = MlKem1024.encapsulate(publicKey, authKey == null ? null : _sealMessage(authKey, storageKey, nonce, plain));
  final sealed = await aesGcmEncrypt(kem.sharedSecret, plain, nonce: nonce);
  return {'kemCT': b64(kem.cipherText), 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)};
}

/// What [stored], a sealed value, holds, and whether its seal is
/// authenticated for [storageKey] by the holder of [secretKey]. Throws
/// [AesGcmAuthError] when it was sealed to another key pair or changed,
/// since ML-KEM then gives a wrong secret rather than failing.
Future<({Uint8List plain, bool verified})> openSealedValue(
  Map<String, Object?> stored,
  Uint8List secretKey, {
  required String storageKey,
}) async {
  final nonce = unb64(stored['nonce']! as String);
  final opened = MlKem1024.decapsulateWithMessage(unb64(stored['kemCT']! as String), secretKey);
  final plain = await aesGcmDecrypt(opened.sharedSecret, nonce, unb64(stored['ct']! as String));
  final message = opened.message;
  final verified = message != null && constantTimeEquals(message, _sealMessage(sealAuthKey(secretKey), storageKey, nonce, plain));
  return (plain: plain, verified: verified);
}

/// What the nonce of a wrap of a private key starts with when the values
/// sealed to that key are authenticated: "KlAuth". A random nonce starts
/// with it once in 2^48.
const _wrapMagic = [0x4b, 0x6c, 0x41, 0x75, 0x74, 0x68];

/// A 12-byte AES-GCM nonce for a wrap of the private key of a vault, or of
/// an export, whose sealed values are authenticated: the magic, then six
/// random bytes. A wrap key wraps a private key a few dozen times in a
/// vault's life, so six random bytes keep its nonces apart: two of a
/// hundred wraps under one key share a nonce about once in 2^35.
///
/// A wrap opens only with the nonce it was made under, so nobody can take
/// the magic off a wrap without the key it was made with. That makes it a
/// flag that travels with the vault and that writing to its storage cannot
/// lower: a session opened through such a wrap demands authenticated values.
Uint8List authenticatedWrapNonce() => concatBytes([_wrapMagic, randomBytes(12 - _wrapMagic.length)]);

/// Whether [nonce], base64 as a config or an export holds it, is one
/// [authenticatedWrapNonce] made. False for anything that isn't a nonce.
bool isAuthenticatedWrapNonce(Object? nonce) {
  if (nonce is! String) return false;
  final Uint8List bytes;
  try {
    bytes = unb64(nonce);
  } on FormatException {
    return false;
  }
  if (bytes.length != 12) return false;
  for (var i = 0; i < _wrapMagic.length; i++) {
    if (bytes[i] != _wrapMagic[i]) return false;
  }
  return true;
}
