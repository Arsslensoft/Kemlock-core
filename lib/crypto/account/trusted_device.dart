// The trusted-device copy of the root key, `docs/crypto.md` "The trusted-device
// copy of the root key". Only the device that made it ever opens it: the
// server stores it as an opaque blob and no other client reads it. So its inner
// format belongs to each platform, as long as:
//
//   - the blob starts with `u8(1)` and a platform byte (`0x01` Secure Enclave,
//     `0x02` Android Keystore, `0x03` WebCrypto), so a device can tell its own
//     format from another version's;
//   - the wrapping key is non-extractable and never leaves the device's key
//     store;
//   - where the platform's AEAD takes associated data, it is
//     `"kemlock/v1/root-wrap/device" || account id (16) || device id (16)
//     || u32be(key version)`.
//
// The prefix and the aad are `crypto.md`'s. The INNER per-platform layout
// below is still PROVISIONAL: it is the plan's own proposal, which the server
// session does not pin (only WebCrypto's is pinned there), and it changes if
// that is decided otherwise.
//
//   1. Dart makes a random 32-byte K_td and seals the root under it:
//        blob = u8(1) || u8(platform) || nonce (12) || AES-256-GCM(K_td, nonce, root key, aad)
//      which for 0x03 is exactly the shape crypto.md pins for WebCrypto, with
//      K_td in the place of the non-extractable key.
//   2. The platform wraps K_td: on iOS by ECIES with a Secure Enclave P-256
//      key, on Android by a non-exportable Keystore AES-256-GCM key. That is
//      platform code on the `com.kemlock.app/device_keys` channel (`wrap` and
//      `unwrap`, add-kemlock-server-sync task 4.1) and is not here.
//
// The two layers exist because iOS's ECIES takes no additional data. K_td is
// the only thing the platform sees; the root is never given to it. The sealed
// root opens nothing on another phone: K_td is wrapped by a key that stays in
// the Secure Enclave or the Keystore of this one.

library;

import 'dart:typed_data';

import '../aes_gcm.dart';
import '../bytes.dart';
import 'encoding.dart';
import 'keys.dart';

/// The length of K_td.
const trustedDeviceKeyLength = 32;

/// The version byte at the start of the blob.
const trustedDeviceBlobVersion = 1;

/// The platform byte of a blob: which device format follows.
enum TrustedDevicePlatform {
  /// An iPhone or iPad, K_td wrapped by ECIES with a Secure Enclave key.
  secureEnclave(0x01),

  /// An Android phone, K_td wrapped by a non-exportable Keystore key.
  androidKeystore(0x02),

  /// A browser, where WebCrypto's non-extractable key does the sealing.
  webCrypto(0x03);

  const TrustedDevicePlatform(this.code);

  final int code;
}

/// The length of the prefix: the version byte and the platform byte.
const trustedDevicePrefixLength = 2;

/// The length of the sealed root after the prefix: nonce, 64-byte root and tag.
const trustedDeviceSealedRootLength = 12 + rootKeyLength + 16;

/// The length of a blob: the prefix and the sealed root.
const trustedDeviceBlobLength = trustedDevicePrefixLength + trustedDeviceSealedRootLength;

/// A fresh random K_td. The caller hands it to the platform to wrap, then
/// wipes it.
Uint8List newTrustedDeviceKey() => randomBytes(trustedDeviceKeyLength);

/// Seals [rootKey] under [trustedKey] (K_td) for a device of [platform],
/// bound to the account, the device and the key version. [nonce] is random
/// unless given, for known-answer tests only. Returns
/// `u8(1) || u8(platform) || nonce || ciphertext || tag`.
Future<Uint8List> sealRootForTrustedDevice({
  required TrustedDevicePlatform platform,
  required Uint8List trustedKey,
  required List<int> accountId,
  required List<int> deviceId,
  required int keyVersion,
  required List<int> rootKey,
  Uint8List? nonce,
}) async {
  requireLength(trustedKey, trustedDeviceKeyLength, 'the trusted-device key');
  requireLength(rootKey, rootKeyLength, 'the root key');
  final sealed = await aesGcmEncrypt(trustedKey, rootKey, nonce: nonce, aad: _aad(accountId, deviceId, keyVersion));
  return concatBytes([u8(trustedDeviceBlobVersion), u8(platform.code), sealed.nonce, sealed.ct]);
}

/// Opens a blob on a device of [platform]. A blob of another length, another
/// version or another platform is a [MalformedException], so a device can tell
/// its own format from another's; another K_td, account id, device id or key
/// version, or a changed byte, is a [CorruptedException]. The caller wipes the
/// root it gets.
Future<Uint8List> openRootForTrustedDevice({
  required TrustedDevicePlatform platform,
  required Uint8List trustedKey,
  required List<int> accountId,
  required List<int> deviceId,
  required int keyVersion,
  required List<int> sealed,
}) async {
  requireLength(trustedKey, trustedDeviceKeyLength, 'the trusted-device key');
  requireLength(sealed, trustedDeviceBlobLength, 'a trusted-device blob');
  if (sealed[0] != trustedDeviceBlobVersion) throw MalformedException('unknown trusted-device blob version ${sealed[0]}');
  if (sealed[1] != platform.code) throw MalformedException('a trusted-device blob of platform ${sealed[1]} is not ${platform.name}');
  final start = trustedDevicePrefixLength;
  try {
    return await aesGcmDecrypt(
      trustedKey,
      sealed.sublist(start, start + 12),
      sealed.sublist(start + 12),
      aad: _aad(accountId, deviceId, keyVersion),
    );
  } on AesGcmAuthError {
    throw const CorruptedException();
  }
}

Uint8List _aad(List<int> accountId, List<int> deviceId, int keyVersion) {
  requireLength(accountId, 16, 'an account id');
  requireLength(deviceId, 16, 'a device id');
  return concatBytes([label('kemlock/v1/root-wrap/device'), accountId, deviceId, u32be(keyVersion)]);
}
