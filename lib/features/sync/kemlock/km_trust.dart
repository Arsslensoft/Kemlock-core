/// "Trust this phone": the trusted-device flow of a Kemlock Server sign-in.
/// After SSO the account opens by an approval from another device, by this
/// phone's trusted-device key, or by the master password. Trusting the phone
/// keeps a copy of the account's root key on the server that only this phone's
/// hardware opens, so turning sync off and on again with SSO opens the
/// account without an approval. An account that SSO made with no keys has no
/// other way to open, so the phone that makes its keys (`KmSignIn.enrolKeys`)
/// seals its copy here and sends it with them. The primitive is
/// `add-account-crypto`'s (`crypto/account/trusted_device.dart`); this is the
/// flow around it.
///
/// What the server holds is one blob, `crypto.md`'s "trusted-device copy":
///
///   blob = sealed root (94 bytes: u8(1) || u8(platform) || nonce || ciphertext || tag)
///          || the hardware's wrap of K_td
///
/// K_td is a random 32-byte key the root is sealed under, bound to the
/// account, the device and the key version. The hardware wraps K_td: ECIES
/// with a Secure Enclave key on iOS, a non-exportable Keystore key on
/// Android. The root is never given to the hardware. The server stores the
/// blob as opaque bytes; only the phone whose hardware holds the wrapping
/// key reads it. The wrap's place after the sealed root is this plan's own
/// layout, which the server doesn't read (the prefix is `crypto.md`'s).
///
/// The hardware key stays when sync is turned off. Removing trust deletes
/// the copy on the server and the key.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/trusted_device.dart';
import 'km_api.dart';

/// The hardware's side of trust: a wrapping key per tag.
abstract interface class KmKeyWrapper {
  /// Where the key lives, the `protection` the server's key copy names: `secure-enclave` or `keystore`.
  String get protection;

  /// Makes the wrapping key under [tag], replacing any earlier one. Throws a [KmTrustUnavailable]
  /// when the phone has no hardware key: a software key would keep the copy as safe as the vault, and
  /// that is no trust.
  Future<void> create(String tag);

  /// Whether a wrapping key is under [tag].
  Future<bool> exists(String tag);

  /// Wraps [key] under the key under [tag]; only this phone's hardware opens it again.
  Future<Uint8List> wrap(String tag, Uint8List key);

  /// Opens what [wrap] returned. A key that is gone, or wrapped by another, throws.
  Future<Uint8List> unwrap(String tag, Uint8List wrapped);

  /// Deletes the key under [tag], if there is one.
  Future<void> delete(String tag);
}

/// The phone has no hardware key, so it can't be trusted.
class KmTrustUnavailable implements Exception {
  const KmTrustUnavailable();

  @override
  String toString() => 'This phone has no hardware key to trust.';
}

/// A copy of the root key this phone can't open: another version's blob, a key the phone lost, or a
/// copy the server changed.
class KmTrustUnreadable implements Exception {
  const KmTrustUnreadable([this.reason]);

  final String? reason;

  @override
  String toString() => 'The trusted-device copy can’t be opened${reason != null ? ': $reason' : ''}.';
}

/// The tag of the wrapping key for [accountId] in [vault]: keys are tagged by vault and account, so
/// vaults stay apart.
String kmTrustTag(String vault, String accountId) => 'trust.$vault.$accountId';

/// Trusts this phone, opens an account with the trust, and removes it.
class KmTrust {
  KmTrust({required this.wrapper});

  final KmKeyWrapper wrapper;

  TrustedDevicePlatform get _platform =>
      wrapper.protection == 'secure-enclave' ? TrustedDevicePlatform.secureEnclave : TrustedDevicePlatform.androidKeystore;

  /// The blob to store: [rootKey] sealed under a fresh K_td bound to the account, the device and the key
  /// version, with the hardware's wrap of K_td after it. The wrapping key under [tag] is made here,
  /// replacing any earlier one. K_td is wiped before this returns.
  Future<Uint8List> seal({
    required String tag,
    required Uint8List rootKey,
    required List<int> accountId,
    required List<int> deviceId,
    required int keyVersion,
  }) async {
    await wrapper.create(tag);
    final trustedKey = newTrustedDeviceKey();
    try {
      final sealed = await sealRootForTrustedDevice(
        platform: _platform,
        trustedKey: trustedKey,
        accountId: accountId,
        deviceId: deviceId,
        keyVersion: keyVersion,
        rootKey: rootKey,
      );
      final wrapped = await wrapper.wrap(tag, trustedKey);
      return Uint8List.fromList([...sealed, ...wrapped]);
    } catch (_) {
      // A copy that can't be made leaves no key behind that no copy needs
      await wrapper.delete(tag);
      rethrow;
    } finally {
      wipe(trustedKey);
    }
  }

  /// The root key [blob] holds, opened with the wrapping key under [tag]. Another phone's hardware, another
  /// account, device or key version, or a changed byte throws a [KmTrustUnreadable]. The caller wipes the root.
  Future<Uint8List> open({
    required String tag,
    required Uint8List blob,
    required List<int> accountId,
    required List<int> deviceId,
    required int keyVersion,
  }) async {
    if (blob.length <= trustedDeviceBlobLength) throw const KmTrustUnreadable('too short');
    final Uint8List trustedKey;
    try {
      trustedKey = await wrapper.unwrap(tag, Uint8List.sublistView(blob, trustedDeviceBlobLength));
    } catch (e) {
      throw KmTrustUnreadable('$e');
    }
    try {
      return await openRootForTrustedDevice(
        platform: _platform,
        trustedKey: trustedKey,
        accountId: accountId,
        deviceId: deviceId,
        keyVersion: keyVersion,
        sealed: Uint8List.sublistView(blob, 0, trustedDeviceBlobLength),
      );
    } on MalformedException catch (e) {
      throw KmTrustUnreadable(e.message);
    } on CorruptedException {
      throw const KmTrustUnreadable();
    } finally {
      wipe(trustedKey);
    }
  }

  /// "Trust this phone": seals [rootKey] and uploads the blob.
  Future<void> trust({
    required KmApi api,
    required Uri server,
    required String token,
    required String tag,
    required Uint8List rootKey,
    required List<int> accountId,
    required List<int> deviceId,
    required int keyVersion,
  }) async {
    final blob = await seal(tag: tag, rootKey: rootKey, accountId: accountId, deviceId: deviceId, keyVersion: keyVersion);
    try {
      await api.putKeyCopy(server, token, blob, wrapper.protection);
    } catch (_) {
      // Not stored: the key it would have opened is of no use
      await wrapper.delete(tag);
      rethrow;
    }
  }

  /// After SSO: fetches this device's copy and opens the root with it, or null when the phone is not
  /// trusted (no copy, or no key for it), so the sign-in goes on to an approval or the password.
  /// A copy this phone can't open throws a [KmTrustUnreadable].
  Future<Uint8List?> openAfterSso({
    required KmApi api,
    required Uri server,
    required String token,
    required String tag,
    required List<int> accountId,
    required List<int> deviceId,
    required int keyVersion,
  }) async {
    if (!await wrapper.exists(tag)) return null;
    final copy = await api.keyCopy(server, token);
    if (copy == null) return null;
    return open(tag: tag, blob: copy.wrappedKey, accountId: accountId, deviceId: deviceId, keyVersion: keyVersion);
  }

  /// Removes trust: deletes the hardware key, so no copy can open again, then the copy on the server.
  /// A server that can't be reached throws after the key is gone, and the sheet says the copy is left.
  Future<void> removeTrust({required KmApi api, required Uri server, required String token, required String tag}) async {
    await wrapper.delete(tag);
    await api.deleteKeyCopy(server, token);
  }
}
