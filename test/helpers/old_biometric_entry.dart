import 'dart:convert';

import 'package:kemlock_core/core/storage/key_value_store.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/vault/vault_registry.dart';
import 'package:kemlock_core/vault/vault_store.dart';

/// Writes the biometric entry versions before the hardware key wrote, as the
/// Capacitor plugin's flow did: a random seal key beside the private key it
/// seals, under `backmycodes_native_bio` of the active vault, or [vault].
Future<void> writeOldBiometricEntry(KeyValueStore store, VaultRegistry vaults, VaultSession session, [String? vault]) async {
  final sealKey = randomBytes(32);
  final sealed = await aesGcmEncrypt(sealKey, session.secretKey);
  store.setItem(
    vaults.vaultKey(keyNativeBio, vault),
    jsonEncode({'sealKey': b64(sealKey), 'nativeSkNonce': b64(sealed.nonce), 'nativeSkEnc': b64(sealed.ct)}),
  );
}
