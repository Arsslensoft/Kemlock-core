@TestOn('vm')
library;

// The gate for the Flutter rewrite: data made by the TypeScript app's
// v0.1.0 (@noble/post-quantum 0.5.4, @noble/hashes 2.0.1) opens with the
// Dart primitives, step by step as `crypto.ts` and `qrVault.ts` lay it out.
// The fixture is a byte-for-byte copy of
// `src/utils/__fixtures__/legacy-v0.1.0.json` and is never regenerated; if
// this fails, people would be locked out of their 2FA codes.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/kdf.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

void main() {
  final fixture = jsonDecode(File('test/fixtures/legacy-v0.1.0.json').readAsStringSync()) as Map<String, Object?>;
  final passwords = fixture['passwords']! as Map<String, Object?>;
  final expected = fixture['expected']! as Map<String, Object?>;
  final storage = fixture['vaultStorage']! as Map<String, Object?>;
  Map<String, Object?> stored(String key) => jsonDecode(storage[key]! as String) as Map<String, Object?>;

  /// scrypt(password, config.salt) with the config's own parameters, as `deriveKek` runs it.
  Future<Uint8List> deriveKek(Map<String, Object?> config, String password) {
    final params = config['scrypt']! as Map<String, Object?>;
    return scryptInBackground(
      utf8.encode(password),
      unb64(config['salt']! as String),
      n: params['N']! as int,
      r: params['r']! as int,
      p: params['p']! as int,
    );
  }

  /// The ML-KEM secret key, unwrapped with the key from the password.
  Future<Uint8List> unwrapSecretKey(Map<String, Object?> config, Uint8List kek) =>
      aesGcmDecrypt(kek, unb64(config['skNonce']! as String), unb64(config['skEnc']! as String));

  /// Decapsulates `kemCT` and decrypts `ct` with the shared secret, as `encryptedLoadFrom` does.
  Future<Object?> openData(Map<String, Object?> data, Uint8List secretKey) async {
    final sharedSecret = MlKem1024.decapsulate(unb64(data['kemCT']! as String), secretKey);
    final plain = await aesGcmDecrypt(sharedSecret, unb64(data['nonce']! as String), unb64(data['ct']! as String));
    return jsonDecode(utf8.decode(plain));
  }

  final vaultConfig = stored('backmycodes_vault_config');
  final fileExport = jsonDecode(fixture['fileExport']! as String) as Map<String, Object?>;
  final exportConfig = fileExport['config']! as Map<String, Object?>;

  // Three N=2^17 scrypt runs. The first warms the JIT up (isolates starting
  // on cold code together are several times slower), then the other two go
  // at once.
  late final Uint8List vaultKek;
  late final Uint8List wrongKek;
  late final Uint8List exportKek;
  setUpAll(() async {
    vaultKek = await deriveKek(vaultConfig, passwords['vault']! as String);
    [wrongKek, exportKek] = await Future.wait([
      deriveKek(vaultConfig, 'not-the-password'),
      deriveKek(exportConfig, passwords['fileExport']! as String),
    ]);
  });

  test('uses the vault parameters', () {
    expect(vaultConfig['scrypt'], {'N': 131072, 'r': 8, 'p': 1});
    expect(exportConfig['scrypt'], {'N': 131072, 'r': 8, 'p': 1});
  });

  test('unlocks the vault and decrypts its accounts and backup services', () async {
    final secretKey = await unwrapSecretKey(vaultConfig, vaultKek);
    expect(secretKey, hasLength(MlKem1024.secretKeyLength));
    // The secret key carries the public key the config stores.
    expect(b64(secretKey.sublist(1536, 1536 + MlKem1024.publicKeyLength)), vaultConfig['publicKey']);

    expect(await openData(stored('backmycodes_vault_data'), secretKey), expected['accounts']);
    expect(await openData(stored('backmycodes_backup_data'), secretKey), expected['backupServices']);
  });

  test('rejects the wrong vault password', () async {
    await expectLater(unwrapSecretKey(vaultConfig, wrongKek), throwsA(isA<AesGcmAuthError>()));
  });

  test('opens the encrypted file export with its own config', () async {
    expect(fileExport['version'], 2);
    final secretKey = await unwrapSecretKey(exportConfig, exportKek);

    expect(await openData(fileExport['vault']! as Map<String, Object?>, secretKey), {
      'accounts': expected['accounts'],
      'backupServices': expected['backupServices'],
    });
  });

  group('QR export', () {
    // BMC1:<index>/<total>:<base64url(salt 16 || iv 12 || AES-GCM ciphertext)>
    final chunks = (fixture['qrExport']! as List<Object?>).cast<String>();
    final blob = concatBytes([for (final chunk in chunks) unb64url(chunk.substring(chunk.indexOf(':', 'BMC1:'.length) + 1))]);
    final salt = blob.sublist(0, 16);
    final iv = blob.sublist(16, 28);
    final ciphertext = blob.sublist(28);

    test('opens with PBKDF2-SHA256 at 200,000 rounds, AES-GCM and raw inflate', () async {
      expect(chunks, hasLength(1));
      expect(chunks.single, startsWith('BMC1:01/01:'));
      final key = await pbkdf2Sha256InBackground(utf8.encode(passwords['qrExport']! as String), salt, 200000, 32);
      final compressed = await aesGcmDecrypt(key, iv, ciphertext);
      final payload = jsonDecode(utf8.decode(ZLibCodec(raw: true).decode(compressed))) as Map<String, Object?>;

      // The compact form qrVault.ts writes: short keys, no ids or dates.
      final accounts = (expected['accounts']! as List<Object?>).cast<Map<String, Object?>>();
      final services = (expected['backupServices']! as List<Object?>).cast<Map<String, Object?>>();
      expect(payload, {
        'a': [
          for (final a in accounts)
            {'i': a['issuer'], 'l': a['label'], 's': a['secret'], 'a': a['algorithm'], 'd': a['digits'], 'p': a['period']},
        ],
        'b': [
          for (final s in services) {'n': s['serviceName'], 'c': s['codes']},
        ],
      });
    });

    test('rejects the wrong password', () async {
      final key = await pbkdf2Sha256InBackground(utf8.encode('not-the-password'), salt, 200000, 32);
      await expectLater(aesGcmDecrypt(key, iv, ciphertext), throwsA(isA<AesGcmAuthError>()));
    });
  });
}
