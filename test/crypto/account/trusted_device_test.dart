@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/trusted_device.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:test/test.dart';

// The prefix (u8(1), then a platform byte) and the aad are crypto.md's. The
// inner per-platform layout is the plan's proposal (design 8), so this checks
// the layer the plan describes: K_td seals the root under the stated additional
// data, and the blob opens only under that K_td, account, device, key version
// and platform. The platform's wrapping of K_td is not Dart and not here.
void main() {
  final trustedKey = Uint8List.fromList(List.generate(32, (i) => 0x30 + i));
  final root = Uint8List.fromList(List.generate(64, (i) => (i * 5 + 2) & 0xff));
  final accountId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ab');
  final deviceId = uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789cd');
  const ios = TrustedDevicePlatform.secureEnclave;

  Future<Uint8List> seal({Uint8List? key, TrustedDevicePlatform platform = ios}) => sealRootForTrustedDevice(
    platform: platform,
    trustedKey: key ?? trustedKey,
    accountId: accountId,
    deviceId: deviceId,
    keyVersion: 1,
    rootKey: root,
  );

  Future<Uint8List> open(
    Uint8List sealed, {
    Uint8List? key,
    List<int>? account,
    List<int>? device,
    int keyVersion = 1,
    TrustedDevicePlatform platform = ios,
  }) => openRootForTrustedDevice(
    platform: platform,
    trustedKey: key ?? trustedKey,
    accountId: account ?? accountId,
    deviceId: device ?? deviceId,
    keyVersion: keyVersion,
    sealed: sealed,
  );

  test('the platform bytes are 1 Secure Enclave, 2 Android Keystore and 3 WebCrypto', () {
    expect(TrustedDevicePlatform.secureEnclave.code, 0x01);
    expect(TrustedDevicePlatform.androidKeystore.code, 0x02);
    expect(TrustedDevicePlatform.webCrypto.code, 0x03);
    expect(trustedDeviceBlobVersion, 1);
  });

  test('writes u8(1), the platform byte, then the root sealed under K_td with the aad of crypto.md', () async {
    final nonce = Uint8List.fromList(List.generate(12, (i) => 0x10 + i));
    for (final platform in TrustedDevicePlatform.values) {
      final blob = await sealRootForTrustedDevice(
        platform: platform,
        trustedKey: trustedKey,
        accountId: accountId,
        deviceId: deviceId,
        keyVersion: 2,
        rootKey: root,
        nonce: nonce,
      );
      // aad = "kemlock/v1/root-wrap/device" || account id || device id || u32be(key version), by hand
      final aad = [...utf8.encode('kemlock/v1/root-wrap/device'), ...accountId, ...deviceId, 0, 0, 0, 2];
      final expected = await aesGcmEncrypt(trustedKey, root, nonce: nonce, aad: aad);
      expect(blob, [1, platform.code, ...nonce, ...expected.ct], reason: platform.name);
      expect(blob, hasLength(trustedDeviceBlobLength));
      expect(trustedDeviceBlobLength, 94);
    }
  });

  test('opens with the same K_td, account, device, key version and platform', () async {
    expect(await open(await seal()), root);
    for (final platform in TrustedDevicePlatform.values) {
      expect(
        await open(await seal(platform: platform), platform: platform),
        root,
        reason: platform.name,
      );
    }
  });

  test("another phone's K_td opens nothing, and neither does another account, device or key version", () async {
    final sealed = await seal();
    await expectLater(open(sealed, key: newTrustedDeviceKey()), throwsA(isA<CorruptedException>()));
    await expectLater(open(sealed, account: uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ac')), throwsA(isA<CorruptedException>()));
    await expectLater(open(sealed, device: uuidBytes('0189f7c2-5a3e-7b21-8d4f-0123456789ce')), throwsA(isA<CorruptedException>()));
    await expectLater(open(sealed, keyVersion: 2), throwsA(isA<CorruptedException>()));
  });

  test("another platform's blob and another version's are refused as malformed", () async {
    final sealed = await seal();
    await expectLater(open(sealed, platform: TrustedDevicePlatform.androidKeystore), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List.fromList(sealed)..[0] = 2), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List.fromList(sealed)..[0] = 0), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List.fromList(sealed)..[1] = 0x04), throwsA(isA<MalformedException>()));
  });

  test('a changed byte after the prefix fails, and a wrong length is malformed', () async {
    final sealed = await seal();
    for (final index in [2, 13, 14, 42, 93]) {
      await expectLater(open(Uint8List.fromList(sealed)..[index] ^= 1), throwsA(isA<CorruptedException>()), reason: 'byte $index');
    }
    await expectLater(open(sealed.sublist(0, 93)), throwsA(isA<MalformedException>()));
    await expectLater(open(Uint8List.fromList([...sealed, 0])), throwsA(isA<MalformedException>()));
    await expectLater(open(sealed, key: Uint8List(31)), throwsA(isA<MalformedException>()));
    await expectLater(open(sealed, device: Uint8List(15)), throwsA(isA<MalformedException>()));
  });

  test('K_td is 32 fresh random bytes, and sealing twice differs', () async {
    expect(newTrustedDeviceKey(), hasLength(32));
    expect(newTrustedDeviceKey(), isNot(newTrustedDeviceKey()));
    expect(await seal(), isNot(await seal()));
  });
}
