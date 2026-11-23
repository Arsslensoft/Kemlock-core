// The manifest check on the real crypto (add-kemlock-server-sync, task 13.1): every test of km_manifest_test.dart,
// run again with each phone signing and verifying its manifests with the real `sig1` (ML-DSA-65 with Ed25519) of
// a real account, and sealing items with the real `kem1`.
@Timeout(Duration(minutes: 10))
@TestOn('vm')
library;

import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'km_manifest_test.dart' as manifest;
import 'real_km_crypto.dart';

void main() {
  setUpAll(() async => useRealCrypto(await KmTestAccount.create('00000000-0000-4000-8000-000000000001')));
  tearDownAll(useFakeCrypto);

  manifest.main();
}
