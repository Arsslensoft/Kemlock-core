// The Kemlock Server run on the real crypto (add-kemlock-server-sync, task 13.1): every test of km_sync_test.dart,
// run again with each phone sealing with `AccountItemCrypto` over a real account's keys in place of the fake's `kem1`
// under a random wrap key and MAC. `sig1` is slow in pure Dart, hence the time.
@Timeout(Duration(minutes: 10))
@TestOn('vm')
library;

import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'km_sync_test.dart' as run;
import 'real_km_crypto.dart';

void main() {
  setUpAll(() async => useRealCrypto(await KmTestAccount.create('00000000-0000-4000-8000-000000000001')));
  tearDownAll(useFakeCrypto);

  run.main();
}
