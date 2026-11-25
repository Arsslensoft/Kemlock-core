@TestOn('vm')
library;

import 'package:kemlock_core/core/storage/key_value_store.dart';
import 'package:kemlock_core/vault/vault_registry.dart';
import 'package:kemlock_core/vault/vault_store.dart';
import 'package:test/test.dart';

import 'fast_kdf.dart';

void main() {
  late KeyValueStore store;
  late VaultRegistry registry;
  late VaultStore vaultStore;

  setUp(() async {
    store = KeyValueStore.memory();
    registry = VaultRegistry(store);
    vaultStore = VaultStore(store, registry, deriveKey: fastKdf);
    await vaultStore.setupVault('right password');
  });

  test('says whether a password is the vault\'s', () async {
    expect(await vaultStore.passwordOpens('right password', registry.active), isTrue);
    expect(await vaultStore.passwordOpens('wrong password', registry.active), isFalse);
  });

  test('writes nothing and leaves the active vault as it was', () async {
    final before = {for (final key in store.storedKeys()) key: store.getItem(key)};
    final active = registry.active;

    await vaultStore.passwordOpens('right password', active);
    await vaultStore.passwordOpens('wrong password', active);

    expect({for (final key in store.storedKeys()) key: store.getItem(key)}, before);
    expect(registry.active, active);
  });

  test('says no for a vault that is not there', () async {
    expect(await vaultStore.passwordOpens('right password', 'no-such-vault'), isFalse);
  });
}
