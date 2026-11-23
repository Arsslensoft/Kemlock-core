@TestOn('vm')
library;

// How the vault tells a key it holds (openspec: add-pgp-key-editing,
// design decision 2): a PGP key by its fingerprint, any other as before.

import 'package:kemlock_core/features/keys/key_bridge.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:test/test.dart';

import 'pgp_kit.dart';

void main() {
  test('a PGP key before and after a change is one key: its fingerprint', () async {
    final before = await pgpVaultKey();
    final after = await pgpVaultKey(path: 'gnupg/editing/signing-subkey.after.secret.asc', id: 'other-id');
    expect(before.publicKey, isNot(after.publicKey));
    expect(keyIdentity(before), 'pgp:E770227F48E661EAF271EAA7F92D39E6751913DD');
    expect(keyIdentity(after), keyIdentity(before));
    expect(keyIdentity(await pgpVaultKey(path: 'gnupg/editing/protected.secret.asc')), isNot(keyIdentity(before)));
  });

  test('a PGP key whose public half does not read is told by its bytes, as before', () async {
    final key = await pgpVaultKey();
    final damaged = VaultKey.fromJson({...key.toJson(), 'public': 'AAAA'});
    final notBase64 = VaultKey.fromJson({...key.toJson(), 'public': 'not base64!'});
    final noPublic = VaultKey.fromJson({...key.toJson()}..remove('public'));
    expect(keyIdentity(damaged), 'AAAA');
    expect(keyIdentity(notBase64), 'not base64!');
    expect(keyIdentity(noPublic), key.privateKey);
  });

  test('every other kind is told by its public half, or its private one without', () {
    for (final kind in [KeyKind.ssh, KeyKind.signing, KeyKind.exchange, KeyKind.other]) {
      final key = VaultKey(
        id: 'k',
        name: 'n',
        kind: kind,
        algorithm: 'ed25519',
        privateKey: 'PRIV',
        publicKey: 'PUB',
        origin: KeyOrigin.generated,
        addedAt: 1,
      );
      expect(keyIdentity(key), 'PUB', reason: kind);
      expect(keyIdentity(VaultKey.fromJson({...key.toJson()}..remove('public'))), 'PRIV', reason: kind);
    }
  });
}
