import 'dart:io';

import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/features/keys/key_bridge.dart';
import 'package:kemlock_core/models/vault_key.dart';

/// The PGP key in [path] under test/fixtures/keys, as the vault keeps it
/// once imported: the `signing-subkey` key of `gnupg/editing` by default,
/// whose `signing-subkey.after` is the same key after GnuPG changed it.
Future<VaultKey> pgpVaultKey({
  String path = 'gnupg/editing/signing-subkey.secret.asc',
  String id = 'k-pgp',
  String name = 'Fixture Signing',
  String? passphrase,
  int addedAt = 100,
  int? updatedAt,
}) async {
  final parsed = await crypto.readPrivateKey(File('test/fixtures/keys/$path').readAsStringSync(), passphrase: passphrase);
  return vaultKeyOf(parsed, id: id, name: name, origin: KeyOrigin.imported).copyWith(addedAt: addedAt, updatedAt: updatedAt);
}
