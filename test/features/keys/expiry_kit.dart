import 'dart:io';

import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/features/keys/key_bridge.dart';
import 'package:kemlock_core/models/vault_key.dart';

/// The GnuPG keys of test/fixtures/keys/gnupg/expiry, by file name: never,
/// expired, future, revoked, revoked-expired and subkey-expired.
String expiryFixtureText(String name) => File('test/fixtures/keys/gnupg/expiry/$name.secret.asc').readAsStringSync();

/// When the `future` key and its subkey expire: 1 January 2095, 17:00 UTC.
final futureExpiry = DateTime.fromMillisecondsSinceEpoch(3944739600 * 1000, isUtc: true);

/// When the `expired` and `revoked-expired` keys expired: 31 December 2020, 12:00 UTC.
final pastExpiry = DateTime.utc(2020, 12, 31, 12);

/// The fixture [name] as the vault keeps an imported key, listed as
/// [title] (its file name unless given) under the id `pgp-<name>`.
Future<VaultKey> expiryFixtureKey(String name, {String? title, bool pinned = false, int addedAt = 0}) async {
  final parsed = await crypto.readPrivateKey(expiryFixtureText(name));
  return vaultKeyOf(
    parsed,
    id: 'pgp-$name',
    name: title ?? name,
    origin: KeyOrigin.imported,
  ).copyWith(addedAt: addedAt, pinned: pinned ? true : null);
}

/// An SSH key as the vault keeps it; its halves are placeholders nothing reads.
VaultKey sshKey({String id = 'ssh-1', String name = 'laptop'}) => VaultKey(
  id: id,
  name: name,
  kind: KeyKind.ssh,
  algorithm: 'ed25519',
  privateKey: 'MC4CAQAwBQYDK2VwBCIEIA==',
  publicKey: 'MCowBQYDK2VwAyEAaaaa',
  origin: KeyOrigin.generated,
  addedAt: 0,
);
