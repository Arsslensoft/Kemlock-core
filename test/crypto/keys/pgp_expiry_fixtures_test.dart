@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The keys in test/fixtures/keys/gnupg/expiry were made by GnuPG 2.4.9 (the
// commands are in the README beside them): keys that never expire, expired,
// expire in 2095, were revoked, and one whose subkey alone expired.
// <name>.colons.txt is what `gpg --list-keys --with-colons` printed.

DateTime _utc(int seconds) => DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

/// The fingerprint and expiry of each `pub` and `sub` line GnuPG listed.
List<({String fingerprint, DateTime? expires})> _listed(String name) {
  final keys = <({String fingerprint, DateTime? expires})>[];
  List<String>? pending;
  for (final line in const LineSplitter().convert(keyFixtureText('gnupg/expiry/$name.colons.txt'))) {
    final f = line.split(':');
    if (f[0] == 'pub' || f[0] == 'sub') {
      pending = f;
    } else if (f[0] == 'fpr' && pending != null) {
      keys.add((fingerprint: f[9], expires: pending[6].isEmpty ? null : _utc(int.parse(pending[6]))));
      pending = null;
    }
  }
  return keys;
}

const _keys = <({String name, bool revoked, bool primaryExpires, bool subkeyExpires})>[
  (name: 'never', revoked: false, primaryExpires: false, subkeyExpires: false),
  (name: 'expired', revoked: false, primaryExpires: true, subkeyExpires: true),
  (name: 'future', revoked: false, primaryExpires: true, subkeyExpires: true),
  (name: 'revoked', revoked: true, primaryExpires: false, subkeyExpires: false),
  (name: 'revoked-expired', revoked: true, primaryExpires: true, subkeyExpires: true),
  (name: 'subkey-expired', revoked: false, primaryExpires: false, subkeyExpires: true),
];

void main() {
  for (final k in _keys) {
    void expectKey(PgpKeyInfo info, {required bool secret}) {
      final listed = _listed(k.name);
      expect(info.isSecret, secret);
      expect(info.primary.fingerprintHex, listed[0].fingerprint);
      expect(info.primary.expires, listed[0].expires, reason: 'as GnuPG lists it');
      expect(info.primary.expires, k.primaryExpires ? isNotNull : isNull);
      expect(info.primary.revoked, k.revoked);

      expect(info.subkeys, hasLength(1));
      expect(info.subkeys.single.fingerprintHex, listed[1].fingerprint);
      // GnuPG lists a subkey as expiring no later than its primary key. The expired key's subkey was
      // made a second after its primary, each for a year, so its own date is a second later.
      final own = info.subkeys.single.expires;
      final primary = info.primary.expires;
      expect(own != null && primary != null && primary.isBefore(own) ? primary : own, listed[1].expires, reason: 'as GnuPG lists it');
      if (k.name == 'expired') expect(own, listed[1].expires!.add(const Duration(seconds: 1)));
      expect(info.subkeys.single.expires, k.subkeyExpires ? isNotNull : isNull);
      // GnuPG revokes the primary key alone: the subkey carries no revocation of its own
      expect(info.subkeys.single.revoked, isFalse);
    }

    test('${k.name}: the secret half gives the expiry and revocation of the primary and the subkey', () async {
      final parsed = await readPrivateKey(keyFixtureText('gnupg/expiry/${k.name}.secret.asc'));

      expectKey(parsed.pgp!, secret: true);
      expectKey(readPgpKeyInfo(parsed.private), secret: true);
    });

    test('${k.name}: the public half gives the same', () async {
      final exported = readArmor(readPemBlocks(keyFixtureText('gnupg/expiry/${k.name}.public.asc')).single);
      expectKey(readPgpKeyInfo(exported), secret: false);

      // The public half the vault keeps beside the secret one
      final parsed = await readPrivateKey(keyFixtureText('gnupg/expiry/${k.name}.secret.asc'));
      expect(parsed.public, exported);
      expectKey(readPgpKeyInfo(parsed.public!), secret: false);
    });
  }
}
