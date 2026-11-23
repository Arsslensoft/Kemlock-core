@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The keys a change to a PGP key is tried on (openspec: add-pgp-key-editing):
// test/fixtures/keys/gnupg/editing, made by GnuPG 2.4.9, and
// test/fixtures/keys/other/editing, made by Sequoia sq 1.3.1. The commands
// are in the README beside each. <name>.colons.txt is what
// `gpg --list-keys --with-colons` printed.

DateTime _utc(int seconds) => DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);

typedef _Listed = ({String fingerprint, DateTime? expires, String usage});

/// The `pub` and `sub` lines GnuPG listed, and the user IDs in its order.
({List<_Listed> keys, List<String> userIds}) _listed(String path) {
  final keys = <_Listed>[];
  final userIds = <String>[];
  List<String>? pending;
  for (final line in const LineSplitter().convert(keyFixtureText('$path.colons.txt'))) {
    final f = line.split(':');
    if (f[0] == 'pub' || f[0] == 'sub') {
      pending = f;
    } else if (f[0] == 'uid') {
      userIds.add(f[9]);
    } else if (f[0] == 'fpr' && pending != null) {
      keys.add((fingerprint: f[9], expires: pending[6].isEmpty ? null : _utc(int.parse(pending[6])), usage: pending[11]));
      pending = null;
    }
  }
  return (keys: keys, userIds: userIds);
}

const _keys = <({String path, bool protected})>[
  (path: 'gnupg/editing/signing-subkey', protected: false),
  (path: 'gnupg/editing/signing-subkey.after', protected: false),
  (path: 'gnupg/editing/rsa3072-expiring', protected: false),
  (path: 'gnupg/editing/protected', protected: true),
  (path: 'other/editing/direct-key', protected: false),
];

void main() {
  for (final k in _keys) {
    void expectKey(PgpKeyInfo info, {required bool secret}) {
      final listed = _listed(k.path);
      expect(info.isSecret, secret);
      expect(info.protected, secret && k.protected);
      expect(info.userIds.toSet(), listed.userIds.toSet());
      expect(info.primary.fingerprintHex, listed.keys.first.fingerprint);
      expect(info.primary.expires, listed.keys.first.expires, reason: 'as GnuPG lists it');
      expect(info.primary.revoked, isFalse);
      expect(info.primary.canCertify, isTrue);
      expect(info.subkeys.map((s) => s.fingerprintHex), listed.keys.skip(1).map((l) => l.fingerprint));
      for (final (i, subkey) in info.subkeys.indexed) {
        final l = listed.keys[i + 1];
        // GnuPG lists a subkey as expiring no later than its primary key
        final own = subkey.expires;
        final primary = info.primary.expires;
        expect(own != null && primary != null && primary.isBefore(own) ? primary : own, l.expires, reason: 'as GnuPG lists it');
        expect(subkey.canSign, l.usage.contains('s'));
        expect(subkey.canEncrypt, l.usage.contains('e'));
        expect(subkey.canAuthenticate, l.usage.contains('a'));
        expect(subkey.revoked, isFalse);
      }
    }

    test('${k.path}: the secret half reads as GnuPG lists it', () async {
      final parsed = await readPrivateKey(keyFixtureText('${k.path}.secret.asc'));
      expectKey(parsed.pgp!, secret: true);
      expectKey(readPgpKeyInfo(parsed.private), secret: true);
    });

    test('${k.path}: the public half reads the same', () async {
      final exported = readArmor(readPemBlocks(keyFixtureText('${k.path}.public.asc')).single);
      expectKey(readPgpKeyInfo(exported), secret: false);
      // GnuPG exported what sq wrote with its own packet headers
      if (k.path.startsWith('gnupg/')) {
        final parsed = await readPrivateKey(keyFixtureText('${k.path}.secret.asc'));
        expect(parsed.public, exported);
      }
    });
  }

  test('GnuPG changed the first key: one more user ID and subkey, later dates', () async {
    final before = (await readPrivateKey(keyFixtureText('gnupg/editing/signing-subkey.secret.asc'))).pgp!;
    final after = (await readPrivateKey(keyFixtureText('gnupg/editing/signing-subkey.after.secret.asc'))).pgp!;
    expect(after.primary.fingerprintHex, before.primary.fingerprintHex);
    expect(before.userIds, ['Fixture Signing <signing@example.org>']);
    // GnuPG exported the user IDs newest first
    expect(after.userIds, ['Fixture Signing <signing@work.example.org>', 'Fixture Signing <signing@example.org>']);
    expect(before.subkeys, hasLength(2));
    expect(after.subkeys, hasLength(3));
    expect(before.primary.expires, DateTime.utc(2030, 1, 1, 17));
    expect(after.primary.expires, DateTime.utc(2035, 1, 1, 17));
    expect(before.subkeys[0].canSign, isTrue);
  });

  test('the stub has no primary secret, and keeps its subkey protected', () async {
    final parsed = await readPrivateKey(keyFixtureText('gnupg/editing/protected.stub.secret.asc'));
    final info = parsed.pgp!;
    final full = (await readPrivateKey(keyFixtureText('gnupg/editing/protected.secret.asc'))).pgp!;
    expect(info.primary.fingerprintHex, full.primary.fingerprintHex);
    expect(info.primary.hasSecret, isTrue);
    expect(info.primary.protected, isTrue, reason: 'a stub counts as protected: there is no secret to use');
    expect(info.subkeys.single.protected, isTrue);
    expect(info.userIds, full.userIds);
  });

  test('the direct-key fixture keeps its flags and expiry in a direct-key signature', () async {
    final info = (await readPrivateKey(keyFixtureText('other/editing/direct-key.secret.asc'))).pgp!;
    expect(info.primary.expires, DateTime.utc(2029, 12, 31, 23, 59, 59));
    expect(info.primary.flags, PgpKeyFlag.certify);
    expect(info.subkeys, hasLength(3));
  });
}
