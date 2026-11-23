@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// The public keys in test/fixtures/keys/contacts were made by GnuPG 2.4.9 (the commands are in the README
// beside them). <name>.colons.txt is what `gpg --list-keys --with-colons` printed for each.

typedef ListedKey = ({String fingerprint, List<String> userIds, List<String> subkeys});

/// What GnuPG listed in `contacts/<name>.colons.txt`: for each key, its fingerprint, user IDs and subkeys.
List<ListedKey> listedKeys(String name) {
  final keys = <ListedKey>[];
  String? pending;
  for (final line in const LineSplitter().convert(keyFixtureText('contacts/$name.colons.txt'))) {
    final f = line.split(':');
    switch (f[0]) {
      case 'pub' || 'sub':
        pending = f[0];
      case 'fpr' when pending == 'pub':
        keys.add((fingerprint: f[9], userIds: [], subkeys: []));
        pending = null;
      case 'fpr' when pending == 'sub':
        keys.last.subkeys.add(f[9]);
        pending = null;
      case 'uid':
        keys.last.userIds.add(f[9]);
    }
  }
  return keys;
}

/// The bytes of an armored fixture under `contacts/`.
Uint8List contactKeyBytes(String file) => readArmor(readPemBlocks(keyFixtureText('contacts/$file')).single);

void expectAsListed(PgpKeyInfo info, ListedKey listed) {
  expect(info.isSecret, isFalse);
  expect(info.primary.fingerprintHex, listed.fingerprint);
  expect(info.userIds, listed.userIds);
  expect([for (final k in info.subkeys) k.fingerprintHex], listed.subkeys);
}

void main() {
  for (final name in ['grace-1', 'grace-2', 'grace-3', 'alan', 'rsa3072-certified-photo', 'sign-only', 'ecdsa-p256']) {
    test('$name reads with the fingerprint, user IDs and subkeys GnuPG lists', () {
      expectAsListed(readTransferableKey(contactKeyBytes('$name.public.asc')).info, listedKeys(name).single);
    });
  }

  test('the three ages of one key: a later expiry and a subkey, then a revocation', () {
    final first = readTransferableKey(contactKeyBytes('grace-1.public.asc')).info;
    final second = readTransferableKey(contactKeyBytes('grace-2.public.asc')).info;
    final third = readTransferableKey(contactKeyBytes('grace-3.public.asc')).info;

    expect(second.fingerprint, first.fingerprint);
    expect(third.fingerprint, first.fingerprint);
    expect(first.primary.expires, DateTime.fromMillisecondsSinceEpoch(1826420030 * 1000, isUtc: true));
    expect(second.primary.expires, DateTime.fromMillisecondsSinceEpoch(1893517200 * 1000, isUtc: true));
    expect(first.subkeys, hasLength(1));
    expect(second.subkeys, hasLength(2));
    expect(second.subkeys.last.canSign, isTrue);
    expect([first.primary.revoked, second.primary.revoked, third.primary.revoked], [false, false, true]);
  });

  test('the sign-only key has no key to encrypt to, and the ECDSA key is a nistp256 one', () {
    final signOnly = readTransferableKey(contactKeyBytes('sign-only.public.asc')).info;
    expect(signOnly.subkeys, isEmpty);
    expect(signOnly.primary.canEncrypt, isFalse);

    expect(readTransferableKey(contactKeyBytes('ecdsa-p256.public.asc')).info.primary.algorithm, 'nistp256');
  });

  test('the keyring holds two keys, one after the other, binary and armored', () {
    final listed = listedKeys('two-keys');
    expect(listed, hasLength(2));
    for (final bytes in [keyFixture('contacts/two-keys.public.gpg'), contactKeyBytes('two-keys.public.asc')]) {
      final first = readTransferableKey(bytes);
      expectAsListed(first.info, listed[0]);
      expect(first.length, lessThan(bytes.length));
      final second = readTransferableKey(Uint8List.sublistView(bytes, first.length));
      expectAsListed(second.info, listed[1]);
      expect(first.length + second.length, bytes.length);
    }
  });
}
