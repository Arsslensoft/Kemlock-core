@TestOn('vm')
library;

import 'dart:io';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// test/fixtures/keys/gnupg/pqc holds the Kyber keys and messages GnuPG
// 2.5.24 made (see its README.md). Here: every file is there, and every
// key reads with its version 5 Kyber subkey, where the reader once refused
// them as "OpenPGP version 5".

const _keys = ['ky768-cv25519', 'pqc', 'ky1024-bp384'];

void main() {
  test('every key, listing and message is there', () {
    for (final base in _keys) {
      for (final name in [base, '$base-protected']) {
        for (final suffix in [
          'public.asc',
          'secret.asc',
          'colons.txt',
          'list.txt',
          'public.packets.txt',
          'secret.packets.txt',
          'message.gpg',
        ]) {
          expect(File('test/fixtures/keys/gnupg/pqc/$name.$suffix').existsSync(), isTrue, reason: '$name.$suffix');
        }
      }
    }
    for (final name in ['ky768-cv25519.force-ocb.gpg', 'ky768-cv25519.seipd1.gpg', 'message.txt', 'packets.txt', 'session-keys.txt']) {
      expect(File('test/fixtures/keys/gnupg/pqc/$name').existsSync(), isTrue, reason: name);
    }
    expect(keyFixtureText('gnupg/pqc/versions.txt'), startsWith('gpg (GnuPG) 2.5.24\n'));
    expect(keyFixtureText('gnupg/pqc/session-keys.txt').trim().split('\n'), hasLength(8));
  });

  test('every key reads, with its version 5 Kyber subkey', () {
    for (final base in _keys) {
      for (final name in [base, '$base-protected']) {
        for (final (half, type) in [('public', pgpPublicKeyBlock), ('secret', pgpPrivateKeyBlock)]) {
          final binary = readArmorBlock(keyFixture('gnupg/pqc/$name.$half.asc'), type: type);
          final subkey = readTransferableKey(binary).info.subkeys.single;
          expect(subkey.version, 5, reason: '$name.$half');
          expect(subkey.algorithm, startsWith('ky'), reason: '$name.$half');
        }
      }
    }
  });
}
