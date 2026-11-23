@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// test/fixtures/keys/rfc9980 holds the samples of RFC 9980 appendix A
// (see its README.md). Here: every file is whole, and the reader names
// the post-quantum algorithms, where it once named A.1's and A.3's
// `algorithm 35` and `algorithm 30` and refused A.2, a version 4 key it
// could not measure.

const _files = {
  'a1': ['secret', 'public', 'message'],
  'a2': ['secret', 'public', 'message-seipd1', 'message-seipd2'],
  'a3': ['secret', 'public', 'message', 'signature'],
  'a4': ['secret', 'public', 'message', 'signature'],
  'a5': ['secret', 'public', 'message', 'signature'],
  'a6': ['secret', 'public', 'signature'],
  'a7': ['secret', 'public', 'signature'],
};

const _types = {'secret': pgpPrivateKeyBlock, 'public': pgpPublicKeyBlock, 'signature': pgpSignatureBlock};

void main() {
  test('every file de-armors into whole packets', () {
    for (final MapEntry(key: section, value: names) in _files.entries) {
      for (final name in names) {
        final text = keyFixture('rfc9980/$section-$name.asc');
        final binary = readArmorBlock(text, type: _types[name] ?? pgpMessageBlock);
        // Messages come in partial lengths, which the key reader refuses
        final packets = PacketReader(PgpReader.bytes(binary));
        var count = 0;
        for (var p = packets.next(); p != null; p = packets.next()) {
          p.body.rest(max: binary.length);
          count++;
        }
        expect(count, name == 'signature' ? 1 : greaterThan(1), reason: '$section-$name');
      }
    }
  });

  test('values.json has the fingerprints and the values of each message', () {
    final values = jsonDecode(keyFixtureText('rfc9980/values.json')) as Map<String, Object?>;
    for (final section in _files.keys) {
      final fingerprints = values[section]! as Map<String, Object?>;
      expect(fingerprints.keys, ['primaryFingerprint', 'subkeyFingerprint'], reason: section);
    }
    for (final message in ['a1-message', 'a2-message-seipd1', 'a2-message-seipd2', 'a3-message', 'a4-message', 'a5-message']) {
      final kem = values[message]! as Map<String, Object?>;
      expect(kem.keys, ['mlkemKeyShare', 'ecdhKeyShare', 'multiKeyCombine', 'sessionKey'], reason: message);
    }
  });

  group('the post-quantum algorithms', () {
    PgpKeyInfo read(String section) =>
        readTransferableKey(readArmorBlock(keyFixture('rfc9980/$section-public.asc'), type: pgpPublicKeyBlock)).info;

    test("names A.1's subkey", () {
      final info = read('a1');
      expect(info.primary.algorithm, 'ed25519');
      expect(info.subkeys.single.algorithm, 'mlk768');
    });

    test('names both keys of A.3', () {
      final info = read('a3');
      expect(info.primary.algorithm, 'mld65');
      expect(info.subkeys.single.algorithm, 'mlk768');
    });

    test("reads A.2's version 4 key and measures its subkey", () {
      final info = read('a2');
      expect(info.version, 4);
      expect(info.subkeys.single.algorithm, 'mlk768');
    });
  });
}
