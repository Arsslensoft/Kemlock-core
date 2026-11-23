@TestOn('vm')
library;

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/stream.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

// test/fixtures/keys/sequoia/pqc holds a version 6 post-quantum key and
// messages sq 1.5.0 made (see its README.md). Here: every file is there
// and de-armors into whole packets.

void main() {
  test('every key, message and signature de-armors into whole packets', () {
    for (final (name, type) in [
      ('standard.secret.asc', pgpPrivateKeyBlock),
      ('standard-protected.secret.asc', pgpPrivateKeyBlock),
      ('standard.public.asc', pgpPublicKeyBlock),
      ('message.pgp', pgpMessageBlock),
      ('message.txt.sig', pgpSignatureBlock),
      ('message.signed.pgp', pgpMessageBlock),
    ]) {
      final binary = readArmorBlock(keyFixture('sequoia/pqc/$name'), type: type);
      final packets = PacketReader(PgpReader.bytes(binary));
      var count = 0;
      for (var p = packets.next(); p != null; p = packets.next()) {
        p.body.rest(max: binary.length);
        count++;
      }
      expect(count, greaterThan(0), reason: name);
    }
    expect(keyFixtureText('sequoia/pqc/message.cleartext.asc'), startsWith('-----BEGIN PGP SIGNED MESSAGE-----'));
    expect(keyFixtureText('sequoia/pqc/versions.txt'), startsWith('sq 1.5.0\n'));
    expect(keyFixtureText('sequoia/pqc/message.decrypt.txt'), contains('Session key: '));
  });
}
