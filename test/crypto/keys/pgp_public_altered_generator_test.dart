@TestOn('vm')
library;

// Writes the three hand-altered keys of test/fixtures/keys/contacts, and runs
// only when asked:
//
//   OUT=test/fixtures/keys/contacts flutter test test/crypto/keys/pgp_public_altered_generator_test.dart
//
// It ran once, when add-pgp-contacts was built (its task 1.1), and the files
// it wrote are frozen: never run it again over them. GnuPG wrote none of
// them; each is a key GnuPG made, changed here the way someone who can
// alter a file on its way would change it.
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

List<PgpPacket> _packets(String path) => readPackets(readArmor(readPemBlocks(File(path).readAsStringSync()).single));

Uint8List _join(Iterable<Uint8List> parts) => (BytesBuilder()..add([for (final p in parts) ...p])).toBytes();

void main() {
  final out = Platform.environment['OUT'];

  test('writes the altered keys to OUT', () {
    final grace = _packets('$out/grace-1.public.asc');
    final alan = _packets('$out/alan.public.asc');

    // Alan's encryption subkey and the binding Alan's primary key made for it, put after Grace's own
    // packets: the fingerprint is still Grace's, and a reader that checks nothing would encrypt to Alan.
    final subkeyAt = alan.indexWhere((p) => p.tag == PgpTag.publicSubkey);
    File('$out/grace-1.foreign-subkey.public.asc').writeAsStringSync(
      writeArmor(pgpPublicKeyBlock, _join([for (final p in grace) p.encoded, alan[subkeyAt].encoded, alan[subkeyAt + 1].encoded])),
    );

    // The last byte of the user ID's certification, in the signature itself, flipped.
    final certAt = grace.indexWhere((p) => p.tag == PgpTag.userId) + 1;
    expect(grace[certAt].tag, PgpTag.signature);
    final flipped = Uint8List.fromList(grace[certAt].encoded);
    flipped[flipped.length - 1] ^= 0x01;
    File('$out/grace-1.flipped-certification.public.asc')
        .writeAsStringSync(writeArmor(pgpPublicKeyBlock, _join([for (final (i, p) in grace.indexed) i == certAt ? flipped : p.encoded])));

    // The armored block as far as its fifth line: no end line, and base64 that stops inside a packet.
    final lines = File('$out/grace-1.public.asc').readAsStringSync().split('\n');
    File('$out/grace-1.cut.public.asc').writeAsStringSync('${lines.take(5).join('\n')}\n');
  }, skip: out == null ? 'Writes the frozen fixtures; set OUT to run' : false);
}
