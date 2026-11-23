@TestOn('vm')
library;

// Writes test/fixtures/keys/contacts/rsa3072-certified-photo.trimmed.public.asc,
// and runs only when asked:
//
//   OUT=test/fixtures/keys/contacts flutter test test/crypto/keys/pgp_public_trimmed_generator_test.dart
//
// It ran once, when add-pgp-contacts was built (its task 2.1): the file is
// what trimPublicKey kept of the certified key with a photo that day, and
// the listing beside it is what GnuPG 2.4.9 printed for it. Both are
// frozen: never run it again over them.
import 'dart:io';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/public_key.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:test/test.dart';

void main() {
  final out = Platform.environment['OUT'];

  test('writes the trimmed key to OUT', () async {
    final given = readArmor(readPemBlocks(File('$out/rsa3072-certified-photo.public.asc').readAsStringSync()).single);

    File('$out/rsa3072-certified-photo.trimmed.public.asc').writeAsStringSync(writeArmor(pgpPublicKeyBlock, await trimPublicKey(given)));
  }, skip: out == null ? 'Writes the frozen fixtures; set OUT to run' : false);
}
