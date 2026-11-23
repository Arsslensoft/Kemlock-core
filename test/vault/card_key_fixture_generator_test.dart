@TestOn('vm')
library;

// Writes test/fixtures/vault-items/card-key-vault.json, and runs only when
// asked:
//
//   OUT=test/fixtures/vault-items flutter test test/vault/card_key_fixture_generator_test.dart
//
// It ran once, when add-openpgp-card was built (its task 4.3), and the file
// it wrote is frozen: never run it again over it. Like
// rotation_fixtures_generator_test.dart it builds the storage by hand in
// the formats the store reads, from fixed seeds, rather than through
// VaultStore, so the fixture also checks those formats.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/aes_gcm.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:kemlock_core/crypto/scrypt.dart';
import 'package:test/test.dart';

/// [n] bytes for [label], always the same.
Uint8List _seeded(String label, int n) {
  final out = BytesBuilder();
  for (var i = 0; out.length < n; i++) {
    out.add(sha256.convert(utf8.encode('kemlock card key fixture/$label/$i')).bytes);
  }
  return Uint8List.fromList(out.toBytes().sublist(0, n));
}

/// [plain] sealed to [publicKey] as the store seals a value, from seeds named [label].
Future<String> _seal(List<int> plain, Uint8List publicKey, String label) async {
  final kem = MlKem1024.encapsulate(publicKey, _seeded('$label/m', 32));
  final sealed = await aesGcmEncrypt(kem.sharedSecret, plain, nonce: _seeded('$label/nonce', 12));
  return jsonEncode({'kemCT': b64(kem.cipherText), 'nonce': b64(sealed.nonce), 'ct': b64(sealed.ct)});
}

const _password = 'fixture password';

void main() {
  final out = Platform.environment['OUT'];

  test('writes the card key vault fixture to OUT', () async {
    // The card key of test/fixtures/keys/gnupg/card: GnuPG's Ed25519 key
    // whose two keys are on a made-up card
    final key = {
      'id': 'k1',
      'name': 'Fixture Ed25519',
      'kind': 'pgp',
      'algorithm': 'pgp',
      'private': b64(File('test/fixtures/keys/gnupg/card/stub-ed25519.gpg').readAsBytesSync()),
      'public': b64(File('test/fixtures/keys/gnupg/ed25519.public.gpg').readAsBytesSync()),
      'origin': 'imported',
      'protected': true,
      'note': 'On the card in the drawer',
      'tags': ['work'],
      'addedAt': 1763337600000,
      'card': {
        'aid': 'D276000124010304FFFF123456780000',
        'slots': {'sig': '1FCDA135EE42400EC2B77CE677249ABE661CF8DB', 'dec': '4BA83174FC8CE762A23BF0A4841A40E3B199EA67'},
      },
    };

    final salt = _seeded('salt', 32);
    final kek = scrypt(utf8.encode(_password), salt, n: 131072, r: 8, p: 1);
    final pair = MlKem1024.keygen(_seeded('pair', 64));
    final wrapped = await aesGcmEncrypt(kek, pair.secretKey, nonce: _seeded('config', 12));
    final storage = {
      'backmycodes_vault_config': jsonEncode({
        'salt': b64(salt),
        'skNonce': b64(wrapped.nonce),
        'skEnc': b64(wrapped.ct),
        'publicKey': b64(pair.publicKey),
        'scrypt': {'N': 131072, 'r': 8, 'p': 1},
      }),
      'backmycodes_key_data': await _seal(utf8.encode(jsonEncode([key])), pair.publicKey, 'keys'),
    };

    const about =
        'Written once by test/vault/card_key_fixture_generator_test.dart, from fixed seeds, when add-openpgp-card '
        'was built, and never regenerated. The storage of a vault holding one PGP key whose private half is on an '
        'OpenPGP card: GnuPG card stubs for a private half, and the card that holds it, with the real scrypt '
        'parameters. card_key_vault_fixture_test.dart opens it with the password, and replaces its key.';
    final fixture = {'about': about, 'password': _password, 'key': key, 'storage': storage};
    File('${Directory(out!).path}/card-key-vault.json').writeAsStringSync('${const JsonEncoder.withIndent('  ').convert(fixture)}\n');
  }, skip: out == null ? 'Writes the frozen fixture; set OUT to run' : false);
}
