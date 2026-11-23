import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';

/// A file under `test/fixtures/pgp`, made by the tools `NOTES.md` names.
/// The fixtures are never regenerated.
Uint8List pgpFixture(String path) => File('test/fixtures/pgp/$path').readAsBytesSync();

String pgpFixtureText(String path) => File('test/fixtures/pgp/$path').readAsStringSync();

String pgpFixturePath(String path) => 'test/fixtures/pgp/$path';

/// The plain text of the GnuPG fixtures made from `message.txt`.
Uint8List get messageTxt => pgpFixture('gnupg/message.txt');

/// The first [size] bytes of the stream `tool/pgp/sample_file.dart` wrote
/// for `gnupg/large.gpg` (5 242 880 bytes) and `gnupg/chunks.ocb.gpg`
/// (1 048 576).
Uint8List sampleBytes(int size) {
  final out = Uint8List(size);
  var x = 0x4b454d4c;
  for (var i = 0; i < size; i++) {
    x ^= (x << 13) & 0xffffffff;
    x ^= x >> 17;
    x ^= (x << 5) & 0xffffffff;
    out[i] = x & 0xff;
  }
  return out;
}

/// What `gpg --show-session-key` printed for a file of `gnupg/`: the
/// cipher's ID (7, 8 or 9) and the session key.
({int cipher, Uint8List key}) gnupgSessionKey(String file) {
  for (final line in pgpFixtureText('gnupg/session-keys.txt').split('\n')) {
    final parts = line.trim().split(' ');
    if (parts.length != 2 || parts[0] != file) continue;
    final [id, hex] = parts[1].split(':');
    // GnuPG drops nothing: the key is as many hex digits as its length.
    return (cipher: int.parse(id.split('.').first), key: unhex(hex));
  }
  throw ArgumentError('no session key recorded for $file');
}

/// GnuPG's `VALIDSIG` lines for a file of `gnupg/`: the signing key's
/// fingerprint, when it was made, and the primary key's fingerprint.
List<({String signer, DateTime made, String primary})> gnupgSignatures(String file) => [
  for (final line in pgpFixtureText('gnupg/signatures.txt').split('\n'))
    if (line.startsWith('$file VALIDSIG '))
      () {
        final f = line.trim().split(' ');
        return (signer: f[2], made: DateTime.fromMillisecondsSinceEpoch(int.parse(f[4]) * 1000, isUtc: true), primary: f.last);
      }(),
];

Uint8List unhex(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([for (var i = 0; i < clean.length; i += 2) int.parse(clean.substring(i, i + 2), radix: 16)]);
}

String hexOf(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

/// A key file under `test/fixtures` as binary packets: `.asc` files are
/// dearmored.
Uint8List binaryKey(String path) {
  final bytes = File('test/fixtures/$path').readAsBytesSync();
  return path.endsWith('.asc') ? readArmorBlock(bytes) : bytes;
}

/// The fixture keys, as the vault would keep them.
abstract final class Keys {
  static Uint8List get ed => binaryKey('keys/gnupg/ed25519.secret.gpg');
  static Uint8List get rsa => binaryKey('keys/gnupg/rsa3072.secret.gpg');
  static Uint8List get edProtected => binaryKey('keys/gnupg/ed25519-protected.secret.gpg');
  static Uint8List get rsaProtected => binaryKey('keys/gnupg/rsa3072-protected.secret.gpg');
  static Uint8List get kemlockEd => binaryKey('keys/kemlock/pgp-ed25519.unprotected.asc');
  static Uint8List get kemlockRsa => binaryKey('keys/kemlock/pgp-rsa4096.unprotected.asc');
  static Uint8List get v6 => binaryKey('keys/rfc9580/v6-secret.asc');
  static Uint8List get signingSubkey => binaryKey('pgp/gnupg/signing-subkey.secret.asc');
  static Uint8List get rsa1024 => binaryKey('pgp/gnupg/rsa1024.secret.asc');
  static Uint8List get nistp256 => binaryKey('pgp/gnupg/nistp256.secret.asc');
  static Uint8List get brainpool => binaryKey('pgp/gnupg/brainpoolP256r1.secret.asc');
  static Uint8List get stub => binaryKey('pgp/gnupg/ed25519.stub.secret.gpg');

  static Uint8List get edPublic => binaryKey('keys/gnupg/ed25519.public.gpg');
  static Uint8List get rsaPublic => binaryKey('keys/gnupg/rsa3072.public.gpg');
  static Uint8List get edProtectedPublic => binaryKey('keys/gnupg/ed25519-protected.public.gpg');
  static Uint8List get rsaProtectedPublic => binaryKey('keys/gnupg/rsa3072-protected.public.gpg');
  static Uint8List get v6Public => binaryKey('keys/rfc9580/v6-public.asc');

  /// Primary key fingerprints.
  static const edFingerprint = '1FCDA135EE42400EC2B77CE677249ABE661CF8DB';
  static const rsaFingerprint = 'EA29C79D1C6570277907BB485D49D28C8EFC2F98';
  static const edProtectedFingerprint = '1BB5EC3961E61EE44F919AB63FCD57EBA0308CA9';
  static const rsaProtectedFingerprint = '40563A0693F24839F76000FE6D181E7A2C932FEA';
}

/// The passphrase of the protected fixture keys and of every
/// passphrase-encrypted GnuPG fixture.
const fixturePassphrase = 'fixture passphrase';

/// A time at which every fixture key that expires is still in order.
final fixtureNow = DateTime.utc(2026, 12, 1);
