// The public-key bundle and its fingerprint, `docs/crypto.md` "Public-key
// bundle and fingerprint":
//
//   bundle      = "kemlock/v1/bundle" || account id (16) || u32be(key version)
//                 || kx1 public key (1600) || sig1 public key (1984)
//   fingerprint = SHA-512("kemlock/v1/fingerprint" || bundle)
//
// The bundle is signed with the account's own `sig1` key under the context
// "bundle". People compare the fingerprint as 12 groups of 5 digits: group i
// (0 to 11) is `u40be(fingerprint[5i .. 5i+5]) mod 100000`, written with
// leading zeros, so the 60 digits use the first 60 of the 64 hash bytes. The
// whole 64 bytes are what a QR code carries, compared in constant time.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'encoding.dart';
import 'kx1.dart';
import 'sig1.dart';

const _bundleLabel = 'kemlock/v1/bundle';
const _fingerprintLabel = 'kemlock/v1/fingerprint';

/// The public keys of one account at one key version.
final class KeyBundle {
  KeyBundle({required List<int> accountId, required this.keyVersion, required List<int> kx1PublicKey, required List<int> sig1PublicKey})
    : accountId = copyBytes(requireLength(accountId, 16, 'an account id')),
      kx1PublicKey = copyBytes(requireLength(kx1PublicKey, Kx1.publicKeyLength, 'a kx1 public key')),
      sig1PublicKey = copyBytes(requireLength(sig1PublicKey, Sig1.publicKeyLength, 'a sig1 public key')) {
    u32be(keyVersion); // range check
  }

  /// Reads the bytes of a bundle. A wrong label or length, or trailing
  /// bytes, are a [MalformedException].
  factory KeyBundle.parse(List<int> bytes) {
    final reader = ByteReader(bytes);
    final prefix = label(_bundleLabel);
    if (!constantTimeEquals(reader.read(prefix.length, 'the bundle label'), prefix)) throw const MalformedException('not a key bundle');
    final accountId = reader.read(16, 'the account id');
    final keyVersion = reader.readU32('the key version');
    final kx1PublicKey = reader.read(Kx1.publicKeyLength, 'the kx1 public key');
    final sig1PublicKey = reader.read(Sig1.publicKeyLength, 'the sig1 public key');
    reader.finish();
    return KeyBundle(accountId: accountId, keyVersion: keyVersion, kx1PublicKey: kx1PublicKey, sig1PublicKey: sig1PublicKey);
  }

  /// The account's id, 16 UUID bytes.
  final Uint8List accountId;
  final int keyVersion;
  final Uint8List kx1PublicKey;
  final Uint8List sig1PublicKey;

  /// The bytes that are signed and hashed.
  Uint8List get bytes => concatBytes([label(_bundleLabel), accountId, u32be(keyVersion), kx1PublicKey, sig1PublicKey]);

  /// `SHA-512("kemlock/v1/fingerprint" || bundle)`, 64 bytes.
  Uint8List get fingerprint => fingerprintOf(bytes);

  /// The 60 digits of [fingerprint] as 12 groups of 5, separated by spaces.
  String get fingerprintDigits => fingerprintDigitsOf(fingerprint);
}

/// The fingerprint of the [bundle] bytes.
Uint8List fingerprintOf(List<int> bundle) => Uint8List.fromList(hash.sha512.convert(concatBytes([label(_fingerprintLabel), bundle])).bytes);

/// The 12 groups of 5 digits of a 64-byte [fingerprint]: group `i` is
/// `u40be(fingerprint[5i .. 5i+5]) mod 100000`, with leading zeros.
String fingerprintDigitsOf(List<int> fingerprint) {
  requireLength(fingerprint, 64, 'a fingerprint');
  final groups = <String>[];
  for (var i = 0; i < 12; i++) {
    var value = 0;
    for (var j = 0; j < 5; j++) {
      value = (value << 8) | fingerprint[5 * i + j];
    }
    groups.add((value % 100000).toString().padLeft(5, '0'));
  }
  return groups.join(' ');
}

/// Whether two fingerprints (the 64 bytes a QR code carries) are the same,
/// in a time that does not depend on where they differ.
bool fingerprintsMatch(List<int> a, List<int> b) => a.length == 64 && b.length == 64 && constantTimeEquals(a, b);

/// The bundle's signature: [bundle] signed with the account's own `sig1`
/// private key under the context "bundle".
Future<Uint8List> signBundle(KeyBundle bundle, Uint8List sig1PrivateKey) =>
    Sig1.sign(sig1PrivateKey, bundle.bytes, context: SignContext.bundle);

/// Whether [signature] is the bundle's signature by the `sig1` key the bundle
/// itself holds. Someone who swaps a key in a bundle can't make this verify.
Future<bool> verifyBundle(KeyBundle bundle, Uint8List signature) =>
    Sig1.verify(bundle.sig1PublicKey, bundle.bytes, signature, context: SignContext.bundle);
