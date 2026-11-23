// Session keys to Curve25519 (RFC 9580 sections 5.1.5, 5.1.6 and 11.4, RFC
// 6637): the version 4 ECDH form, with its KDF and AES key wrap (RFC
// 3394), and X25519 with HKDF. The version 4 ECDH form is also written to
// NIST P-256 and P-384, the curves an OpenPGP card's key may be on
// (openspec: add-openpgp-card); their secrets are never here.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../algorithms.dart' show EcCurve;
import '../der.dart';
import 'key_info.dart';
import 'modes.dart';
import 'pgp_error.dart';
import 's2k.dart';
import 'stream.dart';

const _wrapIv = 0xa6;

/// AES key wrap (RFC 3394) of [data], a multiple of 8 bytes, under [kek].
Uint8List aesKeyWrap(Uint8List kek, Uint8List data) {
  if (data.length % 8 != 0 || data.length < 16) throw ArgumentError.value(data.length, 'data', 'must be a multiple of 8, at least 16');
  final aes = AesBlock(kek);
  final n = data.length ~/ 8;
  final r = Uint8List(data.length + 8)
    ..fillRange(0, 8, _wrapIv)
    ..setAll(8, data);
  final block = Uint8List(16);
  for (var j = 0; j < 6; j++) {
    for (var i = 1; i <= n; i++) {
      block
        ..setRange(0, 8, r)
        ..setRange(8, 16, r, i * 8);
      aes.encrypt(block, 0, block, 0);
      final t = n * j + i;
      for (var k = 0; k < 4; k++) {
        block[7 - k] ^= (t >> (8 * k)) & 0xff;
      }
      r
        ..setRange(0, 8, block)
        ..setRange(i * 8, i * 8 + 8, block, 8);
    }
  }
  return r;
}

/// The data inside [wrapped]. Throws [PgpProblem.damaged] when the
/// integrity value does not come out, which a wrong key gives too.
Uint8List aesKeyUnwrap(Uint8List kek, Uint8List wrapped) {
  const failed = PgpException(PgpProblem.damaged, detail: 'session key');
  if (wrapped.length % 8 != 0 || wrapped.length < 24) throw failed;
  final aes = AesBlock(kek);
  final n = wrapped.length ~/ 8 - 1;
  final r = Uint8List.fromList(wrapped);
  final block = Uint8List(16);
  for (var j = 5; j >= 0; j--) {
    for (var i = n; i >= 1; i--) {
      block
        ..setRange(0, 8, r)
        ..setRange(8, 16, r, i * 8);
      final t = n * j + i;
      for (var k = 0; k < 4; k++) {
        block[7 - k] ^= (t >> (8 * k)) & 0xff;
      }
      aes.decrypt(block, 0, block, 0);
      r
        ..setRange(0, 8, block)
        ..setRange(i * 8, i * 8 + 8, block, 8);
    }
  }
  var diff = 0;
  for (var i = 0; i < 8; i++) {
    diff |= r[i] ^ _wrapIv;
  }
  if (diff != 0) throw failed;
  return Uint8List.sublistView(r, 8);
}

/// The public part of a version 4 ECDH key on Curve25519, or on NIST
/// P-256 or P-384.
class EcdhPublic {
  EcdhPublic._(this.oid, this.point, this.kdfHash, this.kdfCipher, this.curve);

  /// Reads the public material of an ECDH (18) key packet. Throws
  /// [PgpProblem.unsupported] naming the curve when it is another than
  /// Curve25519, P-256 and P-384, or the KDF's hash or cipher when this app
  /// has no use for it.
  factory EcdhPublic.of(KeyPacket key) {
    final r = PgpReader.bytes(key.publicMaterial);
    final oid = r.bytes(r.byte());
    final dotted = decodeOid(oid);
    final curve = EcCurve.byOid(dotted);
    if (dotted != '1.3.6.1.4.1.3029.1.5.1' && curve == null) throw PgpException(PgpProblem.unsupported, detail: key.name);
    final point = r.bytes((r.uint16() + 7) >> 3);
    if (curve == null) {
      pgpCheck(point.length == 33 && point[0] == 0x40, 'ECDH: point');
    } else {
      pgpCheck(point.length == 1 + 2 * curve.size && point[0] == 0x04, 'ECDH: point');
    }
    final kdf = r.bytes(r.byte());
    pgpCheck(kdf.length >= 3 && kdf[0] == 1, 'ECDH: KDF parameters');
    if (kdf[1] != hashSha256 && kdf[1] != hashSha384 && kdf[1] != hashSha512) {
      throw PgpException(PgpProblem.unsupported, detail: 'ECDH with ${hashName(kdf[1])}');
    }
    cipherKeyLength(kdf[2]);
    return EcdhPublic._(oid, curve == null ? Uint8List.sublistView(point, 1) : point, kdf[1], kdf[2], curve);
  }

  /// The curve's OID, as the packet has it.
  final Uint8List oid;

  /// The 32-byte public key, in X25519's own byte order; for a NIST curve
  /// the point, `04`, x and y.
  final Uint8List point;

  /// The NIST curve; null for Curve25519.
  final EcCurve? curve;
  final int kdfHash;
  final int kdfCipher;
}

/// The key-wrapping key of RFC 6637 section 7 for the [shared] secret:
/// one hash over a counter, the secret, and the parameters that name the
/// curve, the KDF and the recipient by [fingerprint].
Uint8List ecdhKek(EcdhPublic key, Uint8List shared, Uint8List fingerprint) {
  final digest = shaHash(key.kdfHash)!.convert([
    0,
    0,
    0,
    1,
    ...shared,
    key.oid.length,
    ...key.oid,
    18,
    3,
    1,
    key.kdfHash,
    key.kdfCipher,
    ...'Anonymous Sender    '.codeUnits,
    ...fingerprint,
  ]);
  return Uint8List.fromList(digest.bytes.sublist(0, cipherKeyLength(key.kdfCipher)));
}

Future<Uint8List> _x25519(Uint8List secret, Uint8List public) async {
  final algorithm = c.X25519();
  final pair = await algorithm.newKeyPairFromSeed(secret);
  final shared = await algorithm.sharedSecretKey(
    keyPair: pair,
    remotePublicKey: c.SimplePublicKey(public, type: c.KeyPairType.x25519),
  );
  final bytes = Uint8List.fromList(await shared.extractBytes());
  // An all-zero secret comes from a point of small order
  pgpCheck(bytes.any((b) => b != 0), 'X25519: weak point');
  return bytes;
}

/// The public key of the X25519 [secret].
Future<Uint8List> x25519Public(Uint8List secret) async =>
    Uint8List.fromList((await (await c.X25519().newKeyPairFromSeed(secret)).extractPublicKey()).bytes);

/// [encoded] (the cipher octet, the session key and its checksum) for the
/// ECDH [recipient]: the ephemeral public key that [ephemeralSecret], 32
/// random bytes, gives, and the key wrapped after padding to 40 bytes, as
/// RFC 6637 section 8 says and GnuPG does.
Future<({Uint8List ephemeral, Uint8List wrapped})> ecdhWrap(KeyPacket recipient, Uint8List encoded, Uint8List ephemeralSecret) async {
  final key = EcdhPublic.of(recipient);
  final curve = key.curve;
  final Uint8List shared;
  final Uint8List ephemeral;
  if (curve == null) {
    shared = await _x25519(ephemeralSecret, key.point);
    ephemeral = await x25519Public(ephemeralSecret);
  } else {
    // A scalar from 1 to n - 1, from more random bytes than the curve's size
    final domain = curve.domain;
    final d = bytesToBigInt(ephemeralSecret) % (domain.n - BigInt.one) + BigInt.one;
    ephemeral = (domain.G * d)!.getEncoded(false);
    final point = domain.curve.decodePoint(key.point);
    final product = point == null ? null : point * d;
    pgpCheck(product != null && !product.isInfinity, 'ECDH: point');
    shared = bigIntToBytes(product!.x!.toBigInteger()!, curve.size);
  }
  final padded = Uint8List(40);
  if (encoded.length >= padded.length) throw ArgumentError.value(encoded.length, 'encoded', 'too long');
  padded
    ..fillRange(0, padded.length, padded.length - encoded.length)
    ..setAll(0, encoded);
  return (ephemeral: ephemeral, wrapped: aesKeyWrap(ecdhKek(key, shared, recipient.fingerprint), padded));
}

/// What [wrapped] holds for the ECDH [recipient], whose secret key in
/// X25519's byte order is [secret]: the cipher octet, the session key and
/// its checksum, the padding taken off. [ephemeral] is the 32-byte point.
Future<Uint8List> ecdhUnwrap(KeyPacket recipient, Uint8List secret, Uint8List ephemeral, Uint8List wrapped) async =>
    ecdhUnwrapShared(recipient, await _x25519(secret, ephemeral), wrapped);

/// What [wrapped] holds for the ECDH [recipient], given the [shared]
/// secret worked out elsewhere (an OpenPGP card): the cipher octet, the
/// session key and its checksum, the padding taken off.
///
/// The padding is PKCS #5's, n bytes of value n, but not only to the next
/// multiple of 8: RFC 6637 section 8, and RFC 9580 section 11.5 after it,
/// let a sender pad every session key to 40 bytes, with 21 bytes for
/// AES-128 and 13 for AES-192, as [ecdhWrap] does itself. Any count
/// that leaves something is taken; the caller checks that what is left is
/// a session key of its cipher's length with its checksum.
Future<Uint8List> ecdhUnwrapShared(KeyPacket recipient, Uint8List shared, Uint8List wrapped) async {
  final key = EcdhPublic.of(recipient);
  pgpCheck(shared.any((b) => b != 0), 'ECDH: weak point');
  final padded = aesKeyUnwrap(ecdhKek(key, shared, recipient.fingerprint), wrapped);
  final pad = padded.last;
  pgpCheck(pad >= 1 && pad < padded.length, 'session key');
  for (var i = padded.length - pad; i < padded.length; i++) {
    pgpCheck(padded[i] == pad, 'session key');
  }
  return Uint8List.sublistView(padded, 0, padded.length - pad);
}

/// The key that wraps a session key for an X25519 (25) key (RFC 9580
/// section 5.1.6): HKDF-SHA256 over the ephemeral key, the recipient's
/// public key and the shared secret.
Uint8List x25519Kek(Uint8List ephemeral, Uint8List recipientPublic, Uint8List shared) =>
    hkdfSha256([...ephemeral, ...recipientPublic, ...shared], info: 'OpenPGP X25519'.codeUnits, length: 16);

/// The shared secret of the X25519 [secret] and the [public] point.
Future<Uint8List> x25519Shared(Uint8List secret, Uint8List public) => _x25519(secret, public);

/// The session key in [wrapped] for the X25519 key whose halves are
/// [secret] and [public].
Future<Uint8List> x25519Unwrap(Uint8List secret, Uint8List public, Uint8List ephemeral, Uint8List wrapped) async =>
    aesKeyUnwrap(x25519Kek(ephemeral, public, await _x25519(secret, ephemeral)), wrapped);
