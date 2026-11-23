// The oblivious pseudorandom function of RFC 9497 in mode 0 (OPRF), with the
// ristretto255-SHA512 suite (section 4.1): the client's Blind and Finalize,
// the server's BlindEvaluate (kept for tests and for parity with the server),
// and DeriveKeyPair.
//
//   contextString = "OPRFV1-" || I2OSP(mode = 0, 1) || "-" || "ristretto255-SHA512"
//
// The client blinds the input with a random scalar, sends the blinded element,
// and unblinds the server's evaluation with the scalar's inverse. The scalar
// and the unblinded element are secret: the caller zeroes the blind it was
// given when it is done, and this code zeroes what it makes itself.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'hash_to_group.dart';
import 'ristretto255.dart';
import 'scalar25519.dart';

/// Why an OPRF step failed.
class OprfException implements Exception {
  const OprfException(this.message);

  final String message;

  @override
  String toString() => 'OprfException: $message';
}

/// "OPRFV1-" || 0x00 || "-ristretto255-SHA512".
final Uint8List oprfContextString = Uint8List.fromList([...ascii.encode('OPRFV1-'), 0x00, ...ascii.encode('-ristretto255-SHA512')]);

final Uint8List _hashToGroupDst = Uint8List.fromList([...ascii.encode('HashToGroup-'), ...oprfContextString]);
final Uint8List _deriveKeyPairDst = Uint8List.fromList([...ascii.encode('DeriveKeyPair'), ...oprfContextString]);

/// The length of the OPRF output, Nh.
const oprfOutputLength = 64;

/// The OPRF, client side, for ristretto255-SHA512.
abstract final class Oprf {
  /// Blind (RFC 9497 section 3.3.1): a random non-zero scalar and the input,
  /// hashed to the group and multiplied by it. [blind] is for known-answer
  /// tests only: a canonical scalar to use in place of a random one.
  ///
  /// Throws an [OprfException] if the input hashes to the identity, which has
  /// negligible probability.
  static ({Uint8List blind, Uint8List blindedElement}) blind(List<int> input, {List<int>? blind}) {
    final scalar = blind == null ? Scalar25519.randomNonZero() : Uint8List.fromList(blind);
    if (!Scalar25519.isCanonical(scalar) || Scalar25519.isZero(scalar) == 1) {
      throw const OprfException('the blind is not a non-zero scalar');
    }
    final inputElement = hashToGroup(input, _hashToGroupDst);
    if (inputElement.isIdentity) {
      _wipe(scalar);
      throw const OprfException('the input maps to the identity');
    }
    return (blind: scalar, blindedElement: inputElement.multiply(scalar).encode());
  }

  /// BlindEvaluate (section 3.3.1), the server's step: [privateKey] times the
  /// blinded element. A blinded element that is not a valid, non-identity
  /// element is an [OprfException].
  static Uint8List blindEvaluate(List<int> privateKey, List<int> blindedElement) {
    final element = deserializeElement(blindedElement);
    return element.multiply(privateKey).encode();
  }

  /// Finalize (section 3.3.1): unblinds [evaluatedElement] with the inverse of
  /// [blind] and hashes the input and the unblinded element. 64 bytes.
  ///
  /// An evaluated element that is not a valid, non-identity element is an
  /// [OprfException]. A wrong password is not an error here: it gives a
  /// different output.
  static Uint8List finalize(List<int> input, List<int> blind, List<int> evaluatedElement) {
    if (input.length > 0xffff) throw const OprfException('the input is over 65535 bytes');
    final element = deserializeElement(evaluatedElement);
    final inverse = Scalar25519.invert(blind);
    final unblinded = element.multiply(inverse).encode();
    try {
      return Uint8List.fromList(
        hash.sha512
            .convert(concatBytes([_i2osp2(input.length), input, _i2osp2(unblinded.length), unblinded, ascii.encode('Finalize')]))
            .bytes,
      );
    } finally {
      _wipe(inverse);
      _wipe(unblinded);
    }
  }

  /// DeriveKeyPair (section 3.2.1): a private scalar and its public element
  /// from a 32-byte [seed] and [info]. Throws an [OprfException] after 256
  /// zero scalars, which has negligible probability. The caller wipes the
  /// returned private key.
  static ({Uint8List privateKey, Uint8List publicKey}) deriveKeyPair(List<int> seed, List<int> info) {
    if (seed.length != 32) throw ArgumentError.value(seed.length, 'seed', 'expected 32 bytes');
    if (info.length > 0xffff) throw ArgumentError.value(info.length, 'info', 'over 65535 bytes');
    final deriveInput = concatBytes([seed, _i2osp2(info.length), info]);
    try {
      for (var counter = 0; counter < 256; counter++) {
        final sk = hashToScalar(
          concatBytes([
            deriveInput,
            [counter],
          ]),
          _deriveKeyPairDst,
        );
        if (Scalar25519.isZero(sk) == 0) {
          return (privateKey: sk, publicKey: RistrettoPoint.generator.multiply(sk).encode());
        }
        _wipe(sk);
      }
    } finally {
      _wipe(deriveInput);
    }
    throw const OprfException('DeriveKeyPairError');
  }

  /// DeserializeElement: decodes 32 bytes, and refuses an invalid encoding or
  /// the identity (RFC 9497 section 4.1).
  static RistrettoPoint deserializeElement(List<int> bytes) {
    final element = RistrettoPoint.decode(bytes);
    if (element == null) throw const OprfException('not a valid group element');
    if (element.isIdentity) throw const OprfException('the identity is not a valid element here');
    return element;
  }
}

Uint8List _i2osp2(int value) => Uint8List(2)
  ..[0] = value >> 8
  ..[1] = value & 0xff;

void _wipe(Uint8List bytes) => bytes.fillRange(0, bytes.length, 0);
