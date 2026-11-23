// RSA as OpenPGP uses it (RFC 9580 sections 5.1.3 and 5.2.3.1, RFC 8017):
// PKCS#1 v1.5 encryption of a session key, its decryption, and the
// signature's encoding and private operation, all with the CRT values.
//
// `BigInt.modPow` is not constant-time. Decryption gives one error for
// every failure, so that what failed does not show.

import 'dart:typed_data';

import '../algorithms.dart';
import '../der.dart';
import '../key_error.dart';
import 'pgp_error.dart';

/// The DER object identifiers of the hashes a signature names (RFC 9580
/// section 9.5).
const hashOids = {
  2: '1.3.14.3.2.26',
  8: '2.16.840.1.101.3.4.2.1',
  9: '2.16.840.1.101.3.4.2.2',
  10: '2.16.840.1.101.3.4.2.3',
  11: '2.16.840.1.101.3.4.2.4',
  12: '2.16.840.1.101.3.4.2.8',
  14: '2.16.840.1.101.3.4.2.10',
};

/// EMSA-PKCS1-v1_5: 00 01 ff ... ff 00, then the DigestInfo of [digest],
/// made with the hash [hashAlgorithm], in [length] bytes.
Uint8List emsaPkcs1(int hashAlgorithm, List<int> digest, int length) {
  final info = derSequence([
    derSequence([derOid(hashOids[hashAlgorithm]!), derNull()]),
    derOctetString(digest),
  ]);
  check(length >= info.length + 11, 'OpenPGP: RSA key too small');
  return Uint8List(length)
    ..[1] = 1
    ..fillRange(2, length - info.length - 1, 0xff)
    ..setAll(length - info.length, info);
}

/// m^d mod n, worked out with the CRT values of [key].
BigInt rsaPrivate(RsaMaterial key, BigInt m) {
  final s1 = m.modPow(key.dp, key.p);
  final s2 = m.modPow(key.dq, key.q);
  final h = (key.qinv * (s1 - s2)) % key.p;
  return s2 + h * key.q;
}

/// An RSA PKCS#1 v1.5 signature of a SHA-512 [digest], as one MPI, worked
/// out with the CRT values of [key].
List<int> signRsa(RsaMaterial key, List<int> digest) {
  final m = bytesToBigInt(emsaPkcs1(10, digest, (key.n.bitLength + 7) >> 3));
  final s = rsaPrivate(key, m);
  return Uint8List.fromList([s.bitLength >> 8, s.bitLength & 0xff, ...bigIntToBytes(s)]);
}

/// The length of the padding [rsaEncryptPkcs1] needs for a message of
/// [messageLength] bytes to the modulus [n].
int rsaPaddingLength(BigInt n, int messageLength) => ((n.bitLength + 7) >> 3) - messageLength - 3;

/// [message] encrypted to the public key ([n], [e]) with EME-PKCS1-v1_5:
/// 00 02, the bytes of [padding], 00, the message. [padding] is
/// [rsaPaddingLength] bytes, at least eight, from a secure random source;
/// a zero in it would end the padding early, so it is replaced, and any
/// random bytes will do.
BigInt rsaEncryptPkcs1(BigInt n, BigInt e, List<int> message, List<int> padding) {
  final k = (n.bitLength + 7) >> 3;
  if (padding.length != k - message.length - 3 || padding.length < 8) {
    throw ArgumentError.value(padding.length, 'padding', 'must be ${k - message.length - 3} bytes');
  }
  final block = Uint8List(k)..[1] = 2;
  for (var i = 0; i < padding.length; i++) {
    block[2 + i] = padding[i] == 0 ? 0x5a : padding[i];
  }
  block.setAll(k - message.length, message);
  return bytesToBigInt(block).modPow(e, n);
}

/// The message in [cipher], decrypted with [key]. A cipher text out of
/// range, a block that does not start 00 02, padding under eight bytes or
/// with no end: each throws the same [PgpProblem.damaged].
Uint8List rsaDecryptPkcs1(RsaMaterial key, BigInt cipher) {
  const failed = PgpException(PgpProblem.damaged, detail: 'session key');
  if (cipher >= key.n || cipher.isNegative) throw failed;
  final k = (key.n.bitLength + 7) >> 3;
  final block = bigIntToBytes(rsaPrivate(key, cipher), k);
  var bad = block[0] | (block[1] ^ 2);
  var end = -1;
  for (var i = 2; i < k; i++) {
    if (block[i] == 0 && end < 0) end = i;
  }
  if (end < 10) bad |= 1;
  if (bad != 0) throw failed;
  return Uint8List.sublistView(block, end + 1);
}
