import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:kemlock_core/crypto/keys/x509.dart';

/// The signature a software [key] gives over [toBeSigned], as X.509
/// carries it: what a slot's key gives through the card, for the tests
/// that have no card.
Uint8List softwareX509Signature(KeyMaterial key, Uint8List toBeSigned) {
  switch (key) {
    case RsaMaterial():
      final signature = rsaSignPkcs1(key, oidSha256, hash.sha256.convert(toBeSigned).bytes);
      return bigIntToBytes(signature, (key.n.bitLength + 7) >> 3);
    case EcMaterial():
      final signature = ecdsaSign(key, toBeSigned);
      return derSequence([derInteger(signature.r), derInteger(signature.s)]);
    default:
      throw ArgumentError('not a key that signs certificates here');
  }
}

/// A certificate for [subjectKey] naming [commonName], issued by a test
/// authority that holds [authorityKey] and calls itself [authorityName]:
/// what an authority sends back for a request.
Uint8List issueCertificate({
  required PublicHalf subjectKey,
  required String commonName,
  required KeyMaterial authorityKey,
  String authorityName = 'Example Test CA',
  required DateTime notBefore,
  required DateTime notAfter,
}) {
  Uint8List name(String cn) => derSequence([
    derSet([
      derSequence([derOid(oidCommonName), derUtf8String(cn)]),
    ]),
  ]);
  final algorithm = switch (authorityKey) {
    RsaMaterial() => derSequence([derOid(oidSha256WithRsa), derNull()]),
    EcMaterial(curve: EcCurve.p256) => derSequence([derOid(oidEcdsaWithSha256)]),
    _ => derSequence([derOid(oidEcdsaWithSha384)]),
  };
  final toBeSigned = derSequence([
    derTlv(contextTag(0), derSmallInteger(2)),
    derInteger(bytesToBigInt(newCertificateSerial())),
    algorithm,
    name(authorityName),
    derSequence([derTime(notBefore), derTime(notAfter)]),
    name(commonName),
    writeSpki(subjectKey),
  ]);
  return derSequence([toBeSigned, algorithm, derBitString(softwareX509Signature(authorityKey, toBeSigned))]);
}
