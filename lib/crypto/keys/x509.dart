// X.509 certificates (RFC 5280), as far as a security key's PIV slots need
// them: reading one to show it, never to judge whether it should be
// trusted. From the to-be-signed part come the serial number, the two
// names, the two dates, the public key and, of the extensions, basic
// constraints, key usage and the subject key identifier; everything else
// is skipped by its length. Strict DER, like the key readers: a slot that
// holds something else is shown as unreadable, not guessed at.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'algorithms.dart';
import 'der.dart';
import 'key_error.dart';
import 'pem.dart';
import 'pkcs8.dart';

const oidCommonName = '2.5.4.3';
const oidSha256WithRsa = '1.2.840.113549.1.1.11';
const oidEcdsaWithSha256 = '1.2.840.10045.4.3.2';
const oidEcdsaWithSha384 = '1.2.840.10045.4.3.3';
const oidBasicConstraints = '2.5.29.19';
const oidKeyUsage = '2.5.29.15';
const oidSubjectKeyIdentifier = '2.5.29.14';

/// The bits of the key usage extension, by their number in RFC 5280.
abstract final class KeyUsageBit {
  static const digitalSignature = 0;
  static const contentCommitment = 1;
  static const keyEncipherment = 2;
  static const dataEncipherment = 3;
  static const keyAgreement = 4;
  static const keyCertSign = 5;
  static const crlSign = 6;
}

/// The short names of the name parts people know; any other part is
/// written by its object identifier.
const _attributeNames = {
  oidCommonName: 'CN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '0.9.2342.19200300.100.1.25': 'DC',
  '0.9.2342.19200300.100.1.1': 'UID',
};

/// A name in a certificate: its [parts] in the order they are written,
/// and [encoded], the name as it appeared, which is what two names are
/// compared by.
class X509Name {
  const X509Name(this.parts, this.encoded);

  final List<({String oid, String value})> parts;
  final Uint8List encoded;

  /// The common name, when the name has one.
  String? get commonName => parts.where((part) => part.oid == oidCommonName).lastOrNull?.value;

  /// The whole name written out, the most specific part first, as
  /// RFC 2253 does: `CN=Ada Example,O=Example,C=FR`.
  String get full => [
    for (final part in parts.reversed)
      '${_attributeNames[part.oid] ?? part.oid}=${part.value.replaceAllMapped(_special, (m) => '\\${m[0]}')}',
  ].join(',');

  /// What to call it: the common name, or else the whole name.
  String get display => commonName ?? full;

  static final _special = RegExp(r'[,+"\\<>;]');
}

/// A certificate, read. Nothing here says whether it should be trusted.
class X509Certificate {
  const X509Certificate({
    required this.encoded,
    required this.toBeSigned,
    required this.serial,
    required this.signatureAlgorithm,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.publicKeyInfo,
    required this.publicKeyAlgorithm,
    this.curve,
    this.publicKey,
    this.isAuthority,
    this.keyUsage,
    this.subjectKeyIdentifier,
    required this.signature,
  });

  /// The whole certificate, and the part of it the signature is over.
  final Uint8List encoded;
  final Uint8List toBeSigned;

  /// The serial number: the content bytes of its INTEGER, two's
  /// complement, since some authorities have issued negative ones.
  final Uint8List serial;

  /// The object identifier of the signature's algorithm.
  final String signatureAlgorithm;
  final X509Name issuer;
  final X509Name subject;
  final DateTime notBefore;
  final DateTime notAfter;

  /// The SubjectPublicKeyInfo as it appeared: what two certificates for
  /// the same key have in common.
  final Uint8List publicKeyInfo;

  /// The object identifier of the key's algorithm and, for an EC key on a
  /// named curve, of the curve.
  final String publicKeyAlgorithm;
  final String? curve;

  /// The public key, or null for a kind of key Kemlock does not know.
  final PublicHalf? publicKey;

  /// Basic constraints: whether the certificate is an authority's. Null
  /// when it does not say.
  final bool? isAuthority;

  /// The bits of the key usage extension that are set ([KeyUsageBit]), or
  /// null without the extension.
  final Set<int>? keyUsage;
  final Uint8List? subjectKeyIdentifier;
  final Uint8List signature;

  /// Whether the certificate names itself as its issuer.
  bool get selfSigned => _same(issuer.encoded, subject.encoded);

  /// The SHA-256 of the whole certificate.
  Uint8List get sha256Fingerprint => Uint8List.fromList(hash.sha256.convert(encoded).bytes);

  /// The serial number in hex, as OpenSSL prints it: `2A2B…`, or `-0A`
  /// for a negative one.
  String get serialText {
    var value = bytesToBigInt(serial);
    if (serial[0] & 0x80 != 0) value -= BigInt.one << (8 * serial.length);
    final digits = value.abs().toRadixString(16).toUpperCase();
    return '${value.isNegative ? '-' : ''}${digits.length.isOdd ? '0' : ''}$digits';
  }

  /// The key's kind as people name it: `RSA 2048`, `ECC P-256`, `Ed25519`,
  /// or the algorithm's object identifier for one with no common name.
  String get keyAlgorithmName => switch (publicKey) {
    RsaPublicHalf(:final n) => 'RSA ${n.bitLength}',
    EcPublicHalf(curve: EcCurve.p256) => 'ECC P-256',
    EcPublicHalf(curve: EcCurve.p384) => 'ECC P-384',
    RawPublicHalf(algorithm: KeyAlgorithm.ed25519) => 'Ed25519',
    RawPublicHalf(algorithm: KeyAlgorithm.x25519) => 'X25519',
    RawPublicHalf(:final algorithm) => algorithm.id.toUpperCase(),
    null => _otherKeyNames[curve ?? publicKeyAlgorithm] ?? curve ?? publicKeyAlgorithm,
  };
}

const _otherKeyNames = {'1.3.132.0.35': 'ECC P-521', '1.3.101.113': 'Ed448', '1.3.101.111': 'X448', '1.3.132.0.10': 'ECC secp256k1'};

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Reads [der], one certificate and nothing after it. Throws
/// [KeyFormatException] with [KeyProblem.damaged] for anything that is not
/// a DER certificate (a request, a private key, a certificate cut short),
/// [KeyProblem.tooLarge] past the size cap, and nothing else.
X509Certificate readCertificate(Uint8List der) {
  checkSize(der.length);
  final outer = readSequence(der);
  final toBeSigned = outer.expect(tagSequence);
  final signatureAlgorithm = _algorithm(outer.sequence());
  final signature = outer.bitString();
  outer.done();

  final tbs = DerReader(toBeSigned.content);
  final version = tbs.optional(contextTag(0));
  if (version != null) {
    check(version.smallInteger() <= 2, 'X.509: version');
    version.done();
  }
  final serial = tbs.rawInteger();
  check(_algorithm(tbs.sequence()) == signatureAlgorithm, 'X.509: two signature algorithms');
  final issuer = _name(tbs.expect(tagSequence));
  final validity = tbs.sequence();
  final notBefore = validity.time();
  final notAfter = validity.time();
  validity.done();
  final subject = _name(tbs.expect(tagSequence));
  final key = _publicKey(tbs.expect(tagSequence));
  // The two unique identifiers, which nothing uses.
  tbs.optionalContent(contextTag(1, constructed: false));
  tbs.optionalContent(contextTag(2, constructed: false));
  bool? isAuthority;
  Set<int>? keyUsage;
  Uint8List? subjectKeyIdentifier;
  final wrapped = tbs.optional(contextTag(3));
  if (wrapped != null) {
    final extensions = wrapped.sequence();
    wrapped.done();
    while (!extensions.isEmpty) {
      final extension = extensions.sequence();
      final oid = extension.oid();
      if (extension.nextTag == tagBoolean) extension.boolean();
      final value = DerReader(extension.octetString());
      extension.done();
      switch (oid) {
        case oidBasicConstraints:
          final constraints = value.sequence();
          isAuthority = constraints.nextTag == tagBoolean && constraints.boolean();
        case oidKeyUsage:
          final bits = value.bitStringWithUnused();
          keyUsage = {
            for (var bit = 0; bit < bits.bytes.length * 8 - bits.unused; bit++)
              if (bits.bytes[bit ~/ 8] & (0x80 >> (bit % 8)) != 0) bit,
          };
        case oidSubjectKeyIdentifier:
          subjectKeyIdentifier = value.octetString();
      }
    }
  }
  tbs.done();

  return X509Certificate(
    encoded: der,
    toBeSigned: toBeSigned.encoded,
    serial: serial,
    signatureAlgorithm: signatureAlgorithm,
    issuer: issuer,
    subject: subject,
    notBefore: notBefore,
    notAfter: notAfter,
    publicKeyInfo: key.encoded,
    publicKeyAlgorithm: key.algorithm,
    curve: key.curve,
    publicKey: key.publicKey,
    isAuthority: isAuthority,
    keyUsage: keyUsage,
    subjectKeyIdentifier: subjectKeyIdentifier,
    signature: signature,
  );
}

/// The object identifier of an AlgorithmIdentifier; its parameters, if
/// any, are not needed.
String _algorithm(DerReader algorithm) => algorithm.oid();

X509Name _name(DerElement name) {
  final parts = <({String oid, String value})>[];
  final names = DerReader(name.content);
  while (!names.isEmpty) {
    final set = names.set();
    check(!set.isEmpty, 'X.509: empty name part');
    while (!set.isEmpty) {
      final attribute = set.sequence();
      final oid = attribute.oid();
      final String value;
      switch (attribute.nextTag) {
        case tagUtf8String || tagPrintableString || tagIa5String || tagTeletexString || tagBmpString:
          value = attribute.string();
        default:
          // A value of another type is shown as its bytes, as RFC 2253 does.
          value = '#${[for (final byte in attribute.read().encoded) byte.toRadixString(16).padLeft(2, '0')].join()}';
      }
      attribute.done();
      parts.add((oid: oid, value: value));
    }
  }
  return X509Name(parts, name.encoded);
}

({Uint8List encoded, String algorithm, String? curve, PublicHalf? publicKey}) _publicKey(DerElement info) {
  final spki = DerReader(info.content);
  final algorithm = spki.sequence();
  final oid = algorithm.oid();
  final curve = oid == oidEcPublicKey && algorithm.nextTag == tagOid ? algorithm.oid() : null;
  spki.bitStringWithUnused();
  spki.done();
  return (encoded: info.encoded, algorithm: oid, curve: curve, publicKey: readSpki(info.encoded));
}

// ─── Checking a signature ─────────────────────────────────────────────────────

/// Whether the signature [signature], made with the algorithm
/// [signatureAlgorithm] names, is [key]'s over [signed]: SHA-256 with RSA
/// (PKCS#1 v1.5), ECDSA with SHA-256 on P-256, or ECDSA with SHA-384 on
/// P-384. False for any other pairing of algorithm and key, and for a
/// signature that is not well formed; never an error.
bool verifyX509Signature(PublicHalf? key, String signatureAlgorithm, Uint8List signed, Uint8List signature) {
  switch (key) {
    case RsaPublicHalf():
      if (signatureAlgorithm != oidSha256WithRsa) return false;
      return rsaVerifyPkcs1(key, oidSha256, hash.sha256.convert(signed).bytes, bytesToBigInt(signature));
    case EcPublicHalf(:final curve):
      // `ecdsaVerify` hashes with the curve's own hash, so only that pairing is checked.
      if (signatureAlgorithm != (curve == EcCurve.p256 ? oidEcdsaWithSha256 : oidEcdsaWithSha384)) return false;
      final BigInt r, s;
      try {
        final value = readSequence(signature);
        r = value.integer();
        s = value.integer();
        value.done();
      } on KeyFormatException {
        return false;
      }
      return ecdsaVerify(key, signed, r, s);
    default:
      return false;
  }
}

/// Whether [certificate] is signed by the key it holds, as a self-signed
/// certificate is: the one check made before a certificate Kemlock built
/// is stored. It says nothing of whether the certificate should be
/// trusted.
bool verifyOwnSignature(X509Certificate certificate) =>
    verifyX509Signature(certificate.publicKey, certificate.signatureAlgorithm, certificate.toBeSigned, certificate.signature);

// ─── Certificate requests ─────────────────────────────────────────────────────

/// A PKCS#10 certificate request (RFC 2986), read.
class X509Request {
  const X509Request({
    required this.encoded,
    required this.toBeSigned,
    required this.subject,
    required this.publicKeyInfo,
    this.publicKey,
    required this.signatureAlgorithm,
    required this.signature,
  });

  final Uint8List encoded;
  final Uint8List toBeSigned;
  final X509Name subject;
  final Uint8List publicKeyInfo;
  final PublicHalf? publicKey;
  final String signatureAlgorithm;
  final Uint8List signature;

  /// Whether the request is signed by the key it asks a certificate for.
  bool get verifies => verifyX509Signature(publicKey, signatureAlgorithm, toBeSigned, signature);
}

/// Reads [der], one certificate request. Throws [KeyFormatException] for
/// anything else.
X509Request readCertificateRequest(Uint8List der) {
  checkSize(der.length);
  final outer = readSequence(der);
  final toBeSigned = outer.expect(tagSequence);
  final signatureAlgorithm = _algorithm(outer.sequence());
  final signature = outer.bitString();
  outer.done();
  final info = DerReader(toBeSigned.content);
  check(info.smallInteger() == 0, 'PKCS#10: version');
  final subject = _name(info.expect(tagSequence));
  final key = _publicKey(info.expect(tagSequence));
  info.expect(contextTag(0));
  info.done();
  return X509Request(
    encoded: der,
    toBeSigned: toBeSigned.encoded,
    subject: subject,
    publicKeyInfo: key.encoded,
    publicKey: key.publicKey,
    signatureAlgorithm: signatureAlgorithm,
    signature: signature,
  );
}

// ─── Reading a file someone picked ────────────────────────────────────────────

/// What a file or pasted text that should hold a certificate holds.
enum CertificateFileKind { certificate, request, privateKey, publicKey, unreadable }

/// Reads [bytes], a picked file or pasted text, as one certificate in PEM
/// (`CERTIFICATE`) or DER. Anything else is named for what it is, by its
/// PEM label or its first tags, so the person can be told what was
/// expected. Never throws.
({CertificateFileKind kind, X509Certificate? certificate}) readCertificateFile(Uint8List bytes) {
  const no = (kind: CertificateFileKind.unreadable, certificate: null);
  if (bytes.length > maxKeyInputLength) return no;
  var der = bytes;
  final text = String.fromCharCodes(bytes.where((byte) => byte < 0x80));
  if (text.contains('-----BEGIN ')) {
    final List<PemBlock> blocks;
    try {
      blocks = readPemBlocks(text);
    } on KeyFormatException {
      return no;
    }
    final block = blocks.where((block) => block.label.endsWith('CERTIFICATE')).firstOrNull;
    if (block == null) {
      final labels = [for (final block in blocks) block.label];
      if (labels.any((label) => label.endsWith('CERTIFICATE REQUEST'))) return (kind: CertificateFileKind.request, certificate: null);
      if (labels.any((label) => label.endsWith('PRIVATE KEY'))) return (kind: CertificateFileKind.privateKey, certificate: null);
      if (labels.any((label) => label.endsWith('PUBLIC KEY'))) return (kind: CertificateFileKind.publicKey, certificate: null);
      return no;
    }
    try {
      der = block.decode();
    } on KeyFormatException {
      return no;
    }
  }
  try {
    return (kind: CertificateFileKind.certificate, certificate: readCertificate(der));
  } on KeyFormatException {
    // Not a certificate: what else it may be is told from its shape.
  }
  try {
    readCertificateRequest(der);
    return (kind: CertificateFileKind.request, certificate: null);
  } on KeyFormatException {
    // Not a request either.
  }
  try {
    if (readSpki(der) != null) return (kind: CertificateFileKind.publicKey, certificate: null);
  } on KeyFormatException {
    // Nor a public key.
  }
  try {
    // PKCS#8, PKCS#1 and SEC1 private keys all start with a version number.
    final first = readSequence(der);
    if (first.nextTag == tagInteger) return (kind: CertificateFileKind.privateKey, certificate: null);
  } on KeyFormatException {
    // Not DER at all.
  }
  return no;
}

// ─── Writing ──────────────────────────────────────────────────────────────────

/// What a certificate's key is for, which decides its key usage: the four
/// uses of a PIV card's slots.
enum CertificateUse {
  /// Signing in: digital signature.
  authentication,

  /// Signing documents and mail: digital signature and content commitment.
  signature,

  /// Opening what was encrypted to the key: key encipherment for RSA, key
  /// agreement for a curve.
  keyManagement,

  /// Proving the card is there: digital signature.
  cardAuthentication,
}

/// Signs [toBeSigned] with the private half of the key a certificate or
/// request is being written for, and returns the signature as X.509
/// carries it: for RSA the PKCS#1 v1.5 signature with SHA-256, for a curve
/// the DER `ECDSA-Sig-Value` over the curve's hash (SHA-256 on P-256,
/// SHA-384 on P-384).
typedef X509Signer = Future<Uint8List> Function(Uint8List toBeSigned);

Uint8List _signatureAlgorithmFor(PublicHalf key) => switch (key) {
  RsaPublicHalf() => derSequence([derOid(oidSha256WithRsa), derNull()]),
  EcPublicHalf(curve: EcCurve.p256) => derSequence([derOid(oidEcdsaWithSha256)]),
  EcPublicHalf(curve: EcCurve.p384) => derSequence([derOid(oidEcdsaWithSha384)]),
  _ => throw ArgumentError.value(key.algorithm.id, 'publicKey', 'not a key a certificate is written for'),
};

Uint8List _commonNameOnly(String commonName) {
  if (commonName.isEmpty || commonName.length > 64) throw ArgumentError.value(commonName, 'commonName', 'must be 1 to 64 characters');
  return derSequence([
    derSet([
      derSequence([derOid(oidCommonName), derUtf8String(commonName)]),
    ]),
  ]);
}

Uint8List _extension(String oid, List<int> value, {bool critical = false}) =>
    derSequence([derOid(oid), if (critical) derBoolean(true), derOctetString(value)]);

/// A new serial number: 16 random bytes with the top bit cleared, so it
/// is positive, as RFC 5280 asks.
Uint8List newCertificateSerial() {
  while (true) {
    final bytes = randomBytes(16)..[0] &= 0x7f;
    if (bytes[0] != 0) return bytes;
  }
}

/// A version 3 certificate for [publicKey], naming [commonName] as both
/// subject and issuer, valid from [notBefore] until [notAfter] to the
/// second, signed through [sign] by the key itself. It says it is no
/// authority, carries the key usage of [use] and the subject key
/// identifier. [serial] is a fresh random one unless given.
///
/// Nothing checks the signature here: read the result back and give it
/// to [verifyOwnSignature] before keeping it.
Future<Uint8List> buildSelfSigned({
  required PublicHalf publicKey,
  required String commonName,
  required DateTime notBefore,
  required DateTime notAfter,
  required CertificateUse use,
  required X509Signer sign,
  Uint8List? serial,
}) async {
  final algorithm = _signatureAlgorithmFor(publicKey);
  final name = _commonNameOnly(commonName);
  final spki = writeSpki(publicKey);
  final key = readSequence(spki)..sequence();
  final keyBits = key.bitString();
  final usage = switch (use) {
    CertificateUse.authentication || CertificateUse.cardAuthentication => {KeyUsageBit.digitalSignature},
    CertificateUse.signature => {KeyUsageBit.digitalSignature, KeyUsageBit.contentCommitment},
    CertificateUse.keyManagement => {publicKey is RsaPublicHalf ? KeyUsageBit.keyEncipherment : KeyUsageBit.keyAgreement},
  };
  final toBeSigned = derSequence([
    derTlv(contextTag(0), derSmallInteger(2)),
    derInteger(bytesToBigInt(serial ?? newCertificateSerial())),
    algorithm,
    name,
    derSequence([derTime(notBefore), derTime(notAfter)]),
    name,
    spki,
    derTlv(
      contextTag(3),
      derSequence([
        _extension(oidBasicConstraints, derSequence(const []), critical: true),
        _extension(oidKeyUsage, derNamedBits(usage), critical: true),
        // RFC 5280's first method: the SHA-1 of the key's bits.
        _extension(oidSubjectKeyIdentifier, derOctetString(hash.sha1.convert(keyBits).bytes)),
      ]),
    ),
  ]);
  return derSequence([toBeSigned, algorithm, derBitString(await sign(toBeSigned))]);
}

/// A PKCS#10 request for a certificate for [publicKey] naming
/// [commonName], with no attributes, signed through [sign] by the key
/// itself.
Future<Uint8List> buildRequest({required PublicHalf publicKey, required String commonName, required X509Signer sign}) async {
  final algorithm = _signatureAlgorithmFor(publicKey);
  final toBeSigned = derSequence([derSmallInteger(0), _commonNameOnly(commonName), writeSpki(publicKey), derTlv(contextTag(0), const [])]);
  return derSequence([toBeSigned, algorithm, derBitString(await sign(toBeSigned))]);
}
