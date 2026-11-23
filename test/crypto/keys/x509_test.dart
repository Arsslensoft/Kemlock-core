@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/key_error.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:kemlock_core/crypto/keys/x509.dart';
import 'package:test/test.dart';

import 'fixtures.dart';
import 'x509_software.dart';

/// The certificates OpenSSL made (`fixtures/keys/openssl/x509/README.md`).
const _fixtures = [
  'rsa2048.selfsigned',
  'p256.selfsigned',
  'p384.selfsigned',
  'p256.expired',
  'p256.until-2090',
  'p256.names',
  'ed25519.selfsigned',
  'authority',
  'p256.issued',
  'p256.negative-serial',
];

const _signatureAlgorithms = {
  'sha256WithRSAEncryption': oidSha256WithRsa,
  'ecdsa-with-SHA256': oidEcdsaWithSha256,
  'ecdsa-with-SHA384': oidEcdsaWithSha384,
  'ED25519': oidEd25519,
};

Uint8List _der(String name) => keyFixture('openssl/x509/$name.der');

/// What OpenSSL read in the certificate [name]: the `key=value` lines at
/// the end of its `.txt`, and the fields of the text above them.
({String serial, String subject, String issuer, DateTime notBefore, DateTime notAfter, String fingerprint, String signature}) _openssl(
  String name,
) {
  final text = keyFixtureText('openssl/x509/$name.txt');
  String line(String key) => RegExp('^$key=(.*)\$', multiLine: true).firstMatch(text)![1]!;
  DateTime date(String key) => DateTime.parse(line(key).replaceFirst(' ', 'T'));
  return (
    serial: line('serial'),
    subject: line('subject'),
    issuer: line('issuer'),
    notBefore: date('notBefore'),
    notAfter: date('notAfter'),
    fingerprint: line('sha256 Fingerprint').replaceAll(':', '').toLowerCase(),
    signature: RegExp(r'Signature Algorithm: (\S+)').firstMatch(text)![1]!,
  );
}

String _hex(List<int> bytes) => [for (final byte in bytes) byte.toRadixString(16).padLeft(2, '0')].join();

void main() {
  group('reads the certificates OpenSSL made', () {
    for (final name in _fixtures) {
      test('$name: the fields OpenSSL reads in it', () {
        final certificate = readCertificate(_der(name));
        final expected = _openssl(name);

        expect(certificate.subject.full, expected.subject);
        expect(certificate.issuer.full, expected.issuer);
        expect(certificate.notBefore, expected.notBefore);
        expect(certificate.notAfter, expected.notAfter);
        expect(certificate.serialText, expected.serial);
        expect(certificate.signatureAlgorithm, _signatureAlgorithms[expected.signature]);
        expect(certificate.selfSigned, expected.subject == expected.issuer);
        expect(_hex(certificate.sha256Fingerprint), expected.fingerprint);
      });

      test('$name: the PEM holds the same certificate', () {
        final block = readPemBlocks(keyFixtureText('openssl/x509/$name.pem')).single;
        expect(block.label, 'CERTIFICATE');
        expect(block.decode(), _der(name));
        expect(readCertificate(block.decode()).encoded, _der(name));
      });
    }

    test('the key of each is the one it was made for', () {
      for (final (name, key, label) in [
        ('rsa2048.selfsigned', 'rsa2048', 'RSA 2048'),
        ('p256.selfsigned', 'p256', 'ECC P-256'),
        ('p384.selfsigned', 'p384', 'ECC P-384'),
        ('ed25519.selfsigned', 'ed25519', 'Ed25519'),
        ('p256.issued', 'p256', 'ECC P-256'),
      ]) {
        final certificate = readCertificate(_der(name));
        expect(certificate.publicKeyInfo, keyFixture('openssl/$key.spki.der'), reason: name);
        expect(certificate.keyAlgorithmName, label);
        expect(certificate.publicKey, isNotNull);
      }
    });

    test('the Ed25519 one is read and named, though no slot makes such a key', () {
      final certificate = readCertificate(_der('ed25519.selfsigned'));
      expect(certificate.publicKey, isA<RawPublicHalf>().having((key) => key.algorithm, 'algorithm', KeyAlgorithm.ed25519));
      expect(certificate.subject.commonName, 'Ed Example');
      expect(certificate.signatureAlgorithm, oidEd25519);
    });

    test('the negative serial number is read as it is', () {
      final certificate = readCertificate(_der('p256.negative-serial'));
      expect(certificate.serial, [0xf6]);
      expect(certificate.serialText, '-0A');
    });

    test('a name of several parts gives its common name, or itself written out', () {
      final certificate = readCertificate(_der('p256.names'));
      expect(certificate.subject.commonName, 'Zoé Müller');
      expect(certificate.subject.display, 'Zoé Müller');
      expect([for (final part in certificate.subject.parts) part.oid], ['2.5.4.6', '2.5.4.10', '2.5.4.11', '2.5.4.3']);
      final authority = readCertificate(_der('authority'));
      expect(authority.subject.full, 'CN=Example Test CA,O=Example Test Authority');
    });

    test('a date from 2050 on is a GeneralizedTime, and read', () {
      expect(readCertificate(_der('p256.until-2090')).notAfter, DateTime.utc(2090));
      expect(readCertificate(_der('p256.expired')).notAfter, DateTime.utc(2021));
    });

    test('basic constraints and key usage are read, and other extensions skipped', () {
      final authority = readCertificate(_der('authority'));
      expect(authority.isAuthority, isTrue);
      expect(authority.keyUsage, {KeyUsageBit.keyCertSign, KeyUsageBit.crlSign});
      final issued = readCertificate(_der('p256.issued'));
      expect(issued.isAuthority, isFalse);
      expect(issued.keyUsage, {KeyUsageBit.digitalSignature});
      expect(issued.selfSigned, isFalse);
      expect(issued.issuer.encoded, authority.subject.encoded);
      // OpenSSL adds subject and authority key identifiers; the second is skipped
      expect(issued.subjectKeyIdentifier, hasLength(20));
    });
  });

  group('checks a certificate’s own signature', () {
    for (final name in ['rsa2048.selfsigned', 'p256.selfsigned', 'p384.selfsigned', 'p256.expired', 'p256.until-2090', 'p256.names']) {
      test('$name verifies, and fails with one byte changed', () {
        final der = _der(name);
        final certificate = readCertificate(der);
        expect(verifyOwnSignature(certificate), isTrue);

        // A byte of the name, well inside the signed part
        final inName = der.indexOf(0x45, 40);
        final changed = Uint8List.fromList(der)..[inName] ^= 0x01;
        expect(verifyOwnSignature(readCertificate(changed)), isFalse);

        // And the last byte of the signature
        final resigned = Uint8List.fromList(der)..[der.length - 1] ^= 0x01;
        expect(verifyOwnSignature(readCertificate(resigned)), isFalse);
      });
    }

    test('a certificate signed by another key does not verify as its own', () {
      final issued = readCertificate(_der('p256.issued'));
      expect(verifyOwnSignature(issued), isFalse);
      final authority = readCertificate(_der('authority'));
      expect(verifyX509Signature(authority.publicKey, issued.signatureAlgorithm, issued.toBeSigned, issued.signature), isTrue);
    });

    test('an algorithm it does not check gives false, not an error', () {
      expect(verifyOwnSignature(readCertificate(_der('ed25519.selfsigned'))), isFalse);
      final p256 = readCertificate(_der('p256.selfsigned'));
      expect(verifyX509Signature(p256.publicKey, oidEcdsaWithSha384, p256.toBeSigned, p256.signature), isFalse);
      expect(verifyX509Signature(p256.publicKey, oidEcdsaWithSha256, p256.toBeSigned, Uint8List.fromList([1, 2, 3])), isFalse);
      expect(verifyX509Signature(null, oidEcdsaWithSha256, p256.toBeSigned, p256.signature), isFalse);
    });
  });

  // Software keys stand in for the slot's key: the OpenSSL fixtures' private halves.
  group('writes', () {
    late RsaMaterial rsa;
    late EcMaterial p256;
    late EcMaterial p384;

    setUpAll(() async {
      rsa = await readPkcs8(keyFixture('openssl/rsa2048.pkcs8.der')) as RsaMaterial;
      p256 = await readPkcs8(keyFixture('openssl/p256.pkcs8.der')) as EcMaterial;
      p384 = await readPkcs8(keyFixture('openssl/p384.pkcs8.der')) as EcMaterial;
    });

    X509Signer signer(KeyMaterial key) =>
        (toBeSigned) async => softwareX509Signature(key, toBeSigned);

    final from = DateTime.utc(2026, 11, 16, 9);
    final until = DateTime.utc(2028, 11, 16, 9);

    Future<Uint8List> selfSigned(KeyMaterial key, CertificateUse use, {String name = 'Ada Example', DateTime? notAfter}) => buildSelfSigned(
      publicKey: key.publicHalf!,
      commonName: name,
      notBefore: from,
      notAfter: notAfter ?? until,
      use: use,
      sign: signer(key),
    );

    test('a self-signed certificate that reads back with the fields given', () async {
      for (final key in [rsa, p256, p384]) {
        final certificate = readCertificate(await selfSigned(key, CertificateUse.authentication));

        expect(certificate.subject.commonName, 'Ada Example');
        expect(certificate.subject.parts, hasLength(1));
        expect(certificate.selfSigned, isTrue);
        expect((certificate.notBefore, certificate.notAfter), (from, until));
        expect(certificate.publicKeyInfo, writeSpki(key.publicHalf!));
        expect(certificate.serial, hasLength(16));
        expect(certificate.serial[0] & 0x80, 0, reason: 'the serial number is positive');
        expect(verifyOwnSignature(certificate), isTrue);
      }
    });

    test('with SHA-256 for RSA and P-256 and SHA-384 for P-384', () async {
      expect(readCertificate(await selfSigned(rsa, CertificateUse.signature)).signatureAlgorithm, oidSha256WithRsa);
      expect(readCertificate(await selfSigned(p256, CertificateUse.signature)).signatureAlgorithm, oidEcdsaWithSha256);
      expect(readCertificate(await selfSigned(p384, CertificateUse.signature)).signatureAlgorithm, oidEcdsaWithSha384);
    });

    test('the extensions of each slot: no authority, the key usage, the subject key identifier', () async {
      for (final (use, key, usage) in [
        (CertificateUse.authentication, p256, {KeyUsageBit.digitalSignature}),
        (CertificateUse.signature, p256, {KeyUsageBit.digitalSignature, KeyUsageBit.contentCommitment}),
        (CertificateUse.keyManagement, p256, {KeyUsageBit.keyAgreement}),
        (CertificateUse.keyManagement, rsa, {KeyUsageBit.keyEncipherment}),
        (CertificateUse.cardAuthentication, p384, {KeyUsageBit.digitalSignature}),
      ]) {
        final certificate = readCertificate(await selfSigned(key, use));
        expect(certificate.isAuthority, isFalse, reason: use.name);
        expect(certificate.keyUsage, usage, reason: use.name);
        final bits = readSequence(writeSpki(key.publicHalf!))..sequence();
        expect(certificate.subjectKeyIdentifier, hash.sha1.convert(bits.bitString()).bytes, reason: use.name);
      }
    });

    test('a date from 2050 on as a GeneralizedTime, and a name that is not ASCII', () async {
      final certificate = readCertificate(
        await selfSigned(p256, CertificateUse.authentication, name: 'Zoé Müller', notAfter: DateTime.utc(2060)),
      );
      expect(certificate.notAfter, DateTime.utc(2060));
      expect(certificate.subject.commonName, 'Zoé Müller');
      expect(verifyOwnSignature(certificate), isTrue);
    });

    test('a fresh serial number each time', () async {
      final serials = {for (var i = 0; i < 5; i++) readCertificate(await selfSigned(p256, CertificateUse.authentication)).serialText};
      expect(serials, hasLength(5));
    });

    test('nothing for a name that is empty or too long, or a key no slot holds', () async {
      await expectLater(selfSigned(p256, CertificateUse.authentication, name: ''), throwsArgumentError);
      await expectLater(selfSigned(p256, CertificateUse.authentication, name: 'a' * 65), throwsArgumentError);
      final ed25519 = await readPkcs8(keyFixture('openssl/ed25519.pkcs8.der'));
      await expectLater(
        buildSelfSigned(
          publicKey: ed25519.publicHalf!,
          commonName: 'Ed',
          notBefore: from,
          notAfter: until,
          use: CertificateUse.authentication,
          sign: (_) async => Uint8List(64),
        ),
        throwsArgumentError,
      );
    });

    test('a signature by another key is found by the check, not by the writer', () async {
      final der = await buildSelfSigned(
        publicKey: p256.publicHalf,
        commonName: 'Ada Example',
        notBefore: from,
        notAfter: until,
        use: CertificateUse.authentication,
        sign: signer(ecMaterial(EcCurve.p256, Uint8List.fromList(List.filled(32, 1)))),
      );
      expect(verifyOwnSignature(readCertificate(der)), isFalse);
    });

    test('a request that reads back, verifies, and is no certificate', () async {
      for (final key in [rsa, p256, p384]) {
        final der = await buildRequest(publicKey: key.publicHalf!, commonName: 'Ada Example', sign: signer(key));
        final request = readCertificateRequest(der);
        expect(request.subject.commonName, 'Ada Example');
        expect(request.publicKeyInfo, writeSpki(key.publicHalf!));
        expect(request.verifies, isTrue);
        expect(() => readCertificate(der), throwsA(isA<KeyFormatException>()));
      }
    });

    test('the request OpenSSL made reads the same way', () {
      final request = readCertificateRequest(keyFixture('openssl/x509/p256.request.der'));
      expect(request.subject.full, 'CN=Ada Example');
      expect(request.publicKeyInfo, keyFixture('openssl/p256.spki.der'));
      expect(request.verifies, isTrue);
      expect(() => readCertificateRequest(_der('p256.selfsigned')), throwsA(isA<KeyFormatException>()));
    });

    // What Kemlock wrote once, kept so OpenSSL's verdict on it can be read
    // in the fixtures' README. RSA signatures and RFC 6979 ECDSA are both
    // deterministic, so the same inputs give the same bytes again.
    test('the three outputs OpenSSL accepted (fixtures/keys/kemlock/x509)', () async {
      final serial = Uint8List.fromList(List.generate(16, (i) => 0x10 + i));
      final rsaCertificate = await buildSelfSigned(
        publicKey: rsa.publicHalf,
        commonName: 'Ada Example',
        notBefore: from,
        notAfter: until,
        use: CertificateUse.signature,
        sign: signer(rsa),
        serial: serial,
      );
      final p256Certificate = await buildSelfSigned(
        publicKey: p256.publicHalf,
        commonName: 'Zoé Müller',
        notBefore: from,
        notAfter: DateTime.utc(2051, 1, 1),
        use: CertificateUse.authentication,
        sign: signer(p256),
        serial: serial,
      );
      final p384Request = await buildRequest(publicKey: p384.publicHalf, commonName: 'Ada Example', sign: signer(p384));

      expect(rsaCertificate, keyFixture('kemlock/x509/rsa2048.selfsigned.der'));
      expect(p256Certificate, keyFixture('kemlock/x509/p256.selfsigned.der'));
      expect(p384Request, keyFixture('kemlock/x509/p384.request.der'));
    });
  });

  group('names what a picked file holds', () {
    Uint8List text(String path) => keyFixture(path);

    test('a certificate, in PEM or DER, with text round it or not', () {
      expect(readCertificateFile(_der('p256.issued')).certificate!.subject.commonName, 'Ada Example');
      expect(readCertificateFile(text('openssl/x509/p256.issued.pem')).kind, CertificateFileKind.certificate);
      final wrapped = Uint8List.fromList([
        ...'Here it is:\r\n\r\n'.codeUnits,
        ...text('openssl/x509/p256.issued.pem'),
        ...'\r\nBye'.codeUnits,
      ]);
      expect(readCertificateFile(wrapped).certificate!.encoded, _der('p256.issued'));
    });

    test('a request, a private key and a public key, each for what it is', () {
      for (final (path, kind) in [
        ('openssl/x509/p256.request.pem', CertificateFileKind.request),
        ('openssl/x509/p256.request.der', CertificateFileKind.request),
        ('openssl/p256.pkcs8.pem', CertificateFileKind.privateKey),
        ('openssl/p256.pkcs8.der', CertificateFileKind.privateKey),
        ('openssl/rsa2048.traditional.pem', CertificateFileKind.privateKey),
        ('openssl/rsa2048.traditional.der', CertificateFileKind.privateKey),
        ('openssl/p256.traditional.der', CertificateFileKind.privateKey),
        ('openssl/p256.pbes2-sha256-aes256.pem', CertificateFileKind.privateKey),
        ('openssl/p256.spki.pem', CertificateFileKind.publicKey),
        ('openssl/p256.spki.der', CertificateFileKind.publicKey),
      ]) {
        final read = readCertificateFile(text(path));
        expect(read.kind, kind, reason: path);
        expect(read.certificate, isNull);
      }
    });

    test('anything else as unreadable, without an error', () {
      for (final bytes in [
        Uint8List(0),
        Uint8List.fromList('hello'.codeUnits),
        Uint8List.fromList('-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----'.codeUnits),
        Uint8List.fromList('-----BEGIN CERTIFICATE-----\nAAAA'.codeUnits),
        Uint8List.fromList('-----BEGIN PGP MESSAGE-----\nAAAA\n-----END PGP MESSAGE-----'.codeUnits),
        Uint8List.sublistView(_der('p256.selfsigned'), 0, 100),
        Uint8List(maxKeyInputLength + 1),
      ]) {
        expect(readCertificateFile(bytes).kind, CertificateFileKind.unreadable);
      }
    });
  });
}
