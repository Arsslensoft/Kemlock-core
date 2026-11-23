// The messages and signatures Kemlock writes for fixed inputs, fixed
// randomness and a fixed time. `tool/pgp/write_samples.dart` wrote them
// once into test/fixtures/pgp/kemlock, `encrypt_test.dart` checks the
// writers still give those bytes, and `tool/pgp/gnupg_check.sh` gives the
// files to GnuPG.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/openpgp/session_key.dart';
import 'package:kemlock_core/crypto/keys/openpgp/usable_keys.dart';
import 'package:kemlock_core/crypto/keys/pgp.dart';

import 'fixtures.dart';

/// When every sample says it was made.
final sampleTime = DateTime.utc(2026, 11, 20, 9, 30);

/// [length] bytes that depend on [label] alone: SHA-256 in counter mode.
Uint8List fixedBytes(String label, int length) {
  final out = BytesBuilder();
  for (var i = 0; out.length < length; i++) {
    out.add(hash.sha256.convert(utf8.encode('$label $i')).bytes);
  }
  return Uint8List.sublistView(out.takeBytes(), 0, length);
}

/// The randomness of the sample [name] to [recipients].
Future<MessageRandom> fixedRandom(String name, List<Uint8List> recipients) async {
  final perRecipient = <Uint8List>[];
  for (final (i, recipient) in recipients.indexed) {
    final key = (await PgpCertificate.read(recipient)).encryptionKey(sampleTime);
    perRecipient.add(fixedBytes('$name recipient $i', pkeskRandomLength(key, 32)));
  }
  return MessageRandom(
    sessionKey: fixedBytes('$name session key', 32),
    prefix: fixedBytes('$name prefix', 16),
    salt: fixedBytes('$name salt', 8),
    perRecipient: perRecipient,
  );
}

/// What a sample is, for the check with GnuPG.
enum SampleKind {
  /// `gpg --decrypt` with the fixture keys.
  toKeys,

  /// `gpg --decrypt` with [fixturePassphrase].
  toPassphrase,

  /// `gpg --verify` of a clear-signed text.
  clearSigned,

  /// `gpg --verify <file> <plain>`.
  detached,
}

class Sample {
  const Sample(this.file, this.kind, this.plain, this.make, {this.signers = const [], this.recipients = const []});

  /// The file under test/fixtures/pgp/kemlock.
  final String file;
  final SampleKind kind;

  /// The file under test/fixtures/pgp/gnupg it was made from.
  final String plain;

  /// The primary key fingerprints of who signed it.
  final List<String> signers;

  /// The secret keys of the recipients, each of which must open it.
  final List<Uint8List Function()> recipients;
  final Future<Uint8List> Function() make;

  bool get armored => file.endsWith('.asc');
}

Future<Uint8List> _encrypt(
  String name, {
  required String plain,
  List<Uint8List> to = const [],
  String? passphrase,
  Uint8List? signer,
  required bool text,
}) async {
  final bytes = await encrypt(
    data: PgpData.bytes(pgpFixture('gnupg/$plain')),
    recipients: to,
    passphrase: passphrase,
    signer: signer == null ? null : PgpSecretKey(signer),
    text: text,
    fileName: plain,
    now: sampleTime,
    random: await fixedRandom(name, to),
  );
  return bytes!;
}

Future<Uint8List> _sign(String plain, Uint8List signer, PgpSignatureForm form) =>
    sign(data: PgpData.bytes(pgpFixture('gnupg/$plain')), signer: PgpSecretKey(signer), form: form, now: sampleTime);

/// The fingerprint of the two keys Kemlock generated, read from the keys.
Future<String> _fingerprint(Uint8List key) async => (await PgpCertificate.read(key)).fingerprintHex;

Future<List<Sample>> kemlockSamples() async {
  final kemlockEd = await _fingerprint(Keys.kemlockEd);
  final kemlockRsa = await _fingerprint(Keys.kemlockRsa);
  return [
    // A typed message: armored, format "u", definite lengths
    Sample(
      'to-ed25519.asc',
      SampleKind.toKeys,
      'message.txt',
      () => _encrypt('to-ed25519', plain: 'message.txt', to: [Keys.edPublic], text: true),
      recipients: [() => Keys.ed],
    ),
    Sample(
      'to-rsa3072.signed.asc',
      SampleKind.toKeys,
      'message.txt',
      () => _encrypt('to-rsa3072.signed', plain: 'message.txt', to: [Keys.rsaPublic], signer: Keys.rsa, text: true),
      signers: [Keys.rsaFingerprint],
      recipients: [() => Keys.rsa],
    ),
    Sample(
      'to-two.signed.asc',
      SampleKind.toKeys,
      'message.txt',
      () => _encrypt('to-two.signed', plain: 'message.txt', to: [Keys.edPublic, Keys.rsaPublic], signer: Keys.ed, text: true),
      signers: [Keys.edFingerprint],
      recipients: [() => Keys.ed, () => Keys.rsa],
    ),
    Sample(
      'to-kemlock.signed.asc',
      SampleKind.toKeys,
      'message.txt',
      () => _encrypt('to-kemlock.signed', plain: 'message.txt', to: [Keys.kemlockEd, Keys.kemlockRsa], signer: Keys.kemlockRsa, text: true),
      signers: [kemlockRsa],
      recipients: [() => Keys.kemlockEd, () => Keys.kemlockRsa],
    ),
    // A file: binary, format "b", partial lengths
    Sample(
      'report.txt.gpg',
      SampleKind.toKeys,
      'report.txt',
      () => _encrypt('report.txt', plain: 'report.txt', to: [Keys.edPublic, Keys.rsaPublic], signer: Keys.kemlockEd, text: false),
      signers: [kemlockEd],
      recipients: [() => Keys.ed, () => Keys.rsa],
    ),
    Sample(
      'report.txt.unsigned.gpg',
      SampleKind.toKeys,
      'report.txt',
      () => _encrypt('report.txt.unsigned', plain: 'report.txt', to: [Keys.rsaPublic], text: false),
      recipients: [() => Keys.rsa],
    ),
    // With a passphrase
    Sample(
      'passphrase.asc',
      SampleKind.toPassphrase,
      'message.txt',
      () => _encrypt('passphrase', plain: 'message.txt', passphrase: fixturePassphrase, text: true),
    ),
    Sample(
      'passphrase.signed.gpg',
      SampleKind.toPassphrase,
      'report.txt',
      () => _encrypt('passphrase.signed', plain: 'report.txt', passphrase: fixturePassphrase, signer: Keys.ed, text: false),
      signers: [Keys.edFingerprint],
    ),
    // Signatures
    Sample(
      'clearsigned.asc',
      SampleKind.clearSigned,
      'message.txt',
      () => _sign('message.txt', Keys.ed, PgpSignatureForm.cleartext),
      signers: [Keys.edFingerprint],
    ),
    Sample(
      'clearsigned-rsa.asc',
      SampleKind.clearSigned,
      'message.txt',
      () => _sign('message.txt', Keys.rsa, PgpSignatureForm.cleartext),
      signers: [Keys.rsaFingerprint],
    ),
    Sample(
      'report.txt.ed25519.sig',
      SampleKind.detached,
      'report.txt',
      () => _sign('report.txt', Keys.ed, PgpSignatureForm.detached),
      signers: [Keys.edFingerprint],
    ),
    Sample(
      'report.txt.rsa3072.sig',
      SampleKind.detached,
      'report.txt',
      () => _sign('report.txt', Keys.rsa, PgpSignatureForm.detached),
      signers: [Keys.rsaFingerprint],
    ),
    Sample(
      'report.txt.kemlock-rsa4096.sig.asc',
      SampleKind.detached,
      'report.txt',
      () => _sign('report.txt', Keys.kemlockRsa, PgpSignatureForm.detachedArmored),
      signers: [kemlockRsa],
    ),
    Sample(
      'message.txt.kemlock-ed25519.sig',
      SampleKind.detached,
      'message.txt',
      () => _sign('message.txt', Keys.kemlockEd, PgpSignatureForm.detached),
      signers: [kemlockEd],
    ),
  ];
}
