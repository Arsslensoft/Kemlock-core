/// Private keys for the vault: reading them from files, their public halves
/// and fingerprints, and exporting them.
///
/// Everything a vault key needs goes through this file:
///
/// - [readPrivateKey] takes the bytes of a file or pasted text, works out
///   the format, and returns a [ParsedKey]: its [KeyKind], its algorithm as
///   `VaultKey.algorithm` stores it, the private half as PKCS#8 DER, and the
///   public half as SPKI DER. It reads OpenSSH private keys (plain or
///   protected), PKCS#8 (PEM or DER, plain or encrypted with PBES2, ML-KEM
///   and ML-DSA keys in each of OpenSSL's forms), PKCS#1 RSA and SEC1 EC
///   keys, and OpenPGP secret keys (armored or binary), whose private half
///   is the transferable secret key as given, its public half the
///   transferable public key, and [ParsedKey.pgp] what the key holds. A
///   protected OpenPGP key is kept as it is, never decrypted.
/// - It throws [KeyFormatException] and nothing else; its [KeyProblem]
///   says why: a public key alone, a PuTTY file, a legacy `DEK-Info` PEM,
///   a cipher it doesn't read (named), more than 1 MB, damaged data,
///   something that isn't a key, a passphrase needed, or a wrong one.
/// - [keyFingerprint], [publicKeyPem] and [sshPublicKeyLine] give what the
///   key sheet shows and hands out: an SSH key's fingerprint is the one
///   `ssh-keygen -l` prints, a PGP key's its OpenPGP fingerprint, any other
///   key's SHA-256 over its SPKI. [readPgpKeyInfo] reads a stored PGP key's
///   user IDs and subkeys again.
/// - [exportPrivateKey] writes the private half out in its kind's form
///   (design decision 5): [exportOpenSsh] for an SSH key, [exportPgpSecretKey]
///   for a PGP key, [exportPkcs8Pem] for the rest; protected when given a
///   passphrase, unprotected only when passed null.
/// - [generateKey] makes a new key in a background isolate, for a
///   [NewKeyRequest] of one of the [generatedAlgorithms] of its kind or a
///   [PgpKeyRequest], and gives a [KeyGeneration] whose `cancel` kills the
///   isolate; its result is the same [ParsedKey] an import gives. [makeKey]
///   does the same on the calling isolate. A generated PGP key's
///   self-signatures are checked with [verifyPgpSelfSignatures] before it
///   is handed out.
/// - [readPublicKeys] reads other people's OpenPGP public keys, one or a
///   keyring of several, each trimmed to what its owner signed and every
///   one of those signatures checked. [readPrivateKey] still refuses a
///   public key alone.
///
/// Reading or exporting with a passphrase runs a key derivation that takes
/// up to a second or two on a phone; call those through `Isolate.run`.
///
/// A [ParsedKey] holds only bytes and strings, so it can be sent between
/// isolates, and it can be rebuilt from a stored `VaultKey` with its
/// constructor.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import 'algorithms.dart';
import 'der.dart';
import 'key_error.dart';
import 'openpgp/armor.dart';
import 'openpgp/key_info.dart';
import 'openpgp/packets.dart';
import 'openpgp/public_key.dart';
import 'openpgp/signatures.dart';
import 'openpgp/writer.dart';
import 'openssh.dart';
import 'pbes2.dart';
import 'pem.dart';
import 'pkcs8.dart';

export 'key_error.dart' show KeyFormatException, KeyProblem, maxKeyInputLength;
export 'keygen.dart'
    show
        GeneratedAlgorithm,
        KeyGenerated,
        KeyGeneration,
        KeyGenerationCancelled,
        KeyGenerationResult,
        KeyRequest,
        NewKeyRequest,
        PgpChangeRequest,
        PgpKeyRequest,
        generateKey,
        generatedAlgorithms,
        makeKey,
        yearsAfter;
export 'openpgp/armor.dart' show pgpPublicKeyBlock, writeArmor;
export 'openpgp/edit.dart'
    show
        AddPgpSubkey,
        AddPgpUserId,
        ApplyPgpRevocation,
        PgpChange,
        PgpEditBlock,
        PgpEditException,
        PgpEditProblem,
        PgpEditRefusal,
        PgpRevocationReason,
        PgpSigner,
        PgpSubkeyUse,
        RevokePgpKey,
        SetPgpExpiry,
        editRefusal,
        primaryNeedsPassphrase,
        revocationCertificate;
export 'openpgp/key_info.dart' show PgpKey, PgpKeyFlag, PgpKeyInfo;
export 'openpgp/merge.dart' show isGrownFrom, mergePgpKeys, verifiesWhatItAdds;
export 'openpgp/public_key.dart' show fingerprintGroups, mergePublicKeys, pgpFailsOwnChecks, unionPublicKeys;
export 'openpgp/writer.dart' show PgpKeyType, cardStubKey, pgpUserId;

/// What a key is for, as `VaultKey.kind` stores it. A key read from an
/// OpenSSH file is [ssh]; a PKCS#8 Ed25519, ECDSA, RSA or ML-DSA key is
/// [signing]; an X25519 or ML-KEM key is [exchange]; a PKCS#8 key of an
/// algorithm this app doesn't know is [other].
enum KeyKind { ssh, signing, exchange, pgp, other }

/// A private key as the vault keeps it.
class ParsedKey {
  const ParsedKey({required this.kind, required this.algorithm, this.bits, required this.private, this.public, this.comment, this.pgp});

  final KeyKind kind;

  /// `ed25519`, `ecdsa-p256`, `ecdsa-p384`, `rsa`, `x25519`, `ml-kem-768`,
  /// `ml-kem-1024`, `ml-dsa-65`, `pgp`, or for an unknown algorithm its dotted
  /// object identifier (for an EC key on a curve other than P-256 and
  /// P-384, the curve's).
  final String algorithm;

  /// The modulus size of an RSA key; null for every other.
  final int? bits;

  /// The private half: PKCS#8 DER, unencrypted. A PKCS#8 file's own bytes
  /// are kept as they were (decrypted when it was encrypted); keys from
  /// other formats are written as `openssl pkey` would write them. For a
  /// PGP key, the binary transferable secret key exactly as given.
  final Uint8List private;

  /// The public half as SPKI DER; for a PGP key the binary transferable
  /// public key; null for an unknown algorithm.
  final Uint8List? public;

  /// The comment of an OpenSSH key file, its name in practice.
  final String? comment;

  /// For a PGP key: its fingerprint, user IDs, subkeys and whether it is
  /// protected by its own passphrase. A key rebuilt from storage can get
  /// it from [readPgpKeyInfo].
  final PgpKeyInfo? pgp;

  /// The same key as another [kind]: the import sheet may let a PKCS#8 or
  /// PKCS#1 key that has an SSH form be kept as an SSH key, and the
  /// reverse.
  ParsedKey withKind(KeyKind kind) =>
      ParsedKey(kind: kind, algorithm: algorithm, bits: bits, private: private, public: public, comment: comment, pgp: pgp);

  /// Whether OpenSSH has a key type for this key's algorithm: Ed25519,
  /// ECDSA P-256 and P-384, and RSA.
  bool get hasSshForm => KeyAlgorithm.values.any((a) => a.id == algorithm && a.hasSshForm);
}

/// Reads a private key from a file's bytes (a `List<int>`) or from pasted
/// text (a `String`). [passphrase] opens an encrypted key; without one, an
/// encrypted key throws [KeyProblem.passphraseNeeded].
///
/// Throws [KeyFormatException] and nothing else.
Future<ParsedKey> readPrivateKey(Object input, {String? passphrase}) async {
  switch (input) {
    case String():
      checkSize(input.length);
      return _readText(input, passphrase);
    case List<int>():
      checkSize(input.length);
      final bytes = Uint8List.fromList(input);
      if (bytes.isNotEmpty && bytes[0] == tagSequence && _isDer(bytes)) return _readDer(bytes, passphrase);
      if (hasOpenSshMagic(bytes)) return _fromOpenSsh(bytes, passphrase);
      switch (_pgpPacketTag(bytes)) {
        case PgpTag.secretKey:
          return _fromPgp(bytes);
        case PgpTag.publicKey:
          throw const KeyFormatException(KeyProblem.publicKeyOnly);
      }
      return _readText(utf8.decode(bytes, allowMalformed: true), passphrase);
    default:
      throw ArgumentError.value(input, 'input', 'must be a String or a List<int>');
  }
}

/// The tag of the OpenPGP packet [bytes] start with, or null when the first
/// byte isn't a packet header.
int? _pgpPacketTag(Uint8List bytes) {
  if (bytes.isEmpty || bytes[0] & 0x80 == 0) return null;
  return bytes[0] & 0x40 == 0 ? (bytes[0] >> 2) & 0x0f : bytes[0] & 0x3f;
}

bool _isDer(Uint8List bytes) {
  try {
    readSequence(bytes);
    return true;
  } on KeyFormatException {
    return false;
  }
}

const _privateLabels = {
  opensshPemLabel,
  pgpPrivateKeyBlock,
  'PRIVATE KEY',
  'ENCRYPTED PRIVATE KEY',
  'RSA PRIVATE KEY',
  'EC PRIVATE KEY',
  'DSA PRIVATE KEY',
};

const _publicLabels = {
  'PUBLIC KEY',
  'RSA PUBLIC KEY',
  'CERTIFICATE',
  'TRUSTED CERTIFICATE',
  'X509 CERTIFICATE',
  'CERTIFICATE REQUEST',
  'NEW CERTIFICATE REQUEST',
  pgpPublicKeyBlock,
};

/// `ssh-ed25519 AAAA...`, `ecdsa-sha2-nistp256 AAAA...`, a certificate, an
/// `authorized_keys` line with options in front: a word, then base64 that
/// starts with the encoded length of the key type.
final _sshPublicLine = RegExp(r'(^|\s)(ssh-|ecdsa-sha2-|sk-)[A-Za-z0-9@.\-]+\s+AAAA[A-Za-z0-9+/]', multiLine: true);

Future<ParsedKey> _readText(String text, String? passphrase) async {
  if (text.trimLeft().startsWith('PuTTY-User-Key-File-')) throw const KeyFormatException(KeyProblem.puttyKey);
  if (text.contains('---- BEGIN SSH2 PUBLIC KEY ----')) throw const KeyFormatException(KeyProblem.publicKeyOnly);

  final blocks = readPemBlocks(text);
  for (final block in blocks) {
    if (!_privateLabels.contains(block.label)) continue;
    if (block.label == pgpPrivateKeyBlock) return _fromPgp(readArmor(block));
    if (block.headers.containsKey('DEK-Info') || block.headers.containsKey('Proc-Type')) {
      throw const KeyFormatException(KeyProblem.legacyPemEncryption);
    }
    final der = block.decode();
    switch (block.label) {
      case opensshPemLabel:
        return _fromOpenSsh(der, passphrase);
      case 'PRIVATE KEY':
        return _fromPkcs8(der);
      case 'ENCRYPTED PRIVATE KEY':
        return _fromPkcs8(decryptPkcs8(der, passphrase));
      case 'RSA PRIVATE KEY':
        return _fromMaterial(readPkcs1(der));
      case 'EC PRIVATE KEY':
        return _fromSec1(der);
      case 'DSA PRIVATE KEY':
        throw const KeyFormatException(KeyProblem.unsupportedKeyType, 'DSA');
    }
  }
  if (blocks.any((b) => _publicLabels.contains(b.label))) throw const KeyFormatException(KeyProblem.publicKeyOnly);
  if (blocks.isEmpty && _sshPublicLine.hasMatch(text)) throw const KeyFormatException(KeyProblem.publicKeyOnly);
  // Markers without a whole block: the text was cut.
  if (blocks.isEmpty && (text.contains('-----BEGIN ') || text.contains('-----END '))) {
    throw const KeyFormatException(KeyProblem.damaged, 'PEM: markers without a block');
  }
  // The base64 of a DER key without its PEM markers.
  if (blocks.isEmpty) {
    final Uint8List bytes;
    try {
      bytes = decodeBase64(text);
    } on KeyFormatException {
      throw const KeyFormatException(KeyProblem.unrecognized);
    }
    if (bytes.length > 16 && bytes[0] == tagSequence && _isDer(bytes)) return _readDer(bytes, passphrase);
  }
  throw const KeyFormatException(KeyProblem.unrecognized);
}

/// A DER key whose structure says which it is: PKCS#8 starts with a
/// version and an algorithm, PKCS#1 with a version and the modulus, SEC1
/// with version 1 and the scalar, encrypted PKCS#8 with the scheme and the
/// data. A public key or certificate is refused.
Future<ParsedKey> _readDer(Uint8List der, String? passphrase) async {
  final r = readSequence(der);
  final first = r.read().tag;
  final second = r.isEmpty ? null : r.read().tag;
  return switch ((first, second)) {
    (tagInteger, tagSequence) => await _fromPkcs8(der),
    (tagInteger, tagInteger) => _fromMaterial(readPkcs1(der)),
    (tagInteger, tagOctetString) => _fromSec1(der),
    (tagSequence, tagOctetString) => await _fromPkcs8(decryptPkcs8(der, passphrase)),
    // SPKI, then a certificate or certificate request.
    (tagSequence, tagBitString) || (tagSequence, tagSequence) => throw const KeyFormatException(KeyProblem.publicKeyOnly),
    _ => throw const KeyFormatException(KeyProblem.unrecognized),
  };
}

Future<ParsedKey> _fromOpenSsh(Uint8List blob, String? passphrase) async {
  final key = await readOpenSsh(blob, passphrase);
  return _fromMaterial(key.material, kind: KeyKind.ssh, comment: key.comment);
}

/// A transferable secret key: its bytes as given (the first key when the
/// file has several), and the public key `gpg --export` would give.
ParsedKey _fromPgp(Uint8List data) {
  final key = readTransferableKey(data);
  if (!key.info.isSecret) throw const KeyFormatException(KeyProblem.publicKeyOnly);
  return ParsedKey(
    kind: KeyKind.pgp,
    algorithm: 'pgp',
    private: Uint8List.fromList(Uint8List.sublistView(data, 0, key.length)),
    public: transferablePublicKey(key.packets),
    pgp: key.info,
  );
}

/// What a stored PGP key holds: its fingerprint, user IDs and subkeys,
/// read from its transferable public or secret key. Throws
/// [KeyFormatException].
PgpKeyInfo readPgpKeyInfo(Uint8List transferableKey) {
  checkSize(transferableKey.length);
  return readTransferableKey(transferableKey).info;
}

// ─── Other people's public keys ───────────────────────────────────────────────

/// Someone else's OpenPGP public key, read by [readPublicKeys]: [bytes] is
/// the binary transferable public key as the vault keeps it, trimmed to
/// what its owner signed, and [info] what it holds.
class PgpPublicKey {
  const PgpPublicKey(this.bytes, this.info);

  final Uint8List bytes;
  final PgpKeyInfo info;
}

/// Reads every OpenPGP public key in a file's bytes (a `List<int>`) or in
/// pasted or scanned text (a `String`): armored `PGP PUBLIC KEY BLOCK`s or
/// binary packets, one key or a keyring of several. Each comes back as
/// [trimPublicKey] gives it, so with every signature of its own checked.
///
/// Throws [KeyFormatException] and nothing else: [KeyProblem.privateKeyGiven]
/// for a secret key, armored or binary; [KeyProblem.unrecognized] for
/// anything that is not an OpenPGP public key (an SSH `.pub` line, a
/// `PUBLIC KEY` PEM, a certificate); [KeyProblem.damaged] for a block that
/// was cut, and, with the detail [pgpFailsOwnChecks], for a key that fails
/// its own checks; [KeyProblem.unsupportedKeyType], naming the algorithm,
/// for a key whose signatures can't be checked; [KeyProblem.tooLarge] over
/// 1 MB.
///
/// With [skipUnsound], a key that fails its own checks or whose signatures
/// can't be checked is left out and the others still come back, perhaps
/// none: for an answer from a server, where each key stands alone.
///
/// Checking an RSA 4096 key's signatures takes a moment on a phone; call it
/// through `Isolate.run`.
Future<List<PgpPublicKey>> readPublicKeys(Object input, {bool skipUnsound = false}) async {
  final Uint8List data;
  switch (input) {
    case String():
      checkSize(input.length);
      data = _publicKeyBlocks(input);
    case List<int>():
      checkSize(input.length);
      final bytes = Uint8List.fromList(input);
      switch (_pgpPacketTag(bytes)) {
        case PgpTag.publicKey:
          data = bytes;
        case PgpTag.secretKey:
          throw const KeyFormatException(KeyProblem.privateKeyGiven);
        default:
          data = _publicKeyBlocks(utf8.decode(bytes, allowMalformed: true));
      }
    default:
      throw ArgumentError.value(input, 'input', 'must be a String or a List<int>');
  }

  // One key runs from a public key packet to the next
  final keys = <List<PgpPacket>>[];
  for (final packet in readPackets(data)) {
    switch (packet.tag) {
      case PgpTag.secretKey || PgpTag.secretSubkey:
        throw const KeyFormatException(KeyProblem.privateKeyGiven);
      case PgpTag.publicKey:
        keys.add([packet]);
      default:
        check(keys.isNotEmpty, 'OpenPGP: not a key');
        keys.last.add(packet);
    }
  }
  if (keys.isEmpty) throw const KeyFormatException(KeyProblem.unrecognized);
  final out = <PgpPublicKey>[];
  for (final packets in keys) {
    final given = BytesBuilder(copy: false);
    for (final packet in packets) {
      given.add(packet.encoded);
    }
    final Uint8List trimmed;
    try {
      trimmed = await trimPublicKey(given.toBytes());
    } on KeyFormatException catch (error) {
      if (skipUnsound && (error.problem == KeyProblem.damaged || error.problem == KeyProblem.unsupportedKeyType)) continue;
      rethrow;
    }
    out.add(PgpPublicKey(trimmed, readTransferableKey(trimmed).info));
  }
  return out;
}

/// [key], as [readPublicKeys] gave it, with only the user IDs [keep] says
/// yes to, trimmed and checked again: for a key found for one address, so
/// that another name a server put on it is not taken in with it.
///
/// Throws [KeyFormatException], [KeyProblem.damaged] with
/// [pgpFailsOwnChecks], when no user ID is left on a version 4 key.
Future<PgpPublicKey> keepUserIds(PgpPublicKey key, bool Function(String userId) keep) async {
  final trimmed = await trimPublicKey(key.bytes, keepUserId: keep);
  return PgpPublicKey(trimmed, readTransferableKey(trimmed).info);
}

/// The bytes of every `PGP PUBLIC KEY BLOCK` in [text], one after the other.
Uint8List _publicKeyBlocks(String text) {
  final blocks = readPemBlocks(text);
  if (blocks.any((b) => b.label == pgpPrivateKeyBlock)) throw const KeyFormatException(KeyProblem.privateKeyGiven);
  final out = BytesBuilder(copy: false);
  for (final block in blocks) {
    if (block.label == pgpPublicKeyBlock) out.add(readArmor(block));
  }
  // Markers without a whole block: the text was cut.
  if (blocks.isEmpty && (text.contains('-----BEGIN ') || text.contains('-----END '))) {
    throw const KeyFormatException(KeyProblem.damaged, 'PEM: markers without a block');
  }
  if (out.isEmpty) throw const KeyFormatException(KeyProblem.unrecognized);
  return out.toBytes();
}

Future<ParsedKey> _fromPkcs8(Uint8List pkcs8) async => _parsed(await readPkcs8(pkcs8), private: pkcs8);

ParsedKey _fromMaterial(KeyMaterial material, {KeyKind? kind, String? comment}) =>
    _parsed(material, private: writePkcs8(material), kind: kind, comment: comment);

ParsedKey _fromSec1(Uint8List sec1) {
  final material = readSec1(sec1);
  if (material is OtherMaterial) return _parsed(material, private: wrapSec1(material.oid, sec1));
  return _fromMaterial(material);
}

ParsedKey _parsed(KeyMaterial material, {required Uint8List private, KeyKind? kind, String? comment}) {
  final half = material.publicHalf;
  return ParsedKey(
    kind: kind ?? _kindOf(half?.algorithm),
    algorithm: half?.algorithm.id ?? (material as OtherMaterial).oid,
    bits: material is RsaMaterial ? material.bits : null,
    private: Uint8List.fromList(private),
    public: half == null ? null : writeSpki(half),
    comment: comment,
  );
}

KeyKind _kindOf(KeyAlgorithm? algorithm) => switch (algorithm) {
  null => KeyKind.other,
  KeyAlgorithm(isExchange: true) => KeyKind.exchange,
  _ => KeyKind.signing,
};

// ─── Public half and fingerprint ──────────────────────────────────────────────

/// A key's fingerprint: [bytes], and [text] as the key sheet shows it.
class KeyFingerprint {
  const KeyFingerprint(this.bytes, this.text);

  final Uint8List bytes;

  /// `SHA256:` and the unpadded base64 of [bytes], the way `ssh-keygen -l`
  /// prints it; for a PGP key, its hexadecimal fingerprint in groups of
  /// four.
  final String text;
}

/// The key's fingerprint: for an SSH key, SHA-256 over its SSH wire form,
/// as `ssh-keygen -l` prints it; for a PGP key, its OpenPGP fingerprint
/// (SHA-1 for version 4, SHA-256 for version 6) as GnuPG prints it, in
/// groups of four; for any other, SHA-256 over its SPKI DER. Null for a key
/// with no public half.
KeyFingerprint? keyFingerprint(ParsedKey key) {
  final public = key.public;
  if (public == null) return null;
  if (key.kind == KeyKind.pgp) {
    final fingerprint = (key.pgp ?? readPgpKeyInfo(public)).primary;
    final hex = fingerprint.fingerprintHex;
    return KeyFingerprint(fingerprint.fingerprint, [for (var i = 0; i < hex.length; i += 4) hex.substring(i, i + 4)].join(' '));
  }
  if (key.kind == KeyKind.ssh) return _fingerprint(sshFingerprint(_publicHalf(key)));
  return _fingerprint(hash.sha256.convert(public).bytes);
}

KeyFingerprint _fingerprint(List<int> digest) =>
    KeyFingerprint(Uint8List.fromList(digest), 'SHA256:${base64.encode(digest).replaceAll('=', '')}');

PublicHalf _publicHalf(ParsedKey key) {
  final half = key.public == null ? null : readSpki(key.public!);
  if (half == null) throw ArgumentError.value(key.algorithm, 'key', 'has no public half this app reads');
  return half;
}

/// The `SHA256:` fingerprint `ssh-keygen -l` prints for the key whose public
/// half is the SPKI DER [public], the one [keyFingerprint] gives an SSH key;
/// null for an algorithm OpenSSH has no key type for. Throws
/// [KeyFormatException] when [public] is not an SPKI.
String? sshFingerprintOfSpki(Uint8List public) {
  final half = readSpki(public);
  return half == null || !half.algorithm.hasSshForm ? null : _fingerprint(sshFingerprint(half)).text;
}

/// The line `ssh` and `authorized_keys` read, `<type> <base64> <comment>`,
/// for a key with an SSH form ([ParsedKey.hasSshForm]); null for any
/// other. `ssh-keygen -l` prints the same fingerprint for it as
/// [keyFingerprint] gives an SSH key.
String? sshPublicKeyLine(ParsedKey key, {String? comment}) =>
    key.hasSshForm ? sshPublicLine(_publicHalf(key), comment: comment ?? key.comment) : null;

/// The public half as a `PUBLIC KEY` PEM block, for a PGP key as an
/// armored `PGP PUBLIC KEY BLOCK`, without the CRC-24 line for a version 6
/// key; null for a key with none.
String? publicKeyPem(ParsedKey key) {
  final public = key.public;
  if (public == null) return null;
  return key.kind == KeyKind.pgp ? writeArmor(pgpPublicKeyBlock, public, checksum: !_isV6(key)) : writePem('PUBLIC KEY', public);
}

/// Whether [key] is a version 6 PGP key, which is armored without the
/// CRC-24 line (design decision 10).
bool _isV6(ParsedKey key) {
  try {
    return (key.pgp ?? readPgpKeyInfo(key.private)).version == 6;
  } on KeyFormatException {
    return false;
  }
}

// ─── Export ───────────────────────────────────────────────────────────────────

/// The private half in the form its kind goes out in: an SSH key as an
/// OpenSSH private key file ([exportOpenSsh], with [comment]), a PGP key as
/// an armored secret key ([exportPgpSecretKey]), any other as PKCS#8 PEM
/// ([exportPkcs8Pem]). [passphrase] protects it; null leaves it
/// unprotected, which the person has to choose, so an empty passphrase is
/// refused with an [ArgumentError] in every export.
Future<String> exportPrivateKey(ParsedKey key, {String? passphrase, String? comment}) async => switch (key.kind) {
  KeyKind.ssh => await exportOpenSsh(key, passphrase: passphrase, comment: comment),
  KeyKind.pgp => exportPgpSecretKey(key, passphrase: passphrase),
  _ => exportPkcs8Pem(key, passphrase: passphrase),
};

void _checkPassphrase(String? passphrase) {
  if (passphrase != null && passphrase.isEmpty) {
    throw ArgumentError.value(passphrase, 'passphrase', 'is empty; pass null to export without one');
  }
}

/// The private half as an OpenSSH private key file, for a key with an SSH
/// form: with a [passphrase], protected the way `ssh-keygen` protects it
/// (`aes256-ctr`, 16 rounds of bcrypt_pbkdf), so `ssh-keygen -y` opens it
/// with that passphrase; [comment] is stored with it.
Future<String> exportOpenSsh(ParsedKey key, {String? passphrase, String? comment}) async {
  if (!key.hasSshForm) throw ArgumentError.value(key.algorithm, 'key', 'has no OpenSSH form');
  _checkPassphrase(passphrase);
  final material = await readPkcs8(key.private);
  return writeOpenSsh(material, comment: comment ?? key.comment ?? '', passphrase: passphrase);
}

/// The private half as PKCS#8 PEM: with a [passphrase], an `ENCRYPTED
/// PRIVATE KEY` block (PBES2, PBKDF2-HMAC-SHA-256 with [iterations] rounds,
/// AES-256-CBC) that `openssl pkey` opens; without, a `PRIVATE KEY` block
/// of the same bytes as were read from a PKCS#8 file.
String exportPkcs8Pem(ParsedKey key, {String? passphrase, int iterations = defaultPbkdf2Iterations}) {
  _checkPassphrase(passphrase);
  return passphrase == null
      ? writePem('PRIVATE KEY', key.private)
      : writePem('ENCRYPTED PRIVATE KEY', encryptPkcs8(key.private, passphrase, iterations: iterations));
}

/// A PGP key's private half as an armored `PGP PRIVATE KEY BLOCK`. A key
/// that keeps its own passphrase, every secret part it holds protected by
/// one ([PgpKeyInfo.protected]), goes out byte for byte as it came in,
/// whatever [passphrase] is. Any other has each secret part in the clear
/// protected with [passphrase] (S2K usage 254, AES-256, Iterated and
/// Salted S2K over SHA-256, as GnuPG reads it), a part behind a passphrase
/// of its own and GnuPG's stub left as they are; or goes out as it is
/// without one. A stub is not a protected secret: a key of a stub and
/// subkeys in the clear, as `gpg --export-secret-subkeys` writes it from a
/// keyring with no passphrase, gets [passphrase] on its subkeys.
String exportPgpSecretKey(ParsedKey key, {String? passphrase}) {
  if (key.kind != KeyKind.pgp) throw ArgumentError.value(key.kind, 'key', 'is not a PGP key');
  _checkPassphrase(passphrase);
  final protected = readPgpKeyInfo(key.private).protected;
  final bytes = passphrase == null || protected ? key.private : protectPgpKey(key.private, passphrase);
  return writeArmor(pgpPrivateKeyBlock, bytes, checksum: !_isV6(key));
}

/// Whether every self-signature of a PGP key (its user IDs'
/// certifications, its direct-key signatures and its subkeys' bindings)
/// verifies: EdDSA, Ed25519 and RSA signatures with SHA-1, SHA-2 or SHA-3.
/// Throws [KeyFormatException] when [transferableKey] isn't a key.
Future<bool> verifyPgpSelfSignatures(Uint8List transferableKey) async {
  checkSize(transferableKey.length);
  return verifySelfSignatures(transferableKey);
}
