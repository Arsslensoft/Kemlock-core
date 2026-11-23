// SSH signatures over files and text: the SSHSIG format of OpenSSH's
// PROTOCOL.sshsig, which `ssh-keygen -Y sign` writes and git uses for
// commits and tags (`gpg.format ssh`). Reading the armored block, checking
// it the way `sshsig.c` does, and signing with the choices `ssh-keygen`
// makes, so an Ed25519 or RSA signature is byte for byte the one it writes.
//
// The armored block holds: the six bytes `SSHSIG`, a version (1), the
// public key, the namespace, a reserved string, the hash's name and the
// signature. What the key signs is `SSHSIG`, the namespace, an empty
// reserved string, the hash's name and the hash of the message.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart' as c;

import 'algorithms.dart';
import 'der.dart';
import 'key_error.dart';
import 'openssh.dart';
import 'pem.dart';

const sshsigPemLabel = 'SSH SIGNATURE';

final _preamble = ascii.encode('SSHSIG');

/// Why text could not be read as an SSH signature.
enum SshsigProblem {
  /// No `SSH SIGNATURE` block in it: a PGP signature, plain text, nothing.
  notASignature,

  /// An `SSH SIGNATURE` block that is cut short, has bytes after its end,
  /// or is not version 1 of the format with a SHA-256 or SHA-512 hash.
  damaged,
}

/// Text that is not an SSH signature Kemlock can read; [problem] says why.
/// [readSshsig] throws this and nothing else.
class SshsigFormatException implements Exception {
  const SshsigFormatException(this.problem, [this.detail]);

  final SshsigProblem problem;

  /// A note for logs, not for people.
  final String? detail;

  @override
  String toString() => 'SshsigFormatException: ${problem.name}${detail == null ? '' : ' ($detail)'}';
}

/// An SSH signature as its armored block carries it.
class SshSignature {
  const SshSignature({
    required this.publicKeyBlob,
    required this.keyType,
    required this.publicKey,
    required this.namespace,
    required this.hashName,
    required this.algorithm,
    required this.signature,
  });

  /// The signer's public key in SSH wire form: what a `.pub` line carries
  /// in base64.
  final Uint8List publicKeyBlob;

  /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, or whatever type the
  /// block names.
  final String keyType;

  /// The signer's key, or null for a key type Kemlock does not check
  /// (`ecdsa-sha2-nistp521`, the `sk-` types, certificates).
  final PublicHalf? publicKey;

  /// What the signature was made for: `file`, `git`, ...
  final String namespace;

  /// `sha256` or `sha512`: the hash of the message.
  final String hashName;

  /// The signature's own algorithm: `ssh-ed25519`, `rsa-sha2-512`, ...
  final String algorithm;

  /// The signature's bytes, as [algorithm] lays them out.
  final Uint8List signature;

  /// The signer's `SHA256:` fingerprint, as `ssh-keygen -l` prints it.
  String get fingerprint => sshBlobFingerprint(publicKeyBlob);
}

/// `SHA256:` and the unpadded base64 of the SHA-256 of a public key's SSH
/// wire form, as `ssh-keygen -l` prints it.
String sshBlobFingerprint(List<int> publicKeyBlob) =>
    'SHA256:${base64.encode(hash.sha256.convert(publicKeyBlob).bytes).replaceAll('=', '')}';

/// How a signature stands against a message and a namespace.
enum SshsigVerdict {
  /// The key in the block signed this message for this namespace.
  good,

  /// It did not: the message, or the signature, is not the one signed.
  bad,

  /// The signature was made for another namespace, [SshsigResult.detail].
  wrongNamespace,

  /// A key type or algorithm Kemlock does not check, [SshsigResult.detail].
  unsupported,

  /// An RSA signature over SHA-1 (`ssh-rsa`), which is refused.
  weak,

  /// A signature that matches, by an RSA key under [minRsaSignatureBits],
  /// which can be factored and then signs for anyone: it proves nothing.
  /// [SshsigResult.detail] names the key, `RSA 1024`.
  weakKey,
}

class SshsigResult {
  const SshsigResult(this.verdict, [this.detail]);

  final SshsigVerdict verdict;

  /// The block's namespace for [SshsigVerdict.wrongNamespace]; the key
  /// type for [SshsigVerdict.unsupported]; the key and its size for
  /// [SshsigVerdict.weakKey]; otherwise null.
  final String? detail;

  bool get isGood => verdict == SshsigVerdict.good;

  @override
  String toString() => 'SshsigResult(${verdict.name}${detail == null ? '' : ', $detail'})';
}

/// Whether [namespace] can be signed for: not empty, and with no space,
/// line break or other control character in it.
bool isSshsigNamespace(String namespace) => namespace.isNotEmpty && !_notInNamespace.hasMatch(namespace);

final _notInNamespace = RegExp(r'[\s\x00-\x1f\x7f]');

// ─── Reading ──────────────────────────────────────────────────────────────────

/// Reads the `SSH SIGNATURE` block in [text], whatever the length of its
/// lines. Throws [SshsigFormatException]: [SshsigProblem.notASignature]
/// when there is no such block, [SshsigProblem.damaged] when it is cut
/// short, has bytes after the signature, or is not version 1 with the
/// `sha256` or `sha512` hash.
SshSignature readSshsig(String text) {
  const begin = '-----BEGIN $sshsigPemLabel-----';
  final start = text.indexOf(begin);
  if (start < 0) throw const SshsigFormatException(SshsigProblem.notASignature);
  try {
    final block = readPemBlocks(text.substring(start)).first;
    return readSshsigBlob(block.decode());
  } on KeyFormatException catch (e) {
    throw SshsigFormatException(SshsigProblem.damaged, e.detail ?? e.problem.name);
  }
}

/// Reads the bytes inside an `SSH SIGNATURE` block. Throws
/// [SshsigFormatException] with [SshsigProblem.damaged].
SshSignature readSshsigBlob(Uint8List blob) {
  try {
    check(blob.length >= _preamble.length && _equal(Uint8List.sublistView(blob, 0, _preamble.length), _preamble), 'SSHSIG: preamble');
    final r = SshReader(Uint8List.sublistView(blob, _preamble.length));
    check(r.uint32() == 1, 'SSHSIG: version');
    final publicKeyBlob = r.string();
    final namespace = r.text();
    r.string(); // reserved: read and, as in sshsig.c, not used
    final hashName = r.text();
    final signatureBlob = SshReader(r.string());
    r.done();
    check(_hashes.containsKey(hashName), 'SSHSIG: hash $hashName');
    final algorithm = signatureBlob.text();
    final signature = signatureBlob.string();
    signatureBlob.done();
    final keyType = SshReader(publicKeyBlob).text();
    return SshSignature(
      publicKeyBlob: Uint8List.fromList(publicKeyBlob),
      keyType: keyType,
      publicKey: _readPublicKey(keyType, publicKeyBlob),
      namespace: namespace,
      hashName: hashName,
      algorithm: algorithm,
      signature: Uint8List.fromList(signature),
    );
  } on KeyFormatException catch (e) {
    throw SshsigFormatException(SshsigProblem.damaged, e.detail ?? e.problem.name);
  }
}

/// The key in a public key blob of one of the four types Kemlock checks;
/// null for any other type.
PublicHalf? _readPublicKey(String type, Uint8List blob) {
  final r = SshReader(blob)..string();
  final PublicHalf half;
  switch (type) {
    case 'ssh-ed25519':
      final key = r.string();
      check(key.length == 32, 'SSHSIG: Ed25519 key length');
      half = RawPublicHalf(KeyAlgorithm.ed25519, Uint8List.fromList(key));
    case 'ssh-rsa':
      final e = r.mpint();
      final n = r.mpint();
      half = RsaPublicHalf(n, e);
    case 'ecdsa-sha2-nistp256' || 'ecdsa-sha2-nistp384':
      final curve = EcCurve.bySshName(r.text());
      check(curve != null && type == 'ecdsa-sha2-${curve.sshName}', 'SSHSIG: ECDSA curve');
      final point = r.string();
      check(point.length == 1 + 2 * curve!.size && point[0] == 4, 'SSHSIG: ECDSA point');
      half = EcPublicHalf(curve, Uint8List.fromList(point));
    default:
      return null;
  }
  r.done();
  return half;
}

/// The public key blob of an `authorized_keys` or `.pub` line
/// (`ssh-ed25519 AAAA... comment`), of any key type. Throws
/// [KeyFormatException] when [line] holds no such key.
Uint8List readSshPublicLine(String line) {
  final match = _publicLine.firstMatch(line);
  if (match == null) throw const KeyFormatException(KeyProblem.unrecognized);
  final blob = decodeBase64(match.group(2)!);
  // The blob starts with the key type the line names.
  check(SshReader(blob).text() == match.group(1), 'SSH: key type differs from the line');
  return blob;
}

final _publicLine = RegExp(r'(?:^|\s)((?:ssh-|ecdsa-sha2-|sk-)[A-Za-z0-9@.\-]+)[ \t]+(AAAA[A-Za-z0-9+/]+={0,2})');

// ─── Verifying ────────────────────────────────────────────────────────────────

final _hashes = <String, (List<int> Function(List<int>), String)>{
  'sha256': ((d) => hash.sha256.convert(d).bytes, oidSha256),
  'sha512': ((d) => hash.sha512.convert(d).bytes, oidSha512),
};

/// What the key signs for [message]: the preamble, [namespace], an empty
/// reserved string, [hashName] and the message's hash.
Uint8List _signedData(String namespace, String hashName, List<int> message) =>
    (SshWriter()
          ..raw(_preamble)
          ..text(namespace)
          ..string(const [])
          ..text(hashName)
          ..string(_hashes[hashName]!.$1(message)))
        .bytes;

/// Checks [signature] over [message] for [namespace], as
/// `ssh-keygen -Y check-novalidate -n <namespace>` does.
///
/// The namespace is compared first, so a signature made for another one
/// says so instead of [SshsigVerdict.bad]. Then the key type must be one
/// of Ed25519, ECDSA P-256 or P-384, or RSA ([SshsigVerdict.unsupported]
/// names any other), and the signature's algorithm must belong to the key:
/// an RSA key signs with `rsa-sha2-256` or `rsa-sha2-512`, and `ssh-rsa`
/// (SHA-1) is [SshsigVerdict.weak]. A good signature by an RSA key under
/// [minRsaSignatureBits] is [SshsigVerdict.weakKey]: ssh-keygen refuses
/// keys under 1024 bits, and Kemlock holds signatures to the bound it
/// holds PGP's to.
Future<SshsigResult> sshsigVerify(SshSignature signature, String namespace, List<int> message) async {
  if (signature.namespace != namespace) return SshsigResult(SshsigVerdict.wrongNamespace, signature.namespace);
  final key = signature.publicKey;
  if (key == null) return SshsigResult(SshsigVerdict.unsupported, signature.keyType);
  final data = _signedData(namespace, signature.hashName, message);
  final bool good;
  try {
    switch (key) {
      case RawPublicHalf(:final bytes):
        if (signature.algorithm != 'ssh-ed25519' || signature.signature.length != 64) return const SshsigResult(SshsigVerdict.bad);
        good = await c.Ed25519().verify(
          data,
          signature: c.Signature(signature.signature, publicKey: c.SimplePublicKey(bytes, type: c.KeyPairType.ed25519)),
        );
      case RsaPublicHalf(:final n):
        if (signature.algorithm == 'ssh-rsa') return const SshsigResult(SshsigVerdict.weak);
        final rsaHash = switch (signature.algorithm) {
          'rsa-sha2-256' => _hashes['sha256']!,
          'rsa-sha2-512' => _hashes['sha512']!,
          _ => null,
        };
        if (rsaHash == null) return const SshsigResult(SshsigVerdict.bad);
        good = rsaVerifyPkcs1(key, rsaHash.$2, rsaHash.$1(data), bytesToBigInt(signature.signature));
        // A modulus this small can be factored, and its factors sign anything
        if (good && n.bitLength < minRsaSignatureBits) return SshsigResult(SshsigVerdict.weakKey, 'RSA ${n.bitLength}');
      case EcPublicHalf(:final curve):
        if (signature.algorithm != 'ecdsa-sha2-${curve.sshName}') return const SshsigResult(SshsigVerdict.bad);
        final r = SshReader(signature.signature);
        final (rValue, sValue) = (r.mpint(), r.mpint());
        r.done();
        good = ecdsaVerify(key, data, rValue, sValue);
    }
  } on KeyFormatException {
    // The signature's own bytes are not laid out as its algorithm says.
    return const SshsigResult(SshsigVerdict.bad);
  }
  return SshsigResult(good ? SshsigVerdict.good : SshsigVerdict.bad);
}

// ─── Signing ──────────────────────────────────────────────────────────────────

/// Signs [message] for [namespace] with an Ed25519, ECDSA P-256 or P-384,
/// or RSA key, and gives the armored block `ssh-keygen -Y sign` writes for
/// that namespace: version 1, the SHA-512 hash, an empty reserved string,
/// base64 in lines of 70 characters and a final line ending.
///
/// An RSA key signs with `rsa-sha2-512` whatever its size; an ECDSA key
/// with its curve's hash and the deterministic nonce of RFC 6979, so no
/// random source is used and the same input gives the same signature.
///
/// Throws an [ArgumentError] for a [namespace] that is empty or has a
/// space or a line break ([isSshsigNamespace]), and for a key of any other
/// algorithm.
Future<String> sshsigSign(KeyMaterial material, String namespace, List<int> message) async {
  if (!isSshsigNamespace(namespace)) throw ArgumentError.value(namespace, 'namespace', 'is empty or has a space in it');
  final half = material.publicHalf;
  if (half == null || !half.algorithm.hasSshForm) throw ArgumentError.value(material, 'material', 'cannot make an SSH signature');
  const hashName = 'sha512';
  final data = _signedData(namespace, hashName, message);
  final String algorithm;
  final List<int> signature;
  switch (material) {
    case Ed25519Material(:final seed):
      final ed25519 = c.Ed25519();
      algorithm = 'ssh-ed25519';
      signature = (await ed25519.sign(data, keyPair: await ed25519.newKeyPairFromSeed(seed))).bytes;
    case RsaMaterial():
      algorithm = 'rsa-sha2-512';
      final s = rsaSignPkcs1(material, oidSha512, hash.sha512.convert(data).bytes);
      signature = bigIntToBytes(s, (material.n.bitLength + 7) >> 3);
    case EcMaterial(:final curve):
      algorithm = 'ecdsa-sha2-${curve.sshName}';
      final (:r, :s) = ecdsaSign(material, data);
      signature =
          (SshWriter()
                ..mpint(r)
                ..mpint(s))
              .bytes;
    default:
      throw ArgumentError.value(material, 'material', 'cannot make an SSH signature');
  }
  final blob = SshWriter()
    ..raw(_preamble)
    ..uint32(1)
    ..string(sshPublicBlob(half))
    ..text(namespace)
    ..string(const [])
    ..text(hashName)
    ..string(
      (SshWriter()
            ..text(algorithm)
            ..string(signature))
          .bytes,
    );
  return writePem(sshsigPemLabel, blob.bytes, lineLength: 70);
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
