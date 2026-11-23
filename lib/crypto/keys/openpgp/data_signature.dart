// Signatures over data (RFC 9580 sections 5.2 and 5.4): binary (type
// 0x00) and canonical text (0x01) documents, hashed as the data streams
// past so a file is never held, then checked against the keys at hand or
// made with one: version 4 by a version 4 key, version 6, salted, by a
// version 6 key, RFC 9980's composite ML-DSA-65+Ed25519 among them.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart' as c;

import '../../bytes.dart';

import '../../keccak.dart';
import '../algorithms.dart' show minRsaSignatureBits;
import '../key_error.dart';
import 'key_info.dart';
import 'pgp_error.dart';
import 's2k.dart';
import 'secret_key.dart';
import 'signatures.dart' hide hashSha512;
import 'usable_keys.dart';

const signatureBinary = 0x00;
const signatureText = 0x01;

/// The hash a signature is over, fed in pieces. In [text] mode every line
/// ending becomes CR LF on the way in (a LF with no CR before it gets one).
class SignatureHasher {
  SignatureHasher._(this.hashAlgorithm, this.text, this._add, this._finish);

  /// The hasher for [hashAlgorithm], with a version 6 signature's [salt]
  /// hashed first; null for a hash this app does not compute.
  static SignatureHasher? of(int hashAlgorithm, {required bool text, List<int>? salt}) {
    final SignatureHasher hasher;
    final sha = shaHash(hashAlgorithm);
    if (sha != null) {
      final sink = _DigestSink();
      final input = sha.startChunkedConversion(sink);
      hasher = SignatureHasher._(hashAlgorithm, text, input.add, () {
        input.close();
        return Uint8List.fromList(sink.value!.bytes);
      });
    } else if (hashAlgorithm == hashSha3_256 || hashAlgorithm == hashSha3_512) {
      final keccak = hashAlgorithm == hashSha3_256 ? Keccak.sha3_256() : Keccak.sha3_512();
      hasher = SignatureHasher._(hashAlgorithm, text, keccak.update, () => keccak.squeeze(hashAlgorithm == hashSha3_256 ? 32 : 64));
    } else {
      return null;
    }
    if (salt != null) hasher._add(salt);
    return hasher;
  }

  final int hashAlgorithm;
  final bool text;
  final void Function(List<int>) _add;
  final Uint8List Function() _finish;
  bool _lastWasCr = false;

  void add(Uint8List data) {
    if (!text) {
      _add(data);
      return;
    }
    var start = 0;
    for (var i = 0; i < data.length; i++) {
      if (data[i] == 0x0a && !(i == 0 ? _lastWasCr : data[i - 1] == 0x0d)) {
        _add(Uint8List.sublistView(data, start, i));
        _add(const [0x0d, 0x0a]);
        start = i + 1;
      }
    }
    _add(Uint8List.sublistView(data, start));
    if (data.isNotEmpty) _lastWasCr = data.last == 0x0d;
  }

  /// The digest of what was added and then [trailer]. Once only.
  Uint8List finish(Uint8List trailer) {
    _add(trailer);
    return _finish();
  }
}

class _DigestSink implements Sink<hash.Digest> {
  hash.Digest? value;

  @override
  void add(hash.Digest data) => value = data;

  @override
  void close() {}
}

/// What checking a signature comes to.
enum SignatureVerdict {
  /// Made by a key at hand, over exactly this data.
  good,

  /// The data or the signature was altered; or the signature has expired,
  /// carries a critical subpacket this app cannot honour, or comes from a
  /// subkey that is not bound both ways.
  bad,

  /// No key at hand made it; [SignatureResult.issuer] names who did.
  unknownSigner,

  /// Made with MD5, SHA-1 or RIPEMD-160, which prove nothing any more.
  weakHash,

  /// Made by an RSA key under [minRsaSignatureBits], which can be factored
  /// and then signs for anyone: it proves nothing. [SignatureResult.detail]
  /// names it, `RSA 1024`.
  weakKey,

  /// A signature version, type, hash or key algorithm this app does not
  /// check; [SignatureResult.detail] names it.
  unsupported,
}

/// The outcome for one signature.
class SignatureResult {
  const SignatureResult(
    this.verdict, {
    this.issuer,
    this.signerFingerprint,
    this.made,
    this.keyExpired = false,
    this.keyExpiredSince = false,
    this.keyRevoked = false,
    this.detail,
  });

  final SignatureVerdict verdict;

  /// The fingerprint, or failing that the key ID, the signature names as
  /// its maker, in upper-case hexadecimal; null when it names none.
  final String? issuer;

  /// The primary key fingerprint of the certificate whose key made it,
  /// when that key is at hand.
  final String? signerFingerprint;

  /// When it says it was made.
  final DateTime? made;

  /// With [SignatureVerdict.good]: the key had expired when the signature
  /// was made, or is revoked.
  final bool keyExpired;

  /// With [SignatureVerdict.good]: the key had not expired when the
  /// signature was made, and has since. Its owner may have stopped keeping
  /// it safe, and anyone who took it since can sign with an earlier date.
  final bool keyExpiredSince;
  final bool keyRevoked;

  /// The name of what is not supported.
  final String? detail;
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase();

/// A signature whose data is being hashed: made for a one-pass signature
/// packet or for the signature itself when it comes first, fed the data,
/// then checked.
class PendingSignature {
  PendingSignature._(this.type, this.hashAlgorithm, this._hasher, this.signature);

  /// For a signature read before its data: a detached one, or one that
  /// leads a message.
  factory PendingSignature.of(PgpSignature signature) => PendingSignature._(
    signature.type,
    signature.hashAlgorithm,
    SignatureHasher.of(signature.hashAlgorithm, text: signature.type == signatureText, salt: signature.salt),
    signature,
  );

  /// For a one-pass signature packet; [signature] is set when the
  /// signature itself is read after the data.
  factory PendingSignature.onePass({required int type, required int hashAlgorithm, List<int>? salt}) =>
      PendingSignature._(type, hashAlgorithm, SignatureHasher.of(hashAlgorithm, text: type == signatureText, salt: salt), null);

  final int type;
  final int hashAlgorithm;
  final SignatureHasher? _hasher;
  PgpSignature? signature;

  void add(Uint8List data) => _hasher?.add(data);

  /// Checks the signature against [certificates] at [now].
  Future<SignatureResult> check(List<PgpCertificate> certificates, DateTime now) async {
    final signature = this.signature;
    if (signature == null) return const SignatureResult(SignatureVerdict.bad, detail: 'no signature for a one-pass packet');
    final issuerBytes = signature.issuerFingerprint ?? signature.issuerKeyId;
    final issuer = issuerBytes == null ? null : _hex(issuerBytes);
    final made = signature.created == null ? null : DateTime.fromMillisecondsSinceEpoch(signature.created! * 1000, isUtc: true);

    PgpCertificate? certificate;
    PgpKeyEntry? entry;
    for (final candidate in certificates) {
      entry = candidate.issuerOf(signature);
      if (entry != null) {
        certificate = candidate;
        break;
      }
    }
    SignatureResult result(
      SignatureVerdict verdict, {
      String? detail,
      bool keyExpired = false,
      bool keyExpiredSince = false,
      bool keyRevoked = false,
    }) => SignatureResult(
      verdict,
      issuer: issuer,
      signerFingerprint: certificate?.fingerprintHex,
      made: made,
      detail: detail,
      keyExpired: keyExpired,
      keyExpiredSince: keyExpiredSince,
      keyRevoked: keyRevoked,
    );

    if (signature.version == 3) return result(SignatureVerdict.unsupported, detail: 'version 3 signatures');
    if (signature.type != signatureBinary && signature.type != signatureText) {
      return result(SignatureVerdict.unsupported, detail: 'signature type 0x${signature.type.toRadixString(16).padLeft(2, '0')}');
    }
    // A one-pass packet that promised another hash or type than the
    // signature has hashed the wrong thing
    if (signature.type != type || signature.hashAlgorithm != hashAlgorithm) return result(SignatureVerdict.bad);
    if (const {hashMd5, hashSha1, hashRipemd160}.contains(signature.hashAlgorithm)) {
      return result(SignatureVerdict.weakHash, detail: hashName(signature.hashAlgorithm));
    }
    final hasher = _hasher;
    if (hasher == null) return result(SignatureVerdict.unsupported, detail: hashName(signature.hashAlgorithm));
    if (certificate == null || entry == null) return result(SignatureVerdict.unknownSigner);

    final key = entry.packet;
    final checkable = switch (key.algorithm) {
      1 || 3 || 27 || 30 => true,
      22 => key.name == 'ed25519',
      19 => key.name == 'nistp256' || key.name == 'nistp384',
      _ => false,
    };
    if (!checkable) return result(SignatureVerdict.unsupported, detail: key.name);

    final digest = hasher.finish(signatureTrailer(signature));
    bool matches;
    try {
      matches = await verifyDigest(signature, key, digest);
    } on KeyFormatException {
      matches = false;
    }
    if (!matches || made == null || signature.unknownCritical) return result(SignatureVerdict.bad);
    if (!await certificate.mayVerify(entry)) return result(SignatureVerdict.bad);
    final expiry = signature.signatureExpiry ?? 0;
    if (expiry != 0 && !now.isBefore(made.add(Duration(seconds: expiry)))) return result(SignatureVerdict.bad);
    // A modulus this small can be factored, and its factors sign anything
    final rsaBits = rsaModulusBits(key);
    if (rsaBits != null && rsaBits < minRsaSignatureBits) return result(SignatureVerdict.weakKey, detail: 'RSA $rsaBits');

    bool expiredAt(PgpKeyEntry k, DateTime when) => k.info.expires != null && !when.isBefore(k.info.expires!);
    final expiredWhenMade = expiredAt(entry, made) || expiredAt(certificate.primary, made);
    return result(
      SignatureVerdict.good,
      keyExpired: expiredWhenMade,
      // Made in time, but whoever holds the key now can date a signature so
      keyExpiredSince: !expiredWhenMade && (expiredAt(entry, now) || expiredAt(certificate.primary, now)),
      keyRevoked: entry.info.revoked || certificate.primary.info.revoked,
    );
  }
}

/// The salt a signature by [signer] hashes first: 32 fresh bytes, as
/// SHA-512 asks, for a version 6 key; null for any other.
Uint8List? signatureSaltFor(KeyPacket signer) => signer.version == 6 ? randomBytes(signatureSaltLength(hashSha512)) : null;

/// The body of a SHA-512 signature packet of [type] by [signer], whose
/// secret part is [secret], over what [hasher] was fed, made at [time]:
/// the issuer fingerprint and creation time hashed; version 4 with the
/// issuer key ID unhashed, as `makeSignature` writes for keys, or for a
/// version 6 signer version 6, whose [salt] [hasher] took first.
Future<Uint8List> signData({
  required SignatureHasher hasher,
  required int type,
  required KeyPacket signer,
  required PgpSecret secret,
  required DateTime time,
  Uint8List? salt,
}) async {
  if (hasher.hashAlgorithm != hashSha512) throw ArgumentError('signatures are made with SHA-512');
  if ((signer.version == 6) != (salt != null)) throw ArgumentError('a version 6 signature, and only one, takes a salt');
  final seconds = time.millisecondsSinceEpoch ~/ 1000;
  final hashedPart = signatureHashedPart(
    type: type,
    signer: signer,
    hashed: [
      ...subpacket(33, [signer.version, ...signer.fingerprint]),
      ...subpacket(2, [(seconds >>> 24) & 0xff, (seconds >>> 16) & 0xff, (seconds >>> 8) & 0xff, seconds & 0xff]),
    ],
  );
  final digest = hasher.finish(signatureTrailerOf(hashedPart));
  return finishSignature(
    hashedPart: hashedPart,
    signer: signer,
    digest: digest,
    salt: salt,
    sign: switch (secret) {
      // Ed25519 (27) signs with the 64 bytes, EdDSA (22) with two MPIs
      Ed25519Secret(:final seed) when signer.algorithm == 27 => (d) async {
        final algorithm = c.Ed25519();
        return (await algorithm.sign(d, keyPair: await algorithm.newKeyPairFromSeed(seed))).bytes;
      },
      Ed25519Secret(:final seed) => (d) => signEdDsa(seed, d),
      RsaSecret(:final material) => (d) async => signRsa(material, d),
      MlDsaEd25519Secret(:final ed25519Seed, :final mlDsaSecretKey) => (d) => signComposite(ed25519Seed, mlDsaSecretKey, d),
      X25519Secret() || MlKemX25519Secret() || KyberSecret() => throw PgpException(PgpProblem.unsupported, detail: signer.name),
      DelegatedSecret(:final sign) => (d) => sign(signer, Uint8List.fromList(d)),
      _ => throw PgpException(PgpProblem.unsupported, detail: signer.name),
    },
  );
}

/// The body of the one-pass signature packet that announces a signature
/// of [type] with SHA-512 by [signer]: version 3 with its key ID, or for a
/// version 6 signer version 6, with the signature's [salt] and the key's
/// fingerprint.
Uint8List onePassSignature(int type, KeyPacket signer, {Uint8List? salt}) => signer.version == 6
    ? Uint8List.fromList([6, type, hashSha512, signer.algorithm, salt!.length, ...salt, ...signer.fingerprint, 1])
    : Uint8List.fromList([3, type, hashSha512, signer.algorithm, ...signer.keyId, 1]);
