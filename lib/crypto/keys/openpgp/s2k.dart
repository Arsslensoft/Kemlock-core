// String-to-key specifiers (RFC 9580 section 3.7): turning a passphrase
// into a key with Simple, Salted, or Iterated and Salted S2K over the SHA
// hashes, or Argon2id, which only [deriveArgon2] runs, since it is
// asynchronous and its memory is capped. GnuPG's extension (type 101)
// marks a key whose secret is elsewhere, or (mode 1003) in gpg-agent's own
// form after it.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart' as c;
import 'package:cryptography/dart.dart' as cd;

import 'pgp_error.dart';
import 'stream.dart';

const hashMd5 = 1;
const hashSha1 = 2;
const hashRipemd160 = 3;
const hashSha256 = 8;
const hashSha384 = 9;
const hashSha512 = 10;
const hashSha224 = 11;
const hashSha3_256 = 12;
const hashSha3_512 = 14;

const _hashNames = {
  1: 'MD5',
  2: 'SHA-1',
  3: 'RIPEMD-160',
  8: 'SHA-256',
  9: 'SHA-384',
  10: 'SHA-512',
  11: 'SHA-224',
  12: 'SHA3-256',
  14: 'SHA3-512',
};

/// The usual name of the hash algorithm [id].
String hashName(int id) => _hashNames[id] ?? 'hash $id';

/// The SHA-1 or SHA-2 hash with [id], which hashes in pieces; null for any
/// other.
hash.Hash? shaHash(int id) => switch (id) {
  hashSha1 => hash.sha1,
  hashSha256 => hash.sha256,
  hashSha384 => hash.sha384,
  hashSha512 => hash.sha512,
  hashSha224 => hash.sha224,
  _ => null,
};

/// An S2K specifier.
class S2k {
  const S2k._(this.type, this.hashAlgorithm, this.salt, this.codedCount, {this.gnuMode, this.argon2Parameters}) : byteCount = null;

  /// Iterated and Salted, as Kemlock writes it.
  S2k.iterated(this.hashAlgorithm, Uint8List this.salt, int this.codedCount)
    : type = iteratedSalted,
      gnuMode = null,
      argon2Parameters = null,
      byteCount = null;

  /// Iterated and Salted with a plain [byteCount] of bytes hashed rather
  /// than a coded one, as gpg-agent counts them in the keys it keeps and an
  /// OpenPGP card's KDF object gives it. Kemlock writes it only in a
  /// gpg-agent key.
  S2k.counted(this.hashAlgorithm, Uint8List this.salt, int this.byteCount)
    : type = iteratedSalted,
      codedCount = null,
      gnuMode = null,
      argon2Parameters = null;

  /// Reads a specifier. Throws [PgpProblem.unsupported] for a type that
  /// is none of the five below.
  factory S2k.read(PgpReader r) {
    final type = r.byte();
    switch (type) {
      case simple:
        return S2k._(type, r.byte(), null, null);
      case salted:
        return S2k._(type, r.byte(), r.bytes(8), null);
      case iteratedSalted:
        return S2k._(type, r.byte(), r.bytes(8), r.byte());
      case argon2:
        // A 16-byte salt, then t, p and the memory exponent
        final salt = r.bytes(16);
        final parameters = r.bytes(3);
        return S2k._(
          type,
          0,
          salt,
          null,
          argon2Parameters: (passes: parameters[0], parallelism: parameters[1], memoryExponent: parameters[2]),
        );
      case gnu:
        final hashAlgorithm = r.byte();
        // "GNU" and the mode: 1 for no secret, 2 for a card, 3 for the
        // agent's own form of the key after it
        final mode = r.bytes(4);
        return S2k._(type, hashAlgorithm, null, null, gnuMode: 1000 + mode[3]);
      default:
        throw PgpException(PgpProblem.unsupported, detail: 'S2K type $type');
    }
  }

  static const simple = 0;
  static const salted = 1;
  static const iteratedSalted = 3;
  static const argon2 = 4;

  /// GnuPG's extension: no secret here (`gnu-dummy`), or on a card.
  static const gnu = 101;

  final int type;
  final int hashAlgorithm;
  final Uint8List? salt;

  /// The count octet of Iterated and Salted S2K.
  final int? codedCount;

  /// The bytes Iterated and Salted S2K hashes, when given as a number.
  final int? byteCount;

  /// The mode of GnuPG's extension: 1001 (no secret), 1002 (on a card),
  /// 1003 (the agent's form follows).
  final int? gnuMode;

  /// Argon2's parameters: the passes t, the parallelism p, and the memory
  /// as an exponent of two KiB.
  final ({int passes, int parallelism, int memoryExponent})? argon2Parameters;

  /// The specifier's bytes, for the types Kemlock writes.
  Uint8List get encoded => Uint8List.fromList([type, hashAlgorithm, ...?salt, ?codedCount]);

  /// The name of what this app does not read, or null when it reads it.
  String? get unsupportedName {
    if (type == argon2) return 'Argon2';
    if (type == gnu) return null;
    return shaHash(hashAlgorithm) == null ? hashName(hashAlgorithm) : null;
  }

  /// The key of [length] bytes that [passphrase] gives. Throws
  /// [PgpProblem.unsupported] for Argon2 and for a hash other than SHA-1
  /// and SHA-2.
  Uint8List derive(List<int> passphrase, int length) {
    final name = unsupportedName;
    if (name != null || type == gnu) throw PgpException(PgpProblem.unsupported, detail: name ?? 'S2K type $type');
    final digest = shaHash(hashAlgorithm)!;
    final unit = Uint8List.fromList([...?salt, ...passphrase]);
    var total = unit.length;
    if (type == iteratedSalted) {
      final count = byteCount ?? (16 + (codedCount! & 15)) << ((codedCount! >> 4) + 6);
      if (count > total) total = count;
    }
    // About 64 KB of the repeated salt and passphrase, hashed over and over
    final repeats = unit.isEmpty || 65536 ~/ unit.length < 1 ? 1 : 65536 ~/ unit.length;
    final piece = Uint8List(unit.length * repeats);
    for (var i = 0; i < piece.length; i++) {
      piece[i] = unit[i % unit.length];
    }
    final out = BytesBuilder();
    // A key longer than one digest takes more passes, each over one more
    // zero byte in front
    for (var pass = 0; out.length < length; pass++) {
      final sink = _DigestSink();
      final input = digest.startChunkedConversion(sink);
      if (pass > 0) input.add(Uint8List(pass));
      var left = total;
      while (left > 0) {
        final n = left < piece.length ? left : piece.length;
        input.add(Uint8List.sublistView(piece, 0, n));
        left -= n;
      }
      input.close();
      out.add(sink.digest!.bytes);
    }
    return Uint8List.sublistView(out.takeBytes(), 0, length);
  }
}

/// The most memory an Argon2 S2K may ask for: 256 MiB, as 2^18 KiB.
/// RFC 9580's smaller recommended setting asks for 64 MiB; its larger, 2
/// GiB, is more than a phone gives, and a key protected with it is refused
/// by name rather than let take the app down.
const maxArgon2MemoryExponent = 18;

/// The key of [length] bytes that the Argon2 [s2k] (RFC 9580 section
/// 3.7.1.4, Argon2id) gives for [passphrase]. Throws
/// [PgpProblem.unsupported] naming the setting when it asks for more
/// memory than [maxArgon2MemoryExponent], or for parameters RFC 9106 does
/// not allow.
Future<Uint8List> deriveArgon2(S2k s2k, List<int> passphrase, int length) async {
  final parameters = s2k.argon2Parameters;
  if (parameters == null) throw ArgumentError.value(s2k.type, 's2k', 'is not Argon2');
  final (:passes, :parallelism, :memoryExponent) = parameters;
  if (memoryExponent > maxArgon2MemoryExponent) {
    throw PgpException(PgpProblem.unsupported, detail: 'Argon2 with ${_memoryName(memoryExponent)}');
  }
  // RFC 9106: t >= 1, p >= 1, and at least 8p KiB
  pgpCheck(passes >= 1 && parallelism >= 1 && (1 << memoryExponent) >= 8 * parallelism, 'Argon2 parameters');
  final argon = cd.DartArgon2id(parallelism: parallelism, memory: 1 << memoryExponent, iterations: passes, hashLength: length);
  final key = await argon.deriveKey(secretKey: c.SecretKey(passphrase), nonce: s2k.salt!);
  return Uint8List.fromList(await key.extractBytes());
}

/// 2^[exponent] KiB in words: `4 GiB`, `512 MiB`.
String _memoryName(int exponent) => exponent >= 20 ? '${1 << (exponent - 20)} GiB' : '${1 << (exponent - 10)} MiB';

/// Iterated and Salted S2K (RFC 9580 section 3.7.1.3): salt and passphrase
/// hashed over and over up to the count [coded] stands for, and at least
/// once, with SHA-256 unless [hashAlgorithm] says SHA-512, into [length]
/// bytes. A key's export uses it as it always did.
Uint8List iteratedSaltedS2k(List<int> passphrase, List<int> salt, int coded, {int hashAlgorithm = hashSha256, int length = 32}) =>
    S2k.iterated(hashAlgorithm, Uint8List.fromList(salt), coded).derive(passphrase, length);

/// [iteratedSaltedS2k] with a plain [count] of bytes, as an OpenPGP card's
/// KDF object gives it (openspec: add-openpgp-card, design decision 9):
/// the whole digest of [hashAlgorithm] by default.
Uint8List iteratedSaltedS2kCount(List<int> passphrase, List<int> salt, int count, {int hashAlgorithm = hashSha256, int? length}) =>
    S2k.counted(hashAlgorithm, Uint8List.fromList(salt), count).derive(passphrase, length ?? (hashAlgorithm == hashSha512 ? 64 : 32));

class _DigestSink implements Sink<hash.Digest> {
  hash.Digest? digest;

  @override
  void add(hash.Digest data) => digest = data;

  @override
  void close() {}
}
