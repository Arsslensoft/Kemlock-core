// The packets that carry a message's session key (RFC 9580 sections 5.1
// and 5.3): to a public key (PKESK versions 3 and 6) and to a passphrase
// (SKESK versions 4 and 6, and GnuPG's version 5). Both are read; PKESK 3
// and 6 and SKESK 4 are written, with their randomness passed in. The
// post-quantum keys take their session keys through `pq_kem.dart`: RFC
// 9980's ML-KEM-768+X25519 (35) in PKESK 3 and 6, LibrePGP's Kyber (8) in
// PKESK 3.

import 'dart:typed_data';

import '../der.dart';
import 'ecdh.dart';
import 'key_info.dart';
import 'modes.dart';
import 'packets.dart';
import 'pgp_error.dart';
import 'pq_kem.dart';
import 'rsa.dart';
import 's2k.dart';
import 'secret_key.dart';
import 'stream.dart';
import 'writer.dart' show cfb;

/// A session key, and the cipher it is for when the packet that carried it
/// says (version 6 packets leave that to the encrypted data).
class SessionKey {
  const SessionKey(this.cipher, this.key);

  final int? cipher;
  final Uint8List key;
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase();

// ─── To a key ─────────────────────────────────────────────────────────────────

/// A Public Key Encrypted Session Key packet.
class Pkesk {
  const Pkesk._(this.version, this.keyId, this.fingerprint, this.algorithm, this.material);

  /// 3 or 6.
  final int version;

  /// The recipient's key ID in a version 3 packet; null when it is zero
  /// (a hidden recipient).
  final Uint8List? keyId;

  /// The recipient's fingerprint in a version 6 packet; null for a hidden
  /// recipient.
  final Uint8List? fingerprint;

  final int algorithm;

  /// The algorithm's fields.
  final Uint8List material;

  /// Whether it does not say whom it is for: every key is tried.
  bool get hidden => keyId == null && fingerprint == null;

  /// The recipient's key ID in upper-case hexadecimal; null when hidden.
  String? get keyIdHex {
    if (keyId != null) return _hex(keyId!);
    final f = fingerprint;
    if (f == null) return null;
    return _hex(f.length == 20 ? f.sublist(12) : f.sublist(0, 8));
  }

  /// Whether it names [key] as its recipient.
  bool isFor(KeyPacket key) {
    if (fingerprint != null) return _same(fingerprint!, key.fingerprint);
    if (keyId != null) return _same(keyId!, key.keyId);
    return false;
  }
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/// Reads a PKESK packet's body. Throws [PgpProblem.unsupported] for a
/// version other than 3 and 6.
Pkesk parsePkesk(Uint8List body) {
  final r = PgpReader.bytes(body);
  final version = r.byte();
  if (version == 3) {
    final keyId = r.bytes(8);
    final algorithm = r.byte();
    return Pkesk._(3, keyId.every((b) => b == 0) ? null : keyId, null, algorithm, r.rest(max: body.length));
  }
  if (version == 6) {
    final length = r.byte();
    Uint8List? fingerprint;
    if (length > 0) {
      final keyVersion = r.byte();
      pgpCheck(length == (keyVersion == 4 ? 21 : 33), 'PKESK: fingerprint length');
      fingerprint = r.bytes(length - 1);
    }
    final algorithm = r.byte();
    return Pkesk._(6, null, fingerprint, algorithm, r.rest(max: body.length));
  }
  throw PgpException(PgpProblem.unsupported, detail: 'PKESK version $version');
}

const _failed = PgpException(PgpProblem.damaged, detail: 'session key');

int _checksum(List<int> bytes) {
  var sum = 0;
  for (final b in bytes) {
    sum = (sum + b) & 0xffff;
  }
  return sum;
}

/// The session key of [encoded]: with the cipher octet in front for a
/// version 3 packet, then the key, then its two-byte checksum.
SessionKey _decode(Uint8List encoded, {required bool withCipher}) {
  if (encoded.length < (withCipher ? 3 : 2) + 16) throw _failed;
  final key = Uint8List.sublistView(encoded, withCipher ? 1 : 0, encoded.length - 2);
  if (_checksum(key) != ((encoded[encoded.length - 2] << 8) | encoded[encoded.length - 1])) throw _failed;
  if (!withCipher) return SessionKey(null, Uint8List.fromList(key));
  // A cipher this app does not read is named, not called damage
  if (cipherKeyLength(encoded[0]) != key.length) throw _failed;
  return SessionKey(encoded[0], Uint8List.fromList(key));
}

/// The session key [pkesk] carries, opened with [secret], the secret part
/// of [key]. A wrong key, bad padding and a bad checksum all throw the
/// same [PgpProblem.damaged]; a key algorithm or a cipher this app does
/// not read throws [PgpProblem.unsupported] with its name.
Future<SessionKey> openPkesk(Pkesk pkesk, KeyPacket key, PgpSecret secret) async {
  final r = PgpReader.bytes(pkesk.material);
  switch ((pkesk.algorithm, secret)) {
    case (1 || 2, RsaSecret(:final material)):
      final cipher = bytesToBigInt(r.bytes((r.uint16() + 7) >> 3));
      return _decode(rsaDecryptPkcs1(material, cipher), withCipher: pkesk.version == 3);
    case (18, X25519Secret(secret: final scalar)):
      final point = r.bytes((r.uint16() + 7) >> 3);
      if (point.length != 33 || point[0] != 0x40) throw _failed;
      final wrapped = r.bytes(r.byte());
      final encoded = await ecdhUnwrap(key, scalar, Uint8List.sublistView(point, 1), wrapped);
      return _decode(encoded, withCipher: pkesk.version == 3);
    case (25, X25519Secret(secret: final scalar)):
      final ephemeral = r.bytes(32);
      var length = r.byte();
      int? cipher;
      if (pkesk.version == 3) {
        // The cipher is in the clear, counted with the wrapped key
        cipher = r.byte();
        length--;
        cipherKeyLength(cipher);
      }
      final public = Uint8List.sublistView(key.publicMaterial, 0, 32);
      return SessionKey(cipher, await x25519Unwrap(scalar, public, ephemeral, r.bytes(length)));
    case (35, final MlKemX25519Secret secret):
      // The X25519 ephemeral key, the ML-KEM ciphertext, then as for X25519
      final ephemeral = r.bytes(32);
      final cipherText = r.bytes(1088);
      var length = r.byte();
      int? cipher;
      if (pkesk.version == 3) {
        cipher = r.byte();
        length--;
        cipherKeyLength(cipher);
      }
      final kek = await mlKemX25519Decapsulate(
        public: key.publicMaterial,
        x25519Secret: secret.x25519,
        mlKemSecretKey: secret.mlKemSecretKey,
        ephemeral: ephemeral,
        mlKemCipherText: cipherText,
      );
      return SessionKey(cipher, aesKeyUnwrap(kek, r.bytes(length)));
    case (8, final KyberSecret secret) when pkesk.version == 3:
      final public = KyberPublic.of(key);
      final point = r.bytes((r.uint16() + 7) >> 3);
      if (point.length > public.curve.pointLength) throw _failed;
      final ephemeral = Uint8List(public.curve.pointLength)..setAll(public.curve.pointLength - point.length, point);
      final cipherText = r.bytes(r.uint32());
      final cipher = r.byte();
      cipherKeyLength(cipher);
      final kek = await kyberDecapsulate(
        curve: public.curve,
        eccPublic: public.point,
        eccSecret: secret.ecc,
        mlKemSecretKey: secret.mlKemSecretKey,
        ephemeral: ephemeral,
        mlKemCipherText: cipherText,
        cipher: cipher,
        fingerprint: key.fingerprint,
      );
      return SessionKey(cipher, aesKeyUnwrap(kek, r.bytes(r.byte())));
    case (1 || 2, DelegatedSecret(:final decipher)):
      final cipher = r.bytes((r.uint16() + 7) >> 3);
      return _decode(await decipher(key, cipher), withCipher: pkesk.version == 3);
    case (18, DelegatedSecret(:final decipher)):
      final point = r.bytes((r.uint16() + 7) >> 3);
      final wrapped = r.bytes(r.byte());
      final shared = await decipher(key, point);
      return _decode(await ecdhUnwrapShared(key, shared, wrapped), withCipher: pkesk.version == 3);
    default:
      throw _failed;
  }
}

/// How many random bytes [writePkesk3] and [writePkesk6] need for
/// [recipient] and a session key of [keyLength] bytes: RSA padding, an
/// X25519 secret, or for a post-quantum key an ECDH secret then the 32
/// bytes ML-KEM's encapsulation takes.
int pkeskRandomLength(KeyPacket recipient, int keyLength) => switch (recipient.algorithm) {
  1 || 2 => rsaPaddingLength(_rsaPublic(recipient).$1, keyLength + 3),
  35 => 64,
  8 => (KyberPublic.of(recipient).curve == KyberCurve.brainpoolP384r1 ? 48 : 32) + 32,
  // A NIST curve's scalar is drawn from 8 more bytes than its size
  18 => switch (EcdhPublic.of(recipient).curve) {
    final curve? => curve.size + 8,
    null => 32,
  },
  _ => 32,
};

(BigInt, BigInt) _rsaPublic(KeyPacket key) {
  final r = PgpReader.bytes(key.publicMaterial);
  final n = bytesToBigInt(r.bytes((r.uint16() + 7) >> 3));
  final e = bytesToBigInt(r.bytes((r.uint16() + 7) >> 3));
  return (n, e);
}

/// The body of a version 3 PKESK packet that carries [sessionKey] of
/// [cipher] to [recipient], an RSA or a Curve25519 ECDH key packet, with
/// the [random] bytes [pkeskRandomLength] asks for.
Future<Uint8List> writePkesk3(KeyPacket recipient, int cipher, Uint8List sessionKey, Uint8List random) async {
  final sum = _checksum(sessionKey);
  final encoded = Uint8List.fromList([cipher, ...sessionKey, sum >> 8, sum & 0xff]);
  final head = [3, ...recipient.keyId, recipient.algorithm];
  switch (recipient.algorithm) {
    case 1 || 2:
      final (n, e) = _rsaPublic(recipient);
      final c = rsaEncryptPkcs1(n, e, encoded, random);
      return Uint8List.fromList([...head, c.bitLength >> 8, c.bitLength & 0xff, ...bigIntToBytes(c)]);
    case 18:
      final (:ephemeral, :wrapped) = await ecdhWrap(recipient, encoded, random);
      if (ephemeral.length == 32) {
        // The point as an MPI: 0x40 and 32 bytes, 263 bits
        return Uint8List.fromList([...head, 0x01, 0x07, 0x40, ...ephemeral, wrapped.length, ...wrapped]);
      }
      // A NIST point, 04, x and y: its top byte has three bits
      final bits = ephemeral.length * 8 - 5;
      return Uint8List.fromList([...head, bits >> 8, bits & 0xff, ...ephemeral, wrapped.length, ...wrapped]);
    case 35:
      // As RFC 9980 section 4.3.1 lays it out: the cipher in the clear,
      // counted with the key wrapped without a checksum
      final (:kek, :eccCipherText, :mlKemCipherText) = await mlKemX25519Encapsulate(
        recipient.publicMaterial,
        ephemeralSecret: Uint8List.sublistView(random, 0, 32),
        mlKemMessage: Uint8List.sublistView(random, 32, 64),
      );
      final wrapped = aesKeyWrap(kek, sessionKey);
      return Uint8List.fromList([...head, ...eccCipherText, ...mlKemCipherText, 1 + wrapped.length, cipher, ...wrapped]);
    case 8:
      // As GnuPG 2.5 writes it: the ephemeral point as an MPI, the ML-KEM
      // ciphertext with a 4-byte count, the cipher, and the key wrapped
      // without a checksum, with its own count
      final public = KyberPublic.of(recipient);
      final scalarLength = random.length - 32;
      final (:kek, :eccCipherText, :mlKemCipherText) = await kyberEncapsulate(
        curve: public.curve,
        eccPublic: public.point,
        mlKemPublic: public.mlKem,
        cipher: cipher,
        fingerprint: recipient.fingerprint,
        ephemeralSecret: Uint8List.sublistView(random, 0, scalarLength),
        mlKemMessage: Uint8List.sublistView(random, scalarLength),
      );
      final wrapped = aesKeyWrap(kek, sessionKey);
      final n = mlKemCipherText.length;
      return Uint8List.fromList([
        ...head,
        ..._sosOf(eccCipherText),
        n >>> 24,
        (n >> 16) & 0xff,
        (n >> 8) & 0xff,
        n & 0xff,
        ...mlKemCipherText,
        cipher,
        wrapped.length,
        ...wrapped,
      ]);
    default:
      throw PgpException(PgpProblem.unsupported, detail: recipient.name);
  }
}

/// [value], all its bytes, with the 2-byte bit count GnuPG's sos_write
/// puts before it: counted from the first set bit of the first byte, or
/// every bit when that byte is zero.
List<int> _sosOf(Uint8List value) {
  var bits = value.length * 8;
  if (value.isNotEmpty && value[0] != 0) {
    for (var b = 0x80; value[0] & b == 0; b >>= 1) {
      bits--;
    }
  }
  return [bits >> 8, bits & 0xff, ...value];
}

/// The body of a version 6 PKESK packet that carries [sessionKey] to
/// [recipient], an RSA, a Curve25519 ECDH, an X25519 or an
/// ML-KEM-768+X25519 key packet, with the [random] bytes
/// [pkeskRandomLength] asks for (RFC 9580 section 5.1.2). The cipher is
/// the version 2 SEIPD packet's to say: the session key goes without it,
/// and with its checksum only where RSA and ECDH want one.
Future<Uint8List> writePkesk6(KeyPacket recipient, Uint8List sessionKey, Uint8List random) async {
  final fingerprint = recipient.fingerprint;
  final head = [6, 1 + fingerprint.length, recipient.version, ...fingerprint, recipient.algorithm];
  final sum = _checksum(sessionKey);
  switch (recipient.algorithm) {
    case 1 || 2:
      final (n, e) = _rsaPublic(recipient);
      final c = rsaEncryptPkcs1(n, e, Uint8List.fromList([...sessionKey, sum >> 8, sum & 0xff]), random);
      return Uint8List.fromList([...head, c.bitLength >> 8, c.bitLength & 0xff, ...bigIntToBytes(c)]);
    case 18:
      final encoded = Uint8List.fromList([...sessionKey, sum >> 8, sum & 0xff]);
      final (:ephemeral, :wrapped) = await ecdhWrap(recipient, encoded, random);
      if (ephemeral.length == 32) {
        return Uint8List.fromList([...head, 0x01, 0x07, 0x40, ...ephemeral, wrapped.length, ...wrapped]);
      }
      // A NIST point, as in [writePkesk3]
      final bits = ephemeral.length * 8 - 5;
      return Uint8List.fromList([...head, bits >> 8, bits & 0xff, ...ephemeral, wrapped.length, ...wrapped]);
    case 25:
      final public = Uint8List.sublistView(recipient.publicMaterial, 0, 32);
      final ephemeral = await x25519Public(random);
      final kek = x25519Kek(ephemeral, public, await x25519Shared(random, public));
      final wrapped = aesKeyWrap(kek, sessionKey);
      return Uint8List.fromList([...head, ...ephemeral, wrapped.length, ...wrapped]);
    case 35:
      final (:kek, :eccCipherText, :mlKemCipherText) = await mlKemX25519Encapsulate(
        recipient.publicMaterial,
        ephemeralSecret: Uint8List.sublistView(random, 0, 32),
        mlKemMessage: Uint8List.sublistView(random, 32, 64),
      );
      final wrapped = aesKeyWrap(kek, sessionKey);
      return Uint8List.fromList([...head, ...eccCipherText, ...mlKemCipherText, wrapped.length, ...wrapped]);
    default:
      throw PgpException(PgpProblem.unsupported, detail: recipient.name);
  }
}

// ─── To a passphrase ──────────────────────────────────────────────────────────

/// A Symmetric Key Encrypted Session Key packet.
class Skesk {
  const Skesk._(this.version, this.cipher, this.aead, this.s2k, this.iv, this.encrypted);

  /// 4, 5 (GnuPG's OCB form) or 6.
  final int version;
  final int cipher;

  /// The AEAD mode of a version 5 or 6 packet.
  final int? aead;
  final S2k s2k;
  final Uint8List? iv;

  /// The encrypted session key, with its tag in versions 5 and 6; null
  /// when the passphrase's key is the session key.
  final Uint8List? encrypted;

  /// The name of what this app does not read in it (`Argon2`, `CAST5`),
  /// or null.
  String? get unsupportedName {
    final s2kName = s2k.type == S2k.gnu ? 'S2K type 101' : s2k.unsupportedName;
    if (s2kName != null) return s2kName;
    if (cipher != cipherAes128 && cipher != cipherAes192 && cipher != cipherAes256) return cipherName(cipher);
    if (aead != null && aead != aeadEax && aead != aeadOcb && aead != aeadGcm) return aeadName(aead!);
    return null;
  }
}

/// Reads an SKESK packet's body. Throws [PgpProblem.unsupported] for a
/// version other than 4, 5 and 6 and for an S2K type it cannot read past.
Skesk parseSkesk(Uint8List body) {
  final r = PgpReader.bytes(body);
  final version = r.byte();
  Uint8List? rest() {
    final bytes = r.rest(max: body.length);
    return bytes.isEmpty ? null : bytes;
  }

  int nonceLength(int aead) => switch (aead) {
    aeadEax => 16,
    aeadOcb => 15,
    aeadGcm => 12,
    _ => throw PgpException(PgpProblem.unsupported, detail: aeadName(aead)),
  };

  switch (version) {
    case 4:
      final cipher = r.byte();
      return Skesk._(4, cipher, null, S2k.read(r), null, rest());
    case 5:
      final cipher = r.byte();
      final aead = r.byte();
      final s2k = S2k.read(r);
      return Skesk._(5, cipher, aead, s2k, r.bytes(nonceLength(aead)), rest());
    case 6:
      r.byte(); // the count of what follows, through the IV
      final cipher = r.byte();
      final aead = r.byte();
      final s2k = S2k.read(PgpReader.bytes(r.bytes(r.byte())));
      return Skesk._(6, cipher, aead, s2k, r.bytes(nonceLength(aead)), rest());
    default:
      throw PgpException(PgpProblem.unsupported, detail: 'SKESK version $version');
  }
}

/// The session key [skesk] gives for [passphrase]. Throws
/// [PgpProblem.unsupported], with the name, for a method or cipher this
/// app does not read, and [PgpProblem.wrongPassphrase] when the packet
/// itself shows the passphrase is wrong. A version 4 packet with no
/// encrypted key cannot show it: there the data's own check has to.
SessionKey openSkesk(Skesk skesk, List<int> passphrase) {
  final name = skesk.unsupportedName;
  if (name != null) throw PgpException(PgpProblem.unsupported, detail: name);
  const wrong = PgpException(PgpProblem.wrongPassphrase);
  final key = skesk.s2k.derive(passphrase, cipherKeyLength(skesk.cipher));
  final encrypted = skesk.encrypted;
  switch (skesk.version) {
    case 4:
      if (encrypted == null) return SessionKey(skesk.cipher, key);
      final plain = cfb(false, key, Uint8List(16), encrypted);
      final cipher = plain[0];
      if (cipher != cipherAes128 && cipher != cipherAes192 && cipher != cipherAes256) throw wrong;
      if (plain.length - 1 != cipherKeyLength(cipher)) throw wrong;
      return SessionKey(cipher, Uint8List.sublistView(plain, 1));
    case 5:
      final ad = Uint8List.fromList([0xc0 | PgpTag.skesk, 5, skesk.cipher, skesk.aead!]);
      final plain = encrypted == null ? null : Aead(skesk.aead!, key).open(skesk.iv!, encrypted, ad);
      if (plain == null) throw wrong;
      return SessionKey(skesk.cipher, plain);
    default:
      final info = Uint8List.fromList([0xc0 | PgpTag.skesk, 6, skesk.cipher, skesk.aead!]);
      final kek = hkdfSha256(key, info: info, length: key.length);
      final plain = encrypted == null ? null : Aead(skesk.aead!, kek).open(skesk.iv!, encrypted, info);
      if (plain == null) throw wrong;
      return SessionKey(skesk.cipher, plain);
  }
}

/// The body of a version 4 SKESK packet for [cipher] and [s2k], with no
/// encrypted session key: the key [s2k] derives from the passphrase is
/// the session key.
Uint8List writeSkesk4(int cipher, S2k s2k) => Uint8List.fromList([4, cipher, ...s2k.encoded]);
