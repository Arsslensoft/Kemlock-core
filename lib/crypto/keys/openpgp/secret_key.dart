// The secret part of a key packet (RFC 9580 sections 5.5.3 and 5.5.5):
// parsing the material the private operation needs, and unlocking a
// packet that a passphrase protects. Nothing here writes: the stored key
// stays as it was given.
//
// This is the one place a private key is taken out of its packet. A later
// change that keeps the key elsewhere (an OpenPGP card) gives the message
// code another [PgpSecret] in place of what [unlockSecretKey] returns.
//
// Post-quantum keys: RFC 9980's ML-DSA-65+Ed25519 (30) and
// ML-KEM-768+X25519 (35) keep their two seeds; LibrePGP's Kyber (8) keeps
// the ECC secret and the expanded ML-KEM key, in a version 5 packet,
// either as LibrePGP lays them out or, as GnuPG 2.5 exports them, in
// gpg-agent's own form (`agent_key.dart`). The Argon2 S2K, which is
// asynchronous, is opened by [unlockSecretKeyAsync] only.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../ml_dsa.dart';
import '../../ml_kem.dart';
import '../algorithms.dart';
import '../der.dart';
import 'agent_key.dart';
import 'key_info.dart';
import 'modes.dart';
import 'pgp_error.dart';
import 's2k.dart';
import 'stream.dart';
import 'writer.dart' show cfb;

/// What the private operation of a key needs: one of the kinds below. It
/// is not sealed, so that code written before [DelegatedSecret] still
/// switches over the three kinds a packet holds.
abstract class PgpSecret {
  const PgpSecret();
}

/// RSA (algorithms 1, 2 and 3): the CRT values.
final class RsaSecret extends PgpSecret {
  const RsaSecret(this.material);

  final RsaMaterial material;
}

/// EdDSA on Ed25519 (22) and Ed25519 (27): the 32-byte seed.
final class Ed25519Secret extends PgpSecret {
  const Ed25519Secret(this.seed);

  final Uint8List seed;
}

/// ECDH on Curve25519 (18) and X25519 (25): the secret key in X25519's own
/// byte order. Algorithm 18 stores it reversed; it is turned here.
final class X25519Secret extends PgpSecret {
  const X25519Secret(this.secret);

  final Uint8List secret;
}

/// ML-DSA-65+Ed25519 (30): the Ed25519 seed and the 32-byte ML-DSA-65
/// seed, from which the expanded ML-DSA key is made again.
final class MlDsaEd25519Secret extends PgpSecret {
  MlDsaEd25519Secret(this.ed25519Seed, this.mlDsaSeed);

  final Uint8List ed25519Seed;
  final Uint8List mlDsaSeed;

  /// The expanded ML-DSA-65 secret key the seed gives.
  late final Uint8List mlDsaSecretKey = MlDsa65.keygen(mlDsaSeed).secretKey;
}

/// ML-KEM-768+X25519 (35): the X25519 secret in its own byte order and the
/// 64-byte ML-KEM-768 seed d || z.
final class MlKemX25519Secret extends PgpSecret {
  MlKemX25519Secret(this.x25519, this.mlKemSeed);

  final Uint8List x25519;
  final Uint8List mlKemSeed;

  /// The expanded ML-KEM-768 decapsulation key the seed gives.
  late final Uint8List mlKemSecretKey = MlKem768.keygen(mlKemSeed).secretKey;
}

/// LibrePGP's Kyber (8): the ECC secret, X25519's in its own byte order or
/// a brainpool scalar big-endian, and the expanded ML-KEM decapsulation
/// key of 2400 (Kyber-768) or 3168 (Kyber-1024) bytes.
final class KyberSecret extends PgpSecret {
  const KyberSecret(this.ecc, this.mlKemSecretKey);

  final Uint8List ecc;
  final Uint8List mlKemSecretKey;
}

/// The size of a curve's scalar, for the Kyber keys that are used.
int? _kyberScalarLength(String name) => switch (name) {
  'ky768_cv25519' || 'ky768_bp256' => 32,
  'ky1024_bp384' => 48,
  _ => null,
};

/// A key whose private step happens elsewhere, as on a security key's
/// OpenPGP card (openspec: add-openpgp-card, design decision 6): the
/// message code hands it the step and goes on with what comes back.
final class DelegatedSecret extends PgpSecret {
  const DelegatedSecret({required this.sign, required this.decipher});

  /// The signature MPIs of [key] over the SHA-512 [digest].
  final Future<Uint8List> Function(KeyPacket key, Uint8List digest) sign;

  /// The private half of opening a session key to [key]: for RSA the
  /// session key's encoding from the cryptogram [input], its padding off;
  /// for ECDH the shared secret from the ephemeral point [input], as the
  /// PKESK carries it.
  final Future<Uint8List> Function(KeyPacket key, Uint8List input) decipher;
}

/// Whether [key] is a secret key packet whose secret is on an OpenPGP
/// card: GnuPG's stub with S2K mode 2, "divert to card".
bool isCardStub(KeyPacket key) {
  final usage = key.s2kUsage;
  if (usage != 254 && usage != 255) return false;
  final rest = Uint8List.sublistView(key.packet.body, key.publicBody.length);
  return rest.length >= 8 && rest[2] == S2k.gnu && rest[4] == 0x47 && rest[5] == 0x4e && rest[6] == 0x55 && rest[7] == 0x02;
}

/// The secret of [key] for the private operation, decided in this one
/// place: [elsewhere] for a key whose secret is on a card, when it is
/// given, and otherwise the secret in the packet, unlocked with
/// [passphrase] as [unlockSecretKeyAsync] does it, Argon2 included
/// (openspec: add-post-quantum-pgp).
Future<PgpSecret> secretOf(KeyPacket key, {String? passphrase, DelegatedSecret? elsewhere}) async {
  if (elsewhere != null && isCardStub(key)) return elsewhere;
  return unlockSecretKeyAsync(key, passphrase: passphrase);
}

/// Parses [plain], the unprotected secret material of [key] without any
/// checksum. Throws [PgpProblem.unsupported], naming the algorithm as
/// GnuPG does (`nistp256`, `ed448`, `dsa2048`), for a key this app cannot
/// use, and [PgpProblem.damaged] for material that does not fit the
/// public part.
PgpSecret parseSecretMaterial(KeyPacket key, Uint8List plain) {
  final r = PgpReader.bytes(plain);
  Uint8List mpi() => r.bytes((r.uint16() + 7) >> 3);
  Uint8List fixed(Uint8List value, int length) {
    pgpCheck(value.length <= length, 'secret key: too long');
    return Uint8List(length)..setAll(length - value.length, value);
  }

  final PgpSecret secret;
  switch (key.algorithm) {
    case 1 || 2 || 3:
      final public = PgpReader.bytes(key.publicMaterial);
      final n = bytesToBigInt(public.bytes((public.uint16() + 7) >> 3));
      final e = bytesToBigInt(public.bytes((public.uint16() + 7) >> 3));
      final d = bytesToBigInt(mpi());
      final p = bytesToBigInt(mpi());
      final q = bytesToBigInt(mpi());
      mpi(); // u, the inverse of p modulo q: worked out again
      secret = RsaSecret(asPgpError(() => RsaMaterial.fromPrimes(n: n, e: e, d: d, p: p, q: q)));
    case 22 when key.name == 'ed25519':
      secret = Ed25519Secret(fixed(mpi(), 32));
    case 18 when key.name == 'cv25519':
      secret = X25519Secret(Uint8List.fromList(fixed(mpi(), 32).reversed.toList()));
    case 25:
      secret = X25519Secret(Uint8List.fromList(r.bytes(32)));
    case 27:
      secret = Ed25519Secret(Uint8List.fromList(r.bytes(32)));
    case 30:
      secret = MlDsaEd25519Secret(Uint8List.fromList(r.bytes(32)), Uint8List.fromList(r.bytes(MlDsa65.seedLength)));
    case 35:
      secret = MlKemX25519Secret(Uint8List.fromList(r.bytes(32)), Uint8List.fromList(r.bytes(64)));
    case 8 when _kyberScalarLength(key.name) != null:
      // An MPI of the ECC secret, then the ML-KEM key with a 4-byte count;
      // X25519's is stored reversed, as for algorithm 18
      final ecc = fixed(mpi(), _kyberScalarLength(key.name)!);
      final mlKem = r.bytes(r.uint32());
      secret = _kyberSecret(key, key.name == 'ky768_cv25519' ? Uint8List.fromList(ecc.reversed.toList()) : ecc, mlKem);
    default:
      throw PgpException(PgpProblem.unsupported, detail: key.name);
  }
  pgpCheck(r.atEnd, 'secret key: bytes left over');
  return secret;
}

/// A [KyberSecret] whose ML-KEM key has the size the public key has.
KyberSecret _kyberSecret(KeyPacket key, Uint8List ecc, Uint8List mlKem) {
  final expected = key.name.startsWith('ky1024') ? MlKem1024.secretKeyLength : MlKem768.secretKeyLength;
  pgpCheck(mlKem.length == expected, 'secret key: ML-KEM key length');
  return KyberSecret(Uint8List.fromList(ecc), Uint8List.fromList(mlKem));
}

/// The Kyber secret of a GnuPG agent key, its ECC secret in the byte order
/// [KyberSecret] keeps: the agent keeps X25519's as GnuPG's packets do.
KyberSecret _fromAgent(KeyPacket key, AgentKyberKey agent) {
  final length = _kyberScalarLength(key.name);
  if (length == null) throw PgpException(PgpProblem.unsupported, detail: key.name);
  var d = agent.eccSecret;
  // An MPI-like value: a leading zero may be there or dropped
  if (d.length == length + 1 && d[0] == 0) d = Uint8List.sublistView(d, 1);
  pgpCheck(d.length <= length, 'secret key: ECC secret length');
  final padded = Uint8List(length)..setAll(length - d.length, d);
  final ecc = key.name == 'ky768_cv25519' ? Uint8List.fromList(padded.reversed.toList()) : padded;
  return _kyberSecret(key, ecc, agent.mlKemSecret);
}

/// The secret material of the secret key packet [key], unlocked with
/// [passphrase] when it is protected.
///
/// Read: no protection; S2K usage 254 (CFB with a SHA-1 check), 255 and a
/// bare cipher octet (CFB with a checksum), and 253 (AEAD); AES-128, 192
/// and 256; Simple, Salted, and Iterated and Salted S2K over SHA-1 and
/// SHA-2; GnuPG's agent form of a Kyber key (S2K mode 1003).
///
/// Throws [PgpProblem.noSecretHere] for a GnuPG stub or a public key
/// packet, [PgpProblem.unsupported] with the name for Argon2 (which only
/// [unlockSecretKeyAsync] opens), an old cipher or an algorithm this app
/// does not use, [PgpProblem.passphraseNeeded] when it is protected and
/// [passphrase] is null, and [PgpProblem.wrongPassphrase] when the check
/// inside does not come out.
PgpSecret unlockSecretKey(KeyPacket key, {String? passphrase}) => _unlock(key, passphrase: passphrase);

/// [unlockSecretKey], and the Argon2 S2K besides, with its memory capped at
/// [maxArgon2MemoryExponent]: a key that asks for more is refused by name.
Future<PgpSecret> unlockSecretKeyAsync(KeyPacket key, {String? passphrase}) async {
  final protection = _protection(key);
  final s2k = protection?.s2k;
  if (s2k == null || s2k.type != S2k.argon2) return _unlock(key, passphrase: passphrase);
  checkSecretKeyKind(key);
  if (passphrase == null) throw const PgpException(PgpProblem.passphraseNeeded);
  final derived = await deriveArgon2(s2k, utf8.encode(passphrase), cipherKeyLength(protection!.cipher));
  return _unlock(key, passphrase: passphrase, argon2Key: derived);
}

/// How a secret key packet is protected, read up to its IV or nonce.
class _Protection {
  _Protection(this.usage, this.cipher, this.aead, this.s2k, this.reader);

  final int usage;
  final int cipher;
  final int? aead;
  final S2k? s2k;

  /// Positioned after the S2K specifier.
  final PgpReader reader;
}

/// The protection of [key]; null when it is not protected. Throws
/// [PgpProblem.noSecretHere] for a public key packet.
_Protection? _protection(KeyPacket key) {
  final usage = key.s2kUsage;
  if (usage == null) throw const PgpException(PgpProblem.noSecretHere);
  if (usage == 0) return null;
  final body = key.packet.body;
  final r = PgpReader.bytes(Uint8List.sublistView(body, key.publicBody.length + 1));
  final v6 = key.version == 6;
  // v5 and v6 count the fields up to the secret material
  if (key.version != 4) r.byte();
  final int cipher;
  int? aead;
  S2k? s2k;
  if (usage == 253 || usage == 254 || usage == 255) {
    cipher = r.byte();
    if (usage == 253) aead = r.byte();
    s2k = v6 && usage != 255 ? S2k.read(PgpReader.bytes(r.bytes(r.byte()))) : S2k.read(r);
  } else {
    // A bare cipher octet: the key is the MD5 of the passphrase
    cipher = usage;
  }
  return _Protection(usage, cipher, aead, s2k, r);
}

PgpSecret _unlock(KeyPacket key, {String? passphrase, Uint8List? argon2Key}) {
  final protection = _protection(key);
  if (protection == null) return parseSecretMaterial(key, key.plainSecret!);
  final KeyPacket(:packet) = key;
  final body = packet.body;
  final _Protection(:usage, :cipher, :aead, :s2k, reader: r) = protection;
  if (s2k != null && s2k.type == S2k.gnu) {
    final agent = key.agentKey;
    if (s2k.gnuMode != 1003 || agent == null) throw const PgpException(PgpProblem.noSecretHere);
    return _fromAgent(key, readAgentKyberKey(agent, passphrase: passphrase == null ? null : utf8.encode(passphrase)));
  }
  // What it is protected with is named before any passphrase is asked for
  final name = s2k?.unsupportedName;
  if (name != null && !(s2k!.type == S2k.argon2 && argon2Key != null)) throw PgpException(PgpProblem.unsupported, detail: name);
  final keyLength = cipherKeyLength(cipher);
  final Aead? mode = aead == null ? null : Aead(aead, Uint8List(keyLength));
  checkSecretKeyKind(key);
  if (passphrase == null) throw const PgpException(PgpProblem.passphraseNeeded);

  final secretBytes = utf8.encode(passphrase);
  final Uint8List derived;
  if (argon2Key != null) {
    derived = argon2Key;
  } else if (s2k != null) {
    derived = s2k.derive(secretBytes, keyLength);
  } else {
    if (keyLength != 16) throw const PgpException(PgpProblem.unsupported, detail: 'MD5');
    derived = Uint8List.fromList(hash.md5.convert(secretBytes).bytes);
  }
  const wrong = PgpException(PgpProblem.wrongPassphrase);
  final Uint8List plain;
  if (mode != null) {
    final nonce = r.bytes(mode.nonceLength);
    if (key.version == 5) r.uint32(); // the count of the secret material
    final typeOctet = 0xc0 | packet.tag;
    final kek = hkdfSha256(derived, info: [typeOctet, key.version, cipher, aead!], length: keyLength);
    final opened = Aead(aead, kek).open(nonce, r.rest(max: body.length), Uint8List.fromList([typeOctet, ...key.publicBody]));
    if (opened == null) throw wrong;
    plain = opened;
  } else {
    final iv = r.bytes(16);
    if (key.version == 5) r.uint32(); // the count of the secret material
    final decrypted = cfb(false, derived, iv, r.rest(max: body.length));
    if (usage == 254) {
      if (decrypted.length < 20) throw wrong;
      plain = Uint8List.sublistView(decrypted, 0, decrypted.length - 20);
      final digest = hash.sha1.convert(plain).bytes;
      var diff = 0;
      for (var i = 0; i < 20; i++) {
        diff |= digest[i] ^ decrypted[plain.length + i];
      }
      if (diff != 0) throw wrong;
    } else {
      if (decrypted.length < 2) throw wrong;
      plain = Uint8List.sublistView(decrypted, 0, decrypted.length - 2);
      var sum = 0;
      for (final b in plain) {
        sum = (sum + b) & 0xffff;
      }
      if (sum != ((decrypted[plain.length] << 8) | decrypted[plain.length + 1])) throw wrong;
    }
  }
  try {
    return parseSecretMaterial(key, plain);
  } on PgpException catch (e) {
    // What passed the check and still does not parse was a lucky checksum
    if (e.problem == PgpProblem.damaged && usage != 253 && usage != 254) throw wrong;
    rethrow;
  }
}

/// Throws [PgpProblem.unsupported], naming the algorithm, when [key] is
/// of a kind [parseSecretMaterial] does not read: said before a
/// passphrase is asked for.
void checkSecretKeyKind(KeyPacket key) {
  final known = switch (key.algorithm) {
    1 || 2 || 3 || 25 || 27 || 30 || 35 => true,
    22 => key.name == 'ed25519',
    18 => key.name == 'cv25519',
    8 => _kyberScalarLength(key.name) != null,
    _ => false,
  };
  if (!known) throw PgpException(PgpProblem.unsupported, detail: key.name);
}

/// Whether [key] is a secret key packet whose secret needs a passphrase:
/// protected, and not a stub.
bool needsPassphrase(KeyPacket key) {
  final usage = key.s2kUsage;
  if (usage == null || usage == 0) return false;
  try {
    unlockSecretKey(key);
    return false;
  } on PgpException catch (e) {
    return e.problem == PgpProblem.passphraseNeeded;
  }
}
