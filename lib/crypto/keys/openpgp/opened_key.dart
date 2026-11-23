// A transferable secret key with its passphrase taken off: every secret
// key packet a passphrase protects is unlocked and written again with S2K
// usage 0 (RFC 9580 section 5.5.3), the rest as it was. The mail provider
// keeps it in memory until the vault locks, so that each mail is not a
// prompt (openspec: add-pgp-mail-provider, decision 13). It is never
// stored: a job is handed it in place of the stored key and a passphrase.

import 'dart:typed_data';

import 'key_info.dart';
import 'packets.dart';
import 'pgp_error.dart';
import 'secret_key.dart';
import 'signatures.dart' show mpi, mpiOfBytes;

/// [packets], a transferable secret key's, with each protected secret key
/// packet opened by [passphrase]. A GnuPG stub and a key of a kind this app
/// does not use are left protected, as nothing here could use them.
///
/// Throws [PgpProblem.wrongPassphrase] when [passphrase] does not open a
/// packet it should, and [PgpProblem.unsupported] for what it is protected
/// with when this app does not read that (Argon2 over 256 MiB, an old
/// cipher). A post-quantum key opens too (openspec: add-post-quantum-pgp):
/// a Kyber subkey in gpg-agent's form is written in the packet's own
/// layout, which only this app reads back.
Future<Uint8List> openedTransferableKey(List<PgpPacket> packets, String passphrase) async {
  final out = BytesBuilder(copy: false);
  for (final packet in packets) {
    if (packet.tag != PgpTag.secretKey && packet.tag != PgpTag.secretSubkey) {
      out.add(packet.encoded);
      continue;
    }
    final key = parseKeyPacket(packet);
    if (key.s2kUsage == 0) {
      out.add(packet.encoded);
      continue;
    }
    final PgpSecret secret;
    try {
      secret = await unlockSecretKeyAsync(key, passphrase: passphrase);
    } on PgpException catch (e) {
      final unusable = e.problem == PgpProblem.noSecretHere || (e.problem == PgpProblem.unsupported && !_knownKind(key));
      if (!unusable) rethrow;
      out.add(packet.encoded);
      continue;
    }
    final material = _material(key, secret);
    final body = BytesBuilder(copy: false)
      ..add(key.publicBody)
      ..addByte(0);
    // Version 5 counts the material that follows
    if (key.version == 5) body.add(_be32(material.length));
    body.add(material);
    // Version 4 ends unprotected material with the sum of its octets; version 6 has no checksum
    if (key.version == 4) {
      var sum = 0;
      for (final b in material) {
        sum = (sum + b) & 0xffff;
      }
      body.add([sum >> 8, sum & 0xff]);
    }
    out.add(writePacket(packet.tag, body.toBytes(), oldFormat: packet.oldFormat));
  }
  return out.toBytes();
}

bool _knownKind(KeyPacket key) {
  try {
    checkSecretKeyKind(key);
    return true;
  } on PgpException {
    return false;
  }
}

/// The unprotected secret material of [key], as `parseSecretMaterial` reads it.
Uint8List _material(KeyPacket key, PgpSecret secret) => switch (secret) {
  // d, p, q, and u, the inverse of p modulo q
  RsaSecret(:final material) => Uint8List.fromList([
    ...mpi(material.d),
    ...mpi(material.p),
    ...mpi(material.q),
    ...mpi(material.p.modInverse(material.q)),
  ]),
  Ed25519Secret(:final seed) => key.algorithm == 27 ? Uint8List.fromList(seed) : mpiOfBytes(seed),
  // Algorithm 18 keeps the secret reversed
  X25519Secret(:final secret) => key.algorithm == 25 ? Uint8List.fromList(secret) : mpiOfBytes(secret.reversed.toList()),
  // RFC 9980's two seeds of each key
  MlDsaEd25519Secret(:final ed25519Seed, :final mlDsaSeed) => Uint8List.fromList([...ed25519Seed, ...mlDsaSeed]),
  MlKemX25519Secret(:final x25519, :final mlKemSeed) => Uint8List.fromList([...x25519, ...mlKemSeed]),
  // The ECC secret as an MPI, X25519's reversed, then the ML-KEM key with
  // a 4-byte count
  KyberSecret(:final ecc, :final mlKemSecretKey) => Uint8List.fromList([
    ...mpiOfBytes(key.name == 'ky768_cv25519' ? ecc.reversed.toList() : ecc),
    ..._be32(mlKemSecretKey.length),
    ...mlKemSecretKey,
  ]),
  // A card's DelegatedSecret (openspec: add-openpgp-card) never comes out of a packet
  _ => throw PgpException(PgpProblem.unsupported, detail: key.name),
};

List<int> _be32(int v) => [v >>> 24 & 0xff, v >>> 16 & 0xff, v >>> 8 & 0xff, v & 0xff];
