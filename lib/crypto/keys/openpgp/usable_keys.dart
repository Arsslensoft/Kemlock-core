// Which key of a transferable key may be used, and for what, at a given
// time (RFC 9580 sections 5.2.3.10, 5.2.3.29 and 10.1):
//
// - to encrypt: the newest encryption subkey that is neither expired nor
//   revoked, a post-quantum one before any classical one, else the
//   primary key if it may encrypt;
// - to sign: the primary key if it may sign, else the newest valid signing
//   subkey;
// - to verify: the key a signature names, a signing subkey only with a
//   valid back-signature;
// - to decrypt: any secret key a message names, whatever its standing.
//
// Expiry and revocation are read from the same `expires` and `revoked` of
// `PgpKey` that `features/keys/key_standing.dart` shows to the person, so
// the two agree; this file does not import it, because `crypto/` never
// imports `features/`.

import 'dart:typed_data';

import '../key_error.dart';
import 'ecdh.dart';
import 'key_info.dart';
import 'packets.dart';
import 'pgp_error.dart';
import 'pq_kem.dart';
import 'session_key.dart';
import 'signatures.dart';

/// RSA keys under this many bits are read (old signatures, old mail) and
/// never encrypted to or signed with.
const minRsaBitsToWrite = 2048;

/// Whether [key] encrypts post-quantum: ML-KEM-768+X25519, ML-KEM-1024+X448
/// or Kyber (design decision 13).
bool isPostQuantumEncryption(KeyPacket key) => key.algorithm == 35 || key.algorithm == 36 || key.algorithm == 8;

/// Whether a message to [certificates] is written in the version 2 form
/// (design decision 3): when there is at least one and each says it
/// reads SEIPD version 2; else in the version 1 form every program reads.
bool writesSeipd2(List<PgpCertificate> certificates) => certificates.isNotEmpty && certificates.every((c) => c.readsSeipd2);

/// One key of a certificate: its packet, and what its self-signatures say.
class PgpKeyEntry {
  PgpKeyEntry(this.packet, this.info, this.bindings);

  final KeyPacket packet;
  final PgpKey info;

  /// The primary key's binding signatures over a subkey; empty for the
  /// primary key.
  final List<PgpSignature> bindings;

  /// Whether it is past its expiry or revoked at [now]: null when not.
  PgpKeyTrouble? troubleAt(DateTime now) {
    if (info.revoked) return PgpKeyTrouble.revoked;
    final expires = info.expires;
    if (expires != null && !now.isBefore(expires)) return PgpKeyTrouble.expired;
    return null;
  }
}

/// A transferable key, public or secret, read and checked once.
class PgpCertificate {
  PgpCertificate._(this.key, this.primary, this.subkeys, this._data, this._valid);

  final PgpTransferableKey key;
  final PgpKeyEntry primary;
  final List<PgpKeyEntry> subkeys;
  final Uint8List _data;
  bool? _valid;

  /// Whether every self-signature verifies. A key that fails is not
  /// encrypted to, signed with or trusted for a signature. A certificate
  /// read without the check must be given it with [checked] first.
  bool get valid => _valid ?? (throw StateError('the self-signatures of this key were not checked'));

  /// Checks the self-signatures unless they were, and gives [valid].
  Future<bool> checked() async {
    if (_valid != null) return _valid!;
    try {
      return _valid = await verifySelfSignatures(_data);
    } on KeyFormatException {
      return _valid = false;
    }
  }

  PgpKeyInfo get info => key.info;

  /// The primary key's fingerprint in upper-case hexadecimal.
  String get fingerprintHex => info.primary.fingerprintHex;

  /// The primary key and its subkeys.
  Iterable<PgpKeyEntry> get keys => [primary, ...subkeys];

  /// Reads the first transferable key of [data], binary packets, and
  /// checks its self-signatures. Throws what a key reader throws, as a
  /// [PgpException].
  ///
  /// Without [checkSelfSignatures] the check is left until it is needed:
  /// a key that only decrypts needs none, and a key that may have made a
  /// signature is checked by [mayVerify] when a signature names it. The
  /// check is most of the cost of reading a key.
  static Future<PgpCertificate> read(Uint8List data, {bool checkSelfSignatures = true}) async {
    final key = asPgpError(() => readTransferableKey(data));
    final packets = key.packets;
    final primaryPacket = asPgpError(() => parseKeyPacket(packets.first));
    final subkeys = <PgpKeyEntry>[];
    List<PgpSignature>? bindings;
    for (final packet in packets.skip(1)) {
      switch (packet.tag) {
        case PgpTag.secretSubkey || PgpTag.publicSubkey:
          bindings = [];
          subkeys.add(PgpKeyEntry(asPgpError(() => parseKeyPacket(packet)), key.info.subkeys[subkeys.length], bindings));
        case PgpTag.signature when bindings != null:
          final signature = asPgpError(() => parseSignature(packet.body));
          if (signature.type == 0x18 && signature.issuedBy(primaryPacket.fingerprint)) bindings.add(signature);
        case PgpTag.userId || PgpTag.userAttribute:
          bindings = null;
      }
    }
    final certificate = PgpCertificate._(key, PgpKeyEntry(primaryPacket, key.info.primary, const []), subkeys, data, null);
    if (checkSelfSignatures) await certificate.checked();
    return certificate;
  }

  PgpException _unusable(PgpKeyTrouble reason) => PgpException(PgpProblem.keyUnusable, reason: reason, fingerprint: fingerprintHex);

  /// GnuPG's name for the primary key's algorithm when its signatures are
  /// of a kind this app cannot check (`nistp256`, `dsa2048`, `ed448`), so
  /// that nothing about the key can be believed; null when it can.
  String? get unsupportedKind {
    final packet = primary.packet;
    final checkable = switch (packet.algorithm) {
      1 || 2 || 3 || 27 || 30 => true,
      22 => packet.name == 'ed25519',
      19 => packet.name == 'nistp256' || packet.name == 'nistp384',
      _ => false,
    };
    return checkable ? null : packet.name;
  }

  /// Whether its self-signatures say it reads SEIPD version 2 (design
  /// decision 3 of add-post-quantum-pgp): every key the standard
  /// post-quantum type makes does.
  bool get readsSeipd2 => (info.primary.features ?? 0) & 0x08 != 0;

  /// Throws unless the key as a whole may be written to or with at [now].
  void _checkWhole(DateTime now) {
    final kind = unsupportedKind;
    if (kind != null) throw PgpException(PgpProblem.unsupported, detail: kind, fingerprint: fingerprintHex);
    if (!valid) throw _unusable(PgpKeyTrouble.invalid);
    final trouble = primary.troubleAt(now);
    if (trouble != null) throw _unusable(trouble);
  }

  /// The newest of [candidates] that is in order at [now], or the reason
  /// none is.
  (PgpKeyEntry?, PgpKeyTrouble) _newestValid(Iterable<PgpKeyEntry> candidates, DateTime now) {
    final sorted = candidates.toList()..sort((a, b) => b.info.created.compareTo(a.info.created));
    for (final entry in sorted) {
      if (entry.troubleAt(now) == null) return (entry, PgpKeyTrouble.noSuchKey);
    }
    return (null, sorted.isEmpty ? PgpKeyTrouble.noSuchKey : sorted.first.troubleAt(now)!);
  }

  /// The key to encrypt to at [now]. Throws [PgpProblem.keyUnusable] with
  /// the reason, or [PgpProblem.unsupported] naming the kind of key
  /// (`nistp256`, `version 6 keys`).
  KeyPacket encryptionKey(DateTime now) {
    _checkWhole(now);
    final encrypting = subkeys.where((k) => k.info.canEncrypt && k.info.usable);
    // A post-quantum subkey in order is taken before any classical one
    final (postQuantum, _) = _newestValid(encrypting.where((k) => isPostQuantumEncryption(k.packet)), now);
    final (newest, reason) = _newestValid(encrypting, now);
    final subkey = postQuantum ?? newest;
    final chosen = subkey ?? (primary.info.canEncrypt && primary.info.usable ? primary : null);
    if (chosen == null) throw _unusable(reason);
    final packet = chosen.packet;
    switch (packet.algorithm) {
      case 1 || 2:
        if ((packet.bits ?? 0) < minRsaBitsToWrite) throw _unusable(PgpKeyTrouble.weak);
      case 18:
        try {
          EcdhPublic.of(packet);
        } on PgpException catch (e) {
          throw PgpException(e.problem, detail: e.detail, fingerprint: fingerprintHex);
        }
      case 25 || 35:
        break;
      case 8 when KyberCurve.ofKey(packet.name) != null:
        break;
      default:
        throw PgpException(PgpProblem.unsupported, detail: packet.name, fingerprint: fingerprintHex);
    }
    return packet;
  }

  /// The key to sign with at [now]: its entry, whose packet must hold the
  /// secret part. Throws as [encryptionKey] does, and
  /// [PgpProblem.noSecretHere] for a public key.
  KeyPacket signingKey(DateTime now) {
    _checkWhole(now);
    PgpKeyEntry? chosen = primary.info.canSign ? primary : null;
    if (chosen == null) {
      final (subkey, reason) = _newestValid(subkeys.where((k) => k.info.canSign), now);
      if (subkey == null) throw _unusable(reason);
      chosen = subkey;
    }
    final packet = chosen.packet;
    switch (packet.algorithm) {
      case 1 || 3:
        if ((packet.bits ?? 0) < minRsaBitsToWrite) throw _unusable(PgpKeyTrouble.weak);
      case 22 when packet.name == 'ed25519':
        break;
      case 27 || 30:
        break;
      case 19 when packet.name == 'nistp256' || packet.name == 'nistp384':
        // Only a key on a card signs so: Kemlock keeps no NIST secret
        break;
      default:
        throw PgpException(PgpProblem.unsupported, detail: packet.name, fingerprint: fingerprintHex);
    }
    if (!packet.isSecret) throw PgpException(PgpProblem.noSecretHere, fingerprint: fingerprintHex);
    return packet;
  }

  /// The key of this certificate that [signature] names as its issuer, by
  /// fingerprint or key ID; null when it names none of them. A signature
  /// with no issuer at all matches nothing.
  PgpKeyEntry? issuerOf(PgpSignature signature) {
    if (signature.issuerFingerprint == null && signature.issuerKeyId == null) return null;
    for (final entry in keys) {
      if (signature.issuedBy(entry.packet.fingerprint)) return entry;
    }
    return null;
  }

  /// Whether [entry] may be believed as the maker of a signature: the
  /// certificate's self-signatures verify, and a subkey is bound both ways,
  /// with a signing flag and a valid back-signature.
  Future<bool> mayVerify(PgpKeyEntry entry) async {
    if (!await checked()) return false;
    if (identical(entry, primary)) return true;
    if (!entry.info.canSign) return false;
    for (final binding in entry.bindings) {
      if (await verifyBackSignature(primary.packet, entry.packet, binding)) return true;
    }
    return false;
  }

  /// The secret keys of this certificate that [pkesk] may be for: the one
  /// it names, or, for a hidden recipient, every one of its algorithm.
  /// Standing does not matter: old mail to an expired key still opens.
  List<KeyPacket> decryptionKeys(Pkesk pkesk) => [
    for (final entry in keys)
      if (entry.packet.isSecret && (pkesk.hidden ? _algorithmFits(entry.packet, pkesk) : pkesk.isFor(entry.packet))) entry.packet,
  ];

  static bool _algorithmFits(KeyPacket key, Pkesk pkesk) =>
      key.algorithm == pkesk.algorithm || (key.algorithm <= 2 && pkesk.algorithm <= 2);
}
