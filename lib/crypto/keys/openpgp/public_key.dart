// Someone else's OpenPGP public key, as the vault keeps it: only what the
// key's own primary key signed, every one of those signatures checked, in
// one order whatever order the packets came in. Comparing a fingerprint
// proves the primary key; the checks here are what carry that proof to the
// user IDs and the subkeys, so a subkey slipped into the file by someone
// else never ends up encrypted to.

import 'dart:convert';
import 'dart:typed_data';

import '../key_error.dart';
import 'key_info.dart';
import 'packets.dart';
import 'signatures.dart';

/// The [KeyFormatException.detail] of a key refused because one of its own
/// signatures does not verify, or a subkey has none that does. Its problem
/// is [KeyProblem.damaged]; this tells it from a file that was cut.
const pgpFailsOwnChecks = 'OpenPGP: the key fails its own checks';

Never _failsChecks() => throw const KeyFormatException(KeyProblem.damaged, pgpFailsOwnChecks);

/// The name of a primary key algorithm whose signatures this app cannot
/// check, for [KeyProblem.unsupportedKeyType]; null when it can: RSA,
/// EdDSA over Ed25519, and Ed25519.
String? _uncheckable(KeyPacket primary) => switch (primary.algorithm) {
  1 || 3 || 27 => null,
  22 when primary.name == 'ed25519' => null,
  19 => 'ECDSA (${primary.name})',
  17 => 'DSA',
  _ => primary.name,
};

class _Section {
  _Section(this.packet, this.order);

  /// The user ID or subkey packet.
  final PgpPacket packet;

  /// What sorts it among its kind when its signatures don't: a subkey's
  /// creation time.
  final int order;

  /// The kept signatures, by their body in hexadecimal, so each is kept once.
  final signatures = <String, (PgpPacket, PgpSignature)>{};

  /// The earliest of its signatures.
  int get firstSigned => signatures.values.fold(0x7fffffffffff, (least, s) => (s.$2.created ?? 0) < least ? (s.$2.created ?? 0) : least);
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();

int _compareBytes(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/// The signatures of a section, oldest first, equal dates by their bytes.
List<PgpPacket> _sorted(_Section section) {
  final all = section.signatures.values.toList()
    ..sort((a, b) {
      final byDate = (a.$2.created ?? 0).compareTo(b.$2.created ?? 0);
      return byDate != 0 ? byDate : _compareBytes(a.$1.body, b.$1.body);
    });
  return [for (final s in all) s.$1];
}

/// The transferable public key [key] starts with, rebuilt from what its own
/// primary key vouches for: the primary key packet; its direct-key
/// signatures and its revocations of itself; each user ID with the
/// certifications and revocations the primary key made; each subkey with
/// its bindings and revocations.
///
/// It drops certifications by other keys, photos (user attribute packets)
/// and their signatures, trust, marker and padding packets, version 3
/// signatures, and a user ID the primary key never certified. A packet that
/// comes twice is kept once. The packets come out in one order whatever
/// order they came in: signatures oldest first, user IDs by their first
/// certification, subkeys by when they were made. The fingerprint covers
/// the primary key alone, so it never changes.
///
/// Throws [KeyFormatException]: [KeyProblem.unsupportedKeyType], naming the
/// algorithm, for a primary key whose signatures this app cannot check
/// (ECDSA, DSA, Ed448, ...); [KeyProblem.damaged] with [pgpFailsOwnChecks]
/// when a signature the primary key is said to have made does not verify,
/// when a subkey has no binding that does, or when no user ID of a version
/// 4 key is left; [KeyProblem.privateKeyGiven] for a secret key; and what
/// [readTransferableKey] throws for anything that is not a key.
///
/// With [keepUserId], only the user IDs it says yes to are kept, each with
/// its signatures; the others are dropped as an uncertified one is (openspec:
/// add-key-lookup, decision 7).
Future<Uint8List> trimPublicKey(Uint8List key, {bool Function(String userId)? keepUserId}) async {
  final gathered = _gather(key, keepUserId);
  final uncheckable = _uncheckable(gathered.primary);
  if (uncheckable != null) throw KeyFormatException(KeyProblem.unsupportedKeyType, uncheckable);
  for (final found in gathered.found) {
    if (!await verifySignature(found.signature, gathered.primary, found.covered)) _failsChecks();
    found.keep();
  }
  return _assemble(gathered);
}

/// A signature found in a key, in the section it belongs to, with the
/// bytes it covers there; kept once [keep] is called.
class _Found {
  _Found(this.section, this.packet, this.signature, this.covered);

  final _Section section;
  final PgpPacket packet;
  final PgpSignature signature;
  final List<int> covered;

  void keep() => section.signatures.putIfAbsent(_hex(packet.body), () => (packet, signature));
}

/// A public key taken apart: its sections, each packet once, and the
/// signatures that may be kept in them, none kept yet.
class _Gathered {
  _Gathered(this.primary, this.own);

  final KeyPacket primary;
  final _Section own;
  final userIds = <String, _Section>{};
  final subkeys = <String, _Section>{};
  final found = <_Found>[];
}

/// Takes the transferable public key [key] starts with apart. Certifications
/// by other keys, photos and their signatures, version 3 signatures and
/// packets that are no part of a key are left out here, and so is a user ID
/// [keepUserId] says no to.
_Gathered _gather(Uint8List key, [bool Function(String userId)? keepUserId]) {
  final read = readTransferableKey(key);
  if (read.info.isSecret) throw const KeyFormatException(KeyProblem.privateKeyGiven);
  final primary = parseKeyPacket(read.packets.first);
  final primaryBytes = hashedKey(primary);
  final gathered = _Gathered(primary, _Section(read.packets.first, 0));

  // The section a signature belongs to, the bytes it covers there, and the
  // signature types kept in it. Null while inside a photo.
  _Section? section = gathered.own;
  List<int> covered = primaryBytes;
  var isSubkey = false;
  var types = const {0x1f, 0x20};

  for (final packet in read.packets.skip(1)) {
    switch (packet.tag) {
      case PgpTag.userId when keepUserId != null && !keepUserId(utf8.decode(packet.body, allowMalformed: true)):
        // Left out with its signatures, as a photo is
        section = null;
      case PgpTag.userId:
        section = gathered.userIds.putIfAbsent(_hex(packet.body), () => _Section(packet, 0));
        covered = [...primaryBytes, ...hashedUserId(packet.body)];
        isSubkey = false;
        types = const {0x10, 0x11, 0x12, 0x13, 0x30};
      case PgpTag.userAttribute:
        section = null;
      case PgpTag.publicSubkey:
        final subkey = parseKeyPacket(packet);
        section = gathered.subkeys.putIfAbsent(_hex(packet.body), () => _Section(packet, subkey.createdSeconds));
        covered = [...primaryBytes, ...hashedKey(subkey)];
        isSubkey = true;
        types = const {0x18, 0x28};
      case PgpTag.signature:
        if (section == null) continue;
        final signature = parseSignature(packet.body);
        if (signature.version == 3 || !types.contains(signature.type)) continue;
        // Only the primary key binds or revokes a subkey, so there every such signature is checked,
        // whoever it names as its issuer. On a user ID, another key's certification is dropped unread.
        if (!isSubkey && !signature.issuedBy(primary.fingerprint)) continue;
        gathered.found.add(_Found(section, packet, signature, covered));
    }
  }
  return gathered;
}

/// The key [gathered] holds with the signatures that were kept, in the one
/// order a stored key has. Throws when a subkey is left with no binding or
/// a version 4 key with no user ID.
Uint8List _assemble(_Gathered gathered) {
  final own = gathered.own;
  bool has(_Section s, bool Function(int type) test) => s.signatures.values.any((sig) => test(sig.$2.type));
  // A subkey is kept only under a binding the primary key made
  if (gathered.subkeys.values.any((s) => !has(s, (type) => type == 0x18))) _failsChecks();
  final kept =
      [
        for (final s in gathered.userIds.values)
          if (has(s, (type) => type >= 0x10 && type <= 0x13)) s,
      ]..sort((a, b) {
        final bySigned = a.firstSigned.compareTo(b.firstSigned);
        return bySigned != 0 ? bySigned : _compareBytes(a.packet.body, b.packet.body);
      });
  if (gathered.primary.version == 4 ? kept.isEmpty : kept.isEmpty && own.signatures.isEmpty) _failsChecks();
  final keptSubkeys = gathered.subkeys.values.toList()
    ..sort((a, b) {
      final byMade = a.order.compareTo(b.order);
      return byMade != 0 ? byMade : _compareBytes(a.packet.body, b.packet.body);
    });

  final out = BytesBuilder(copy: false)..add(own.packet.encoded);
  for (final section in [own, ...kept, ...keptSubkeys]) {
    if (!identical(section, own)) out.add(section.packet.encoded);
    for (final signature in _sorted(section)) {
      out.add(signature.encoded);
    }
  }
  return out.toBytes();
}

/// Two copies of one key, each as [trimPublicKey] gives it, as one: every
/// user ID, subkey and self-signature either holds, each once, in the order
/// [trimPublicKey] puts them. A revocation or a later self-signature is
/// only ever added, so an older copy never undoes a newer one; a copy with
/// one that holds nothing more comes back byte for byte, and the order of
/// the two does not matter.
///
/// Nothing is verified here, so both copies must be ones [trimPublicKey]
/// gave: the vault's own, as when sync brings two copies of one contact
/// together. For a copy from outside, use [mergePublicKeys].
///
/// Throws an [ArgumentError] when the two are not the same key, and
/// [KeyFormatException] when either is not a public key.
Uint8List unionPublicKeys(Uint8List a, Uint8List b) {
  final first = readTransferableKey(a);
  final second = readTransferableKey(b);
  if (_compareBytes(first.info.fingerprint, second.info.fingerprint) != 0) {
    throw ArgumentError('unionPublicKeys: two different keys');
  }
  // The primary key packet once, then the signatures on it of both copies, then the user IDs and
  // subkeys of both: the sections are gathered, each packet once, and put in order.
  bool onPrimary(PgpPacket packet) => packet.tag == PgpTag.signature;
  final joined = BytesBuilder(copy: false)..add(first.packets.first.encoded);
  for (final key in [first, second]) {
    for (final packet in key.packets.skip(1).takeWhile(onPrimary)) {
      joined.add(packet.encoded);
    }
  }
  for (final key in [first, second]) {
    for (final packet in key.packets.skip(1).skipWhile(onPrimary)) {
      joined.add(packet.encoded);
    }
  }
  final gathered = _gather(joined.toBytes());
  for (final found in gathered.found) {
    found.keep();
  }
  return _assemble(gathered);
}

/// Two copies of one key as one, as [unionPublicKeys] joins them, with
/// every signature of the result checked again: for a copy that comes from
/// outside, a file, a code or pasted text.
///
/// Throws an [ArgumentError] when the two are not the same key, and
/// [KeyFormatException] when either is not a sound public key.
Future<Uint8List> mergePublicKeys(Uint8List a, Uint8List b) async => trimPublicKey(unionPublicKeys(a, b));

/// An upper-case hexadecimal fingerprint in groups of four, the way people
/// read one out: ten groups for a version 4 key, sixteen for version 6.
List<String> fingerprintGroups(String fingerprintHex) => [
  for (var i = 0; i < fingerprintHex.length; i += 4)
    fingerprintHex.substring(i, i + 4 > fingerprintHex.length ? fingerprintHex.length : i + 4).toUpperCase(),
];
