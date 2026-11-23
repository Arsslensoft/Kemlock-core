// Changing a PGP key in the vault (openspec: add-pgp-key-editing): when it
// or one subkey expires, a new user ID, a new subkey, a revocation.
//
// A change only adds. The key's fingerprint, its key material and every
// packet it held stay as they were, in their order, and the new packets go
// where a reader looks for them: a new self-signature after the ones it
// supersedes, a new user ID after the last one, a new subkey at the end.
// New self-signatures copy the subpackets of the ones they supersede
// (`readSubpackets`), with a new creation time, and are of the key's own
// version, SHA-512, made by the key's own primary key. Each is newer than every
// self-signature the key held, whatever the clock says, so that every
// program takes it for the latest. New packets have the header format of
// the key's first packet. Every result has its self-signatures checked
// before it is handed back.
//
// Version 4 and 6 keys: a version 6 key's new signatures are version 6,
// with their salt, and a standard post-quantum key signs them with
// ML-DSA-65 and Ed25519 together (openspec: add-post-quantum-pgp, design
// decision 14).

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../key_error.dart';
import 'armor.dart';
import 'key_info.dart';
import 'packets.dart';
import 'pgp_error.dart';
import 'secret_key.dart';
import 'signatures.dart';
import 'writer.dart';

// ─── What can be changed ──────────────────────────────────────────────────────

/// Why a key cannot be changed here.
enum PgpEditBlock {
  /// The key revoked itself.
  revoked,

  /// A key of a version other than 4 and 6, which nothing reads as one.
  /// Version 6 keys are changed since add-post-quantum-pgp.
  version6,

  /// This copy does not hold the primary key's secret: a public key, or
  /// GnuPG's stub (a secret key exported with `--export-secret-subkeys`).
  noPrimarySecret,

  /// The primary key is of an algorithm this app does not sign with;
  /// [PgpEditRefusal.detail] names it as GnuPG does.
  algorithm,

  /// The primary key's secret is protected in a way this app does not
  /// open; [PgpEditRefusal.detail] names it (`Argon2`, `CAST5`).
  protection,
}

class PgpEditRefusal {
  const PgpEditRefusal(this.block, [this.detail]);

  final PgpEditBlock block;
  final String? detail;

  @override
  String toString() => 'PgpEditRefusal(${block.name}${detail == null ? '' : ', $detail'})';
}

/// Why the transferable secret key [key] cannot be changed, or null when it
/// can. Throws [KeyFormatException] for one that does not read.
PgpEditRefusal? editRefusal(Uint8List key) {
  final read = readTransferableKey(key);
  final primary = parseKeyPacket(read.packets.first);
  if (read.info.primary.revoked) return const PgpEditRefusal(PgpEditBlock.revoked);
  if (primary.version != 4 && primary.version != 6) return const PgpEditRefusal(PgpEditBlock.version6);
  if (!primary.isSecret) return const PgpEditRefusal(PgpEditBlock.noPrimarySecret);
  if (!_signs(primary)) return PgpEditRefusal(PgpEditBlock.algorithm, primary.name);
  try {
    unlockSecretKey(primary);
  } on PgpException catch (e) {
    switch (e.problem) {
      case PgpProblem.passphraseNeeded:
        break;
      case PgpProblem.noSecretHere:
        return const PgpEditRefusal(PgpEditBlock.noPrimarySecret);
      case PgpProblem.unsupported:
        return PgpEditRefusal(PgpEditBlock.protection, e.detail);
      default:
        throw KeyFormatException(KeyProblem.damaged, 'OpenPGP: primary secret key: ${e.problem.name}');
    }
  }
  return null;
}

/// Whether this app makes signatures with [key]: RSA, EdDSA or Ed25519,
/// and RFC 9980's ML-DSA-65+Ed25519.
bool _signs(KeyPacket key) => switch (key.algorithm) {
  1 || 3 || 27 || 30 => true,
  22 => key.name == 'ed25519',
  _ => false,
};

/// Whether [key]'s primary secret needs a passphrase to be opened.
bool primaryNeedsPassphrase(Uint8List key) => needsPassphrase(parseKeyPacket(readPackets(key).first));

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Why a change was not made.
enum PgpEditProblem {
  /// What was given as a revocation certificate holds no signature.
  notACertificate,

  /// It holds signatures, none of which revokes a key.
  notARevocation,

  /// It revokes another key.
  otherKey,

  /// It names this key and does not verify: altered or cut short.
  damaged,

  /// A signature the change made does not verify, or the result does not
  /// read: nothing is saved.
  failedCheck,
}

class PgpEditException implements Exception {
  const PgpEditException(this.problem, [this.detail]);

  final PgpEditProblem problem;

  /// A note for tests, never for people.
  final String? detail;

  @override
  String toString() => 'PgpEditException: ${problem.name}${detail == null ? '' : ' ($detail)'}';
}

// ─── The primary key ──────────────────────────────────────────────────────────

/// The opened primary key of the key being changed: what signs the new
/// self-signatures.
class PgpSigner {
  PgpSigner(this.key, this.secret);

  /// Opens the primary key of the transferable secret key [key], with
  /// [passphrase] when it is protected. Throws what [unlockSecretKey]
  /// throws, and [PgpProblem.unsupported] for a key this app does not sign
  /// with.
  factory PgpSigner.of(Uint8List key, {String? passphrase}) {
    final primary = parseKeyPacket(readPackets(key).first);
    if (!_signs(primary)) throw PgpException(PgpProblem.unsupported, detail: primary.name);
    return PgpSigner(primary, unlockSecretKey(primary, passphrase: passphrase));
  }

  final KeyPacket key;
  final PgpSecret secret;

  /// The signature material of a SHA-512 [digest].
  Future<List<int>> sign(List<int> digest) => signDigest(key, secret, digest);
}

/// The signature material [key], whose secret part is [secret], makes over
/// a SHA-512 [digest]: an RSA MPI, the two MPIs of EdDSA, Ed25519's 64
/// bytes, or RFC 9980's composite of Ed25519's and ML-DSA-65's.
Future<List<int>> signDigest(KeyPacket key, PgpSecret secret, List<int> digest) async {
  switch (secret) {
    case RsaSecret(:final material):
      return signRsa(material, digest);
    case Ed25519Secret(:final seed) when key.algorithm == 27:
      final ed = c.Ed25519();
      return (await ed.sign(digest, keyPair: await ed.newKeyPairFromSeed(seed))).bytes;
    case Ed25519Secret(:final seed):
      return signEdDsa(seed, digest);
    case MlDsaEd25519Secret(:final ed25519Seed, :final mlDsaSecretKey):
      return signComposite(ed25519Seed, mlDsaSecretKey, digest);
    case X25519Secret():
      throw PgpException(PgpProblem.unsupported, detail: key.name);
    // A key on an OpenPGP card (openspec: add-openpgp-card) signs no change
    // yet: a change is made in an isolate, where the card is not reached.
    case DelegatedSecret():
    default:
      throw PgpException(PgpProblem.unsupported, detail: key.name);
  }
}

// ─── The key taken apart ──────────────────────────────────────────────────────

/// A packet that starts a part of a key, and the packets after it up to
/// the next one: the primary key, a user ID or attribute, or a subkey, each
/// with its signatures (and whatever else lay there, kept in place).
class _Part {
  _Part(this.head);

  final PgpPacket head;
  final List<PgpPacket> rest = [];

  /// What is added to the part, after [rest].
  final List<Uint8List> added = [];

  bool get isUserId => head.tag == PgpTag.userId;
  bool get isUser => isUserId || head.tag == PgpTag.userAttribute;
  bool get isSubkey => head.tag == PgpTag.secretSubkey || head.tag == PgpTag.publicSubkey;

  Iterable<PgpSignature> get signatures sync* {
    for (final packet in rest) {
      if (packet.tag == PgpTag.signature) yield parseSignature(packet.body);
    }
  }
}

/// A transferable secret key being changed.
class _Key {
  _Key(Uint8List data) {
    final read = readTransferableKey(data);
    packets = read.packets;
    primary = parseKeyPacket(packets.first);
    check(primary.version == 4 || primary.version == 6, 'OpenPGP: only version 4 and 6 keys are changed');
    for (final packet in packets) {
      final head =
          parts.isEmpty || const {PgpTag.userId, PgpTag.userAttribute, PgpTag.secretSubkey, PgpTag.publicSubkey}.contains(packet.tag);
      if (head) {
        parts.add(_Part(packet));
      } else {
        parts.last.rest.add(packet);
      }
    }
  }

  late final List<PgpPacket> packets;
  late final KeyPacket primary;
  final List<_Part> parts = [];

  /// Parts that come after the user IDs: new ones go before them.
  final List<_Part> _newUsers = [];
  final List<Uint8List> _newSubkeys = [];

  _Part get primaryPart => parts.first;
  bool get oldFormat => packets.first.oldFormat;

  /// What a self-signature of the primary key over a part covers.
  List<int> covered(_Part part) => [
    ...hashedKey(primary),
    if (part.isUserId) ...hashedUserId(part.head.body),
    if (part.isSubkey) ...hashedKey(parseKeyPacket(part.head)),
  ];

  bool isSelf(PgpSignature s) => s.issuedBy(primary.fingerprint) && s.version == primary.version;

  /// The latest self-signature of [part] of one of [types], or null.
  PgpSignature? latest(_Part part, bool Function(int type) types) {
    PgpSignature? best;
    for (final s in part.signatures) {
      if (!isSelf(s) || !types(s.type)) continue;
      if (best == null || (s.created ?? 0) >= (best.created ?? 0)) best = s;
    }
    return best;
  }

  /// The creation time of every new signature of a change made at [now]:
  /// the clock's, or a second after the latest self-signature the key
  /// holds when the clock is not past it, so the new ones always win.
  int timeOf(DateTime now) {
    var latest = primary.createdSeconds;
    for (final part in parts) {
      for (final s in part.signatures) {
        if (isSelf(s) && (s.created ?? 0) > latest) latest = s.created!;
      }
    }
    final clock = now.millisecondsSinceEpoch ~/ 1000;
    return clock > latest ? clock : latest + 1;
  }

  Uint8List packet(int tag, List<int> body) => writePacket(tag, body, oldFormat: oldFormat);

  void addUser(_Part part) => _newUsers.add(part);
  void addSubkey(Uint8List packets) => _newSubkeys.add(packets);

  /// The key with what was added.
  Uint8List write() {
    final out = BytesBuilder(copy: false);
    void put(_Part part) {
      out.add(part.head.encoded);
      for (final p in part.rest) {
        out.add(p.encoded);
      }
      part.added.forEach(out.add);
    }

    final lastUser = parts.lastIndexWhere((p) => p.isUser);
    for (final (i, part) in parts.indexed) {
      put(part);
      if (i == (lastUser < 0 ? 0 : lastUser)) _newUsers.forEach(put);
    }
    _newSubkeys.forEach(out.add);
    return out.toBytes();
  }
}

/// [data] as the 4 bytes of a big-endian number.
List<int> _be32(int v) => [v >>> 24 & 0xff, v >>> 16 & 0xff, v >>> 8 & 0xff, v & 0xff];

/// What a key that expires at [expires] says in its self-signatures of a
/// key made at [created] (seconds): the seconds in between. Throws an
/// [ArgumentError] when that is not ahead of [now] or does not fit.
int _expirySeconds(DateTime expires, int created, DateTime now) {
  if (!expires.isAfter(now)) throw ArgumentError.value(expires, 'expires', 'must be in the future');
  final seconds = expires.millisecondsSinceEpoch ~/ 1000 - created;
  if (seconds <= 0 || seconds >= 1 << 32) throw ArgumentError.value(expires, 'expires', 'out of range');
  return seconds;
}

const _keep = Object();

/// The hashed and unhashed subpackets of a new signature copied from [old]:
/// the creation time set to [created]; the key expiry set to [expiry], or
/// removed when it is null, unless it is [_keep]; the primary user ID flag
/// set or dropped when [primaryUserId] is given. The issuer's key ID goes
/// unhashed before the rest, as [makeSignature] writes it.
({Uint8List hashed, Uint8List unhashed}) _copied(PgpSignature old, {required int created, Object? expiry = _keep, bool? primaryUserId}) {
  final hashed = <Subpacket>[];
  var hasTime = false;
  var hasExpiry = false;
  for (final s in readSubpackets(old.hashedArea)) {
    switch (s.type) {
      case 2:
        hashed.add(Subpacket(2, Uint8List.fromList(_be32(created)), critical: s.critical));
        hasTime = true;
      case 9 when expiry != _keep:
        if (expiry != null) hashed.add(Subpacket(9, Uint8List.fromList(_be32(expiry as int)), critical: s.critical));
        hasExpiry = true;
      case 25 when primaryUserId != null:
        break;
      default:
        hashed.add(s);
    }
  }
  if (!hasTime) hashed.insert(0, Subpacket(2, Uint8List.fromList(_be32(created))));
  if (!hasExpiry && expiry != _keep && expiry != null) hashed.add(Subpacket(9, Uint8List.fromList(_be32(expiry as int))));
  if (primaryUserId ?? false) hashed.add(Subpacket(25, Uint8List.fromList([1])));
  return (hashed: writeSubpackets(hashed), unhashed: writeSubpackets(readSubpackets(old.unhashedArea).where((s) => s.type != 16)));
}

/// A new self-signature of [type] over [part], by [signer], with the
/// subpackets [areas].
Future<Uint8List> _sign(_Key key, _Part part, int type, PgpSigner signer, ({Uint8List hashed, Uint8List unhashed}) areas) async {
  final body = await makeSignature(
    type: type,
    signer: key.primary,
    data: key.covered(part),
    hashed: areas.hashed,
    unhashed: areas.unhashed,
    sign: signer.sign,
  );
  return key.packet(PgpTag.signature, body);
}

/// [data] once its self-signatures are checked: throws
/// [PgpEditProblem.failedCheck] when one does not verify or the key does
/// not read.
Future<Uint8List> _checked(Uint8List data) async {
  try {
    readTransferableKey(data);
    if (!await verifySelfSignatures(data)) throw const PgpEditException(PgpEditProblem.failedCheck, 'a self-signature');
  } on KeyFormatException catch (e) {
    throw PgpEditException(PgpEditProblem.failedCheck, e.detail);
  }
  return data;
}

// ─── Expiry ───────────────────────────────────────────────────────────────────

/// [key] with a new expiry, [expires] (null for never), signed by [signer]
/// at [now].
///
/// For the primary key (no [subkey]): a new positive certification of every
/// user ID that has a self-certification and was not revoked, and a new
/// direct-key signature when the key has one, since readers take the
/// expiry from it first; and when [alsoSubkeys], a new binding of every
/// subkey that was not revoked. For the subkey whose fingerprint is
/// [subkey]: a new binding of it alone. Each is copied from the latest
/// self-signature it supersedes, a signing subkey's back-signature with it.
///
/// Throws an [ArgumentError] for a date not after [now], a subkey the key
/// does not have or that was revoked.
Future<Uint8List> setExpiry(
  Uint8List key,
  PgpSigner signer, {
  required DateTime? expires,
  Uint8List? subkey,
  bool alsoSubkeys = false,
  required DateTime now,
}) async {
  final k = _Key(key);
  final at = k.timeOf(now);

  Future<void> rebind(_Part part) async {
    final created = parseKeyPacket(part.head).createdSeconds;
    final binding = k.latest(part, (type) => type == 0x18);
    if (binding == null) return;
    final expiry = expires == null ? null : _expirySeconds(expires, created, now);
    part.added.add(await _sign(k, part, 0x18, signer, _copied(binding, created: at, expiry: expiry)));
  }

  bool revoked(_Part part) => part.signatures.any((s) => k.isSelf(s) && s.type == 0x28);

  if (subkey != null) {
    final part = k.parts.where((p) => p.isSubkey && _same(parseKeyPacket(p.head).fingerprint, subkey)).firstOrNull;
    if (part == null) throw ArgumentError.value(subkey, 'subkey', 'not a subkey of this key');
    if (revoked(part)) throw ArgumentError.value(subkey, 'subkey', 'revoked');
    if (expires != null) _expirySeconds(expires, parseKeyPacket(part.head).createdSeconds, now);
    await rebind(part);
  } else {
    final expiry = expires == null ? null : _expirySeconds(expires, k.primary.createdSeconds, now);
    final direct = k.latest(k.primaryPart, (type) => type == 0x1f);
    if (direct != null) {
      k.primaryPart.added.add(await _sign(k, k.primaryPart, 0x1f, signer, _copied(direct, created: at, expiry: expiry)));
    }
    var certified = direct != null;
    for (final part in k.parts.where((p) => p.isUserId)) {
      final cert = k.latest(part, (type) => type >= 0x10 && type <= 0x13);
      if (cert == null) continue;
      final revocation = k.latest(part, (type) => type == 0x30);
      if (revocation != null && (revocation.created ?? 0) >= (cert.created ?? 0)) continue;
      part.added.add(await _sign(k, part, 0x13, signer, _copied(cert, created: at, expiry: expiry)));
      certified = true;
    }
    check(certified, 'OpenPGP: no self-signature to carry the expiry');
    if (alsoSubkeys) {
      for (final part in k.parts.where((p) => p.isSubkey && !revoked(p))) {
        await rebind(part);
      }
    }
  }
  return _checked(k.write());
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// ─── User IDs ─────────────────────────────────────────────────────────────────

/// [key] with a new user ID for [name] and [email], `Name <email>` as
/// [pgpUserId] writes it, certified by [signer] at [now] with the
/// subpackets of the main user ID's latest self-certification: its
/// preferences, key flags and expiry, so the key expires as it did. With
/// [makePrimary] the new one is marked the main user ID; otherwise it is
/// not marked.
///
/// Throws an [ArgumentError] for an empty name or email (its `name` says
/// which) and for a user ID the key has already (`name` `userId`).
Future<Uint8List> addUserId(
  Uint8List key,
  PgpSigner signer, {
  required String name,
  required String email,
  bool makePrimary = false,
  required DateTime now,
}) async {
  final userId = pgpUserId(name, email);
  final k = _Key(key);
  final bytes = Uint8List.fromList(utf8.encode(userId));
  if (k.parts.any((p) => p.isUserId && _same(p.head.body, bytes))) {
    throw ArgumentError.value(userId, 'userId', 'the key has this user ID already');
  }
  final main = _mainCertification(k);
  check(main != null, 'OpenPGP: no self-certification to copy');
  final part = _Part(PgpPacket(PgpTag.userId, bytes, k.packet(PgpTag.userId, bytes), oldFormat: k.oldFormat));
  part.added.add(await _sign(k, part, 0x13, signer, _copied(main!, created: k.timeOf(now), primaryUserId: makePrimary)));
  k.addUser(part);
  return _checked(k.write());
}

/// The latest self-certification of the key's main user ID: of the user
/// IDs that were not revoked, the one whose latest certification is marked
/// primary, the latest such; else the first that has one.
PgpSignature? _mainCertification(_Key k) {
  PgpSignature? first;
  PgpSignature? marked;
  for (final part in k.parts.where((p) => p.isUserId)) {
    final cert = k.latest(part, (type) => type >= 0x10 && type <= 0x13);
    if (cert == null) continue;
    final revocation = k.latest(part, (type) => type == 0x30);
    if (revocation != null && (revocation.created ?? 0) >= (cert.created ?? 0)) continue;
    first ??= cert;
    if (cert.primaryUserId && (marked == null || (cert.created ?? 0) > (marked.created ?? 0))) marked = cert;
  }
  return marked ?? first;
}

// ─── Subkeys ──────────────────────────────────────────────────────────────────

/// What a new subkey is for.
enum PgpSubkeyUse { encrypt, sign }

/// [key] with a new subkey made on the phone at [now]: of [type] (Curve25519
/// to encrypt or Ed25519 to sign for [PgpKeyType.ed25519], RSA 4096 for
/// either), for [use], expiring at [expires] or never. It is bound by a
/// binding signature of [signer] with its key flags and expiry; a signing
/// subkey's carries its own signature over the primary key (0x19), without
/// which nobody may take its signatures for the key's. When [passphrase] is
/// given, the key's own, the new secret is protected with it.
///
/// [PgpKeyType.pqStandard] and [PgpKeyType.pqGnupg] make a post-quantum
/// subkey to encrypt (openspec: add-post-quantum-pgp, design decision 14):
/// ML-KEM-768+X25519, or Kyber-768 with X25519 as a version 5 subkey. A
/// version 6 key takes only version 6 subkeys, of [PgpKeyType.pqStandard]:
/// ML-KEM-768+X25519 to encrypt, ML-DSA-65+Ed25519 to sign.
///
/// Making an RSA key takes seconds: run it in the background
/// (`generateKey` with a `PgpChangeRequest`). Throws an [ArgumentError] for
/// an expiry not after [now], and for a type the key does not take.
Future<Uint8List> addSubkey(
  Uint8List key,
  PgpSigner signer, {
  required PgpKeyType type,
  required PgpSubkeyUse use,
  DateTime? expires,
  String? passphrase,
  required DateTime now,
}) async {
  final k = _Key(key);
  final at = k.timeOf(now);
  final expiry = expires == null ? null : _expirySeconds(expires, at, now);
  final signs = use == PgpSubkeyUse.sign;
  final material = await newPgpKeyMaterial(type, signs: signs, time: at, version: k.primary.version);
  final sub = parseKeyPacket(readPackets(writePacket(PgpTag.publicSubkey, material.public)).single);
  final covered = [...hashedKey(k.primary), ...hashedKey(sub)];
  final time = subpacket(2, _be32(at));
  final hashed = [
    ...subpacket(33, [k.primary.version, ...k.primary.fingerprint]),
    ...time,
    ...subpacket(27, [if (signs) PgpKeyFlag.sign else PgpKeyFlag.encryptCommunications | PgpKeyFlag.encryptStorage]),
    if (expiry != null) ...subpacket(9, _be32(expiry)),
    if (signs)
      ...subpacket(
        32,
        await makeSignature(
          type: 0x19,
          signer: sub,
          data: covered,
          hashed: [
            ...subpacket(33, [sub.version, ...sub.fingerprint]),
            ...time,
          ],
          sign: material.sign,
        ),
      ),
  ];
  final binding = await makeSignature(type: 0x18, signer: k.primary, data: covered, hashed: hashed, sign: signer.sign);
  if (signs && !await verifyBackSignature(k.primary, sub, parseSignature(binding))) {
    throw const PgpEditException(PgpEditProblem.failedCheck, 'the back-signature');
  }
  var secret = k.packet(PgpTag.secretSubkey, [...material.public, ...material.secret]);
  if (passphrase != null) secret = protectSecretKeyPacket(readPackets(secret).single, passphrase);
  k.addSubkey(Uint8List.fromList([...secret, ...k.packet(PgpTag.signature, binding)]));
  return _checked(k.write());
}

// ─── All of them ──────────────────────────────────────────────────────────────

/// A change to a key, as the sheets ask for it: what [changePgpKey] makes.
sealed class PgpChange {
  const PgpChange();
}

/// [setExpiry]: of the primary key (with its subkeys when [alsoSubkeys]),
/// or of the subkey whose fingerprint is [subkey].
final class SetPgpExpiry extends PgpChange {
  const SetPgpExpiry(this.expires, {this.subkey, this.alsoSubkeys = false});

  final DateTime? expires;
  final Uint8List? subkey;
  final bool alsoSubkeys;
}

/// [addUserId].
final class AddPgpUserId extends PgpChange {
  const AddPgpUserId({required this.name, required this.email, this.makePrimary = false});

  final String name;
  final String email;
  final bool makePrimary;
}

/// [addSubkey].
final class AddPgpSubkey extends PgpChange {
  const AddPgpSubkey({required this.type, required this.use, this.expires});

  final PgpKeyType type;
  final PgpSubkeyUse use;
  final DateTime? expires;
}

/// [revokePgpKey]: revoked at once with [reason] and [note].
final class RevokePgpKey extends PgpChange {
  const RevokePgpKey({required this.reason, this.note = ''});

  final PgpRevocationReason reason;
  final String note;
}

/// [applyRevocation] of [certificate], the bytes of a file or pasted text.
/// It needs no secret and no passphrase.
final class ApplyPgpRevocation extends PgpChange {
  const ApplyPgpRevocation(this.certificate);

  final Uint8List certificate;
}

/// [change] made to the transferable secret key [key] at [now], its primary
/// key opened with [passphrase] when it keeps one. Throws what the change
/// throws, and what [PgpSigner.of] throws: a wrong passphrase among them.
Future<Uint8List> changePgpKey(Uint8List key, PgpChange change, {String? passphrase, required DateTime now}) async {
  if (change is ApplyPgpRevocation) return applyRevocation(key, change.certificate);
  final signer = PgpSigner.of(key, passphrase: passphrase);
  return switch (change) {
    SetPgpExpiry(:final expires, :final subkey, :final alsoSubkeys) => setExpiry(
      key,
      signer,
      expires: expires,
      subkey: subkey,
      alsoSubkeys: alsoSubkeys,
      now: now,
    ),
    AddPgpUserId(:final name, :final email, :final makePrimary) => addUserId(
      key,
      signer,
      name: name,
      email: email,
      makePrimary: makePrimary,
      now: now,
    ),
    AddPgpSubkey(:final type, :final use, :final expires) => addSubkey(
      key,
      signer,
      type: type,
      use: use,
      expires: expires,
      passphrase: needsPassphrase(signer.key) ? passphrase : null,
      now: now,
    ),
    RevokePgpKey(:final reason, :final note) => revokePgpKey(key, signer, reason: reason, note: note, now: now),
    ApplyPgpRevocation() => throw StateError('applied above'),
  };
}

// ─── Revocation ───────────────────────────────────────────────────────────────

/// Why a key is revoked: the reason codes of RFC 9580 section 5.2.3.31.
enum PgpRevocationReason {
  /// No reason given.
  none(0),

  /// Replaced by another key.
  superseded(1),

  /// Its secret may be in other hands.
  compromised(2),

  /// No longer used.
  retired(3);

  const PgpRevocationReason(this.code);

  final int code;
}

/// A revocation certificate for [key]: its key revocation signature (0x20)
/// by [signer], made at [now], with [reason] and [note], as one signature
/// packet, the bare form GnuPG writes and Sequoia imports; for a version 6
/// key, the primary key's public packet and then the signature, as
/// Sequoia writes one (openspec: add-post-quantum-pgp, design decision
/// 14). It revokes the
/// key once applied, here or by any OpenPGP program that has the key; [key]
/// itself is left as it is.
Future<Uint8List> revocation(
  Uint8List key,
  PgpSigner signer, {
  required PgpRevocationReason reason,
  String note = '',
  required DateTime now,
}) async {
  final k = _Key(key);
  final body = await makeSignature(
    type: 0x20,
    signer: k.primary,
    data: hashedKey(k.primary),
    hashed: [
      ...subpacket(33, [k.primary.version, ...k.primary.fingerprint]),
      ...subpacket(2, _be32(k.timeOf(now))),
      ...subpacket(29, [reason.code, ...utf8.encode(note.trim())]),
    ],
    sign: signer.sign,
  );
  if (k.primary.version == 6) {
    return Uint8List.fromList([...k.packet(PgpTag.publicKey, k.primary.publicBody), ...k.packet(PgpTag.signature, body)]);
  }
  return k.packet(PgpTag.signature, body);
}

/// [certificate] armored to be saved, shared or copied: a public key block,
/// as GnuPG and Sequoia write theirs, with a comment saying what it is and
/// for which key.
String armorRevocation(Uint8List certificate, String fingerprintHex) {
  final armored = writeArmor(pgpPublicKeyBlock, certificate);
  final firstLine = armored.indexOf('\n');
  return '${armored.substring(0, firstLine + 1)}Comment: Revocation certificate for $fingerprintHex${armored.substring(firstLine)}';
}

/// [key] revoked with [reason] and [note], at [now]: [revocation] applied.
Future<Uint8List> revokePgpKey(
  Uint8List key,
  PgpSigner signer, {
  required PgpRevocationReason reason,
  String note = '',
  required DateTime now,
}) async => applyRevocation(key, await revocation(key, signer, reason: reason, note: note, now: now));

/// The armored revocation certificate of the transferable secret key
/// [key], its primary key opened with [passphrase] when it keeps one: what
/// the sheet hands out, in the background.
Future<String> revocationCertificate(
  Uint8List key, {
  String? passphrase,
  required PgpRevocationReason reason,
  String note = '',
  required DateTime now,
}) async {
  final signer = PgpSigner.of(key, passphrase: passphrase);
  final certificate = await revocation(key, signer, reason: reason, note: note, now: now);
  return armorRevocation(certificate, _hex(signer.key.fingerprint));
}

/// [key] with the revocation certificate [certificate] applied: after the
/// primary key's own signatures. [certificate] is the bytes of a file or a
/// pasted text: armored, with or without the colon GnuPG writes before the
/// armor's first line, or binary; a bare signature, as GnuPG writes it, or
/// the primary key and the signature, as Sequoia does. A certificate the
/// key holds already changes nothing.
///
/// Throws [PgpEditException]: [PgpEditProblem.notACertificate] when it
/// holds no signature, [PgpEditProblem.notARevocation] when none revokes a
/// key, [PgpEditProblem.otherKey] when it revokes another key, and
/// [PgpEditProblem.damaged] when it names this key and does not verify.
Future<Uint8List> applyRevocation(Uint8List key, List<int> certificate) async {
  final k = _Key(key);
  final signatures = <PgpPacket>[];
  final keys = <KeyPacket>[];
  try {
    for (final packet in readPackets(_certificateBytes(certificate))) {
      if (packet.tag == PgpTag.signature) signatures.add(packet);
      if (packet.tag == PgpTag.publicKey || packet.tag == PgpTag.secretKey) keys.add(parseKeyPacket(packet));
    }
  } on KeyFormatException {
    throw const PgpEditException(PgpEditProblem.damaged, 'packets');
  }
  if (signatures.isEmpty) throw const PgpEditException(PgpEditProblem.notACertificate);
  final revocations = <PgpPacket>[];
  for (final packet in signatures) {
    try {
      if (parseSignature(packet.body).type == 0x20) revocations.add(packet);
    } on KeyFormatException {
      throw const PgpEditException(PgpEditProblem.damaged, 'signature');
    }
  }
  if (revocations.isEmpty) throw const PgpEditException(PgpEditProblem.notARevocation);
  if (keys.any((other) => !_same(other.fingerprint, k.primary.fingerprint))) throw const PgpEditException(PgpEditProblem.otherKey);
  final held = [for (final p in k.primaryPart.rest) p.body];
  for (final packet in revocations) {
    final signature = parseSignature(packet.body);
    if (!signature.issuedBy(k.primary.fingerprint)) throw const PgpEditException(PgpEditProblem.otherKey);
    if (!await verifySignature(signature, k.primary, hashedKey(k.primary))) throw const PgpEditException(PgpEditProblem.damaged);
    if (held.any((body) => _same(body, packet.body))) continue;
    k.primaryPart.added.add(k.packet(PgpTag.signature, packet.body));
    held.add(packet.body);
  }
  if (k.primaryPart.added.isEmpty) return key;
  return _checked(k.write());
}

/// The packets of a certificate given as a file or text.
Uint8List _certificateBytes(List<int> input) {
  final bytes = Uint8List.fromList(input);
  if (bytes.isNotEmpty && bytes[0] & 0x80 != 0) return bytes;
  // GnuPG puts a colon before the armor's first line, against an import by mistake
  final text = latin1.decode(bytes).replaceAllMapped(RegExp('^:(-----BEGIN )', multiLine: true), (m) => m[1]!);
  try {
    return readArmorBlock(Uint8List.fromList(latin1.encode(text)), type: pgpPublicKeyBlock);
  } on PgpException catch (e) {
    throw PgpEditException(e.problem == PgpProblem.notAMessage ? PgpEditProblem.notACertificate : PgpEditProblem.damaged, 'armor');
  }
}

String _hex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join().toUpperCase();
