// Combining two copies of one OpenPGP key (openspec: add-pgp-key-editing,
// design decision 3): the vault's and an imported one, or the copies two
// phones changed before they synced. The result holds every user ID,
// subkey and signature either holds, so no change made to either is lost.
//
// It works on public keys as on secret ones, and is the one merge of the
// vault's own keys. Other people's keys (`add-pgp-contacts`) keep their
// own union, `unionPublicKeys` in `public_key.dart`: sync joins two copies
// of a contact where it cannot wait, and in the order every stored contact
// key has, which this order is not. No key goes through both.

import 'dart:convert';
import 'dart:typed_data';

import 'key_info.dart';
import 'packets.dart';
import 'signatures.dart';

/// One user ID, user attribute or subkey, or the primary key: its packet
/// and the signatures over it, each once.
class _Part {
  _Part(this.head);

  PgpPacket head;

  /// By the bytes of their bodies.
  final Map<String, PgpPacket> signatures = {};
}

/// A transferable key taken apart.
class _Copy {
  _Copy(Uint8List data) {
    final key = readTransferableKey(data);
    bytes = Uint8List.sublistView(data, 0, key.length);
    _Part? current;
    for (final packet in key.packets) {
      switch (packet.tag) {
        case PgpTag.secretKey || PgpTag.publicKey:
          current = primary = _Part(packet);
        case PgpTag.userId || PgpTag.userAttribute:
          current = users.putIfAbsent('${packet.tag}:${_id(packet.body)}', () => _Part(packet));
        case PgpTag.secretSubkey || PgpTag.publicSubkey:
          final fingerprint = _id(parseKeyPacket(packet).fingerprint);
          current = subkeys.putIfAbsent(fingerprint, () => _Part(packet));
          // The same subkey twice: its secret packet wins
          if (_isSecret(packet) && !_isSecret(current.head)) current.head = packet;
        case PgpTag.signature:
          current!.signatures.putIfAbsent(_id(packet.body), () => packet);
        default:
          // Trust, marker and padding packets, and those a reader skips
          break;
      }
    }
  }

  late final Uint8List bytes;
  late final _Part primary;
  final Map<String, _Part> users = {};
  final Map<String, _Part> subkeys = {};

  List<_Part> get parts => [primary, ...users.values, ...subkeys.values];
}

String _id(List<int> bytes) => base64.encode(bytes);

bool _isSecret(PgpPacket packet) => packet.tag == PgpTag.secretKey || packet.tag == PgpTag.secretSubkey;

/// The union of [a] and [b], two transferable keys (secret or public) with
/// the same primary key, as one transferable key.
///
/// User IDs and attributes are matched by their bytes, subkeys by their
/// fingerprints and signatures by their bodies. Where both hold one key
/// packet with other bytes (protected on one side only, or with another
/// salt), the preferred side's ([a] when [preferA]) is taken, unless only
/// the other holds the secret: a public-only side never removes a secret.
/// GnuPG's stub, a secret packet with no secret in it, counts as a secret
/// packet, so a key moved to a security key on the preferred side stays
/// moved. A revocation found only on the side that is not preferred is
/// taken only once it verifies against the primary key.
///
/// The result is written in one fixed order: the primary key and its
/// signatures, the user IDs in the order of their earliest
/// self-certification, then the subkeys in the order they were made, each
/// followed by its signatures, those by creation time and then by bytes.
/// Trust, marker and padding packets are dropped. When the union holds
/// what one input holds, that input's own bytes are returned, the
/// preferred one's first: a key nobody changed keeps its bytes, and
/// merging the result again with either input gives the result.
///
/// Throws an [ArgumentError] for keys of two primary keys, and a
/// `KeyFormatException` for one that does not read.
Future<Uint8List> mergePgpKeys(Uint8List a, Uint8List b, {required bool preferA}) async {
  final first = _Copy(preferA ? a : b);
  final second = _Copy(preferA ? b : a);
  final primary = parseKeyPacket(first.primary.head);
  if (!_same(primary.fingerprint, parseKeyPacket(second.primary.head).fingerprint)) {
    throw ArgumentError('two copies of different keys');
  }
  final primaryBytes = hashedKey(primary);

  PgpPacket pick(PgpPacket preferred, PgpPacket other) => !_isSecret(preferred) && _isSecret(other) ? other : preferred;

  /// [into] with [from]'s signatures, those that revoke only once they verify over [covered].
  Future<void> join(_Part into, _Part from, List<int>? covered, Set<int> revocations) async {
    into.head = pick(into.head, from.head);
    for (final MapEntry(key: id, value: packet) in from.signatures.entries) {
      if (into.signatures.containsKey(id)) continue;
      final signature = parseSignature(packet.body);
      if (revocations.contains(signature.type)) {
        if (covered == null || !signature.issuedBy(primary.fingerprint) || !await verifySignature(signature, primary, covered)) continue;
      }
      into.signatures[id] = packet;
    }
  }

  final merged = _Part(first.primary.head)..signatures.addAll(first.primary.signatures);
  await join(merged, second.primary, primaryBytes, const {0x20});
  final users = {for (final MapEntry(:key, :value) in first.users.entries) key: _Part(value.head)..signatures.addAll(value.signatures)};
  for (final MapEntry(:key, :value) in second.users.entries) {
    final into = users.putIfAbsent(key, () => _Part(value.head));
    final covered = value.head.tag == PgpTag.userId ? [...primaryBytes, ...hashedUserId(value.head.body)] : null;
    await join(into, value, covered, const {0x30});
  }
  final subkeys = {for (final MapEntry(:key, :value) in first.subkeys.entries) key: _Part(value.head)..signatures.addAll(value.signatures)};
  for (final MapEntry(:key, :value) in second.subkeys.entries) {
    final into = subkeys.putIfAbsent(key, () => _Part(value.head));
    await join(into, value, [...primaryBytes, ...hashedKey(parseKeyPacket(value.head))], const {0x28});
  }

  // When the union is one of the inputs, it is that input
  final union = _content([merged, ...users.values, ...subkeys.values]);
  for (final copy in [first, second]) {
    if (_content(copy.parts) == union) return copy.bytes;
  }

  bool isSelf(PgpSignature s) => s.issuedBy(primary.fingerprint);
  int earliestCertification(_Part part) {
    final times = [
      for (final packet in part.signatures.values)
        if (parseSignature(packet.body) case final s when isSelf(s) && s.type >= 0x10 && s.type <= 0x13) s.created ?? 0,
    ];
    return times.isEmpty ? 1 << 32 : times.reduce((x, y) => x < y ? x : y);
  }

  final userOrder = users.values.toList()
    ..sort((x, y) {
      final byTime = earliestCertification(x).compareTo(earliestCertification(y));
      return byTime != 0 ? byTime : _compareBytes(x.head.encoded, y.head.encoded);
    });
  final subkeyOrder = subkeys.values.toList()
    ..sort((x, y) {
      final byTime = parseKeyPacket(x.head).createdSeconds.compareTo(parseKeyPacket(y.head).createdSeconds);
      return byTime != 0 ? byTime : _compareBytes(parseKeyPacket(x.head).fingerprint, parseKeyPacket(y.head).fingerprint);
    });

  final out = BytesBuilder(copy: false);
  void put(_Part part) {
    out.add(part.head.encoded);
    final signatures = part.signatures.values.toList()
      ..sort((x, y) {
        final byTime = (parseSignature(x.body).created ?? 0).compareTo(parseSignature(y.body).created ?? 0);
        return byTime != 0 ? byTime : _compareBytes(x.body, y.body);
      });
    for (final s in signatures) {
      out.add(s.encoded);
    }
  }

  put(merged);
  userOrder.forEach(put);
  subkeyOrder.forEach(put);
  return out.toBytes();
}

/// What [parts] hold, whatever their order: each packet's tag and body,
/// sorted.
String _content(List<_Part> parts) {
  final all = [
    for (final part in parts) ...[
      '${part.head.tag}:${_id(part.head.body)}',
      for (final s in part.signatures.values) '${s.tag}:${_id(s.body)}',
    ],
  ]..sort();
  return all.join(' ');
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

int _compareBytes(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i].compareTo(b[i]);
  }
  return a.length.compareTo(b.length);
}

/// Whether [grown] is [old] with packets added, as a change or a merge
/// leaves a key: the same primary key, and every packet of [old] in it,
/// matched by tag and body whatever the order (trust, marker and padding
/// packets aside, which a merge drops). Throws a `KeyFormatException` when
/// either does not read.
bool isGrownFrom(Uint8List grown, Uint8List old) {
  final before = _Copy(old);
  final after = _Copy(grown);
  if (!_same(parseKeyPacket(before.primary.head).fingerprint, parseKeyPacket(after.primary.head).fingerprint)) return false;
  final held = _content(after.parts).split(' ').toSet();
  return _content(before.parts).split(' ').every(held.contains);
}

/// Whether what [merged] holds beyond [held], two copies of one key, is the
/// primary key's own doing: every signature it adds that names the primary
/// key as its maker, or names none, verifies against it, and every user ID
/// and subkey it adds comes with a certification or binding that does.
///
/// For a copy from outside, a file or pasted text: [mergePgpKeys] takes
/// what the other side holds as it is, and the key's user IDs, expiry,
/// flags and revocation are read from its latest self-signatures, so a
/// copy made by somebody else could otherwise put an address in the key,
/// expire it or revoke it. A certification by another key is not read for
/// any of these and is kept unchecked, and so are a photo's signatures; a
/// version 3 signature, which names no maker the reader sees, must verify
/// as the others do. Throws a `KeyFormatException` when either does not
/// read.
Future<bool> verifiesWhatItAdds(Uint8List merged, Uint8List held) async {
  final before = _Copy(held);
  final after = _Copy(merged);
  final primary = parseKeyPacket(after.primary.head);
  if (!_same(primary.fingerprint, parseKeyPacket(before.primary.head).fingerprint)) return false;
  final primaryBytes = hashedKey(primary);

  /// Whether the signatures [part] adds to [old] verify over [covered], and
  /// a part [old] lacks comes with one of a type [vouches] for.
  Future<bool> checked(_Part part, _Part? old, List<int>? covered, bool Function(int type) vouches) async {
    var vouched = old != null || covered == null;
    for (final MapEntry(key: id, value: packet) in part.signatures.entries) {
      if (old != null && old.signatures.containsKey(id)) continue;
      final signature = parseSignature(packet.body);
      if (covered == null || !signature.issuedBy(primary.fingerprint)) continue;
      if (!await verifySignature(signature, primary, covered)) return false;
      if (vouches(signature.type)) vouched = true;
    }
    return vouched;
  }

  if (!await checked(after.primary, before.primary, primaryBytes, (_) => true)) return false;
  for (final MapEntry(:key, :value) in after.users.entries) {
    final covered = value.head.tag == PgpTag.userId ? [...primaryBytes, ...hashedUserId(value.head.body)] : null;
    if (!await checked(value, before.users[key], covered, (type) => type >= 0x10 && type <= 0x13)) return false;
  }
  for (final MapEntry(:key, :value) in after.subkeys.entries) {
    final covered = [...primaryBytes, ...hashedKey(parseKeyPacket(value.head))];
    if (!await checked(value, before.subkeys[key], covered, (type) => type == 0x18)) return false;
  }
  return true;
}
