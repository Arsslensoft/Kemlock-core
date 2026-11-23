// The signed manifest of `docs/crypto.md` "Signed manifest", which shows
// rollback:
//
//   manifest = "kemlock/v1/manifest" || owner (17) || u64be(counter) || u32be(n)
//              || n x (item id (16) || u64be(revision) || SHA-256(ciphertext) (32) || u8(deleted))
//
// Entries are sorted by item id bytes. A tombstone's hash is 32 zero bytes.
// The writer signs it with `sig1` under the context "manifest". The counter
// only goes up; a device keeps the highest it has seen (manifest_compare.dart
// says how a sync is compared with it).

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../bytes.dart';
import 'encoding.dart';
import 'sig1.dart';

const _manifestLabel = 'kemlock/v1/manifest';

/// One item of a manifest.
final class ManifestEntry {
  ManifestEntry({required List<int> itemId, required this.revision, required List<int> ciphertextHash, required this.deleted})
    : itemId = copyBytes(requireLength(itemId, 16, 'an item id')),
      ciphertextHash = copyBytes(requireLength(ciphertextHash, 32, 'a ciphertext hash')) {
    u64be(revision); // range check
    if (deleted && !_allZero(this.ciphertextHash)) throw const MalformedException('the hash of a tombstone is 32 zero bytes');
  }

  /// The entry of an item at [revision]: the SHA-256 of its [ciphertext], or
  /// a tombstone (32 zero bytes) when [ciphertext] is null.
  factory ManifestEntry.forItem({required List<int> itemId, required int revision, List<int>? ciphertext}) => ManifestEntry(
    itemId: itemId,
    revision: revision,
    ciphertextHash: ciphertext == null ? Uint8List(32) : hash.sha256.convert(ciphertext).bytes,
    deleted: ciphertext == null,
  );

  /// The bytes of one entry: `item id (16) || u64be(revision) || hash (32) || u8(deleted)`.
  static const length = 16 + 8 + 32 + 1;

  final Uint8List itemId;
  final int revision;
  final Uint8List ciphertextHash;
  final bool deleted;

  Uint8List get bytes => concatBytes([itemId, u64be(revision), ciphertextHash, u8(deleted ? 1 : 0)]);
}

/// The manifest of one owner at one counter.
final class Manifest {
  Manifest._(this.owner, this.counter, this.entries);

  /// A manifest for [owner] at [counter], with [entries] sorted by item id.
  /// Two entries for one item are a [MalformedException].
  factory Manifest({required Owner owner, required int counter, required List<ManifestEntry> entries}) {
    u64be(counter); // range check
    final sorted = [...entries]..sort((a, b) => _compare(a.itemId, b.itemId));
    for (var i = 1; i < sorted.length; i++) {
      if (_compare(sorted[i - 1].itemId, sorted[i].itemId) == 0) throw const MalformedException('an item appears twice in a manifest');
    }
    u32be(sorted.length); // range check
    return Manifest._(owner, counter, List.unmodifiable(sorted));
  }

  /// Reads the bytes of a manifest. A wrong label, a length that does not
  /// match `n`, entries out of order or repeated, a `deleted` byte other than
  /// 0 or 1, or trailing bytes are a [MalformedException].
  factory Manifest.parse(List<int> bytes) {
    final reader = ByteReader(bytes);
    final prefix = label(_manifestLabel);
    if (!constantTimeEquals(reader.read(prefix.length, 'the manifest label'), prefix)) throw const MalformedException('not a manifest');
    final owner = Owner.fromBytes(reader.read(17, 'the owner'));
    final counter = _readU64(reader.read(8, 'the counter'));
    final n = reader.readU32('the entry count');
    // Check the length before reading n entries: n can't promise more than is there.
    if (reader.remaining != n * ManifestEntry.length) throw const MalformedException('the entry count does not match the length');
    final entries = <ManifestEntry>[];
    for (var i = 0; i < n; i++) {
      final itemId = reader.read(16, 'an item id');
      final revision = _readU64(reader.read(8, 'a revision'));
      final ciphertextHash = reader.read(32, 'a ciphertext hash');
      final flag = reader.readU8('the deleted byte');
      if (flag > 1) throw const MalformedException('the deleted byte is 0 or 1');
      entries.add(ManifestEntry(itemId: itemId, revision: revision, ciphertextHash: ciphertextHash, deleted: flag == 1));
    }
    reader.finish();
    for (var i = 1; i < entries.length; i++) {
      if (_compare(entries[i - 1].itemId, entries[i].itemId) >= 0) throw const MalformedException('manifest entries are sorted by item id');
    }
    return Manifest._(owner, counter, List.unmodifiable(entries));
  }

  final Owner owner;
  final int counter;

  /// Sorted by item id bytes.
  final List<ManifestEntry> entries;

  /// The bytes that are signed.
  Uint8List get bytes =>
      concatBytes([label(_manifestLabel), owner.bytes, u64be(counter), u32be(entries.length), for (final e in entries) e.bytes]);

  /// SHA-256 of [bytes], which a device keeps beside the highest counter it
  /// verified.
  Uint8List get digest => Uint8List.fromList(hash.sha256.convert(bytes).bytes);

  /// The entry for [itemId], or null.
  ManifestEntry? entryFor(List<int> itemId) {
    for (final entry in entries) {
      if (_compare(entry.itemId, itemId) == 0) return entry;
    }
    return null;
  }
}

/// The signature of [manifest] by the `sig1` private key of its writer, under
/// the context "manifest".
Future<Uint8List> signManifest(Manifest manifest, Uint8List sig1PrivateKey) =>
    Sig1.sign(sig1PrivateKey, manifest.bytes, context: SignContext.manifest);

/// Reads [manifestBytes] and returns the manifest only when [signature] is a
/// valid `sig1` signature of it by [signerPublicKey]. A manifest that is
/// malformed is a [MalformedException]; one whose signature is bad is a
/// [CorruptedException], so a device keeps the manifest it had.
Future<Manifest> verifyManifest(List<int> manifestBytes, Uint8List signature, Uint8List signerPublicKey) async {
  final manifest = Manifest.parse(manifestBytes);
  if (!await Sig1.verify(signerPublicKey, manifestBytes, signature, context: SignContext.manifest)) {
    throw const CorruptedException('the manifest signature does not verify');
  }
  return manifest;
}

int _readU64(Uint8List bytes) {
  final data = ByteData.sublistView(bytes);
  final high = data.getUint32(0);
  if (high > 0x7fffffff) throw const MalformedException('a number over 2^63 is not supported');
  return (high << 32) | data.getUint32(4);
}

int _compare(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

bool _allZero(List<int> bytes) {
  var any = 0;
  for (final b in bytes) {
    any |= b;
  }
  return any == 0;
}
