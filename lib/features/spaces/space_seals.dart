// Keys and seals through the chain (the space chain section of docs/crypto.md, "Commitments" and "Using the
// state"). The chain never holds a sealed key: it holds the hash of every box a record published, the digest of
// those hashes and the check of each key version. A client opens a key only through them:
//
//   seal hash = SHA-256(box)
//   digest    = SHA-256("kemlock/v1/space-chain/seals" || space id (16) || key ref || u32be(key version)
//                       || u32be(n) || n x (account id (16) || u32be(bundle key version) || seal hash (32)))
//   check     = HKDF(ikm = key, salt = absent,
//                    info = "kemlock/v1/space-chain/key-check" || space id (16) || key ref || u32be(key version), L = 32)
//
// with the recipients in ascending order of account id. `openCommittedKey` takes the key at the chain's current
// version only, never the version the server names; the box must be the one the chain committed, must open under
// the committed bundle version with the aad of space_keys.dart, and the key must have the chain's check.
// `sealKeyTo` and `buildSealRecord` are the other side: a holder seals to the members Awaiting gives, and publishes
// the boxes with a `seal` record.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../crypto/account/bundle.dart';
import '../../crypto/account/encoding.dart';
import '../../crypto/bytes.dart';
import '../../crypto/hkdf.dart';
import 'chain_body.dart' show SealCommitment;
import 'space_chain.dart';
import 'space_keys.dart';
import 'space_state.dart';

const _sealsLabel = 'kemlock/v1/space-chain/seals';
const _checkLabel = 'kemlock/v1/space-chain/key-check';

/// One recipient of a commitment: the account, the bundle key version its box is to and the hash of the box.
typedef SealRecipient = ({String account, int bundleVersion, Uint8List sealHash});

/// `SHA-256(box)`.
Uint8List sealHashOf(List<int> box) => Uint8List.fromList(hash.sha256.convert(box).bytes);

/// The digest of the seals of [key] at [version] to [recipients], who are put in ascending order of account id.
Uint8List sealsDigest({required String space, required KeyRef key, required int version, required List<SealRecipient> recipients}) {
  final sorted = [...recipients]..sort((a, b) => a.account.compareTo(b.account));
  return Uint8List.fromList(
    hash.sha256
        .convert(
          concatBytes([
            label(_sealsLabel),
            uuidBytes(space),
            key.bytes,
            u32be(version),
            u32be(sorted.length),
            for (final recipient in sorted) ...[uuidBytes(recipient.account), u32be(recipient.bundleVersion), recipient.sealHash],
          ]),
        )
        .bytes,
  );
}

/// The check of [key] at [version]: what lets every recipient see that the key they opened is that version's key and
/// not another a holder sealed them.
Uint8List keyCheckOf({required Uint8List key, required String space, required KeyRef ref, required int version}) =>
    hkdfSha256(key, salt: const [], info: concatBytes([label(_checkLabel), uuidBytes(space), ref.bytes, u32be(version)]), length: 32);

/// One element of the server's seal hash list for a record (`GET /kem/v1/spaces/{id}/chain/{seq}/seals`).
final class ChainSealHash {
  ChainSealHash({required this.bundleVersion, required this.key, required this.member, required List<int> sealHash, required this.version})
    : sealHash = copyBytes(requireLength(sealHash, 32, 'a seal hash'));

  factory ChainSealHash.fromJson(Object? json) {
    final fields = strictObject(json, required: {'bundleVersion', 'key', 'member', 'sealHash', 'version'});
    final bundleVersion = fields['bundleVersion'];
    final version = fields['version'];
    final key = fields['key'];
    final member = fields['member'];
    final sealHash = fields['sealHash'];
    if (bundleVersion is! int || version is! int || key is! String || member is! String || sealHash is! String || !isUuidText(member)) {
      throw const MalformedException('a seal hash is a key, a member, two versions and a hash');
    }
    return ChainSealHash(
      bundleVersion: bundleVersion,
      key: KeyRef.parse(key),
      member: member,
      sealHash: b64urlDecode(sealHash),
      version: version,
    );
  }

  final int bundleVersion;
  final KeyRef key;
  final String member;
  final Uint8List sealHash;
  final int version;
}

/// What opening a key through the chain gave: the key, or null and why not, for the logs.
typedef OpenedKey = ({Uint8List? key, String? why});

/// Opens [box], the box the server served to [member] for [key], through the chain's commitment.
///
/// The key is the chain's current version of [key]. The box is accepted only when (1) the commitment at the seal's
/// `seq` covers just this member and the digest recomputed from the box is the committed one, or [hashes], the
/// server's list for that `seq`, names exactly the recipients the chain gives, with their bundle versions, holds
/// `SHA-256` of this box for this member and gives the committed digest; (2) the box opens with the `aad` under
/// [kx1PrivateKey], which is of [bundleVersion], the bundle version the chain committed; and (3) the key's check is
/// the chain's.
Future<OpenedKey> openCommittedKey({
  required SpaceState state,
  required KeyRef key,
  required String member,
  required Uint8List kx1PrivateKey,
  required int bundleVersion,
  required Uint8List box,
  List<ChainSealHash>? hashes,
}) async {
  OpenedKey no(String why) => (key: null, why: '${key.wire}: $why');
  final version = state.keyVersionOf(key);
  final seal = state.sealOf(key, member);
  if (version == null || seal == null) {
    return no('the chain has no seal of this key for $member');
  }
  if (seal.bundleVersion != bundleVersion) {
    return no('the chain sealed it to bundle version ${seal.bundleVersion}, and this device holds version $bundleVersion');
  }
  final commitment = state.commitmentsOf(key).where((record) => record.seq == seal.seq).firstOrNull;
  if (commitment == null) {
    return no('the chain has no commitment at seq ${seal.seq}');
  }
  final own = sealHashOf(box);
  final List<SealRecipient> recipients;
  if (commitment.count == 1 && commitment.recipients.length == 1) {
    recipients = [(account: member, bundleVersion: seal.bundleVersion, sealHash: own)];
  } else {
    final listed = [
      for (final item in hashes ?? const <ChainSealHash>[])
        if (item.key == key && item.version == version) item,
    ];
    final accounts = {for (final item in listed) item.member};
    final exact =
        listed.length == commitment.recipients.length &&
        accounts.length == listed.length &&
        listed.every((item) => commitment.recipients[item.member] == item.bundleVersion);
    if (!exact) {
      return no('the server\'s seal hash list is not the recipients the chain gives');
    }
    final mine = listed.firstWhere((item) => item.member == member);
    if (!constantTimeEquals(mine.sealHash, own)) {
      return no('the box is not the one the server\'s list hashes');
    }
    recipients = [for (final item in listed) (account: item.member, bundleVersion: item.bundleVersion, sealHash: item.sealHash)];
  }
  final digest = sealsDigest(space: state.space, key: key, version: version, recipients: recipients);
  if (!constantTimeEquals(digest, commitment.digest)) {
    return no('the box is not the one the chain committed');
  }
  final Uint8List opened;
  try {
    opened = key.isSpace
        ? await openSpaceKey(box: box, kx1PrivateKey: kx1PrivateKey, space: state.space, keyVersion: version, member: member)
        : await openCollectionKey(
            box: box,
            kx1PrivateKey: kx1PrivateKey,
            space: state.space,
            collection: key.collection!,
            keyVersion: version,
            member: member,
          );
  } on CorruptedException {
    return no('the box does not open');
  } on MalformedException {
    return no('the box does not open');
  }
  final expected = state.keyCheck(key);
  if (expected == null || !constantTimeEquals(keyCheckOf(key: opened, space: state.space, ref: key, version: version), expected)) {
    wipe(opened);
    return no('the key is not the one whose check the chain holds');
  }
  return (key: opened, why: null);
}

/// What [SpaceKeyring] needs from the server: the box it served for the space key and for each collection key, and the
/// seal hash lists by `seq` for the commitments that cover more than one member.
typedef SealHashesAt = Future<List<ChainSealHash>> Function(int seq);

/// Opens every key [member] holds in [state], at the chain's current versions and through its commitments: the space
/// key from [spaceKeyBox], and for each collection the chain has [member] hold, its box among [collectionBoxes] (by
/// collection and key version, as the server serves them, of which only the chain's current version is used). A key
/// that doesn't open leaves only that key out, and its collection is named in `unreadable`.
Future<SpaceKeyring> openKeyringFromChain({
  required SpaceState state,
  required String member,
  required Uint8List kx1PrivateKey,
  required int bundleVersion,
  Uint8List? spaceKeyBox,
  List<SealedCollectionKey> collectionBoxes = const [],
  required SealHashesAt hashesAt,
  void Function(String problem)? log,
}) async {
  final cache = <int, List<ChainSealHash>>{};
  Future<OpenedKey> open(KeyRef key, Uint8List box) async {
    final seal = state.sealOf(key, member);
    List<ChainSealHash>? hashes;
    if (seal != null) {
      final commitment = state.commitmentsOf(key).where((record) => record.seq == seal.seq).firstOrNull;
      if (commitment != null && commitment.recipients.length > 1) {
        hashes = cache[seal.seq] ??= await hashesAt(seal.seq);
      }
    }
    final opened = await openCommittedKey(
      state: state,
      key: key,
      member: member,
      kx1PrivateKey: kx1PrivateKey,
      bundleVersion: bundleVersion,
      box: box,
      hashes: hashes,
    );
    if (opened.key == null && log != null) {
      log(opened.why!);
    }
    return opened;
  }

  Uint8List? spaceKey;
  if (spaceKeyBox != null) {
    spaceKey = (await open(const KeyRef.space(), spaceKeyBox)).key;
  }
  final held = <String, Map<int, Uint8List>>{};
  final unreadable = <String>{};
  for (final collection in state.collections.keys) {
    if (state.sealOf(KeyRef.collection(collection), member) == null) {
      continue;
    }
    final version = state.keyVersionOf(KeyRef.collection(collection))!;
    final copy = collectionBoxes.where((item) => item.collection == collection && item.keyVersion == version).firstOrNull;
    final opened = copy == null ? null : (await open(KeyRef.collection(collection), copy.sealed)).key;
    if (opened == null) {
      unreadable.add(collection);
    } else {
      held[collection] = {version: opened};
    }
  }
  return SpaceKeyring.fromKeys(
    space: state.space,
    member: member,
    spaceKeyVersion: state.spaceKeyVersion,
    spaceKey: spaceKey,
    collectionKeys: held,
    unreadable: unreadable,
  );
}

/// The boxes and the commitment of one key version sealed to [recipients], by account: each is sealed to the `kx1` key
/// of the bundle the chain recorded for them. [makes] gives the commitment its key check, for a new key version.
Future<({SealCommitment commitment, Map<String, Uint8List> boxes})> sealKeyTo({
  required String space,
  required KeyRef key,
  required int version,
  required Uint8List keyBytes,
  required Map<String, KeyBundle> recipients,
  required bool makes,
}) async {
  final boxes = <String, Uint8List>{};
  for (final entry in recipients.entries) {
    boxes[entry.key] = key.isSpace
        ? await sealSpaceKey(to: entry.value, key: keyBytes, space: space, keyVersion: version)
        : await sealCollectionKey(to: entry.value, key: keyBytes, space: space, collection: key.collection!, keyVersion: version);
  }
  final digest = sealsDigest(
    space: space,
    key: key,
    version: version,
    recipients: [
      for (final entry in recipients.entries)
        (account: entry.key, bundleVersion: entry.value.keyVersion, sealHash: sealHashOf(boxes[entry.key]!)),
    ],
  );
  return (
    commitment: SealCommitment(
      key: key,
      version: version,
      count: recipients.length,
      digest: digest,
      check: makes ? keyCheckOf(key: keyBytes, space: space, ref: key, version: version) : null,
    ),
    boxes: boxes,
  );
}

/// A `seal` record by [signer] that shares each of [keys] (the key bytes this device holds, by key) with the members
/// Awaiting gives for it in [state], and the boxes it commits, by key and account. Null when nobody awaits any of
/// them, or a key is marked: a marked key is replaced, not shared.
Future<({SpaceChainEntry entry, Map<KeyRef, Map<String, Uint8List>> boxes})?> buildSealRecord({
  required SpaceState state,
  required String signer,
  required Map<KeyRef, Uint8List> keys,
  required int at,
}) async {
  final commitments = <SealCommitment>[];
  final boxes = <KeyRef, Map<String, Uint8List>>{};
  final ordered = keys.keys.toList()..sort((a, b) => a.wire.compareTo(b.wire));
  for (final key in ordered) {
    final awaiting = state.awaiting(key);
    final version = state.keyVersionOf(key);
    if (awaiting.isEmpty || version == null || state.isMarked(key) || state.spaceKeyMarked) {
      continue;
    }
    final sealed = await sealKeyTo(
      space: state.space,
      key: key,
      version: version,
      keyBytes: keys[key]!,
      recipients: {for (final account in awaiting) account: state.member(account)!.bundle!},
      makes: false,
    );
    commitments.add(sealed.commitment);
    boxes[key] = sealed.boxes;
  }
  if (commitments.isEmpty) {
    return null;
  }
  final entry = SpaceChainEntry(
    space: state.space,
    seq: state.nextSeq,
    prev: state.headHash ?? chainGenesisLink,
    epoch: state.epoch,
    at: at,
    by: signer,
    kind: ChainKind.seal,
    body: {
      'seals': [for (final commitment in commitments) commitment.toJson()],
    },
  );
  return (entry: entry, boxes: boxes);
}
