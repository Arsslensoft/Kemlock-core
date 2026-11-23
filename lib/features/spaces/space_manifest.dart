// The space's signed manifest (docs/plans/add-server-spaces.md, design 4a), built on the
// account crypto's manifest (`crypto/account/manifest.dart`, `manifest_compare.dart`): a signed
// list of every item of the space, so a member sees a withheld or rolled-back item even in a
// collection they can't open.
//
// - **Who signs.** A confirmed member the verified chain lets write items. The server's rule is
//   its own: edit on at least one collection, through a grant, since owners and admins read and
//   write a collection's items only through a grant like anyone else (kemlock-domain's spaces.rs,
//   `authorize_item_write`). The design said Owner, Admin or an edit or manage grant; the server wins.
//   A manifest signed by anyone else, or by a key the chain doesn't confirm, is refused.
// - **What it lists.** Every item of the space, every collection's, each with its revision and the
//   SHA-256 of its ciphertext, or 32 zero bytes for a tombstone. It doesn't cover only what the
//   signer can open. The signer leaves out an item it holds back as unlisted.
// - **What a member checks.** Presence and revision for every entry, and the ciphertext hash, against
//   the envelopes received, whether or not they hold the collection's key. Contents only for the
//   collections they hold, which the sync run decides. So a member granted only Engineering still
//   notices a Finance item withheld or rolled back, and a full sync of a partly granted member doesn't
//   stop on items it can't open.
// - **When it is signed.** At the end of each run that wrote to the space, by the writing device, and
//   after a key replacement's last batch.
// - **Unlisted items** are held and flagged: a removed member writing with a key kept from before the
//   replacement is listed by no permitted signer.
//
// server: to confirm
// The server's manifest route keeps only an account's own manifest today (`"manifests of spaces are not
// kept by this route yet"`). The shape to follow is the coordinator's: PUT and GET
// /kem/v1/manifests/space:<id>, the same route as the user one; PUT needs edit rights on at least one
// collection and answers 423 while the space waits for new keys; GET works for any confirmed member and
// a stranger gets 404; counters are per owner. The sync run builds against a fake until it lands.
//
// Pure Dart, no Flutter.

library;

import 'dart:typed_data';

import '../../crypto/account/encoding.dart';
import '../../crypto/account/manifest.dart';
import '../../crypto/account/manifest_compare.dart';
import 'space_state.dart';

/// The signature work a space manifest needs, so a test can put cheap signatures in place of `sig1`'s.
abstract interface class SpaceManifestCrypto {
  /// The signature of [manifest] with the signer's `sig1` private key.
  Future<Uint8List> sign(Manifest manifest, Uint8List sig1PrivateKey);

  /// Reads [bytes] as a manifest when [signature] is by [signerPublicKey]: a [MalformedException] for bytes that
  /// aren't a manifest, a [CorruptedException] for a signature that doesn't verify.
  Future<Manifest> verify(Uint8List bytes, Uint8List signature, Uint8List signerPublicKey);
}

/// [SpaceManifestCrypto] with `sig1`, under the context "manifest".
final class RealSpaceManifestCrypto implements SpaceManifestCrypto {
  const RealSpaceManifestCrypto();

  @override
  Future<Uint8List> sign(Manifest manifest, Uint8List sig1PrivateKey) => signManifest(manifest, sig1PrivateKey);

  @override
  Future<Manifest> verify(Uint8List bytes, Uint8List signature, Uint8List signerPublicKey) =>
      verifyManifest(bytes, signature, signerPublicKey);
}

/// Whether [member] may write the space's items, and so sign its manifest: confirmed, with edit on at least one
/// collection through a grant.
bool mayWriteItems(SpaceState state, String member) {
  final record = state.member(member);
  if (record == null || !record.isConfirmed) {
    return false;
  }
  return state.collections.keys.any((collection) => state.accessOf(member, collection)?.edit ?? false);
}

/// The space's manifest as the server serves it: the exact bytes, the signature and the account that signed.
final class FetchedSpaceManifest {
  FetchedSpaceManifest({required List<int> manifest, required List<int> signature, required this.signer})
    : manifest = copyBytes(manifest),
      signature = copyBytes(signature);

  final Uint8List manifest;
  final Uint8List signature;

  /// The account whose bundle's `sig1` key made the signature.
  final String signer;
}

/// Why a space's manifest is refused.
enum SpaceManifestProblem {
  /// Signed by someone the verified chain doesn't confirm, or who may not write the space's items.
  signerNotAllowed,

  /// The signature doesn't verify under the signer's recorded key.
  badSignature,

  /// Not a manifest, or one of another owner.
  malformed,

  /// Counts less than the one this device verified.
  rolledBack,

  /// The server no longer has the manifest this device held.
  vanished,
}

/// What checking the server's manifest found.
final class SpaceManifestCheck {
  const SpaceManifestCheck({required this.manifest, this.findings = const [], this.newer = false, this.problem, this.detail});

  /// The manifest the answer was compared with: the server's, the one this device held, or an empty one.
  final Manifest manifest;

  /// One finding for each item of the answer and each listed item it lacks.
  final List<ItemFinding> findings;

  /// Whether the server's manifest is newer than the one held: keep it.
  final bool newer;

  /// Set when the manifest is refused: the run stops, keeps what it had, and the space shows as older data.
  final SpaceManifestProblem? problem;
  final String? detail;
}

/// Checks the manifest the server holds for the space against every item of the answer.
///
/// [state] is the verified chain's state, which says who may sign. [record] is the highest manifest this device
/// verified, [deleted] the ids it saw deleted and [answer] every item of the space the server sent, whether or not
/// the device can open its collection. [fetched] is null when the server has no manifest for the space.
Future<SpaceManifestCheck> checkSpaceManifest({
  required SpaceState state,
  required Owner owner,
  required FetchedSpaceManifest? fetched,
  required ManifestRecord? record,
  required DeletedItems deleted,
  required Iterable<ServerItemState> answer,
  required SpaceManifestCrypto crypto,
}) async {
  Manifest? candidate;
  if (fetched != null) {
    final signer = state.member(fetched.signer);
    final bundle = signer?.bundle;
    if (signer == null || bundle == null || !mayWriteItems(state, signer.id)) {
      return SpaceManifestCheck(
        manifest: record?.manifest ?? Manifest(owner: owner, counter: 0, entries: const []),
        problem: SpaceManifestProblem.signerNotAllowed,
        detail: '${fetched.signer} may not sign this space\'s manifest',
      );
    }
    try {
      candidate = await crypto.verify(fetched.manifest, fetched.signature, bundle.sig1PublicKey);
    } on CorruptedException {
      return _refused(record, owner, SpaceManifestProblem.badSignature, 'the manifest signature does not verify');
    } on MalformedException {
      return _refused(record, owner, SpaceManifestProblem.malformed, 'the manifest is malformed');
    }
    if (candidate.owner != owner) {
      return _refused(record, owner, SpaceManifestProblem.malformed, 'a manifest of another owner');
    }
  } else if (record != null) {
    return _refused(record, owner, SpaceManifestProblem.vanished, 'the server no longer has the manifest it had');
  }

  var current = candidate ?? record?.manifest ?? Manifest(owner: owner, counter: 0, entries: const []);
  var newer = false;
  if (candidate != null) {
    switch (checkManifest(record, candidate)) {
      case ManifestVerdict.rolledBack:
        return _refused(record, owner, SpaceManifestProblem.rolledBack, 'the manifest counts less than one this device verified');
      case ManifestVerdict.newer:
        newer = true;
      case ManifestVerdict.same:
        break;
      case ManifestVerdict.fork:
        // Two members signed one counter: the higher revision of each item, and the next write signs above both
        current = mergeSameCounter(record!.manifest, candidate);
    }
  }
  return SpaceManifestCheck(
    manifest: current,
    newer: newer,
    findings: compareItems(manifest: current, deleted: deleted, answer: answer),
  );
}

SpaceManifestCheck _refused(ManifestRecord? record, Owner owner, SpaceManifestProblem problem, String detail) => SpaceManifestCheck(
  manifest: record?.manifest ?? Manifest(owner: owner, counter: 0, entries: const []),
  problem: problem,
  detail: detail,
);

/// The manifest to sign: every item of the space in [items], whatever its collection, one entry each, above the
/// highest [counter] this device saw. The caller leaves out the items it holds back as unlisted.
Manifest buildSpaceManifest({required Owner owner, required int counter, required Iterable<ServerItemState> items}) => Manifest(
  owner: owner,
  counter: counter,
  entries: [
    for (final item in items)
      ManifestEntry(itemId: item.itemId, revision: item.revision, ciphertextHash: item.ciphertextHash, deleted: item.deleted),
  ],
);
