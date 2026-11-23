// What a record of a space's chain does, and why a record or a chain is refused (the space chain
// section of docs/crypto.md, "Kinds" and "Verification").
//
// Pure Dart, no Flutter.

library;

/// What a record does. The wire names are the record's `kind`. There are 21.
enum ChainKind {
  /// Makes the space: its maker as Owner, its first collection and their keys. Only as `seq` 0.
  create('create'),

  /// Invites an account with a role, and grants it collections.
  invite('invite'),

  /// Confirms an invited member, or a confirmed member's newer bundle, after a fingerprint comparison.
  confirm('confirm'),

  /// A member replaces their own bundle, signed by the old key and the new.
  rekey('rekey'),

  /// Changes a member's role or Custom permissions, making an Owner included.
  role('role'),

  /// Removes a member, or a member leaves.
  remove('remove'),

  /// Sets a grant.
  grant('grant'),

  /// Takes a grant away.
  ungrant('ungrant'),

  /// Makes a collection.
  collection('collection'),

  /// Moves a collection.
  move('move'),

  /// Deletes a collection.
  collectionDelete('collection-delete'),

  /// Makes a group.
  group('group'),

  /// Changes a group's members.
  groupMembers('group-members'),

  /// Deletes a group.
  groupDelete('group-delete'),

  /// Commits a new name for the space, a collection or a group.
  rename('rename'),

  /// Shares keys a member holds with the members awaiting them.
  seal('seal'),

  /// Replaces keys with new versions.
  keys('keys'),

  /// Sets the space's policies.
  policies('policies'),

  /// Sets the account recovery key.
  recoveryKey('recovery-key'),

  /// Clears the account recovery key.
  recoveryKeyClear('recovery-key-clear'),

  /// Raises the epoch after the home moved.
  fence('fence');

  const ChainKind(this.wire);

  final String wire;

  /// The kind with the wire name [text], or null.
  static ChainKind? fromWire(String text) {
    for (final kind in values) {
      if (kind.wire == text) {
        return kind;
      }
    }
    return null;
  }
}

/// Why a chain, or an entry of it, is not accepted, in the order the checks run. Each is a refusal the app shows as
/// the space "Can't be checked", and keeps the last valid state under.
enum ChainProblem {
  /// Not the shape an entry or its body has.
  malformed,

  /// A record, a list or a chain beyond the limits.
  tooLarge,

  /// An entry of another space.
  wrongSpace,

  /// A sequence number that isn't the next, a missing entry, or a repeated one.
  badSequence,

  /// `prev` isn't the link of the entry before.
  badLink,

  /// An epoch that isn't the current one, or the next one on an Owner's `fence`.
  badEpoch,

  /// The signer isn't a confirmed member whose key the chain records.
  unknownSigner,

  /// A signature doesn't verify under the key the chain records.
  badSignature,

  /// A bundle that isn't the account's own: not signed by its own key, or for another account.
  badBundle,

  /// A confirmation that doesn't cover the member's bundle, or that the confirmer didn't sign.
  badConfirmation,

  /// A change that makes no sense in the state it meets: confirming someone who wasn't invited, a collection that
  /// isn't there, a key version that doesn't follow, a record that changes nothing.
  invalid,

  /// The signer, in the state before, may not make this entry.
  notAllowed,

  /// The server's chain holds another entry at a sequence number this device already accepted, other than at a fence.
  forked,

  /// The server's chain ends before an entry this device already accepted.
  rolledBack,
}

/// A refusal of an entry, with what to tell the logs.
class ChainRefusal implements Exception {
  const ChainRefusal(this.problem, this.detail, {this.index});

  final ChainProblem problem;
  final String detail;

  /// For a refusal of one element of a served array (`parseChain`), its position in the array, which is its `seq` when
  /// the array starts at `seq` 0. Null when the refusal is of the chain as a whole, or of an entry the verifier read.
  final int? index;

  @override
  String toString() => 'ChainRefusal(${problem.name}: $detail)';
}
