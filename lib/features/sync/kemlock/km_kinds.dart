/// One `kem1` item per entry, its JSON the entry's own (add-kemlock-server-sync,
/// design 3). An entry becomes an item whose plaintext is its `toJson()`, so the
/// keys of later versions survive a round trip as they do in sync files. Its
/// kind is decided by its list and, for keys, by the key's kind, which never
/// changes once a key is in the vault:
///
/// | List | Kind |
/// |---|---|
/// | `accounts` | `otp` |
/// | `backupServices` | `backup-codes` |
/// | `keys`, a PGP key | `pgp-key` |
/// | `keys`, an SSH key | `ssh-key` |
/// | `keys`, one holding a certificate | `certificate` |
/// | `keys`, any other | `key` |
/// | `notes` | `note` |
/// | `passkeys` | `passkey` |
/// | `keyAccounts` | `key-otp` |
/// | `contacts` | `contact` |
/// | `logins` | `login` |
/// | `cards` | `card` |
/// | `identities` | `identity` |
///
/// The kind sits in the item's additional data, so the server can't relabel
/// an item. `key`, `key-otp` and `contact` are not in `crypto.md` yet; the
/// server takes any kind of 1 to 64 characters, and the names are a contract
/// with it, the web vault and Amethystora Vault. A kind this version doesn't
/// know (a later one) is never decoded, deleted or written: it passes
/// through the cache untouched.
///
/// An id that isn't a UUID, such as 0.1.0's `acc-1`, is sent as the UUID
/// `crypto.md`'s "Legacy ids" gives (`legacy_ids.dart`); the entry's JSON keeps
/// its own id, and the merge pairs copies by it.
///
/// Pure Dart, no Flutter.
library;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/legacy_ids.dart';
import '../../../models/vault_key.dart' show KeyKind, VaultKey;
import '../sync_merge.dart';

/// The kind names of items.
abstract final class KmKind {
  // In `crypto.md`
  static const login = 'login';
  static const otp = 'otp';
  static const note = 'note';
  static const backupCodes = 'backup-codes';
  static const passkey = 'passkey';
  static const pgpKey = 'pgp-key';
  static const sshKey = 'ssh-key';
  static const certificate = 'certificate';
  static const card = 'card';
  static const identity = 'identity';

  // Not in `crypto.md` yet
  static const key = 'key';
  static const keyOtp = 'key-otp';
  static const contact = 'contact';

  /// The anchors of the account's server spaces (`SpaceAnchors`): one item owned by the user, so the account's
  /// devices carry them to each other. It is no entry: a run reads and writes it apart from the lists
  /// (`KmScopeSync`), and `kmKnowsKind` is false for it.
  // server: to confirm
  static const spaceAnchors = 'space-anchors';

  /// Marks a moved WebDAV space as complete on the server (`space_bridge.dart`): one item owned by the space, written
  /// once by the Owner's app when the move's read-back matched. Only its existence is read, so a build that doesn't know the
  /// kind passes it through untouched. It is no entry.
  // server: to confirm
  static const bridgeOpen = 'space-bridge';

  /// Marks the WebDAV copy of a moved space as closed by its Owner: written once, and read by existence like [bridgeOpen].
  // server: to confirm
  static const bridgeClosed = 'space-bridge-closed';
}

/// The ids the two bridge markers have in the sync's own id scheme: `kmItemId` of one under the space's owner is the item's
/// UUID, the same in every member's app.
const kmBridgeOpenId = 'space-bridge';
const kmBridgeClosedId = 'space-bridge-closed';

/// The id the anchors item has in the sync's own id scheme: `kmItemId` of it is the item's UUID, the same on every
/// device of the account.
const kmSpaceAnchorsEntryId = 'space-anchors';

/// The `SyncDoc` list each kind this version knows belongs to.
const _listOfKind = {
  KmKind.otp: 'accounts',
  KmKind.backupCodes: 'backupServices',
  KmKind.pgpKey: 'keys',
  KmKind.sshKey: 'keys',
  KmKind.certificate: 'keys',
  KmKind.key: 'keys',
  KmKind.note: 'notes',
  KmKind.passkey: 'passkeys',
  KmKind.keyOtp: 'keyAccounts',
  KmKind.contact: 'contacts',
  KmKind.login: 'logins',
  KmKind.card: 'cards',
  KmKind.identity: 'identities',
};

/// The lists of a sync document, in the order its JSON writes them.
const _lists = ['accounts', 'backupServices', 'keys', 'notes', 'passkeys', 'keyAccounts', 'contacts', 'logins', 'cards', 'identities'];

/// Whether this version reads items of [kind].
bool kmKnowsKind(String kind) => _listOfKind.containsKey(kind);

/// The kind a key whose JSON is [json] is stored as.
String _kindOfKey(Map<String, Object?> json) => switch (json['kind']) {
  KeyKind.pgp => KmKind.pgpKey,
  KeyKind.ssh => KmKind.sshKey,
  _ when json['certificate'] != null => KmKind.certificate,
  _ => KmKind.key,
};

/// An entry as an item holds it: its kind and its own JSON.
typedef KmEntry = ({String kind, Map<String, Object?> json});

/// The app's id of an entry: the `id` its JSON holds.
String kmEntryId(KmEntry entry) => entry.json['id'] as String;

/// The item id of the entry with the app's id [entryId], for [owner]: the id itself when it is a UUID, else
/// the legacy-id UUID.
String kmItemId(String entryId, Owner owner) => itemUuid(entryId, owner);

/// Every entry of [lists] as an item holds it.
List<KmEntry> kmEntriesOf(Lists lists) => [
  for (final account in lists.accounts) (kind: KmKind.otp, json: account.toJson()),
  for (final service in lists.backupServices) (kind: KmKind.backupCodes, json: service.toJson()),
  for (final key in lists.keys) _keyEntry(key),
  for (final note in lists.notes) (kind: KmKind.note, json: note.toJson()),
  for (final passkey in lists.passkeys) (kind: KmKind.passkey, json: passkey.toJson()),
  for (final account in lists.keyAccounts) (kind: KmKind.keyOtp, json: account.toJson()),
  for (final contact in lists.contacts) (kind: KmKind.contact, json: contact.toJson()),
  for (final login in lists.logins) (kind: KmKind.login, json: login.toJson()),
  for (final card in lists.cards) (kind: KmKind.card, json: card.toJson()),
  for (final identity in lists.identities) (kind: KmKind.identity, json: identity.toJson()),
];

KmEntry _keyEntry(VaultKey key) {
  final json = key.toJson();
  return (kind: _kindOfKey(json), json: json);
}

/// Whether [json], an item's plaintext of [kind], is an entry this version can read: an object with the
/// `id` of an item of this [owner]'s, `itemId`. An entry whose id doesn't map to its item's id is not
/// the item's: the pairing by id would be spoofed.
bool kmReadable(String kind, Object? json, String itemId, Owner owner) {
  if (!kmKnowsKind(kind) || json is! Map<String, Object?>) return false;
  final id = json['id'];
  if (id is! String || id.isEmpty) return false;
  try {
    return kmItemId(id, owner) == itemId;
  } on MalformedException {
    return false;
  }
}

/// A sync document of [entries], each in the list of its kind, with the deletions [deleted]. An entry of
/// a kind this version doesn't know is left out.
SyncDoc kmDocOf(Iterable<KmEntry> entries, {List<Tombstone> deleted = const []}) {
  final lists = {for (final name in _lists) name: <Map<String, Object?>>[]};
  for (final entry in entries) {
    final list = _listOfKind[entry.kind];
    if (list != null) lists[list]!.add(entry.json);
  }
  return SyncDoc.fromJson({
    ...lists,
    'deleted': [for (final tombstone in deleted) tombstone.toJson()],
  });
}
