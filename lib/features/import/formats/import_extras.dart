// What a foreign import tells the person besides its entries: what it
// skipped and why, what it kept with a caveat, and the places its entries
// can go. Pure Dart; the sheet turns each reason into a message.

/// Why a credential or an item wasn't imported.
enum SkipReason {
  /// A file: neither hand-off carries its bytes.
  file,
  wifi,
  apiKey,
  generatedPassword,
  itemReference,

  /// A credential type this version doesn't know; [ImportSkip.detail] names it.
  unknownType,

  /// A required part is missing, or holds a value the format doesn't list.
  unreadable,

  /// A code with an algorithm Kemlock can't generate.
  totpAlgorithm,

  /// A code with a number of digits Kemlock can't generate.
  totpDigits,

  /// A code whose secret isn't Base32.
  totpSecret,

  /// A passkey whose key isn't an ES256 (P-256) key; [ImportSkip.detail] names the kind.
  passkeyAlgorithm,

  /// A passkey whose key is over the size limit or can't be decoded.
  passkeyKey,

  /// An SSH key that is over the size limit, can't be read, or has no OpenSSH form.
  sshKey,

  /// An item with nothing in it.
  nothingKept,
}

/// A credential or item left out, with the item's title.
class ImportSkip {
  const ImportSkip(this.title, this.reason, {this.detail});

  /// The title of the item it was in.
  final String title;
  final SkipReason reason;

  /// A file's name, an unknown type's name or a key's kind, when the reason has one.
  final String? detail;

  @override
  bool operator ==(Object other) => other is ImportSkip && other.title == title && other.reason == reason && other.detail == detail;

  @override
  int get hashCode => Object.hash(title, reason, detail);

  @override
  String toString() => 'ImportSkip(${reason.name})';
}

/// What an entry was kept with, or without.
enum NoticeReason {
  /// A passkey kept without the extra secrets (PRF, credential and large
  /// blobs) its exporter held: Kemlock's authenticator doesn't serve them.
  passkeyExtras,
}

class ImportNotice {
  const ImportNotice(this.title, this.reason);

  final String title;
  final NoticeReason reason;

  @override
  bool operator ==(Object other) => other is ImportNotice && other.title == title && other.reason == reason;

  @override
  int get hashCode => Object.hash(title, reason);

  @override
  String toString() => 'ImportNotice(${reason.name})';
}

/// A place the preview asks about: an exported account, or a collection
/// shared with other people in the old app.
class ImportUnit {
  const ImportUnit({required this.id, required this.name, this.shared = false});

  final String id;

  /// What it is called for people: the account's name, or the collection's.
  final String name;

  /// A shared collection, which gets a new space preselected.
  final bool shared;

  @override
  bool operator ==(Object other) => other is ImportUnit && other.id == id && other.name == name && other.shared == shared;

  @override
  int get hashCode => Object.hash(id, name, shared);

  @override
  String toString() => 'ImportUnit($id)';
}
