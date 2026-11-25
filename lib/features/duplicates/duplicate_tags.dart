// An item's duplicate tags (the add-duplicate-cleaner plan, design 2 and 5):
// each of the item's tag inputs from `duplicate_rules.dart`, keyed with the
// owner's dedup key by the builder in `crypto/account/dedup.dart`.
//
// Pure Dart, no Flutter package.
import 'dart:typed_data';

import '../../crypto/account/dedup.dart';
import '../../models/backup_service.dart';
import '../../models/contact.dart';
import '../../models/identity.dart';
import '../../models/login.dart';
import '../../models/otp_account.dart';
import '../../models/passkey.dart';
import '../../models/payment_card.dart';
import '../../models/secure_note.dart';
import '../../models/vault_key.dart';
import 'duplicate_normalise.dart';
import 'duplicate_rules.dart';

/// One tag: its [kind] and the 32 bytes of its HMAC. Two tags are equal when
/// their bytes are, compared in constant time.
final class DuplicateTag {
  DuplicateTag(this.kind, List<int> bytes) : bytes = Uint8List.fromList(bytes) {
    if (bytes.length != dedupTagLength) {
      throw ArgumentError.value(bytes.length, 'bytes', 'a tag is $dedupTagLength bytes');
    }
  }

  final TagKind kind;
  final Uint8List bytes;

  @override
  bool operator ==(Object other) => other is DuplicateTag && other.kind == kind && dedupTagsEqual(other.bytes, bytes);

  // Tags are keyed hashes, so any bytes of one spread as well as the first
  @override
  int get hashCode => Object.hash(kind, bytes[0], bytes[1], bytes[2], bytes[3]);

  @override
  String toString() => 'DuplicateTag(${kind.name})';
}

/// The text that tells a key or a contact, which is the fingerprint of a PGP key. Reading it takes
/// the key apart, so the caller does that; null for an item it can't read, which makes no tag.
typedef KeyIdentityOf = String? Function(Object item);

/// The tag inputs of [item], as its kind makes them; none for an item of a kind with no tags, and
/// for one with nothing to match on. A key or a contact is told by [keyIdentityOf].
List<TagInput> tagInputsOf(Object item, {SiteResolver sites = const SiteResolver(), KeyIdentityOf? keyIdentityOf}) => switch (item) {
  Login() => loginTagInputs(item, sites),
  OtpAccount() => [?codeTagInput(item)],
  Passkey() => [passkeyTagInput(item)],
  PaymentCard() => [?cardTagInput(item)],
  SecureNote() => [?noteTagInput(item)],
  VaultKey() || Contact() => [?keyTagInput(keyIdentityOf?.call(item))],
  BackupService() => [?codesTagInput(item)],
  Identity() => [?identityTagInput(item)],
  _ => const [],
};

/// The tags of [inputs] under [dedupKey].
List<DuplicateTag> makeTags(Iterable<TagInput> inputs, List<int> dedupKey) => [
  for (final input in inputs) DuplicateTag(input.kind, dedupTag(dedupKey, input.kind.name, input.values)),
];

/// The tags of [item] under [dedupKey]: at most [maxTagsPerItem], and none for a kind that has
/// none. The key is the caller's to wipe once the tags are made.
List<DuplicateTag> itemTags(Object item, List<int> dedupKey, {SiteResolver sites = const SiteResolver(), KeyIdentityOf? keyIdentityOf}) =>
    makeTags(tagInputsOf(item, sites: sites, keyIdentityOf: keyIdentityOf), dedupKey);
