// What the public key of a contact holds, and which of a file's contacts are sound, without Flutter: the part of the app's
// `contact_standing.dart` and `contact_keys.dart` that an import needs. The app should switch to this copy later.
import '../../crypto/bytes.dart';
import '../../crypto/keys/keys.dart' as crypto;
import '../../models/contact.dart';

/// What the key of [contact] holds, or null when it can't be read or the contact has none.
crypto.PgpKeyInfo? contactKeyInfo(Contact contact) {
  if (!contact.hasKey) return null;
  try {
    return crypto.readPgpKeyInfo(unb64(contact.publicKey));
  } on crypto.KeyFormatException {
    return null;
  } on FormatException {
    return null;
  }
}

/// The contacts of [contacts] whose key passes the checks a key is read
/// with, each holding its key as that reading gives it: a file is outside
/// input, so what an import brings is read again with [read] before it is
/// kept. One whose key fails, or holds anything but one key, is left out. A contact with no key has none to check, and
/// stays as it is.
Future<List<Contact>> soundContacts(List<Contact> contacts, Future<List<crypto.PgpPublicKey>> Function(Object input) read) async {
  final sound = <Contact>[];
  for (final contact in contacts) {
    if (!contact.hasKey) {
      sound.add(contact);
      continue;
    }
    try {
      final keys = await read(unb64(contact.publicKey));
      if (keys.length == 1) sound.add(contact.copyWith(publicKey: b64(keys.single.bytes)));
    } on crypto.KeyFormatException {
      continue;
    } on FormatException {
      continue;
    }
  }
  return sound;
}
