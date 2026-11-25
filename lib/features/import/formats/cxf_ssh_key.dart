// A Credential Exchange SSH key as Kemlock keeps it (the
// add-credential-exchange plan, task 1.4). The format sends the private key
// as PKCS#8 and nothing else; the public half is worked out from it by the
// reader the key import already uses, so the key sheet shows the same
// fingerprint and `ssh-keygen -y` line as for a key imported from a file.
import '../../../crypto/bytes.dart';
import '../../../crypto/keys/keys.dart' as crypto;
import '../../../models/json.dart' show unset;
import '../../../models/vault_key.dart';
import '../../keys/key_bridge.dart' show vaultKeyOf;
import 'cxf.dart';
import 'import_extras.dart';

/// What [readCxfSshKey] made of a key: the [key], or the [skip] reason.
typedef CxfSshKeyResult = ({VaultKey? key, SkipReason? skip});

/// Reads [source] into an SSH key named [name] with the id [id], added at
/// [addedAt] (epoch ms). Ed25519, ECDSA (P-256 and P-384) and RSA keys have
/// an OpenSSH form and are kept as SSH keys; a key over 16 KiB, one that
/// can't be read, and any other algorithm are skipped.
Future<CxfSshKeyResult> readCxfSshKey(
  CxfSshKey source, {
  required String id,
  required String name,
  required int addedAt,
  String? note,
  List<String>? tags,
  bool pinned = false,
}) async {
  final bytes = <int>[];
  try {
    bytes.addAll(unb64url(source.privateKey));
  } on FormatException {
    return (key: null, skip: SkipReason.sshKey);
  }
  if (bytes.isEmpty || bytes.length > cxfMaxSshKeyBytes) {
    return (key: null, skip: SkipReason.sshKey);
  }
  final crypto.ParsedKey parsed;
  try {
    parsed = await crypto.readPrivateKey(bytes);
  } on crypto.KeyFormatException {
    return (key: null, skip: SkipReason.sshKey);
  }
  if (!parsed.hasSshForm || parsed.public == null) {
    return (key: null, skip: SkipReason.sshKey);
  }
  final key = vaultKeyOf(parsed.withKind(crypto.KeyKind.ssh), id: id, name: name, origin: KeyOrigin.imported);
  return (
    key: key.copyWith(
      addedAt: addedAt,
      note: note == null || note.isEmpty ? unset : note,
      tags: tags == null || tags.isEmpty ? unset : tags,
      pinned: pinned ? true : unset,
    ),
    skip: null,
  );
}
