// A Credential Exchange passkey as Kemlock keeps it (the
// add-credential-exchange plan, design decision 4 "Passkeys").
//
// Kemlock's authenticator signs ES256 only, so the PKCS#8
// `AlgorithmIdentifier` decides: `id-ecPublicKey` on `prime256v1` is kept;
// Ed25519, RSA, P-384 and anything else are skipped and named. Pure Dart,
// like the reader.
import 'dart:typed_data';

import '../../../crypto/bytes.dart';
import '../../../crypto/keys/algorithms.dart';
import '../../../crypto/keys/key_error.dart';
import '../../../crypto/keys/pkcs8.dart';
import '../../../models/passkey.dart';
import 'cxf.dart';
import 'import_extras.dart';

/// What [readCxfPasskey] made of a passkey: the [passkey], or the [skip]
/// reason (with a [detail] naming the key's kind), and whether the exporter
/// held extra secrets that weren't kept ([extras]).
typedef CxfPasskeyResult = ({Passkey? passkey, SkipReason? skip, String? detail, bool extras});

/// The kind of key a PKCS#8 key holds, as a skipped passkey names it.
String _kindOf(KeyMaterial material) => switch (material) {
  EcMaterial(:final curve) => curve == EcCurve.p256 ? 'p256' : 'p384',
  Ed25519Material() => 'ed25519',
  RsaMaterial() => 'rsa',
  _ => 'other',
};

/// Reads [source] into a passkey with the id [id], added at [addedAt] (epoch
/// ms) and tagged [tags]. The credential id and user handle are decoded from
/// base64url and stored as the model stores them, and the relying party in
/// lower case; the username and display name stay as given. The key is read
/// whole, so one whose point doesn't belong to its scalar is skipped.
Future<CxfPasskeyResult> readCxfPasskey(CxfPasskey source, {required String id, required int addedAt, List<String>? tags}) async {
  final extras = source.fido2Extensions;
  final lost = extras != null && (extras.hmacCredentials || extras.credBlob || extras.largeBlob);
  CxfPasskeyResult skipped(SkipReason reason, [String? detail]) => (passkey: null, skip: reason, detail: detail, extras: false);

  final Uint8List key;
  final Uint8List credentialId;
  final Uint8List userHandle;
  try {
    key = unb64url(source.key);
    credentialId = unb64url(source.credentialId);
    userHandle = unb64url(source.userHandle);
  } on FormatException {
    return skipped(SkipReason.unreadable);
  }
  final rpId = source.rpId.trim().toLowerCase();
  if (credentialId.isEmpty || userHandle.isEmpty || rpId.isEmpty) {
    return skipped(SkipReason.unreadable);
  }
  if (key.isEmpty || key.length > cxfMaxPasskeyKeyBytes) {
    return skipped(SkipReason.passkeyKey);
  }

  final KeyMaterial material;
  try {
    material = await readPkcs8(key);
  } on KeyFormatException catch (error) {
    // A multi-prime RSA key is a kind of key; any other failure is a key that can't be read
    return error.problem == KeyProblem.unsupportedKeyType ? skipped(SkipReason.passkeyAlgorithm, 'rsa') : skipped(SkipReason.passkeyKey);
  }
  if (material is! EcMaterial || material.curve != EcCurve.p256) {
    return skipped(SkipReason.passkeyAlgorithm, _kindOf(material));
  }

  final displayName = source.userDisplayName.trim();
  final passkey = Passkey(
    id: id,
    credentialId: b64url(credentialId),
    rpId: rpId,
    userHandle: b64url(userHandle),
    userName: source.username,
    userDisplayName: displayName.isEmpty ? null : source.userDisplayName,
    privateKey: b64(key),
    addedAt: addedAt,
    tags: tags == null || tags.isEmpty ? null : tags,
  );
  return (passkey: passkey, skip: null, detail: null, extras: lost);
}
