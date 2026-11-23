// The sealed box of `docs/crypto.md`: seals a short secret, such as a key, to
// a `kx1` public key under a context label.
//
//   (ct, ss) = kx1.Encaps(pk)
//   key      = HKDF(ikm = ss, salt = absent, info = "kemlock/v1/seal" || lp(context), L = 32)
//   box      = u8(1) || ct (1600) || AES-256-GCM(key, nonce, secret, aad = lp(context) || lp(aad))
//
// The AES-GCM part is a sealed value: nonce (12) || ciphertext || tag (16).
// `aad` is the caller's extra binding, for example the recipient's account id.
// It is not stored in the box. A box opened under another context label, or
// another `aad`, fails.

library;

import 'dart:typed_data';

import '../aes_gcm.dart';
import '../bytes.dart';
import '../hkdf.dart';
import 'encoding.dart';
import 'kx1.dart';

/// The contexts `crypto.md` lists, each for what it seals.
abstract final class SealContext {
  /// The root key, to a new device's one-time key pair.
  static const deviceApproval = 'device-approval';

  /// A space key, to a member.
  static const spaceKey = 'space-key';

  /// A collection key, to a member.
  static const collectionKey = 'collection-key';

  /// A root key, to an emergency contact.
  static const emergencyAccess = 'emergency-access';

  /// A member's root key, to a space's recovery key.
  static const accountRecovery = 'account-recovery';
}

/// The version byte of a box.
const sealedBoxVersion = 1;

const _nonceLength = 12;
const _tagLength = 16;

/// The shortest box: the version byte, the `kx1` ciphertext, a nonce and a
/// tag around an empty secret.
const sealedBoxMinimumLength = 1 + Kx1.ciphertextLength + _nonceLength + _tagLength;

/// Seals [secret] to the 1600-byte `kx1` [publicKey] under [context], with the
/// extra binding [aad]. [mlKemMessage], [ephemeralSecret] and [nonce] are
/// random unless given, which is for known-answer tests only.
Future<Uint8List> sealBox(
  Uint8List publicKey,
  List<int> secret, {
  required String context,
  List<int> aad = const [],
  Uint8List? mlKemMessage,
  Uint8List? ephemeralSecret,
  Uint8List? nonce,
}) async {
  final contextBytes = _contextBytes(context);
  final (:ciphertext, :sharedSecret) = await Kx1.encapsulate(publicKey, mlKemMessage: mlKemMessage, ephemeralSecret: ephemeralSecret);
  final key = _boxKey(sharedSecret, contextBytes);
  try {
    final sealed = await aesGcmEncrypt(key, secret, nonce: nonce, aad: _boxAad(contextBytes, aad));
    return concatBytes([u8(sealedBoxVersion), ciphertext, sealed.nonce, sealed.ct]);
  } finally {
    wipe(sharedSecret);
    wipe(key);
  }
}

/// Opens [box] with the 96-byte `kx1` [privateKey] under [context] and [aad].
/// A box too short or of another version is a [MalformedException]; anything
/// that does not authenticate, whichever byte was changed and whichever
/// half of the key was wrong, is a [CorruptedException].
Future<Uint8List> openBox(Uint8List box, Uint8List privateKey, {required String context, List<int> aad = const []}) async {
  final contextBytes = _contextBytes(context);
  if (box.length < sealedBoxMinimumLength) throw const MalformedException('a sealed box is too short');
  if (box[0] != sealedBoxVersion) throw MalformedException('unknown sealed box version ${box[0]}');
  final ciphertext = Uint8List.sublistView(box, 1, 1 + Kx1.ciphertextLength);
  final nonceStart = 1 + Kx1.ciphertextLength;
  final nonce = Uint8List.sublistView(box, nonceStart, nonceStart + _nonceLength);
  final sealed = Uint8List.sublistView(box, nonceStart + _nonceLength);
  final sharedSecret = await Kx1.decapsulate(ciphertext, privateKey);
  final key = _boxKey(sharedSecret, contextBytes);
  try {
    return await aesGcmDecrypt(key, nonce, sealed, aad: _boxAad(contextBytes, aad));
  } on AesGcmAuthError {
    throw const CorruptedException();
  } finally {
    wipe(sharedSecret);
    wipe(key);
  }
}

Uint8List _contextBytes(String context) {
  if (context.isEmpty) throw ArgumentError.value(context, 'context', 'must not be empty');
  return label(context);
}

Uint8List _boxKey(Uint8List sharedSecret, Uint8List context) =>
    hkdfSha256(sharedSecret, salt: const [], info: concatBytes([label('kemlock/v1/seal'), lp(context)]), length: 32);

Uint8List _boxAad(Uint8List context, List<int> aad) => concatBytes([lp(context), lp(aad)]);
