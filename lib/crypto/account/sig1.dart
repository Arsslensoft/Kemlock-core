// `sig1`, the hybrid signing key of `docs/crypto.md`: ML-DSA-65 and Ed25519,
// both of which must verify.
//
//   public key   ML-DSA-65 public key (1952) || Ed25519 public key (32)    1984 bytes
//   private key  ML-DSA-65 seed xi (32) || Ed25519 seed (32)                 64 bytes
//   signed       m' = "kemlock/v1/sig1" || lp(context) || lp(message)
//   signature    ML-DSA-65.Sign(sk_m, m', ctx = empty) (3309) || Ed25519.Sign(sk_e, m') (64)
//                                                                          3373 bytes
//
// ML-DSA signing is hedged unless fixed randomness is passed, and verifiers
// accept both. The context is a label such as "bundle" or "manifest"; a
// signature made under one does not verify under another.
//
// `MlDsa65` is not constant-time (see ml_dsa.dart); Ed25519 is
// `package:cryptography`'s.

library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../bytes.dart';
import '../ml_dsa.dart';
import 'encoding.dart';

/// The contexts `crypto.md` names for `sig1`.
abstract final class SignContext {
  /// A key bundle, signed by its own account.
  static const bundle = 'bundle';

  /// A signed manifest.
  static const manifest = 'manifest';

  /// A member confirmation, signed by whoever compared the member's fingerprint (confirm.dart).
  static const confirm = 'confirm';

  /// An entry of a space's chain, signed by the member who made it (features/spaces/space_chain.dart).
  // server: to confirm
  // crypto.md doesn't list this context yet.
  static const spaceChain = 'space-chain';
}

abstract final class Sig1 {
  static const publicKeyLength = 1984;
  static const privateKeyLength = 64;
  static const signatureLength = 3373;

  static const _mlDsaPublic = MlDsa65.publicKeyLength; // 1952
  static const _mlDsaSignature = MlDsa65.signatureLength; // 3309

  /// A key pair from the 64-byte [privateKey], or from 64 fresh random bytes.
  /// The caller owns and should wipe the returned private key.
  static Future<({Uint8List publicKey, Uint8List privateKey})> generate([Uint8List? privateKey]) async {
    final sk = copyBytes(requireLength(privateKey ?? randomBytes(privateKeyLength), privateKeyLength, 'a sig1 private key'));
    return (publicKey: await publicKeyOf(sk), privateKey: sk);
  }

  /// The 1984-byte public key of the 64-byte [privateKey].
  static Future<Uint8List> publicKeyOf(Uint8List privateKey) async {
    requireLength(privateKey, privateKeyLength, 'a sig1 private key');
    final mlDsa = MlDsa65.keygen(Uint8List.fromList(privateKey.sublist(0, 32)));
    wipe(mlDsa.secretKey);
    final ed = await c.Ed25519().newKeyPairFromSeed(privateKey.sublist(32, 64));
    return concatBytes([mlDsa.publicKey, (await ed.extractPublicKey()).bytes]);
  }

  /// The 3373-byte signature of [message] under [privateKey] in [context].
  /// [randomness] (32 bytes) is for ML-DSA's hedging, fresh unless given; fix
  /// it only for known-answer tests.
  static Future<Uint8List> sign(Uint8List privateKey, List<int> message, {required String context, Uint8List? randomness}) async {
    requireLength(privateKey, privateKeyLength, 'a sig1 private key');
    final signed = _signedMessage(context, message);
    final mlDsa = MlDsa65.keygen(Uint8List.fromList(privateKey.sublist(0, 32)));
    try {
      final mlDsaSignature = MlDsa65.sign(mlDsa.secretKey, signed, randomness: randomness);
      final ed = c.Ed25519();
      final pair = await ed.newKeyPairFromSeed(privateKey.sublist(32, 64));
      final edSignature = (await ed.sign(signed, keyPair: pair)).bytes;
      return concatBytes([mlDsaSignature, edSignature]);
    } finally {
      wipe(mlDsa.secretKey);
    }
  }

  /// Whether [signature] signs [message] in [context] under [publicKey]:
  /// true only when both the ML-DSA-65 and the Ed25519 half verify over the
  /// same `m'`. A public key or signature of the wrong length is a
  /// [MalformedException]; one that does not verify is false.
  static Future<bool> verify(Uint8List publicKey, List<int> message, Uint8List signature, {required String context}) async {
    requireLength(publicKey, publicKeyLength, 'a sig1 public key');
    requireLength(signature, signatureLength, 'a sig1 signature');
    final signed = _signedMessage(context, message);
    final mlDsaOk = MlDsa65.verify(
      Uint8List.sublistView(publicKey, 0, _mlDsaPublic),
      signed,
      Uint8List.sublistView(signature, 0, _mlDsaSignature),
    );
    final edOk = await c.Ed25519().verify(
      signed,
      signature: c.Signature(
        signature.sublist(_mlDsaSignature),
        publicKey: c.SimplePublicKey(publicKey.sublist(_mlDsaPublic), type: c.KeyPairType.ed25519),
      ),
    );
    return mlDsaOk & edOk;
  }
}

/// `m' = "kemlock/v1/sig1" || lp(context) || lp(message)`.
Uint8List _signedMessage(String context, List<int> message) {
  if (context.isEmpty) throw ArgumentError.value(context, 'context', 'must not be empty');
  return concatBytes([label('kemlock/v1/sig1'), lp(label(context)), lp(message)]);
}
