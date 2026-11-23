// `kx1`, the hybrid exchange key of `docs/crypto.md`: ML-KEM-1024 and X25519
// combined as X-Wing combines ML-KEM-768 and X25519
// (draft-connolly-cfrg-xwing-kem), with Kemlock's own label.
//
//   public key    ML-KEM-1024 encapsulation key (1568) || X25519 public key (32)   1600 bytes
//   private key   ML-KEM-1024 seed d || z (64) || X25519 private key (32)            96 bytes
//   ciphertext    ct_m (1568) || ct_x (32)                                          1600 bytes
//   secret        SHA3-256("kemlock/v1/kx1" || ss_m || ss_x || ct_x || pk_x)
//
// The ML-KEM key pair is expanded from the 64-byte seed as FIPS 203
// ML-KEM.KeyGen_internal(d, z) does, which `MlKem1024.keygen(seed)` is.
// `ct_m` stays out of the hash because ML-KEM's implicit rejection already
// binds it. Decapsulation never says which half failed.
//
// The ML-KEM code is not constant-time (see ml_kem.dart); X25519 is
// `package:cryptography`'s.

library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;

import '../bytes.dart';
import '../keccak.dart';
import '../ml_kem.dart';
import 'encoding.dart';

const _kx1Label = 'kemlock/v1/kx1';

/// The `kx1` combiner: SHA3-256 of `"kemlock/v1/kx1"`, `ss_m`, `ss_x`, `ct_x`
/// and `pk_x`, with the label first as a domain-separation prefix. `crypto.md`
/// fixes that order on purpose, where the X-Wing draft puts its label last, so
/// there is no switch for it: the draft's order exists only in the test that
/// runs the draft's vectors.
Uint8List _combine({required List<int> ssM, required List<int> ssX, required List<int> ctX, required List<int> pkX}) =>
    sha3_256(concatBytes([label(_kx1Label), ssM, ssX, ctX, pkX]));

/// A `kx1` key pair, or the pieces of one.
abstract final class Kx1 {
  static const publicKeyLength = 1600;
  static const privateKeyLength = 96;
  static const ciphertextLength = 1600;
  static const sharedSecretLength = 32;

  static const _mlKemPublic = MlKem1024.publicKeyLength; // 1568
  static const _mlKemCipher = MlKem1024.cipherTextLength; // 1568

  /// A key pair from the 96-byte [privateKey], or from 96 fresh random bytes.
  /// The caller owns and should wipe the returned private key.
  static Future<({Uint8List publicKey, Uint8List privateKey})> generate([Uint8List? privateKey]) async {
    final sk = copyBytes(requireLength(privateKey ?? randomBytes(privateKeyLength), privateKeyLength, 'a kx1 private key'));
    return (publicKey: await publicKeyOf(sk), privateKey: sk);
  }

  /// The 1600-byte public key of the 96-byte [privateKey].
  static Future<Uint8List> publicKeyOf(Uint8List privateKey) async {
    requireLength(privateKey, privateKeyLength, 'a kx1 private key');
    final mlKem = MlKem1024.keygen(Uint8List.sublistView(privateKey, 0, 64));
    wipe(mlKem.secretKey);
    final pkX = await _x25519PublicKey(Uint8List.sublistView(privateKey, 64, 96));
    return concatBytes([mlKem.publicKey, pkX]);
  }

  /// Encapsulates to the 1600-byte [publicKey]: a shared secret and the
  /// 1600-byte ciphertext that carries it.
  ///
  /// [mlKemMessage] (32 bytes, ML-KEM's `m`) and [ephemeralSecret] (32 bytes,
  /// the X25519 key `e`) are random unless given, which is for known-answer
  /// tests only. An all-zero X25519 secret, which a public key of small order
  /// gives, is refused with a [MalformedException].
  static Future<({Uint8List ciphertext, Uint8List sharedSecret})> encapsulate(
    Uint8List publicKey, {
    Uint8List? mlKemMessage,
    Uint8List? ephemeralSecret,
  }) async {
    requireLength(publicKey, publicKeyLength, 'a kx1 public key');
    final pkM = Uint8List.sublistView(publicKey, 0, _mlKemPublic);
    final pkX = Uint8List.sublistView(publicKey, _mlKemPublic, publicKeyLength);
    final e = ephemeralSecret == null ? randomBytes(32) : copyBytes(requireLength(ephemeralSecret, 32, 'the X25519 ephemeral secret'));
    try {
      final ({Uint8List cipherText, Uint8List sharedSecret}) mlKem;
      try {
        mlKem = MlKem1024.encapsulate(pkM, mlKemMessage);
      } on ArgumentError {
        throw const MalformedException('the ML-KEM half of the public key is not valid');
      }
      final ctX = await _x25519PublicKey(e);
      final ssX = await _x25519(e, pkX);
      if (_allZero(ssX)) throw const MalformedException('the X25519 half of the public key has small order');
      final ss = _combine(ssM: mlKem.sharedSecret, ssX: ssX, ctX: ctX, pkX: pkX);
      final ciphertext = concatBytes([mlKem.cipherText, ctX]);
      wipe(mlKem.sharedSecret);
      wipe(ssX);
      return (ciphertext: ciphertext, sharedSecret: ss);
    } finally {
      wipe(e);
    }
  }

  /// The shared secret in the 1600-byte [ciphertext] for the 96-byte
  /// [privateKey]. A ciphertext this key did not make gives a [CorruptedException],
  /// or, for a ML-KEM half that was changed, an unrelated secret by implicit
  /// rejection, so a wrong key shows up when the seal's tag does not verify.
  /// Nothing says which half failed.
  static Future<Uint8List> decapsulate(Uint8List ciphertext, Uint8List privateKey) async {
    requireLength(ciphertext, ciphertextLength, 'a kx1 ciphertext');
    requireLength(privateKey, privateKeyLength, 'a kx1 private key');
    final skX = Uint8List.sublistView(privateKey, 64, 96);
    final ctM = Uint8List.sublistView(ciphertext, 0, _mlKemCipher);
    final ctX = Uint8List.sublistView(ciphertext, _mlKemCipher, ciphertextLength);
    final mlKem = MlKem1024.keygen(Uint8List.sublistView(privateKey, 0, 64));
    Uint8List? ssM;
    Uint8List? ssX;
    try {
      ssM = MlKem1024.decapsulate(ctM, mlKem.secretKey);
      final pkX = await _x25519PublicKey(skX);
      ssX = await _x25519(skX, ctX);
      if (_allZero(ssX)) throw const CorruptedException();
      return _combine(ssM: ssM, ssX: ssX, ctX: ctX, pkX: pkX);
    } finally {
      wipe(mlKem.secretKey);
      if (ssM != null) wipe(ssM);
      if (ssX != null) wipe(ssX);
    }
  }
}

/// Whether every byte is zero, without stopping at the first one that is not.
bool _allZero(List<int> bytes) {
  var any = 0;
  for (final b in bytes) {
    any |= b;
  }
  return any == 0;
}

final _x25519Algorithm = c.X25519();

Future<Uint8List> _x25519PublicKey(List<int> secret) async {
  final pair = await _x25519Algorithm.newKeyPairFromSeed(secret);
  return Uint8List.fromList((await pair.extractPublicKey()).bytes);
}

Future<Uint8List> _x25519(List<int> secret, List<int> publicKey) async {
  final pair = await _x25519Algorithm.newKeyPairFromSeed(secret);
  final shared = await _x25519Algorithm.sharedSecretKey(
    keyPair: pair,
    remotePublicKey: c.SimplePublicKey(List<int>.of(publicKey), type: c.KeyPairType.x25519),
  );
  return Uint8List.fromList(await shared.extractBytes());
}
