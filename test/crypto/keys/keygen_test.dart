@TestOn('vm')
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/algorithms.dart';
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:kemlock_core/crypto/ml_dsa.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:test/test.dart';

final _message = utf8.encode('a message for the key to sign');

/// Signs with the private half and verifies with the public half, through
/// libraries other than the generator: cryptography for Ed25519,
/// pointycastle's signers for ECDSA and RSA.
Future<void> _expectSignatureChecks(ParsedKey key) async {
  final material = await readPkcs8(key.private);
  final half = readSpki(key.public!)!;
  switch ((material, half)) {
    case (Ed25519Material(:final seed), RawPublicHalf(:final bytes)):
      final algorithm = c.Ed25519();
      final signature = await algorithm.sign(_message, keyPair: await algorithm.newKeyPairFromSeed(seed));
      final public = c.SimplePublicKey(bytes, type: c.KeyPairType.ed25519);
      expect(await algorithm.verify(_message, signature: c.Signature(signature.bytes, publicKey: public)), isTrue);
      expect(await algorithm.verify(utf8.encode('another'), signature: c.Signature(signature.bytes, publicKey: public)), isFalse);
    case (EcMaterial(:final curve, :final d), EcPublicHalf(:final point)):
      final domain = curve.domain;
      pc.Digest digest() => curve == EcCurve.p256 ? pc.SHA256Digest() : pc.SHA384Digest();
      final random = pc.FortunaRandom()..seed(pc.KeyParameter(randomBytes(32)));
      final signer = pc.ECDSASigner(digest())
        ..init(true, pc.ParametersWithRandom(pc.PrivateKeyParameter(pc.ECPrivateKey(bytesToBigInt(d), domain)), random));
      final signature = signer.generateSignature(Uint8List.fromList(_message)) as pc.ECSignature;
      final verifier = pc.ECDSASigner(digest())
        ..init(false, pc.PublicKeyParameter(pc.ECPublicKey(domain.curve.decodePoint(point), domain)));
      expect(verifier.verifySignature(Uint8List.fromList(_message), signature), isTrue);
    case (RsaMaterial(:final n, :final d, :final p, :final q), RsaPublicHalf(n: final publicN, :final e)):
      final signer = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
        ..init(true, pc.PrivateKeyParameter<pc.RSAPrivateKey>(pc.RSAPrivateKey(n, d, p, q)));
      final signature = signer.generateSignature(Uint8List.fromList(_message));
      final verifier = pc.RSASigner(pc.SHA256Digest(), '0609608648016503040201')
        ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(pc.RSAPublicKey(publicN, e)));
      expect(verifier.verifySignature(Uint8List.fromList(_message), signature), isTrue);
    case (PqMaterial(parameters: PqParameters.mlDsa65, :final expanded), RawPublicHalf(:final bytes)):
      // Kemlock doesn't sign with ML-DSA; the secret key must give back
      // the public key.
      expect(MlDsa65.publicKeyOf(expanded), bytes);
    default:
      fail('no signature check for ${key.algorithm}');
  }
}

/// Agrees on a secret with another key of the same algorithm, or
/// encapsulates one to it.
Future<void> _expectAgreementChecks(ParsedKey a, ParsedKey b) async {
  final materialA = await readPkcs8(a.private);
  final materialB = await readPkcs8(b.private);
  switch ((materialA, materialB)) {
    case (final X25519Material x, final X25519Material y):
      final x25519 = c.X25519();
      Future<List<int>> shared(X25519Material mine, X25519Material theirs) async {
        final secret = await x25519.sharedSecretKey(
          keyPair: await x25519.newKeyPairFromSeed(mine.privateKey),
          remotePublicKey: c.SimplePublicKey(theirs.publicKey, type: c.KeyPairType.x25519),
        );
        return secret.extractBytes();
      }
      final ab = await shared(x, y);
      expect(ab, await shared(y, x));
      expect(ab, isNot(List.filled(32, 0)));
    case (PqMaterial(:final parameters, expanded: final secretA), PqMaterial()):
      final publicA = (readSpki(a.public!)! as RawPublicHalf).bytes;
      final (cipherText, sharedSecret, back) = switch (parameters) {
        PqParameters.mlKem768 => () {
          final e = MlKem768.encapsulate(publicA);
          return (e.cipherText, e.sharedSecret, MlKem768.decapsulate(e.cipherText, secretA));
        }(),
        _ => () {
          final e = MlKem1024.encapsulate(publicA);
          return (e.cipherText, e.sharedSecret, MlKem1024.decapsulate(e.cipherText, secretA));
        }(),
      };
      expect(back, sharedSecret);
      expect(cipherText, isNotEmpty);
    default:
      fail('no agreement check for ${a.algorithm}');
  }
}

void main() {
  group('makes each key in a background isolate', () {
    for (final MapEntry(key: kind, value: algorithms) in generatedAlgorithms.entries) {
      for (final algorithm in algorithms) {
        test('${kind.name} ${algorithm.name}: the public half is the private half\'s, and it works', () async {
          final result = await generateKey(NewKeyRequest(kind, algorithm)).result;
          final key = (result as KeyGenerated).key;
          expect(key.kind, kind);
          expect(key.algorithm, algorithm.id);
          expect(key.bits, algorithm.bits);
          expect(key.comment, isNull);

          // Read back from the private half alone, the public half is the same.
          final again = await readPrivateKey(key.private);
          expect(again.public, key.public);
          expect(again.algorithm, key.algorithm);
          if (algorithm.bits != null) expect(again.bits, algorithm.bits);

          if (kind == KeyKind.exchange) {
            final other = await makeKey(NewKeyRequest(kind, algorithm));
            expect(other.public, isNot(key.public));
            await _expectAgreementChecks(key, other);
          } else {
            await _expectSignatureChecks(key);
          }

          if (kind == KeyKind.ssh) {
            final file = await exportOpenSsh(key, comment: 'laptop');
            final back = await readPrivateKey(file);
            expect(keyFingerprint(back)!.text, keyFingerprint(key)!.text);
            expect(sshPublicKeyLine(key, comment: 'laptop'), sshPublicKeyLine(back));
          }
        });
      }
    }

    test('the defaults are Ed25519 for SSH and signing keys and X25519 for exchange keys', () {
      expect(generatedAlgorithms[KeyKind.ssh]!.first, GeneratedAlgorithm.ed25519);
      expect(generatedAlgorithms[KeyKind.signing]!.first, GeneratedAlgorithm.ed25519);
      expect(generatedAlgorithms[KeyKind.exchange]!.first, GeneratedAlgorithm.x25519);
    });

    test('an SSH Ed25519 key gives an ssh-ed25519 line', () async {
      final key = await makeKey(const NewKeyRequest(KeyKind.ssh, GeneratedAlgorithm.ed25519));
      expect(sshPublicKeyLine(key, comment: 'laptop'), matches(r'^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{43} laptop$'));
    });
  });

  group('cancel', () {
    test('stops an RSA 4096 generation and gives nothing', () async {
      final generation = generateKey(const NewKeyRequest(KeyKind.signing, GeneratedAlgorithm.rsa4096));
      await Future<void>.delayed(const Duration(milliseconds: 30));
      final watch = Stopwatch()..start();
      generation.cancel();
      expect(await generation.result, isA<KeyGenerationCancelled>());
      expect(watch.elapsedMilliseconds, lessThan(200));
    });

    test('works before the isolate has started', () async {
      final generation = generateKey(const NewKeyRequest(KeyKind.signing, GeneratedAlgorithm.rsa4096))..cancel();
      expect(await generation.result, isA<KeyGenerationCancelled>());
    });

    test('does nothing once the key is made', () async {
      final generation = generateKey(const NewKeyRequest(KeyKind.exchange, GeneratedAlgorithm.x25519));
      final result = await generation.result;
      generation.cancel();
      expect(result, isA<KeyGenerated>());
      expect(await generation.result, same(result));
    });
  });

  test('refuses an algorithm its kind does not offer', () {
    expect(() => generateKey(const NewKeyRequest(KeyKind.ssh, GeneratedAlgorithm.x25519)), throwsArgumentError);
    expect(() => generateKey(const NewKeyRequest(KeyKind.exchange, GeneratedAlgorithm.ed25519)), throwsArgumentError);
    expect(() => generateKey(const NewKeyRequest(KeyKind.ssh, GeneratedAlgorithm.ecdsaP384)), throwsArgumentError);
    expect(() => generateKey(const NewKeyRequest(KeyKind.other, GeneratedAlgorithm.ed25519)), throwsArgumentError);
  });
}
