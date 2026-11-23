@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as c;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keccak.dart';
import 'package:kemlock_core/crypto/ml_kem.dart';
import 'package:test/test.dart';

import '../vectors.dart';

Future<Uint8List> _x25519Public(List<int> secret) async =>
    Uint8List.fromList((await (await c.X25519().newKeyPairFromSeed(secret)).extractPublicKey()).bytes);

Future<Uint8List> _x25519(List<int> secret, List<int> publicKey) async {
  final pair = await c.X25519().newKeyPairFromSeed(secret);
  final shared = await c.X25519().sharedSecretKey(
    keyPair: pair,
    remotePublicKey: c.SimplePublicKey(publicKey, type: c.KeyPairType.x25519),
  );
  return Uint8List.fromList(await shared.extractBytes());
}

// X-Wing's combiner as the draft (draft-connolly-cfrg-xwing-kem-10) has it:
// the label last. kx1's own combiner is private to kx1.dart and puts its label
// first, as crypto.md fixes it, so this order lives only here, in the test
// that runs the draft's published vectors.
Uint8List _xwingCombine({
  required List<int> ssM,
  required List<int> ssX,
  required List<int> ctX,
  required List<int> pkX,
  required List<int> xwingLabel,
}) => sha3_256(concatBytes([ssM, ssX, ctX, pkX, xwingLabel]));

// The X-Wing draft's vectors (draft-connolly-cfrg-xwing-kem-10, appendix C)
// run through the draft's combiner with ML-KEM-768 and the draft's own label,
// so the plumbing around the combiner (the key expansion, X25519, the order of
// the four values) is held to published answers. kx1 itself uses ML-KEM-1024
// and a label in front, as crypto.md fixes it, and has no published vectors
// until the server's arrive.
void main() {
  final xwing = (jsonDecode(File('test/fixtures/account/rfc/xwing_draft10.json').readAsStringSync()) as Map<String, Object?>)['vectors'];
  // XWingLabel is the six ASCII bytes of the draft's section 5.3, 5c2e2f2f5e5c in hexadecimal.
  final xwingLabel = fromHex('5c2e2f2f5e5c');

  group('the X-Wing draft', () {
    for (final (i, v) in objects(xwing).indexed) {
      test('vector ${i + 1}: key expansion, encapsulation and decapsulation', () async {
        final sk = fromHex(v['sk']! as String);
        final expanded = shake256(sk, 96);
        final mlKem = MlKem768.keygen(Uint8List.sublistView(expanded, 0, 64));
        final skX = Uint8List.sublistView(expanded, 64, 96);
        final pkX = await _x25519Public(skX);
        expect(toHex(concatBytes([mlKem.publicKey, pkX])), v['pk'], reason: 'public key');

        // EncapsulateDerand
        final eseed = fromHex(v['eseed']! as String);
        final ekX = Uint8List.sublistView(eseed, 32, 64);
        final ctX = await _x25519Public(ekX);
        final ssXSender = await _x25519(ekX, pkX);
        final encaps = MlKem768.encapsulate(mlKem.publicKey, Uint8List.sublistView(eseed, 0, 32));
        final ss = _xwingCombine(ssM: encaps.sharedSecret, ssX: ssXSender, ctX: ctX, pkX: pkX, xwingLabel: xwingLabel);
        expect(toHex(concatBytes([encaps.cipherText, ctX])), v['ct'], reason: 'ciphertext');
        expect(toHex(ss), v['ss'], reason: 'shared secret');

        // Decapsulate
        final ssM = MlKem768.decapsulate(encaps.cipherText, mlKem.secretKey);
        final ssX = await _x25519(skX, ctX);
        expect(toHex(_xwingCombine(ssM: ssM, ssX: ssX, ctX: ctX, pkX: pkX, xwingLabel: xwingLabel)), v['ss']);
      });
    }
  });

  group('kx1', () {
    final privateKey = Uint8List.fromList(List.generate(96, (i) => (i * 7 + 3) & 0xff));
    final message = Uint8List.fromList(List.generate(32, (i) => i + 1));
    final ephemeral = Uint8List.fromList(List.generate(32, (i) => 0xa0 + i));

    test('has the sizes crypto.md gives', () async {
      final pair = await Kx1.generate(privateKey);
      expect(pair.publicKey, hasLength(1600));
      expect(pair.privateKey, hasLength(96));
      final sealed = await Kx1.encapsulate(pair.publicKey);
      expect(sealed.ciphertext, hasLength(1600));
      expect(sealed.sharedSecret, hasLength(32));
    });

    test('the public key is the ML-KEM-1024 key of d and z, then the X25519 public key', () async {
      final pair = await Kx1.generate(privateKey);
      expect(pair.publicKey.sublist(0, 1568), MlKem1024.keygen(privateKey.sublist(0, 64)).publicKey);
      expect(pair.publicKey.sublist(1568), await _x25519Public(privateKey.sublist(64)));
      expect(pair.privateKey, privateKey);
    });

    test('the shared secret is SHA3-256 of the label, ss_m, ss_x, ct_x and pk_x', () async {
      final pair = await Kx1.generate(privateKey);
      final sealed = await Kx1.encapsulate(pair.publicKey, mlKemMessage: message, ephemeralSecret: ephemeral);
      final pkX = pair.publicKey.sublist(1568);
      final mlKem = MlKem1024.encapsulate(pair.publicKey.sublist(0, 1568), message);
      final ctX = await _x25519Public(ephemeral);
      final ssX = await _x25519(ephemeral, pkX);
      expect(sealed.ciphertext, [...mlKem.cipherText, ...ctX]);
      expect(sealed.sharedSecret, sha3_256([...utf8.encode('kemlock/v1/kx1'), ...mlKem.sharedSecret, ...ssX, ...ctX, ...pkX]));
    });

    test('decapsulation gives the secret encapsulation made', () async {
      final pair = await Kx1.generate(privateKey);
      final sealed = await Kx1.encapsulate(pair.publicKey);
      expect(await Kx1.decapsulate(sealed.ciphertext, pair.privateKey), sealed.sharedSecret);
      final again = await Kx1.encapsulate(pair.publicKey);
      expect(again.sharedSecret, isNot(sealed.sharedSecret), reason: 'fresh randomness each time');
    });

    test('a random key pair round-trips', () async {
      final pair = await Kx1.generate();
      final sealed = await Kx1.encapsulate(pair.publicKey);
      expect(await Kx1.decapsulate(sealed.ciphertext, pair.privateKey), sealed.sharedSecret);
    });

    test('needs both halves of the private key', () async {
      final pair = await Kx1.generate(privateKey);
      final sealed = await Kx1.encapsulate(pair.publicKey);
      final onlyMlKem = Uint8List.fromList(privateKey)..setRange(64, 96, List.filled(32, 9));
      final onlyX25519 = Uint8List.fromList(privateKey)..setRange(0, 64, List.filled(64, 9));
      expect(await Kx1.decapsulate(sealed.ciphertext, onlyMlKem), isNot(sealed.sharedSecret));
      expect(await Kx1.decapsulate(sealed.ciphertext, onlyX25519), isNot(sealed.sharedSecret));
    });

    test('a changed ciphertext byte, in either half, gives another secret', () async {
      final pair = await Kx1.generate(privateKey);
      final sealed = await Kx1.encapsulate(pair.publicKey);
      for (final index in [0, 700, 1567, 1568, 1599]) {
        final changed = Uint8List.fromList(sealed.ciphertext)..[index] ^= 1;
        expect(await Kx1.decapsulate(changed, pair.privateKey), isNot(sealed.sharedSecret), reason: 'byte $index');
      }
    });

    test('refuses an all-zero X25519 secret', () async {
      final pair = await Kx1.generate(privateKey);
      // u = 0 is a point of small order: X25519 gives all zeros for any scalar
      final weak = Uint8List.fromList(pair.publicKey)..fillRange(1568, 1600, 0);
      await expectLater(Kx1.encapsulate(weak), throwsA(isA<MalformedException>()));
      final sealed = await Kx1.encapsulate(pair.publicKey);
      final weakCiphertext = Uint8List.fromList(sealed.ciphertext)..fillRange(1568, 1600, 0);
      await expectLater(Kx1.decapsulate(weakCiphertext, pair.privateKey), throwsA(isA<CorruptedException>()));
    });

    test('refuses keys and ciphertexts of the wrong length', () async {
      final pair = await Kx1.generate(privateKey);
      await expectLater(Kx1.encapsulate(Uint8List(1599)), throwsA(isA<MalformedException>()));
      await expectLater(Kx1.decapsulate(Uint8List(1599), pair.privateKey), throwsA(isA<MalformedException>()));
      await expectLater(Kx1.decapsulate(Uint8List(1600), Uint8List(95)), throwsA(isA<MalformedException>()));
      await expectLater(Kx1.generate(Uint8List(64)), throwsA(isA<MalformedException>()));
    });

    test('refuses an ML-KEM public key with a coefficient out of range', () async {
      final pair = await Kx1.generate(privateKey);
      final bad = Uint8List.fromList(pair.publicKey)..fillRange(0, 2, 0xff);
      await expectLater(Kx1.encapsulate(bad), throwsA(isA<MalformedException>()));
    });
  });
}
