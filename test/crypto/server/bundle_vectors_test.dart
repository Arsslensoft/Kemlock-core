@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/bundle.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kx1.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's bundle.json (crypto.md "Public-key bundle and fingerprint"):
// the bundle bytes, the SHA-512 fingerprint, its 12 groups of 5 digits, and
// the bundle's sig1 signature under the context "bundle". The case doesn't
// say whether the ML-DSA half of the signature is hedged, so the signature
// is verified, and only its Ed25519 half, which is always deterministic, is
// made again and compared.
void main() {
  group("the server's bundle vectors", () {
    for (final c in readServerCases('bundle.json')) {
      final name = c['name']! as String;
      final accountId = fromHex(c['account_id']! as String);
      final keyVersion = c['key_version']! as int;
      final kx1Public = fromHex(c['kx1_public_key']! as String);
      final sig1Public = fromHex(c['sig1_public_key']! as String);
      final bundleBytes = fromHex(c['bundle']! as String);
      final signature = fromHex(c['signature']! as String);

      KeyBundle build({List<int>? account, int? version, List<int>? kx1, List<int>? sig1}) => KeyBundle(
        accountId: account ?? accountId,
        keyVersion: version ?? keyVersion,
        kx1PublicKey: kx1 ?? kx1Public,
        sig1PublicKey: sig1 ?? sig1Public,
      );

      test('$name: the public keys are those of the private keys', () async {
        expect(toHex(await Kx1.publicKeyOf(fromHex(c['kx1_private_key']! as String))), c['kx1_public_key']);
        expect(toHex(await Sig1.publicKeyOf(fromHex(c['sig1_private_key']! as String))), c['sig1_public_key']);
      });

      test('$name: the bundle is its label, account id, key version and both public keys', () {
        expect(toHex(build().bytes), c['bundle']);
        expect(bundleBytes, hasLength(17 + 16 + 4 + Kx1.publicKeyLength + Sig1.publicKeyLength));
      });

      test('$name: parses back to its fields, and a changed or longer bundle is refused', () {
        final parsed = KeyBundle.parse(bundleBytes);
        expect(toHex(parsed.accountId), c['account_id']);
        expect(parsed.keyVersion, keyVersion);
        expect(toHex(parsed.kx1PublicKey), c['kx1_public_key']);
        expect(toHex(parsed.sig1PublicKey), c['sig1_public_key']);
        expect(() => KeyBundle.parse([...bundleBytes, 0]), throwsA(isA<MalformedException>()));
        expect(() => KeyBundle.parse(bundleBytes.sublist(0, bundleBytes.length - 1)), throwsA(isA<MalformedException>()));
        expect(() => KeyBundle.parse(Uint8List.fromList(bundleBytes)..[0] ^= 1), throwsA(isA<MalformedException>()));
      });

      test('$name: the fingerprint is SHA-512 over the label and the bundle', () {
        expect(toHex(fingerprintOf(bundleBytes)), c['fingerprint']);
        expect(toHex(build().fingerprint), c['fingerprint']);
      });

      test('$name: the fingerprint shows as 12 groups of 5 digits', () {
        final fingerprint = fromHex(c['fingerprint']! as String);
        final groups = (c['fingerprint_groups']! as List<Object?>).cast<String>();
        expect(groups, hasLength(12));
        expect(groups.every((group) => group.length == 5), isTrue);
        expect(c['fingerprint_text'], groups.join(' '));
        expect(fingerprintDigitsOf(fingerprint), c['fingerprint_text']);
        expect(build().fingerprintDigits, c['fingerprint_text']);
        expect(fingerprintDigitsOf(fingerprint).split(' '), groups);
      });

      test('$name: two bundles of the same keys have the same fingerprint, any change gives another', () {
        expect(fingerprintsMatch(build().fingerprint, fromHex(c['fingerprint']! as String)), isTrue);
        final swappedKx1 = Uint8List.fromList(kx1Public)..[0] ^= 1;
        final swappedSig1 = Uint8List.fromList(sig1Public)..[0] ^= 1;
        final otherAccount = Uint8List.fromList(accountId)..[0] ^= 1;
        for (final other in [
          build(kx1: swappedKx1),
          build(sig1: swappedSig1),
          build(account: otherAccount),
          build(version: keyVersion + 1),
        ]) {
          expect(fingerprintsMatch(other.fingerprint, fromHex(c['fingerprint']! as String)), isFalse);
        }
      });

      test('$name: the signature verifies over the bundle under the key it holds', () async {
        expect(signature, hasLength(Sig1.signatureLength));
        expect(await verifyBundle(build(), signature), isTrue);
        expect(await Sig1.verify(sig1Public, bundleBytes, signature, context: SignContext.bundle), isTrue);
      });

      test('$name: the Ed25519 half of the signature is made again byte for byte', () async {
        final again = await signBundle(build(), fromHex(c['sig1_private_key']! as String));
        expect(toHex(again.sublist(3309)), toHex(signature.sublist(3309)));
        expect(await verifyBundle(build(), again), isTrue);
      });

      test('$name: a swapped key, account id or key version does not verify', () async {
        final swappedKx1 = Uint8List.fromList(kx1Public)..[0] ^= 1;
        final otherAccount = Uint8List.fromList(accountId)..[0] ^= 1;
        expect(await verifyBundle(build(kx1: swappedKx1), signature), isFalse);
        expect(await verifyBundle(build(account: otherAccount), signature), isFalse);
        expect(await verifyBundle(build(version: keyVersion + 1), signature), isFalse);
      });

      test('$name: a signature under the context "manifest" is not a bundle signature', () async {
        expect(await Sig1.verify(sig1Public, bundleBytes, signature, context: SignContext.manifest), isFalse);
      });
    }
  });
}
