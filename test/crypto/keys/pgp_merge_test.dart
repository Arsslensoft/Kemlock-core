@TestOn('vm')
library;

// Combining two copies of one PGP key (openspec: add-pgp-key-editing,
// design decision 3), on the editing fixtures and on copies Kemlock
// changed.

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/edit.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

Uint8List _key(String path) => readArmorBlock(keyFixture(path));

const _before = 'gnupg/editing/signing-subkey.secret.asc';
const _after = 'gnupg/editing/signing-subkey.after.secret.asc';
final _now = DateTime.utc(2026, 11, 20, 12);

/// What [key] holds, whatever the order: each packet's tag and body.
Set<String> _packets(Uint8List key) => {
  for (final p in readPackets(key))
    if (p.tag != PgpTag.trust) '${p.tag}:${p.body.join(',')}',
};

/// The tags of the secret key packets' S2K usage, in order.
List<int?> _usages(Uint8List key) => [
  for (final p in readPackets(key))
    if (p.tag == PgpTag.secretKey || p.tag == PgpTag.secretSubkey || p.tag == PgpTag.publicKey || p.tag == PgpTag.publicSubkey)
      parseKeyPacket(p).s2kUsage,
];

void main() {
  late Uint8List before;
  late Uint8List withUserId;
  late Uint8List withSubkey;

  setUpAll(() async {
    before = _key(_before);
    final signer = PgpSigner.of(before);
    withUserId = await addUserId(before, signer, name: 'Fixture Signing', email: 'signing@home.example.org', now: _now);
    withSubkey = await addSubkey(
      before,
      signer,
      type: PgpKeyType.ed25519,
      use: PgpSubkeyUse.encrypt,
      now: _now.add(const Duration(minutes: 1)),
    );
  });

  test('the key before GnuPG changed it and after: every packet of the after, and it reads as the after', () async {
    final after = _key(_after);
    // GnuPG exports the latest self-signature of each part only
    expect(_packets(after).containsAll(_packets(before)), isFalse);
    for (final merged in [await mergePgpKeys(before, after, preferA: true), await mergePgpKeys(after, before, preferA: true)]) {
      expect(_packets(merged), {..._packets(after), ..._packets(before)});
      expect(await verifySelfSignatures(merged), isTrue);
      final info = readPgpKeyInfo(merged);
      final expected = readPgpKeyInfo(after);
      expect(info.userIds.toSet(), expected.userIds.toSet());
      expect(info.primary.expires, expected.primary.expires);
      expect(
        info.subkeys.map((s) => (s.fingerprintHex, s.expires, s.flags)),
        expected.subkeys.map((s) => (s.fingerprintHex, s.expires, s.flags)),
      );
      // The fixed order: the user ID GnuPG certified first comes first
      expect(info.userIds.first, 'Fixture Signing <signing@example.org>');
      expect(await mergePgpKeys(merged, after, preferA: true), merged);
    }
  });

  test('two different changes give both, in the fixed order, and verify', () async {
    final merged = await mergePgpKeys(withUserId, withSubkey, preferA: true);
    final info = readPgpKeyInfo(merged);
    expect(info.userIds, ['Fixture Signing <signing@example.org>', 'Fixture Signing <signing@home.example.org>']);
    expect(info.subkeys, hasLength(3));
    expect(await verifySelfSignatures(merged), isTrue);
    expect(_packets(merged), {..._packets(withUserId), ..._packets(withSubkey)});
    // The primary key and its signatures, the user IDs by earliest certification, the subkeys by creation
    final tags = readPackets(merged).map((p) => p.tag).toList();
    expect(tags, [5, 13, 2, 13, 2, 7, 2, 7, 2, 7, 2]);
    final created = [
      for (final p in readPackets(merged))
        if (p.tag == PgpTag.secretSubkey) parseKeyPacket(p).createdSeconds,
    ];
    expect([...created]..sort(), created);
  });

  test('merge(a, b) and merge(b, a) hold the same packets', () async {
    final ab = await mergePgpKeys(withUserId, withSubkey, preferA: true);
    final ba = await mergePgpKeys(withSubkey, withUserId, preferA: true);
    expect(_packets(ab), _packets(ba));
    expect(ab, ba, reason: 'one fixed order');
    expect(await mergePgpKeys(withSubkey, withUserId, preferA: false), ab);
  });

  test('merging the result again with either input returns the result, byte for byte', () async {
    final merged = await mergePgpKeys(withUserId, withSubkey, preferA: true);
    for (final input in [withUserId, withSubkey, before]) {
      expect(await mergePgpKeys(merged, input, preferA: true), merged);
      expect(await mergePgpKeys(input, merged, preferA: false), merged);
      expect(await mergePgpKeys(input, merged, preferA: true), merged, reason: 'the same key packets on both sides');
    }
  });

  test('equal inputs give the preferred one back untouched, with what it carries beside the key', () async {
    final gnupg = keyFixture('gnupg/ed25519.secret.gpg');
    expect(await mergePgpKeys(gnupg, Uint8List.fromList(gnupg), preferA: true), gnupg);
    expect(await mergePgpKeys(before, Uint8List.fromList(before), preferA: false), before);
  });

  test('a protected and an unprotected copy keep the preferred side\'s secret packets', () async {
    final protected = protectPgpKey(withUserId, 'a passphrase', s2kCount: 0x60);
    final keepProtected = await mergePgpKeys(protected, withSubkey, preferA: true);
    final keepPlain = await mergePgpKeys(protected, withSubkey, preferA: false);
    // The new subkey only one side has keeps its own form
    expect(_usages(keepProtected), [254, 254, 254, 0]);
    expect(_usages(keepPlain), [0, 0, 0, 0]);
    expect(readPgpKeyInfo(keepPlain).subkeys, hasLength(3));
  });

  test('a public-only side never removes a secret', () async {
    final public = transferablePublicKey(readPackets(withSubkey));
    for (final preferA in [true, false]) {
      final merged = await mergePgpKeys(public, withUserId, preferA: preferA);
      final info = readPgpKeyInfo(merged);
      expect(info.primary.hasSecret, isTrue);
      expect(info.subkeys.map((s) => s.hasSecret), [true, true, false], reason: 'the subkey only the public copy has');
      expect(info.userIds, hasLength(2));
    }
  });

  test('GnuPG\'s stub is a secret packet: the preferred side\'s stays', () async {
    final whole = _key('gnupg/editing/protected.secret.asc');
    final stub = _key('gnupg/editing/protected.stub.secret.asc');
    expect(editRefusal(await mergePgpKeys(stub, whole, preferA: true))?.block, PgpEditBlock.noPrimarySecret);
    expect(editRefusal(await mergePgpKeys(stub, whole, preferA: false)), isNull);
  });

  test('a revocation from the side that is not preferred is taken only when it verifies', () async {
    final signer = PgpSigner.of(before);
    final revoked = await revokePgpKey(before, signer, reason: PgpRevocationReason.compromised, now: _now);
    // The same revocation with a flipped byte: the reader takes any 0x20 the key issued
    final packets = readPackets(revoked);
    final good = packets[1];
    expect(parseSignature(good.body).type, 0x20);
    final badBody = Uint8List.fromList(good.body)..[good.body.length - 5] ^= 1;
    final forged = Uint8List.fromList([
      ...packets.first.encoded,
      ...writePacket(PgpTag.signature, badBody, oldFormat: true),
      for (final p in packets.skip(2)) ...p.encoded,
    ]);
    expect(readPgpKeyInfo(forged).primary.revoked, isTrue);

    expect(readPgpKeyInfo(await mergePgpKeys(withUserId, forged, preferA: true)).primary.revoked, isFalse);
    expect(readPgpKeyInfo(await mergePgpKeys(withUserId, revoked, preferA: true)).primary.revoked, isTrue);
    // From the preferred side, it is kept as it was
    expect(readPgpKeyInfo(await mergePgpKeys(forged, withUserId, preferA: true)).primary.revoked, isTrue);
  });

  test('what a copy from outside adds is taken only when the primary key made it', () async {
    // Copies Kemlock and GnuPG made: all they add verifies
    for (final copy in [withUserId, withSubkey, _key(_after)]) {
      expect(await verifiesWhatItAdds(await mergePgpKeys(before, copy, preferA: true), before), isTrue);
    }
    expect(await verifiesWhatItAdds(before, before), isTrue);

    // A user ID put in with no certification would be read as the key's own
    final bare = Uint8List.fromList([...before, ...writePacket(PgpTag.userId, utf8.encode('Alice <alice@corp.com>'))]);
    final withBare = await mergePgpKeys(before, bare, preferA: true);
    expect(readPgpKeyInfo(withBare).userIds, contains('Alice <alice@corp.com>'));
    expect(await verifiesWhatItAdds(withBare, before), isFalse);

    // A certification with a flipped byte, as somebody who made it up would give it
    final packets = readPackets(withUserId);
    final added = packets.indexWhere((p) => p.tag == PgpTag.userId && utf8.decode(p.body).contains('home.example.org'));
    final certification = packets[added + 1];
    expect(parseSignature(certification.body).type, inInclusiveRange(0x10, 0x13));
    final badBody = Uint8List.fromList(certification.body)..[certification.body.length - 5] ^= 1;
    final forged = Uint8List.fromList([
      for (final (i, p) in packets.indexed) ...(i == added + 1 ? writePacket(PgpTag.signature, badBody, oldFormat: true) : p.encoded),
    ]);
    expect(await verifiesWhatItAdds(await mergePgpKeys(before, forged, preferA: true), before), isFalse);
  });

  test('two different keys are refused', () async {
    await expectLater(mergePgpKeys(before, _key('gnupg/editing/protected.secret.asc'), preferA: true), throwsArgumentError);
  });

  // openspec: add-post-quantum-pgp, task 9.3
  for (final (name, path) in [
    ('a GnuPG-format key, with its version 5 Kyber subkey', 'kemlock/pgp-pq-gnupg.unprotected.asc'),
    ('a standard key, version 6', 'kemlock/pgp-pq-standard.unprotected.asc'),
  ]) {
    test('$name: a copy with a new user ID and one with a new expiry merge to both, either way round', () async {
      final key = _key(path);
      final signer = PgpSigner.of(key);
      final named = await addUserId(key, signer, name: 'Ada Added', email: 'added@example.org', now: _now);
      final expiring = await setExpiry(
        key,
        signer,
        expires: DateTime.utc(2030, 1, 1),
        alsoSubkeys: true,
        now: _now.add(const Duration(minutes: 1)),
      );
      for (final merged in [await mergePgpKeys(named, expiring, preferA: true), await mergePgpKeys(expiring, named, preferA: false)]) {
        expect(_packets(merged), {..._packets(named), ..._packets(expiring)});
        expect(await verifySelfSignatures(merged), isTrue);
        final info = readPgpKeyInfo(merged);
        expect(info.primary.fingerprintHex, readPgpKeyInfo(key).primary.fingerprintHex);
        expect(info.userIds, contains('Ada Added <added@example.org>'));
        expect((info.primary.expires, info.subkeys.single.expires), (DateTime.utc(2030, 1, 1), DateTime.utc(2030, 1, 1)));
        expect(info.subkeys.single.fingerprintHex, readPgpKeyInfo(key).subkeys.single.fingerprintHex);
        // Merged again with either copy, nothing changes
        expect(await mergePgpKeys(merged, named, preferA: true), merged);
      }
    });
  }
}
