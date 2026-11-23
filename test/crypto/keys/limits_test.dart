@TestOn('vm')
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/keys/der.dart';
import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/openpgp/packets.dart';
import 'package:kemlock_core/crypto/keys/openpgp/signatures.dart';
import 'package:kemlock_core/crypto/keys/openpgp/writer.dart';
import 'package:kemlock_core/crypto/keys/openssh.dart';
import 'package:kemlock_core/crypto/keys/pbes2.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/crypto/keys/pkcs8.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

final _random = Random(4100);

BigInt _bigNumber(int bits) => bytesToBigInt([for (var i = 0; i < bits ~/ 8; i++) _random.nextInt(256)]) | BigInt.one << (bits - 1);

void main() {
  test('every reader refuses more than 1 MB before reading it', () async {
    final big = Uint8List(maxKeyInputLength + 1);
    final text = 'A' * (maxKeyInputLength + 1);
    final tooLarge = throwsKeyProblem(KeyProblem.tooLarge);
    await expectLater(readPrivateKey(big), tooLarge);
    await expectLater(readPrivateKey(text), tooLarge);
    await expectLater(readPkcs8(big), tooLarge);
    expect(() => readPkcs1(big), tooLarge);
    expect(() => readSec1(big), tooLarge);
    expect(() => readSpki(big), tooLarge);
    expect(() => decryptPkcs8(big, 'x'), tooLarge);
    await expectLater(readOpenSsh(big, null), tooLarge);
    expect(() => readPemBlocks(text), tooLarge);
    expect(() => readArmor(PemBlock(pgpPrivateKeyBlock, const {}, text, text)), tooLarge);
    expect(() => readPackets(big), tooLarge);
    expect(() => readTransferableKey(big), tooLarge);
    expect(() => readPgpKeyInfo(big), tooLarge);
    await expectLater(verifyPgpSelfSignatures(big), tooLarge);
  });

  test('an RSA key with numbers far bigger than any real key is refused at once', () async {
    final n = _bigNumber(40000);
    final pkcs1 = derSequence([
      derSmallInteger(0),
      for (final v in [n, BigInt.from(65537), n - BigInt.two, n ~/ BigInt.two, BigInt.two]) derInteger(v),
      derInteger(n),
      derInteger(n),
      derInteger(n),
    ]);
    final watch = Stopwatch()..start();
    await expectLater(readPrivateKey(writePem('RSA PRIVATE KEY', pkcs1)), throwsKeyProblem(KeyProblem.unsupportedKeyType, 'RSA 40000'));
    // Numbers bigger than the modulus are damage, not a key.
    final m = _bigNumber(2048);
    final odd = derSequence([
      derSmallInteger(0),
      for (final v in [m, _bigNumber(4096), m, m, m, m, m, m]) derInteger(v),
    ]);
    await expectLater(readPrivateKey(odd), throwsKeyProblem(KeyProblem.damaged));
    expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
  });

  test('a PGP signature by an RSA key with an absurd modulus is not checked', () async {
    // A v4 RSA key whose modulus has 60000 bits, a user ID, and a
    // certification whose hash prefix is right, so only the size stops it.
    final n = _bigNumber(60000);
    final keyBody = [4, 0, 0, 0, 1, 1, ...mpi(n), ...mpi(BigInt.from(65537))];
    final key = parseKeyPacket(readPackets(writePacket(PgpTag.publicKey, keyBody, oldFormat: true)).single);
    final uid = utf8.encode('Big <big@example.org>');
    final hashedPart = [4, 0x13, 1, 10, 0, 0];
    final digest = hash.sha512.convert([...hashedKey(key), ...hashedUserId(uid), ...hashedPart, 4, 0xff, 0, 0, 0, hashedPart.length]).bytes;
    final signature = [...hashedPart, 0, 0, digest[0], digest[1], ...mpi(n - BigInt.one)];
    final data = concatForTest([
      writePacket(PgpTag.publicKey, keyBody, oldFormat: true),
      writePacket(PgpTag.userId, uid, oldFormat: true),
      writePacket(PgpTag.signature, signature, oldFormat: true),
    ]);
    final watch = Stopwatch()..start();
    expect(await verifyPgpSelfSignatures(data), isFalse);
    expect(watch.elapsed, lessThan(const Duration(seconds: 1)));
  });

  test('a PGP key cut between packets is refused when what is left is not a key', () async {
    final data = keyFixture('gnupg/ed25519.secret.gpg');
    final packets = readPackets(data);
    var offset = 0;
    final ends = <int, int>{};
    for (final (i, p) in packets.indexed) {
      offset += p.encoded.length;
      ends[i] = offset;
    }
    // After the primary key alone: a version 4 key needs a user ID.
    await expectLater(readPrivateKey(data.sublist(0, ends[0])), throwsKeyProblem(KeyProblem.damaged));
    // After the subkey, before its binding signature.
    final subkey = packets.indexWhere((p) => p.tag == PgpTag.secretSubkey);
    await expectLater(readPrivateKey(data.sublist(0, ends[subkey])), throwsKeyProblem(KeyProblem.damaged));
    // After the certification: a key without its subkey, which is a key.
    final key = await readPrivateKey(data.sublist(0, ends[subkey - 1]));
    expect(key.pgp!.subkeys, isEmpty);
  });

  test('a PGP key with a user ID longer than GnuPG takes is refused, own or someone else\'s', () async {
    // Signed by its own key, as a key somebody made to be slow to show would be
    Future<Uint8List> keyWith(int length) => generatePgpKey(userId: '${'(' * (length - 18)} <ada@example.org>', type: PgpKeyType.ed25519);
    final fits = await keyWith(maxUserIdLength);
    expect(readTransferableKey(fits).info.userIds.single.length, maxUserIdLength);
    expect((await readPublicKeys(transferablePublicKey(readPackets(fits)))).single.info.userIds.single.length, maxUserIdLength);

    final long = await keyWith(maxUserIdLength + 1);
    final tooLong = throwsKeyProblem(KeyProblem.damaged, 'OpenPGP: a user ID over 2048 bytes');
    expect(() => readTransferableKey(long), tooLong);
    await expectLater(readPrivateKey(long), tooLong);
    await expectLater(verifyPgpSelfSignatures(long), tooLong);
    final public = transferablePublicKey(readPackets(long));
    await expectLater(readPublicKeys(public), tooLong);
    // A server's answer leaves such a key out and keeps the others
    final both = concatForTest([public, transferablePublicKey(readPackets(fits))]);
    expect(await readPublicKeys(both, skipUnsound: true), hasLength(1));
    // Nor is one made: the name of a key being made or given a user ID is
    // refused first, counted in bytes
    // (two bytes each, and 18 for ` <ada@example.org>`)
    expect(pgpUserId('${'é' * 1015} ', 'ada@example.org'), hasLength(1015 + 18));
    expect(() => pgpUserId('${'é' * 1016} ', 'ada@example.org'), throwsArgumentError);
  });

  test('OpenSSH and PBES2 refuse to run more rounds than they allow', () async {
    final options =
        (SshWriter()
              ..string(Uint8List(16))
              ..uint32(maxBcryptRounds + 1))
            .bytes;
    final blob =
        (SshWriter()
              ..raw('openssh-key-v1\x00'.codeUnits)
              ..text('aes256-ctr')
              ..text('bcrypt')
              ..string(options)
              ..uint32(1)
              ..string(
                (SshWriter()
                      ..text('ssh-ed25519')
                      ..string(Uint8List(32)))
                    .bytes,
              )
              ..string(Uint8List(64)))
            .bytes;
    await expectLater(readOpenSsh(blob, 'x'), throwsKeyProblem(KeyProblem.unsupportedCipher, 'bcrypt with ${maxBcryptRounds + 1} rounds'));
  });
}

Uint8List concatForTest(List<List<int>> parts) => Uint8List.fromList([for (final p in parts) ...p]);
