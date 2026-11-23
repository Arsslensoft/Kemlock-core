@TestOn('vm')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:test/test.dart';

Uint8List _bytes(int length) => Uint8List.fromList([for (var i = 0; i < length; i++) (i * 31 + 7) & 0xff]);

final _damaged = throwsA(isA<AttachmentDamagedError>());

void main() {
  final key = randomBytes(32);

  group('KMA1 round trips', () {
    for (final (name, length) in [
      ('an empty file', 0),
      ('one byte', 1),
      ('one partial chunk', 1000),
      ('exactly one chunk', kma1ChunkLength),
      ('a chunk and a byte', kma1ChunkLength + 1),
      ('exactly two chunks', 2 * kma1ChunkLength),
      ('several chunks', 5 * kma1ChunkLength + 12345),
    ]) {
      test(name, () async {
        final plain = _bytes(length);

        final file = await kma1Encrypt(plain, key);

        expect(file.length, kma1Length(length));
        expect(file.sublist(0, 4), kma1Magic);
        expect(await kma1Decrypt(file, key), plain);
      });
    }

    test('gives every file its own nonce prefix', () {
      final a = kma1EncryptSync(_bytes(10), key);
      final b = kma1EncryptSync(_bytes(10), key);

      expect(a.sublist(4, 12), isNot(b.sublist(4, 12)));
      expect(a.sublist(12), isNot(b.sublist(12)));
    });

    test('streams to and from files', () async {
      final dir = Directory.systemTemp.createTempSync('kma1');
      addTearDown(() => dir.deleteSync(recursive: true));
      final plain = _bytes(3 * kma1ChunkLength + 99);

      await kma1EncryptToFile(plain, key, '${dir.path}/sealed');
      await kma1DecryptFile('${dir.path}/sealed', '${dir.path}/plain', key);

      expect(File('${dir.path}/sealed').lengthSync(), kma1Length(plain.length));
      expect(File('${dir.path}/plain').readAsBytesSync(), plain);
      expect(kma1DecryptSync(File('${dir.path}/sealed').readAsBytesSync(), key), plain);
    });
  });

  group('KMA1 refuses', () {
    final plain = _bytes(3 * kma1ChunkLength + 500);
    late Uint8List file;
    setUpAll(() => file = kma1EncryptSync(plain, key));

    const header = 12;
    const sealedChunk = kma1ChunkLength + 16;

    test('a flipped byte anywhere', () {
      for (final at in [0, 5, header, header + 100, header + sealedChunk + 3, file.length - 1]) {
        final changed = Uint8List.fromList(file);
        changed[at] ^= 0x01;
        expect(() => kma1DecryptSync(changed, key), _damaged, reason: 'byte $at');
      }
    });

    test('a file cut short, inside a chunk or at its end', () {
      for (final length in [0, 11, header, header + 15, header + sealedChunk, header + 2 * sealedChunk, file.length - 1]) {
        expect(() => kma1DecryptSync(Uint8List.sublistView(file, 0, length), key), _damaged, reason: 'length $length');
      }
    });

    test('swapped chunks', () {
      final swapped = Uint8List.fromList(file)
        ..setRange(header, header + sealedChunk, file, header + sealedChunk)
        ..setRange(header + sealedChunk, header + 2 * sealedChunk, file, header);

      expect(() => kma1DecryptSync(swapped, key), _damaged);
    });

    test('a chunk taken from another file under the same key', () {
      final other = kma1EncryptSync(plain, key);
      final mixed = Uint8List.fromList(file)..setRange(header, header + sealedChunk, other, header);

      expect(() => kma1DecryptSync(mixed, key), _damaged);
    });

    test('data after the last chunk', () {
      final longer = Uint8List.fromList([...file, ...file.sublist(header, header + 16)]);

      expect(() => kma1DecryptSync(longer, key), _damaged);
    });

    test('the wrong key', () {
      expect(() => kma1DecryptSync(file, randomBytes(32)), _damaged);
    });

    test('a file that is not KMA1', () {
      final other = Uint8List.fromList([...'KMA2'.codeUnits, ...file.sublist(4)]);

      expect(() => kma1DecryptSync(other, key), _damaged);
    });

    test('and leaves no plaintext behind when decrypting to a file', () async {
      final dir = Directory.systemTemp.createTempSync('kma1');
      addTearDown(() => dir.deleteSync(recursive: true));
      final changed = Uint8List.fromList(file);
      changed[changed.length - 1] ^= 0x01;
      File('${dir.path}/sealed').writeAsBytesSync(changed);

      await expectLater(kma1DecryptFile('${dir.path}/sealed', '${dir.path}/plain', key), _damaged);

      expect(File('${dir.path}/plain').existsSync(), isFalse);
    });

    test('in a background isolate, with the same error', () async {
      final changed = Uint8List.fromList(file);
      changed[header] ^= 0x01;

      await expectLater(kma1Decrypt(changed, key), _damaged);
    });
  });
}
