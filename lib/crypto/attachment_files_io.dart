// The `KMA1` file helpers that need `dart:io` and isolates: a whole file
// encrypted to or decrypted from a path, chunk by chunk, in a background
// isolate. The format and the in-memory functions are in
// `attachment_core.dart`, which has neither, so the account crypto can run
// under dart2wasm. `attachment_format.dart` exports both.

library;

import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'attachment_core.dart';

/// Encrypts [plain] to the file at [path] chunk by chunk in a background
/// isolate, so the ciphertext is never held whole.
Future<void> kma1EncryptToFile(Uint8List plain, Uint8List key, String path) => Isolate.run(() {
  final writer = Kma1Writer(key);
  final out = File(path).openSync(mode: FileMode.writeOnly);
  try {
    out.writeFromSync(writer.header());
    var offset = 0;
    do {
      final end = offset + kma1ChunkLength;
      final last = end >= plain.length;
      out.writeFromSync(writer.chunk(Uint8List.sublistView(plain, offset, last ? plain.length : end), last: last));
      offset = end;
    } while (offset < plain.length);
    out.flushSync();
  } finally {
    out.closeSync();
  }
}, debugName: 'kma1');

/// Decrypts the `KMA1` file at [input] to [output] chunk by chunk in a
/// background isolate. On [AttachmentDamagedError], or any other failure,
/// [output] is deleted, so no part of the plaintext is left behind.
Future<void> kma1DecryptFile(String input, String output, Uint8List key) => Isolate.run(() {
  final source = File(input).openSync();
  final target = File(output).openSync(mode: FileMode.writeOnly);
  var ok = false;
  try {
    final length = source.lengthSync();
    if (length < kma1HeaderLength + kma1TagLength) throw const AttachmentDamagedError('too short');
    final reader = Kma1Reader(key, source.readSync(kma1HeaderLength));
    var offset = kma1HeaderLength;
    while (true) {
      final size = length - offset < kma1SealedChunkLength ? length - offset : kma1SealedChunkLength;
      final last = offset + size >= length;
      target.writeFromSync(reader.chunk(source.readSync(size), last: last));
      if (last) break;
      offset += size;
    }
    target.flushSync();
    ok = true;
  } finally {
    source.closeSync();
    target.closeSync();
    if (!ok) File(output).deleteSync();
  }
}, debugName: 'kma1');
