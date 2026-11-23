/// `KMA1`, the format a file attached to a note is stored in, on the phone,
/// in exports and on sync servers:
///
/// ```text
/// "KMA1" | nonce prefix (8 random bytes) | chunk 0 | chunk 1 | … | last chunk
/// chunk = AES-256-GCM(key, nonce = prefix || counter (4 bytes, big-endian),
///                     aad = 0x00, or 0x01 for the last chunk,
///                     up to 64 KiB of plaintext) || tag (16 bytes)
/// ```
///
/// Every chunk but the last holds exactly 64 KiB; the last holds the rest,
/// possibly nothing, so a file always ends in exactly one last chunk. The
/// counter makes reordered chunks fail, and the last-chunk byte in the
/// associated data makes a file cut short at a chunk boundary fail. Each
/// file has its own random 256-bit key, kept in the note's record in the
/// vault, never with the file.
///
/// Files written by other versions read this, so once released it doesn't
/// change: the fixture in test/fixtures/attachments pins it.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

import 'background.dart';
import 'bytes.dart';

/// The bytes every `KMA1` file starts with.
final kma1Magic = Uint8List.fromList('KMA1'.codeUnits);

/// The plaintext in every chunk but the last.
const kma1ChunkLength = 64 * 1024;

const _prefixLength = 8;

/// The length of a chunk's tag.
const kma1TagLength = 16;

/// The length of the header: the magic and the nonce prefix.
const kma1HeaderLength = 4 + _prefixLength;

/// The length of a full sealed chunk: 64 KiB of plaintext and its tag.
const kma1SealedChunkLength = kma1ChunkLength + kma1TagLength;

/// The size of the `KMA1` file a [plainLength]-byte file becomes.
int kma1Length(int plainLength) {
  final chunks = plainLength == 0 ? 1 : (plainLength + kma1ChunkLength - 1) ~/ kma1ChunkLength;
  return kma1HeaderLength + plainLength + chunks * kma1TagLength;
}

/// The file isn't a `KMA1` file this key opens: changed, cut short, put
/// together from another file's chunks, or opened with the wrong key. No
/// plaintext is returned once this is thrown.
class AttachmentDamagedError implements Exception {
  const AttachmentDamagedError(this.reason);

  final String reason;

  @override
  String toString() => 'AttachmentDamagedError: $reason';
}

final _aes = DartAesGcm.with256bits();
final _middle = Uint8List.fromList(const [0]);
final _last = Uint8List.fromList(const [1]);

/// Encrypts one file's chunks in order, from its header to its last chunk.
class Kma1Writer {
  Kma1Writer(Uint8List key, {Uint8List? noncePrefix})
    : _key = SecretKeyData(_checkKey(key)),
      _prefix = noncePrefix ?? randomBytes(_prefixLength) {
    if (_prefix.length != _prefixLength) throw ArgumentError.value(_prefix.length, 'noncePrefix', 'must be 8 bytes');
  }

  final SecretKeyData _key;
  final Uint8List _prefix;
  var _counter = 0;
  var _done = false;

  /// The file's first 12 bytes.
  Uint8List header() => concatBytes([kma1Magic, _prefix]);

  /// The next chunk sealed: exactly [kma1ChunkLength] bytes of [plain]
  /// unless it is the [last] one.
  Uint8List chunk(List<int> plain, {required bool last}) {
    if (_done) throw StateError('The last chunk was written already');
    if (plain.length > kma1ChunkLength || (!last && plain.length != kma1ChunkLength)) {
      throw ArgumentError.value(plain.length, 'plain', 'a chunk holds $kma1ChunkLength bytes, the last one at most that');
    }
    _done = last;
    final box = _aes.encryptSync(plain, secretKeyData: _key, nonce: _nonce(_prefix, _counter++), aad: last ? _last : _middle);
    return concatBytes([box.cipherText, box.mac.bytes]);
  }
}

/// Opens one file's chunks in order, after its header.
class Kma1Reader {
  Kma1Reader(Uint8List key, Uint8List header) : _key = SecretKeyData(_checkKey(key)), _prefix = _readHeader(header);

  final SecretKeyData _key;
  final Uint8List _prefix;
  var _counter = 0;
  var _done = false;

  /// The plaintext of the next sealed chunk. Throws [AttachmentDamagedError]
  /// when it doesn't open as the chunk at this place, [last] or not.
  Uint8List chunk(List<int> sealed, {required bool last}) {
    if (_done) throw const AttachmentDamagedError('data after the last chunk');
    if (sealed.length < kma1TagLength || sealed.length > kma1SealedChunkLength || (!last && sealed.length != kma1SealedChunkLength)) {
      throw const AttachmentDamagedError('a chunk of the wrong size');
    }
    _done = last;
    final split = sealed.length - kma1TagLength;
    final box = SecretBox(sealed.sublist(0, split), nonce: _nonce(_prefix, _counter++), mac: Mac(sealed.sublist(split)));
    try {
      return Uint8List.fromList(_aes.decryptSync(box, secretKeyData: _key, aad: last ? _last : _middle));
    } on SecretBoxAuthenticationError {
      throw const AttachmentDamagedError('a chunk does not open');
    }
  }
}

Uint8List _readHeader(Uint8List header) {
  if (header.length != kma1HeaderLength) throw const AttachmentDamagedError('too short');
  for (var i = 0; i < kma1Magic.length; i++) {
    if (header[i] != kma1Magic[i]) throw const AttachmentDamagedError('not a KMA1 file');
  }
  return header.sublist(4);
}

List<int> _nonce(Uint8List prefix, int counter) {
  if (counter > 0xffffffff) throw StateError('Too many chunks');
  final nonce = Uint8List(12)..setRange(0, _prefixLength, prefix);
  ByteData.sublistView(nonce).setUint32(_prefixLength, counter);
  return nonce;
}

Uint8List _checkKey(Uint8List key) {
  if (key.length != 32) throw ArgumentError.value(key.length, 'key', 'a KMA1 key is 32 bytes');
  return Uint8List.fromList(key);
}

// ─── Whole files ─────────────────────────────────────────────────────────────

/// [plain] as a `KMA1` file, on this isolate.
Uint8List kma1EncryptSync(Uint8List plain, Uint8List key, {Uint8List? noncePrefix}) {
  final writer = Kma1Writer(key, noncePrefix: noncePrefix);
  final out = BytesBuilder(copy: false)..add(writer.header());
  var offset = 0;
  do {
    final end = offset + kma1ChunkLength;
    final last = end >= plain.length;
    out.add(writer.chunk(Uint8List.sublistView(plain, offset, last ? plain.length : end), last: last));
    offset = end;
  } while (offset < plain.length);
  return out.takeBytes();
}

/// The plaintext of the `KMA1` [file], on this isolate; throws
/// [AttachmentDamagedError] when it doesn't open.
Uint8List kma1DecryptSync(Uint8List file, Uint8List key) {
  if (file.length < kma1HeaderLength + kma1TagLength) throw const AttachmentDamagedError('too short');
  final reader = Kma1Reader(key, Uint8List.sublistView(file, 0, kma1HeaderLength));
  final out = BytesBuilder(copy: false);
  var offset = kma1HeaderLength;
  while (true) {
    final end = offset + kma1SealedChunkLength;
    // A full chunk with nothing after it is the last one, as the writer made it
    final last = end >= file.length;
    out.add(reader.chunk(Uint8List.sublistView(file, offset, last ? file.length : end), last: last));
    if (last) break;
    offset = end;
  }
  return out.takeBytes();
}

/// [plain] as a `KMA1` file, encrypted in a background isolate, or on this thread where there are none (dart2wasm).
Future<Uint8List> kma1Encrypt(Uint8List plain, Uint8List key) => runInBackground(() => kma1EncryptSync(plain, key), debugName: 'kma1');

/// The plaintext of [file], decrypted in a background isolate, or on this thread where there are none (dart2wasm).
Future<Uint8List> kma1Decrypt(Uint8List file, Uint8List key) => runInBackground(() => kma1DecryptSync(file, key), debugName: 'kma1');
