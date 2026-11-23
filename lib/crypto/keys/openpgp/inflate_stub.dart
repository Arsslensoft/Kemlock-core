// ZIP and ZLIB decompression where there is no `dart:io` (dart2wasm):
// `package:archive`'s own inflate.

import 'dart:typed_data';

import 'package:archive/archive.dart';

import 'pgp_error.dart';
import 'stream.dart';

/// The most compressed data read for one packet: its length is four bytes.
const _maxCompressed = 1 << 32;

/// ZIP (raw DEFLATE) or ZLIB data read from [_in] and inflated by `archive`, a piece at a time.
/// The compressed data is read whole when the first piece is asked for; the inflated data is not.
class StreamInflate implements ByteSource {
  StreamInflate(this._in, {required this.raw});

  final PgpReader _in;
  final bool raw;
  InputStream? _stream;
  bool _done = false;

  @override
  Uint8List? next() {
    if (_done) return null;
    try {
      final stream = _stream ??= const ZLibDecoderWeb().decodeLazy(InputMemoryStream(_in.rest(max: _maxCompressed)), raw: raw);
      final piece = stream.readBytes(pgpPieceSize).toUint8List();
      if (piece.isEmpty) {
        _done = true;
        return null;
      }
      return piece;
    } on PgpException {
      rethrow;
    } on Object catch (e) {
      throw PgpException(PgpProblem.damaged, detail: 'compressed data: $e');
    }
  }
}
