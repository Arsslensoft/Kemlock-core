// ZIP and ZLIB decompression through `dart:io`, where there is one.

import 'dart:io';
import 'dart:typed_data';

import 'pgp_error.dart';
import 'stream.dart';

/// ZIP (raw DEFLATE) or ZLIB data read from [_in] and inflated through `dart:io`, a piece at a time.
class StreamInflate implements ByteSource {
  StreamInflate(this._in, {required bool raw}) : _filter = RawZLibFilter.inflateFilter(raw: raw);

  final PgpReader _in;
  final RawZLibFilter _filter;
  bool _inEnded = false;
  bool _done = false;

  @override
  Uint8List? next() {
    while (!_done) {
      final List<int>? out;
      try {
        out = _filter.processed(flush: false, end: _inEnded);
      } on PgpException {
        rethrow;
      } on Object catch (e) {
        throw PgpException(PgpProblem.damaged, detail: 'compressed data: $e');
      }
      if (out != null && out.isNotEmpty) return out is Uint8List ? out : Uint8List.fromList(out);
      if (_inEnded) {
        _done = true;
        break;
      }
      final piece = _in.some();
      if (piece == null) {
        _inEnded = true;
        continue;
      }
      try {
        _filter.process(piece, 0, piece.length);
      } on Object catch (e) {
        throw PgpException(PgpProblem.damaged, detail: 'compressed data: $e');
      }
    }
    return null;
  }
}
