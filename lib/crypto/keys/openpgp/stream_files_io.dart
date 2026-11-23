// The file sources and sinks of `stream.dart`, which need `dart:io`:
// `stream_files.dart` gives them where there is an io library.

import 'dart:io';
import 'dart:typed_data';

import 'pgp_error.dart';
import 'stream.dart';

/// A file read by path, [pgpPieceSize] at a time. [onRead] is told how
/// many bytes have been read so far. [close] it when done.
class FileSource implements ByteSource {
  FileSource(String path, {this.onRead}) : _file = File(path).openSync();

  final RandomAccessFile _file;
  final void Function(int read)? onRead;
  int _read = 0;
  bool _closed = false;

  @override
  Uint8List? next() {
    if (_closed) return null;
    final piece = _file.readSync(pgpPieceSize);
    if (piece.isEmpty) return null;
    _read += piece.length;
    onRead?.call(_read);
    return piece;
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _file.closeSync();
  }
}

/// Writes what it is given to a file. A full disk is
/// [PgpProblem.outOfSpace].
class FileSink implements ByteSink {
  FileSink(String path) : _file = File(path).openSync(mode: FileMode.writeOnly);

  final RandomAccessFile _file;
  int length = 0;
  bool _closed = false;

  @override
  void add(Uint8List data) {
    try {
      _file.writeFromSync(data);
    } on FileSystemException catch (e) {
      throw PgpException(PgpProblem.outOfSpace, detail: e.message);
    }
    length += data.length;
  }

  void close() {
    if (_closed) return;
    _closed = true;
    try {
      _file.flushSync();
    } on FileSystemException catch (e) {
      throw PgpException(PgpProblem.outOfSpace, detail: e.message);
    } finally {
      _file.closeSync();
    }
  }
}
