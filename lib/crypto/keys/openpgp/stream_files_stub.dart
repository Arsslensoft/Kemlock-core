// [FileSource] and [FileSink] where there is no `dart:io` (dart2wasm): the
// browser reads and writes no files, so making one throws.

import 'dart:typed_data';

import 'stream.dart';

const _unsupported = 'Files are not read or written in this build';

/// A file read by path, [pgpPieceSize] at a time: not possible in this build.
class FileSource implements ByteSource {
  FileSource(String path, {this.onRead}) {
    throw UnsupportedError(_unsupported);
  }

  final void Function(int read)? onRead;

  @override
  Uint8List? next() => throw UnsupportedError(_unsupported);

  void close() {}
}

/// Writes what it is given to a file: not possible in this build.
class FileSink implements ByteSink {
  FileSink(String path) {
    throw UnsupportedError(_unsupported);
  }

  int length = 0;

  @override
  void add(Uint8List data) => throw UnsupportedError(_unsupported);

  void close() {}
}
