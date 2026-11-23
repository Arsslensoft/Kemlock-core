// Files as sources and sinks of OpenPGP data: [FileSource] and [FileSink]
// need `dart:io`, so they sit apart from `stream.dart`, and where there is
// no `dart:io` (dart2wasm) they only throw.

export 'stream_files_stub.dart' if (dart.library.io) 'stream_files_io.dart';
