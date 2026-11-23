// ZIP (raw DEFLATE) and ZLIB data read a piece at a time, as `message.dart`
// needs it. With a `dart:io` the platform's own zlib does it; without one
// (dart2wasm) `package:archive`'s inflate does.

export 'inflate_stub.dart' if (dart.library.io) 'inflate_io.dart';
