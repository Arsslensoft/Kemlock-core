// The `KMA1` file helpers that need `dart:io` and isolates: a whole file
// encrypted to or decrypted from a path, chunk by chunk, in a background
// isolate. The format and the in-memory functions are in
// `attachment_core.dart`, which has neither, so the account crypto can run
// under dart2wasm. `attachment_format.dart` exports both. Where there is no
// `dart:io` (the browser) the file functions only throw.

export 'attachment_files_stub.dart' if (dart.library.io) 'attachment_files_io.dart';
