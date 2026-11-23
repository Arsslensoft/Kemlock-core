// The few things `pgp.dart` does to files by path that need `dart:io`:
// measuring, sniffing, writing, renaming and deleting. Where there is no
// `dart:io` (dart2wasm) the browser passes its data as bytes, so these only
// throw, and no error is a file error.

export 'pgp_files_stub.dart' if (dart.library.io) 'pgp_files_io.dart';
