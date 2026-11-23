// One function to run a computation off the calling thread where the
// platform has isolates, and on it where it has none. `Isolate.run` throws
// under dart2wasm and `dart:isolate` is not there for the browser, so the
// account crypto, which has to run in the browser extension's dart2wasm core
// (`add-account-crypto`, task 6.4), reaches isolates only through this file.
// The extension's own workers take the place of the isolates there.
//
// `startBackgroundJob` is the same for a computation somebody may stop, like
// the making of a key.

export 'background_job.dart';
export 'background_stub.dart' if (dart.library.io) 'background_io.dart';
