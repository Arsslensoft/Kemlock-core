// Whether a failed request failed over a certificate the phone refused. `HandshakeException` is `dart:io`'s, which
// the browser build has not got, so the engines ask here: a browser reports no such failure to the code, and the
// answer there is always no.

export 'tls_failure_stub.dart' if (dart.library.io) 'tls_failure_io.dart';
