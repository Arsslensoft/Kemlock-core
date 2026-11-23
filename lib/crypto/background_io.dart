import 'dart:async';
import 'dart:isolate';

import 'background_job.dart';

/// Runs [computation] in a short-lived isolate and gives its result. It and
/// everything it captures must be sendable to another isolate.
Future<T> runInBackground<T>(FutureOr<T> Function() computation, {String? debugName}) => Isolate.run<T>(computation, debugName: debugName);

/// Starts [computation] in an isolate that [BackgroundJob.cancel] kills. A
/// value it returns, including an exception it returns instead of throwing,
/// comes back as it is; anything it throws comes back as a [BackgroundError].
BackgroundJob<T> startBackgroundJob<T extends Object>(FutureOr<T> Function() computation) => _IsolateJob<T>(computation);

class _IsolateJob<T extends Object> implements BackgroundJob<T> {
  _IsolateJob(FutureOr<T> Function() computation) {
    unawaited(_start(computation));
  }

  final _done = Completer<T?>();
  Isolate? _isolate;
  RawReceivePort? _port;

  @override
  Future<T?> get result => _done.future;

  @override
  void cancel() {
    if (_done.isCompleted) return;
    _done.complete(null);
    _isolate?.kill(priority: Isolate.immediate);
    _port?.close();
  }

  Future<void> _start(FutureOr<T> Function() computation) async {
    final port = _port = RawReceivePort();
    port.handler = (Object? message) {
      port.close();
      if (_done.isCompleted) return;
      switch (message) {
        case final T value:
          _done.complete(value);
        case [final Object? error, final Object? stack]:
          _done.completeError(BackgroundError('$error', '$stack'), StackTrace.fromString('$stack'));
        default:
          _done.completeError(const BackgroundStopped());
      }
    };
    try {
      final isolate = await Isolate.spawn(_run, (port.sendPort, computation), onError: port.sendPort, onExit: port.sendPort);
      _isolate = isolate;
      // Cancelled while the isolate was starting.
      if (_done.isCompleted) isolate.kill(priority: Isolate.immediate);
    } on Object catch (e, stack) {
      port.close();
      if (!_done.isCompleted) _done.completeError(e, stack);
    }
  }
}

Future<void> _run((SendPort, FutureOr<Object> Function()) message) async {
  final (port, computation) = message;
  Isolate.exit(port, await computation());
}
