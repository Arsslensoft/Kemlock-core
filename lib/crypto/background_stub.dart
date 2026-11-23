import 'dart:async';

import 'background_job.dart';

/// Runs [computation] on the calling thread, where there are no isolates (dart2wasm).
Future<T> runInBackground<T>(FutureOr<T> Function() computation, {String? debugName}) => Future<T>.sync(computation);

/// Runs [computation] on the calling thread; [BackgroundJob.cancel] only
/// drops its result, as nothing can interrupt it.
BackgroundJob<T> startBackgroundJob<T extends Object>(FutureOr<T> Function() computation) => _InlineJob<T>(computation);

class _InlineJob<T extends Object> implements BackgroundJob<T> {
  _InlineJob(FutureOr<T> Function() computation) {
    unawaited(_start(computation));
  }

  final _done = Completer<T?>();

  @override
  Future<T?> get result => _done.future;

  @override
  void cancel() {
    if (!_done.isCompleted) _done.complete(null);
  }

  Future<void> _start(FutureOr<T> Function() computation) async {
    try {
      final value = await computation();
      if (!_done.isCompleted) _done.complete(value);
    } on Object catch (e, stack) {
      if (!_done.isCompleted) _done.completeError(BackgroundError('$e', '$stack'), stack);
    }
  }
}
