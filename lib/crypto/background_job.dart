import 'dart:async';

/// A computation started by `startBackgroundJob` that can be stopped.
abstract interface class BackgroundJob<T extends Object> {
  /// The computation's value, or null once [cancel] stopped it. Fails with a
  /// [BackgroundError] if the computation threw, or a [BackgroundStopped] if
  /// it ended without a value.
  Future<T?> get result;

  /// Stops the computation; does nothing once it has finished.
  void cancel();
}

/// The computation threw. [error] and [stack] are how it said so, as text,
/// since an error cannot always cross from one isolate to another.
class BackgroundError implements Exception {
  const BackgroundError(this.error, this.stack);

  final String error;
  final String stack;

  @override
  String toString() => 'BackgroundError: $error';
}

/// The computation ended without giving a value or an error.
class BackgroundStopped implements Exception {
  const BackgroundStopped();

  @override
  String toString() => 'BackgroundStopped';
}
