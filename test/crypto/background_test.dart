@TestOn('vm')
library;

import 'package:kemlock_core/crypto/background.dart';
import 'package:kemlock_core/crypto/background_stub.dart' as stub;
import 'package:test/test.dart';

// `runInBackground` is the one place the account crypto reaches isolates. On the VM it is an isolate; under
// dart2wasm it is the stub, which this runs directly so both halves are held to the same behaviour.
void main() {
  group('runInBackground', () {
    test('gives the result of a synchronous computation', () async {
      expect(await runInBackground(() => 6 * 7), 42);
    });

    test('gives the result of an asynchronous computation', () async {
      expect(await runInBackground<String>(() async => 'done'), 'done');
    });

    test('passes an error on', () async {
      await expectLater(runInBackground<int>(() => throw const FormatException('nope')), throwsA(anything));
    });
  });

  group('the stub that stands in under dart2wasm', () {
    test('gives the result of a synchronous computation', () async {
      expect(await stub.runInBackground(() => 6 * 7), 42);
    });

    test('gives the result of an asynchronous computation', () async {
      expect(await stub.runInBackground<String>(() async => 'done'), 'done');
    });

    test('passes an error on, as a failed future and not a throw', () async {
      final future = stub.runInBackground<int>(() => throw const FormatException('nope'));
      await expectLater(future, throwsFormatException);
    });
  });
}
