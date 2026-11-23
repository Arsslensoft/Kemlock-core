// The library has nothing to call yet: importing it is the test, since it must compile on the VM and on dart2wasm.
// ignore: unused_import
import 'package:kemlock_core/kemlock_core.dart';
import 'package:test/test.dart';

void main() {
  test('the library loads', () {
    expect(true, isTrue);
  });
}
