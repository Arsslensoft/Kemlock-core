@TestOn('vm')
library;

// The entry library names the package and holds nothing to call: importing it is the test.
// ignore: unused_import
import 'package:kemlock_core/kemlock_core.dart';
import 'package:test/test.dart';

void main() {
  test('the library loads', () {
    expect(true, isTrue);
  });
}
