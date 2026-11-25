@TestOn('vm')
library;

import 'package:kemlock_core/features/sends/sends_recipient.dart';
import 'package:kemlock_core/features/sends/sends_rules.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sends_api.dart';
import 'package:test/test.dart';

void main() {
  test('the wait after too many tries is the server\'s, from 1 to 60 seconds, and a minute when it said none', () {
    expect(sendsWaitSeconds(null), 60);
    expect(sendsWaitSeconds(0), 1);
    expect(sendsWaitSeconds(7), 7);
    expect(sendsWaitSeconds(600), 60);
  });

  test('a closed Send is a not found answer, and nothing else is', () {
    expect(isNotAvailable(const SendsError(SendsProblem.notFound)), isTrue);
    expect(isNotAvailable(const SendsError(SendsProblem.wrongPassword)), isFalse);
    expect(isNotAvailable(const FormatException('x')), isFalse);
  });

  test('a link that opens nothing is a payload that is not the Send\'s', () {
    expect(isDoesntOpen(const SendsDoesntOpen()), isTrue);
    expect(isDoesntOpen(const SendsError(SendsProblem.notFound)), isFalse);
  });
}
