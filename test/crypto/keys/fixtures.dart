import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart';
import 'package:test/test.dart';

/// A file under `test/fixtures/keys`, made by the tools `NOTES.md` names.
/// The fixtures are never regenerated.
Uint8List keyFixture(String path) => File('test/fixtures/keys/$path').readAsBytesSync();

String keyFixtureText(String path) => File('test/fixtures/keys/$path').readAsStringSync();

/// Matches a [KeyFormatException] with [problem], and [detail] when given.
Matcher throwsKeyProblem(KeyProblem problem, [String? detail]) =>
    throwsA(isA<KeyFormatException>().having((e) => e.problem, 'problem', problem).having((e) => e.detail, 'detail', detail ?? anything));
