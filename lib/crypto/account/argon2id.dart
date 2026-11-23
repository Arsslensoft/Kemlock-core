// The master key of `docs/crypto.md` "Master key":
// `Argon2id(password, salt, m, t, p, L = 32)`, version 0x13, over the UTF-8
// of the password in Unicode NFC form. New accounts use m = 65536 KiB, t = 3,
// p = 4 and a 16-byte salt the server keeps and returns before sign-in.
//
// Argon2id runs behind one function, [Argon2idRunner]. The default runs it
// in a short-lived isolate, as the Bitwarden master key does, or on the
// calling thread where there are no isolates (`runInBackground`). Under
// dart2wasm the browser extension's key-derivation runner
// (add-browser-extension, task 2.2) takes its place by being passed as
// `runner`, so Argon2id runs in a worker, not on the page.

library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import '../background.dart';
import 'encoding.dart';

/// The Argon2id settings the server returns before sign-in. The defaults are
/// the ones new accounts use.
final class Argon2idSettings {
  const Argon2idSettings({this.memoryKiB = 65536, this.iterations = 3, this.parallelism = 4});

  /// Memory in KiB (`m`).
  final int memoryKiB;

  /// Passes over the memory (`t`).
  final int iterations;

  /// Lanes (`p`).
  final int parallelism;

  /// The master key's length (`L`).
  static const keyLength = 32;

  /// The salt's length. The server picks it at random for a new account.
  static const saltLength = 16;

  @override
  bool operator ==(Object other) =>
      other is Argon2idSettings && other.memoryKiB == memoryKiB && other.iterations == iterations && other.parallelism == parallelism;

  @override
  int get hashCode => Object.hash(memoryKiB, iterations, parallelism);

  @override
  String toString() => 'Argon2idSettings(m=$memoryKiB, t=$iterations, p=$parallelism)';
}

/// Runs Argon2id (version 0x13) over [password] and [salt] and gives the
/// 32-byte key. The seam of design 1: the default is [isolateArgon2id].
typedef Argon2idRunner = Future<Uint8List> Function(Uint8List password, Uint8List salt, Argon2idSettings settings);

/// Argon2id in a background isolate, off the UI thread. Under dart2wasm there is no isolate, so it runs on the calling
/// thread, and the extension passes its own runner.
Future<Uint8List> isolateArgon2id(Uint8List password, Uint8List salt, Argon2idSettings settings) {
  final memory = settings.memoryKiB;
  final iterations = settings.iterations;
  final parallelism = settings.parallelism;
  final secret = Uint8List.fromList(password);
  final nonce = Uint8List.fromList(salt);
  return runInBackground<Uint8List>(() async {
    final argon = DartArgon2id(parallelism: parallelism, memory: memory, iterations: iterations, hashLength: Argon2idSettings.keyLength);
    final key = await argon.deriveKey(secretKey: SecretKeyData(secret), nonce: nonce);
    return Uint8List.fromList(await key.extractBytes());
  }, debugName: 'argon2id');
}

/// [password] in Unicode NFC form, as `crypto.md` "Master key" has it hashed.
/// A decomposed "e" followed by U+0301 and the precomposed U+00E9 give the
/// same text, so one password typed on two keyboards gives one master key.
String normalizePassword(String password) => unorm.nfc(password);

/// The master key: Argon2id of the UTF-8 of [password] in NFC form, with the
/// server's [salt] and [settings]. Needs a 16-byte salt.
///
/// [normalize] puts the password in NFC form, [normalizePassword] by default;
/// [runner] runs Argon2id, [isolateArgon2id] by default. The password's bytes
/// are zeroed once the runner is done with them.
Future<Uint8List> deriveMasterKey(
  String password,
  List<int> salt, {
  Argon2idSettings settings = const Argon2idSettings(),
  String Function(String) normalize = normalizePassword,
  Argon2idRunner runner = isolateArgon2id,
}) async {
  requireLength(salt, Argon2idSettings.saltLength, 'the Argon2id salt');
  final bytes = Uint8List.fromList(utf8.encode(normalize(password)));
  try {
    final key = await runner(bytes, Uint8List.fromList(salt), settings);
    return requireLength(key, Argon2idSettings.keyLength, 'the master key');
  } finally {
    wipe(bytes);
  }
}
