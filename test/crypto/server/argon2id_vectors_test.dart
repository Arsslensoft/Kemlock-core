@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:test/test.dart';

import '../account/server_vectors.dart';
import '../vectors.dart';

// The server's argon2id.json (crypto.md "Master key"): Argon2id version 0x13
// over the UTF-8 of the NFC password, 32 bytes out.
void main() {
  group("the server's argon2id vectors", () {
    for (final c in readServerCases('argon2id.json')) {
      final name = c['name']! as String;
      final settings = Argon2idSettings(
        memoryKiB: c['memory_kib']! as int,
        iterations: c['iterations']! as int,
        parallelism: c['parallelism']! as int,
      );
      final salt = fromHex(c['salt']! as String);
      final passwordText = c['password_text']! as String;

      test(name, () async {
        // The vector's password bytes are the UTF-8 of its text, already NFC.
        expect(toHex(utf8.encode(passwordText)), c['password']);
        expect(normalizePassword(passwordText), passwordText);

        final key = await deriveMasterKey(passwordText, salt, settings: settings);
        expect(toHex(key), c['master_key']);
      }, timeout: const Timeout(Duration(minutes: 2)));
    }

    test('nfc-password: the decomposed spelling of the password gives the same master key', () async {
      final c = readServerCases('argon2id.json').firstWhere((c) => c['name'] == 'nfc-password');
      // "e" followed by U+0301 is the decomposed form of U+00E9.
      const decomposed = 'café \u{1F511}';
      expect(decomposed, isNot(c['password_text']));
      final key = await deriveMasterKey(
        decomposed,
        fromHex(c['salt']! as String),
        settings: Argon2idSettings(
          memoryKiB: c['memory_kib']! as int,
          iterations: c['iterations']! as int,
          parallelism: c['parallelism']! as int,
        ),
      );
      expect(toHex(key), c['master_key']);
    });
  });
}
