@Tags(['wasm'])
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:test/test.dart';

void main() {
  final salt = Uint8List.fromList(List.generate(16, (i) => i));

  test('the defaults are the settings of new accounts', () {
    const settings = Argon2idSettings();
    expect(settings.memoryKiB, 65536);
    expect(settings.iterations, 3);
    expect(settings.parallelism, 4);
  });

  test('hands the runner the UTF-8 of the password, the salt and the settings', () async {
    Uint8List? gotPassword;
    Uint8List? gotSalt;
    Argon2idSettings? gotSettings;
    final key = await deriveMasterKey(
      'hunter2',
      salt,
      settings: const Argon2idSettings(memoryKiB: 8, iterations: 1, parallelism: 1),
      runner: (password, saltBytes, settings) async {
        gotPassword = Uint8List.fromList(password);
        gotSalt = saltBytes;
        gotSettings = settings;
        return Uint8List(32)..fillRange(0, 32, 7);
      },
    );
    expect(gotPassword, utf8.encode('hunter2'));
    expect(gotSalt, salt);
    expect(gotSettings, const Argon2idSettings(memoryKiB: 8, iterations: 1, parallelism: 1));
    expect(key, List.filled(32, 7));
  });

  test('zeroes its copy of the password afterwards', () async {
    late Uint8List seen;
    await deriveMasterKey(
      'hunter2',
      salt,
      runner: (password, _, _) async {
        seen = password;
        return Uint8List(32);
      },
    );
    expect(seen, List.filled(7, 0));
  });

  test('puts the password through the normalizer first', () async {
    late Uint8List seen;
    await deriveMasterKey(
      'a',
      salt,
      normalize: (text) => '${text}b',
      runner: (password, _, _) async {
        seen = Uint8List.fromList(password);
        return Uint8List(32);
      },
    );
    expect(seen, utf8.encode('ab'));
  });

  group('NFC', () {
    Future<List<int>> inputOf(String password) async {
      late List<int> seen;
      await deriveMasterKey(
        password,
        salt,
        runner: (bytes, _, _) async {
          seen = List<int>.of(bytes);
          return Uint8List(32);
        },
      );
      return seen;
    }

    test('a decomposed and a precomposed e acute give the same input bytes', () async {
      // "café" in NFC: 63 61 66, then U+00E9 as c3 a9
      const cafe = [0x63, 0x61, 0x66, 0xc3, 0xa9];
      expect(await inputOf('café'), cafe);
      expect(await inputOf('café'), cafe);
    });

    test('a singleton compatibility character maps to its canonical one', () async {
      // U+2126 OHM SIGN normalises to U+03A9 (ce a9), U+212B ANGSTROM SIGN to U+00C5 (c3 85)
      expect(await inputOf('Ω'), [0xce, 0xa9]);
      expect(await inputOf('Å'), [0xc3, 0x85]);
    });

    test('ASCII is left alone', () {
      expect(normalizePassword('hunter2'), 'hunter2');
    });
  });

  test('refuses a salt that is not 16 bytes and a key that is not 32', () async {
    await expectLater(deriveMasterKey('x', Uint8List(8), runner: (_, _, _) async => Uint8List(32)), throwsA(isA<MalformedException>()));
    await expectLater(deriveMasterKey('x', salt, runner: (_, _, _) async => Uint8List(31)), throwsA(isA<MalformedException>()));
  });
}
