@Tags(['wasm'])
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/session.dart';
import 'package:test/test.dart';

void main() {
  AccountSession build({bool withExportKey = true}) => AccountSession(
    keys: AccountKeys.fromRoot(Uint8List.fromList(List.generate(64, (i) => i + 1))),
    kx1PrivateKey: Uint8List.fromList(List.generate(96, (i) => i + 1)),
    sig1PrivateKey: Uint8List.fromList(List.generate(64, (i) => i + 1)),
    exportKey: withExportKey ? Uint8List.fromList(List.generate(64, (i) => i + 1)) : null,
  );

  test('disposing zeroes the root, the user key, the children, the private keys and the export key', () {
    final session = build();
    final buffers = [
      session.keys.root,
      session.keys.userKey,
      session.keys.itemWrapKey,
      session.keys.privateKeysKey,
      session.keys.manifestKey,
      session.kx1PrivateKey,
      session.sig1PrivateKey,
      session.exportKey!,
    ];
    for (final buffer in buffers) {
      expect(buffer.any((byte) => byte != 0), isTrue);
    }
    session.dispose();
    expect(session.isDisposed, isTrue);
    for (final (i, buffer) in buffers.indexed) {
      expect(buffer.every((byte) => byte == 0), isTrue, reason: 'buffer $i');
    }
  });

  test('a disposed session gives out nothing', () {
    final session = build()..dispose();
    expect(() => session.kx1PrivateKey, throwsStateError);
    expect(() => session.sig1PrivateKey, throwsStateError);
    expect(() => session.exportKey, throwsStateError);
    expect(() => session.keys.root, throwsStateError);
  });

  test('an account without an export key has none, and disposes fine', () {
    final session = build(withExportKey: false);
    expect(session.exportKey, isNull);
    session.dispose();
    expect(session.exportKey, isNull);
  });

  test('refuses keys of the wrong length', () {
    final keys = AccountKeys.fromRoot(Uint8List(64));
    expect(
      () => AccountSession(keys: keys, kx1PrivateKey: Uint8List(95), sig1PrivateKey: Uint8List(64)),
      throwsA(isA<MalformedException>()),
    );
    expect(
      () => AccountSession(keys: keys, kx1PrivateKey: Uint8List(96), sig1PrivateKey: Uint8List(63)),
      throwsA(isA<MalformedException>()),
    );
    expect(
      () => AccountSession(keys: keys, kx1PrivateKey: Uint8List(96), sig1PrivateKey: Uint8List(64), exportKey: Uint8List(32)),
      throwsA(isA<MalformedException>()),
    );
  });
}
