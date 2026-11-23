import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

/// The JSON that `tool/fixtures/crypto_vectors.mjs` wrote from the
/// TypeScript app's libraries.
Object? readVectors(String name) => jsonDecode(File('test/fixtures/crypto/$name').readAsStringSync());

/// The objects of a JSON list.
List<Map<String, Object?>> objects(Object? list) => (list! as List<Object?>).cast<Map<String, Object?>>();

Uint8List fromHex(String hex) =>
    Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

String toHex(List<int> bytes) => [for (final b in bytes) b.toRadixString(16).padLeft(2, '0')].join();
