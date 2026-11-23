import 'dart:typed_data';

/// The bytes [hex] spells, spaces ignored.
Uint8List unhex(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([for (var i = 0; i < clean.length; i += 2) int.parse(clean.substring(i, i + 2), radix: 16)]);
}

/// [bytes] in lowercase hex.
String hex(List<int> bytes) => [for (final byte in bytes) byte.toRadixString(16).padLeft(2, '0')].join();
