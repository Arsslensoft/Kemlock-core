@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:test/test.dart';

/// The KMA1 files in test/fixtures/attachments were written once, when the
/// format was added, and are never regenerated: attached files on phones,
/// in exports and on sync servers are in this format, and every later
/// version must open them. When they were written, Node 25's own
/// AES-256-GCM (node:crypto) opened all three as well, so the format is
/// what the comment in attachment_format.dart says and not just what this
/// code does.
final _fixture = jsonDecode(File('test/fixtures/attachments/kma1.json').readAsStringSync()) as Map<String, Object?>;

void main() {
  final key = unb64(_fixture['key']! as String);

  for (final file in (_fixture['files']! as List<Object?>).cast<Map<String, Object?>>()) {
    test('opens the ${file['name']} fixture', () {
      final kma1 = file['kma1'] is String
          ? unb64(file['kma1']! as String)
          : File('test/fixtures/attachments/${file['kma1File']}').readAsBytesSync();
      if (file['kma1Sha256'] case final String sum) expect(sha256.convert(kma1).toString(), sum);

      final plain = kma1DecryptSync(kma1, key);

      if (file['plain'] case final String expected) {
        expect(plain, unb64(expected));
      } else {
        expect(plain.length, file['plainLength']);
        expect(plain, Uint8List.fromList([for (var i = 0; i < plain.length; i++) (i * 31 + 7) & 0xff]));
        expect(sha256.convert(plain).toString(), file['plainSha256']);
      }
    });
  }

  test('writes the fixtures again byte for byte from the same nonce prefix', () {
    final short = (_fixture['files']! as List<Object?>).cast<Map<String, Object?>>().firstWhere((file) => file['name'] == 'short');

    final again = kma1EncryptSync(unb64(short['plain']! as String), key, noncePrefix: Uint8List.fromList([9, 10, 11, 12, 13, 14, 15, 16]));

    expect(b64(again), short['kma1']);
  });
}
