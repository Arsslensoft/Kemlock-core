@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/send.dart';
import 'package:kemlock_core/features/sends/send_link.dart';
import 'package:test/test.dart';

import '../../crypto/account/server_vectors.dart';
import '../../crypto/vectors.dart';

/// [bytes] in the standard base64 alphabet, padded.
String _standard(Uint8List bytes) => b64urlEncode(bytes).replaceAll('-', '+').replaceAll('_', '/').padRight(44, '=');

void main() {
  final sendId = Uint8List.fromList(List.generate(16, (i) => i + 1));
  final key = Uint8List.fromList(List.generate(32, (i) => 255 - i));
  final access = sendAccessId(sendId);
  final keyText = b64urlEncode(key);
  final link = 'https://vault.example.com/#/send/$access/$keyText';

  SendLink read(String text) => SendLink.parse(text)! as SendLink;

  group('building', () {
    test('writes the link of crypto.md: the access id and the key in the fragment', () {
      expect(sendLink(Uri.parse('https://vault.example.com'), sendId, key), link);
      expect(access, hasLength(22));
      expect(keyText, hasLength(43));
    });

    test('keeps the port and the path of the server', () {
      expect(
        sendLink(Uri.parse('https://example.com:8443/kemlock'), sendId, key),
        'https://example.com:8443/kemlock/#/send/$access/$keyText',
      );
    });

    test("writes the server's own vectors", () {
      for (final c in readServerCases('send.json')) {
        final server = Uri.parse('https://example.org');
        expect(sendLink(server, fromHex(c['send_id']! as String), fromHex(c['link_key']! as String)), c['link']);
      }
    });
  });

  group('reading', () {
    test('reads a whole URL, and gives back its server, send id and key', () {
      final parsed = read(link);
      expect(parsed.server.toString(), 'https://vault.example.com');
      expect(parsed.sendId, sendId);
      expect(parsed.key, key);
      expect(parsed.accessId, access);
      expect(parsed.toLinkText(), link);
    });

    test("reads the server's vectors", () {
      for (final c in readServerCases('send.json')) {
        final parsed = read(c['link']! as String);
        expect(toHex(parsed.sendId), c['send_id']);
        expect(toHex(parsed.key), c['link_key']);
      }
    });

    test('reads a path before the #, and drops its trailing slash', () {
      final parsed = read('https://example.com/kemlock/#/send/$access/$keyText');
      expect(parsed.server.toString(), 'https://example.com/kemlock');
      expect(read('https://example.com:8443/#/send/$access/$keyText').server.toString(), 'https://example.com:8443');
    });

    test('finds the first link inside a message, with punctuation around it', () {
      expect(read('Here is the Wi-Fi password: $link thanks!').key, key);
      expect(read('(see <$link>.)').key, key);
      expect(read('"$link",\nand later https://other.example.com/#/send/$access/$keyText').server.host, 'vault.example.com');
    });

    test('reads the scheme in capitals', () {
      expect(read('HTTPS://vault.example.com/#/send/$access/$keyText').key, key);
    });

    test('skips a word that is not a link and reads the next', () {
      expect(read('http://vault.example.com/#/send/$access/$keyText $link').server.scheme, 'https');
    });

    test('refuses http, user info and a query', () {
      expect(SendLink.parse('http://vault.example.com/#/send/$access/$keyText'), isNull);
      expect(SendLink.parse('https://ann:pw@vault.example.com/#/send/$access/$keyText'), isNull);
      expect(SendLink.parse('https://vault.example.com/?a=b#/send/$access/$keyText'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access/$keyText?x=1'), isNull);
    });

    test('refuses padded and standard-alphabet base64, and a key of another length', () {
      expect(SendLink.parse('$link='), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access/${_standard(key)}'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access/${b64urlEncode(key.sublist(0, 31))}'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access/${b64urlEncode(Uint8List(33))}'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/${access}A/$keyText'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/${access.substring(1)}/$keyText'), isNull);
    });

    test('refuses a fragment that is not exactly /send/<id>/<key>', () {
      expect(SendLink.parse('https://vault.example.com/#/vault/$access/$keyText'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access/$keyText/'), isNull);
      expect(SendLink.parse('https://vault.example.com/#/send/$access'), isNull);
      expect(SendLink.parse('https://vault.example.com/send/$access/$keyText'), isNull);
      expect(SendLink.parse(''), isNull);
      expect(SendLink.parse('just some words'), isNull);
    });

    test('reads a key of 22 characters as a Bitwarden Send, for the browser', () {
      final bitwarden = 'https://vault.bitwarden.com/#/send/$access/${b64urlEncode(Uint8List(16))}';
      final parsed = SendLink.parse(bitwarden);
      expect(parsed, isA<BitwardenSendLink>());
      expect((parsed! as BitwardenSendLink).url, bitwarden);
      expect((parsed as BitwardenSendLink).host, 'vault.bitwarden.com');
    });

    test('hides the key when printed', () {
      final text = read(link).toString();
      expect(text, contains('key hidden'));
      expect(text, contains('vault.example.com'));
      expect(text, contains(access));
      expect(text, isNot(contains(keyText)));
      final bitwarden = SendLink.parse('https://vault.bitwarden.com/#/send/$access/${b64urlEncode(Uint8List(16))}')!;
      expect('$bitwarden', contains('key hidden'));
    });

    test('wipes the key on request', () {
      final parsed = read(link)..wipeKey();
      expect(parsed.key, everyElement(0));
    });
  });
}
