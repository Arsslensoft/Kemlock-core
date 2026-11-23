@TestOn('vm')
library;

// The message code, fed what a damaged or hostile message holds: fixtures
// cut at every byte, and with bytes flipped at random under a fixed seed.
// Each attempt must give the right content or throw a PgpException:
// never another error, and never wrong content from an encrypted message.

import 'dart:math';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/pgp.dart';
import 'package:test/test.dart';

import 'fixtures.dart';

typedef _Case = ({String fixture, Uint8List expected, bool encrypted, bool detached});

/// The key that opens [fixture], and the keys its signatures are by.
/// Reading a key checks its self-signatures, which is most of the time
/// these loops take: each case is given the keys it needs and no more.
List<PgpSecretKey> _keys(String fixture) => [
  if (fixture.contains('sym-')) ...[] else if (fixture.contains('rsa')) PgpSecretKey(Keys.rsa) else PgpSecretKey(Keys.ed),
];

List<Uint8List> _verifiers(String fixture) => [
  if (fixture.contains('sign') || fixture.contains('.ed25519.')) Keys.edPublic,
  if (fixture.contains('two-signers') || fixture.contains('.rsa3072.')) Keys.rsaPublic,
];

/// Reads [input] as the kind of thing [c] is. Returns the content, or
/// null when a [PgpException] was thrown; anything else thrown fails.
Future<Uint8List?> _read(_Case c, Uint8List input, String what) async {
  Object? other;
  StackTrace? stack;
  try {
    // Looking at it must be as safe as opening it
    try {
      inspectMessage(PgpData.bytes(input));
    } on PgpException {
      // Fine: what it cannot name, it refuses
    }
    if (c.detached) {
      await verify(signed: PgpData.bytes(input), data: PgpData.bytes(c.expected), verifiers: _verifiers(c.fixture), now: fixtureNow);
      return c.expected;
    }
    final result = await decrypt(
      data: PgpData.bytes(input),
      keys: _keys(c.fixture),
      passphrase: fixturePassphrase,
      verifiers: _verifiers(c.fixture),
      now: fixtureNow,
    );
    return result.bytes;
  } on PgpException {
    return null;
  } on Object catch (e, s) {
    other = e;
    stack = s;
  }
  fail('$what threw ${other.runtimeType}, not a PgpException: $other\n$stack');
}

void main() {
  final cases = <_Case>[
    (fixture: 'gnupg/to-ed25519.seipd.gpg', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/to-ed25519.ocb.gpg', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/to-rsa3072.seipd.gpg', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/sym-s2k0.gpg', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/signed-encrypted.gpg', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/armored.asc', expected: messageTxt, encrypted: true, detached: false),
    (fixture: 'gnupg/inline-signed.gpg', expected: messageTxt, encrypted: false, detached: false),
    (fixture: 'gnupg/two-signers.gpg', expected: messageTxt, encrypted: false, detached: false),
    (fixture: 'gnupg/clearsigned.asc', expected: messageTxt, encrypted: false, detached: false),
    (fixture: 'gnupg/message.txt.rsa3072.sig', expected: messageTxt, encrypted: false, detached: true),
    (fixture: 'gnupg/message.txt.ed25519.asc', expected: messageTxt, encrypted: false, detached: true),
  ];

  for (final c in cases) {
    final whole = pgpFixture(c.fixture);

    test('${c.fixture}: whole, it reads', () async {
      expect(await _read(c, whole, c.fixture), c.expected);
    });

    test('${c.fixture}: cut at every byte', () async {
      for (var length = 0; length < whole.length; length++) {
        final content = await _read(c, Uint8List.sublistView(whole, 0, length), '${c.fixture} cut to $length bytes');
        // An encrypted message cut short gives nothing: its check is at the
        // end. Armor cut after its last line of base64 is still whole.
        if (c.encrypted && !c.fixture.endsWith('.asc')) expect(content, isNull, reason: 'cut to $length bytes');
        if (c.encrypted && content != null) expect(content, c.expected, reason: 'cut to $length bytes');
      }
    });

    test('${c.fixture}: bytes flipped at random', () async {
      final random = Random(20261116 + whole.length);
      var refused = 0;
      for (var i = 0; i < 120; i++) {
        final changed = Uint8List.fromList(whole);
        final flips = 1 + random.nextInt(3);
        for (var j = 0; j < flips; j++) {
          changed[random.nextInt(changed.length)] ^= 1 << random.nextInt(8);
        }
        final content = await _read(c, changed, '${c.fixture} with $flips flips (run $i)');
        if (content == null) {
          refused++;
        } else if (c.encrypted) {
          // What still decrypts was changed where it does not matter (an
          // armor comment, a key ID's hint): the text is the right one
          expect(content, c.expected, reason: 'run $i');
        }
      }
      // Encrypted data is all check: nearly every flip is caught
      if (c.encrypted && !c.fixture.endsWith('.asc')) expect(refused, greaterThan(95));
    });
  }

  test('random bytes throw nothing but a PgpException', () async {
    final random = Random(7);
    for (var i = 0; i < 300; i++) {
      final bytes = Uint8List.fromList(List.generate(1 + random.nextInt(400), (_) => random.nextInt(256)));
      // Half of them start like a packet
      if (i.isEven) bytes[0] = 0xc0 | const [1, 2, 3, 4, 8, 9, 11, 18, 20][i % 9];
      final c = (fixture: 'random', expected: messageTxt, encrypted: true, detached: false);
      // Bytes that happen to be a literal data packet are a message, and
      // read as one: all that is asked is that nothing else is thrown
      await _read(c, bytes, 'random bytes (run $i)');
    }
  });
}
