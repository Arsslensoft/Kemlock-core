// One-time codes (RFC 4226 HOTP, RFC 6238 TOTP and Steam Guard) and the
// secrets they come from, as `src/lib/totp.ts` and `src/utils/otp.ts` make
// them with the otpauth package. Where JavaScript's strings and regular
// expressions behave differently from Dart's, the JavaScript behaviour is
// kept, so a secret reads the same in both apps.
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../../models/otp_account.dart';

/// HOTP codes change when asked; TOTP and Steam codes change with the clock.
bool isTimeBased(OtpAccount account) => account.kind != OtpType.hotp;

/// The most digits a code has: the truncated value has no more.
const maxCodeDigits = 10;

/// Whether [account]'s codes are no longer than a code can be,
/// [maxCodeDigits] digits. An account read from an export, a QR transfer or
/// a sync file carries whatever number its file gave. Zero and less stay as
/// the TypeScript app had them (test/fixtures/otp/codes.json): they make
/// short codes, never long ones.
bool hasCodeLength(OtpAccount account) => account.kind == OtpType.steam || account.digits <= maxCodeDigits;

/// How many characters the account's codes have: always 5 for Steam, its
/// digits otherwise, and 6 for an account with more digits than a code has
/// ([hasCodeLength]), so that a file asking for millions of them can't make
/// the list build a text that long at every unlock.
int codeLength(OtpAccount account) => account.kind == OtpType.steam ? 5 : (hasCodeLength(account) ? account.digits : 6);

/// The code for the window containing [nowSec] (Unix time in whole seconds),
/// shifted by [offset] windows. For HOTP the clock is ignored and [offset]
/// counts from the stored counter. An account whose secret, algorithm or
/// number of digits can't be used gets dashes as long as its codes.
String codeAt(OtpAccount account, int nowSec, [int offset = 0]) {
  final generate = hasCodeLength(account) ? _generatorFor(account) : null;
  if (generate == null) return '-' * codeLength(account);
  final int counter;
  if (!isTimeBased(account)) {
    counter = (account.counter ?? 0) + offset;
  } else if (account.period == 0) {
    // JavaScript divides by zero to Infinity, whose counter bytes are all 0
    counter = 0;
  } else {
    counter = _floorDiv(nowSec, account.period) + offset;
  }
  return generate(counter);
}

/// Seconds left before the code of a [period]-second window changes, at [now]: 1 to [period].
int secondsRemaining(int period, DateTime now) => period - _floorDiv(now.millisecondsSinceEpoch, 1000).remainder(period);

const _steamAlphabet = '23456789BCDFGHJKMNPQRTVWXY';

/// Steam Guard: RFC 4226 dynamic truncation of an HMAC-SHA1, then 5 characters from Steam's alphabet.
String steamCode(List<int> key, int counter) {
  final mac = Hmac(sha1, key).convert(_counterBytes(counter)).bytes;
  var value = _truncate(mac, mac[19] & 0xf);
  final code = StringBuffer();
  for (var i = 0; i < 5; i++) {
    code.write(_steamAlphabet[value % _steamAlphabet.length]);
    value ~/= _steamAlphabet.length;
  }
  return code.toString();
}

/// "287082" → "287 082", "94287082" → "9428 7082"; other lengths stay as they are.
String formatCode(String code) {
  if (code.length != 6 && code.length != 8) return code;
  final half = code.length ~/ 2;
  return '${code.substring(0, half)} ${code.substring(half)}';
}

final _spaceOrDash = RegExp(r'[\s-]');

/// Normalises a typed secret: upper-case, without spaces or dashes.
String normalizeSecret(String input) => _jsUpperCase(input).replaceAll(_spaceOrDash, '');

final _base32Secret = RegExp(r'^[A-Z2-7]+=*$');

/// Whether [secret] is upper-case base32 (with optional `=` padding) of at least 10 bytes.
bool isValidSecret(String secret) => _base32Secret.hasMatch(secret) && base32Decode(secret).length >= 10;

final _fourChars = RegExp('.{4}');
final _edgeSpace = RegExp(r'^\s+|\s+$');

/// "JBSWY3DPEHPK3PXP" → "JBSW Y3DP EHPK 3PXP", for showing a secret.
String groupSecret(String secret) => secret.replaceAllMapped(_fourChars, (m) => '${m[0]} ').replaceAll(_edgeSpace, '');

const _base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/// The bytes of an RFC 4648 base32 string, read the way otpauth reads secrets:
/// spaces are dropped, lower case is accepted, trailing `=` padding is
/// ignored, and leftover bits that don't fill a byte are dropped. Throws a
/// [FormatException] for any other character.
Uint8List base32Decode(String input) {
  var text = _jsUpperCase(input.replaceAll(' ', ''));
  var end = text.length;
  while (end > 0 && text.codeUnitAt(end - 1) == 0x3d) {
    end--;
  }
  text = text.substring(0, end);
  final bytes = Uint8List(text.length * 5 ~/ 8);
  var bits = 0;
  var value = 0;
  var index = 0;
  for (var i = 0; i < text.length; i++) {
    final digit = _base32Alphabet.indexOf(text[i]);
    if (digit < 0) throw FormatException('Invalid base32 character', input);
    value = (value << 5 | digit) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = value >> bits;
    }
  }
  return bytes;
}

/// RFC 4648 base32 of [bytes], upper case and without padding.
String base32Encode(List<int> bytes) {
  final out = StringBuffer();
  var bits = 0;
  var value = 0;
  for (final byte in bytes) {
    value = (value << 8 | byte & 0xff) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out.write(_base32Alphabet[value >> bits - 5 & 31]);
      bits -= 5;
    }
  }
  if (bits > 0) out.write(_base32Alphabet[value << 5 - bits & 31]);
  return out.toString();
}

final _sha1Name = RegExp(r'^(?:SHA-?1|SSL3-SHA1)$');
final _sha2Name = RegExp(r'^SHA(?:2?-)?(224|256|384|512)$');
final _sha3Name = RegExp(r'^SHA3-(224|256|384|512)$');

/// otpauth's name for a hash algorithm, in any case: 'SHA1' for 'sha-1',
/// 'SHA256' for 'SHA2-256', 'SHA3-256' for 'sha3-256'; null for one it doesn't know.
String? canonicalAlgorithm(String name) {
  final upper = _asciiUpperCase(name);
  if (_sha1Name.hasMatch(upper)) return 'SHA1';
  if (_sha2Name.firstMatch(upper) case final match?) return 'SHA${match[1]}';
  if (_sha3Name.firstMatch(upper) case final match?) return 'SHA3-${match[1]}';
  return null;
}

// package:crypto has no SHA-3, which otpauth would make codes with; no
// account the app reads or makes uses it.
final _hashes = <String, Hash>{'SHA1': sha1, 'SHA224': sha224, 'SHA256': sha256, 'SHA384': sha384, 'SHA512': sha512};

typedef _Generator = String Function(int counter);

/// A generator, or none when the account's secret or algorithm can't be used.
class _CachedGenerator {
  const _CachedGenerator(this.generate);
  final _Generator? generate;
}

// Generators are kept per account object, so a once-per-second rebuild
// doesn't decode every secret again.
final _generators = Expando<_CachedGenerator>('otp generators');

_Generator? _generatorFor(OtpAccount account) => (_generators[account] ??= _CachedGenerator(_newGenerator(account))).generate;

_Generator? _newGenerator(OtpAccount account) {
  final Uint8List key;
  try {
    key = base32Decode(account.secret);
  } on FormatException {
    return null;
  }
  if (account.kind == OtpType.steam) return (counter) => steamCode(key, counter);
  // A TOTP code is the HOTP code for the current time window
  final hash = _hashes[canonicalAlgorithm(account.algorithm)];
  if (hash == null) return null;
  final hmac = Hmac(hash, key);
  final digits = account.digits;
  return (counter) => _hotp(hmac, digits, counter);
}

/// RFC 4226: the HMAC of the counter, truncated to [digits] decimal digits.
String _hotp(Hmac hmac, int digits, int counter) {
  final mac = hmac.convert(_counterBytes(counter)).bytes;
  final value = _truncate(mac, mac.last & 0xf);
  // Any value fits in 10 digits; 10 or more pad it with zeros
  final code = digits >= 10 ? value : value % _pow10(digits);
  return '$code'.padLeft(digits, '0');
}

int _truncate(List<int> mac, int offset) =>
    (mac[offset] & 0x7f) << 24 | (mac[offset + 1] & 0xff) << 16 | (mac[offset + 2] & 0xff) << 8 | mac[offset + 3] & 0xff;

/// The counter as 8 big-endian bytes, in two's complement when negative.
Uint8List _counterBytes(int counter) {
  final bytes = Uint8List(8);
  var rest = counter;
  for (var i = 7; i >= 0; i--) {
    bytes[i] = rest & 0xff;
    rest >>= 8;
  }
  return bytes;
}

int _pow10(int exponent) {
  var value = 1;
  for (var i = 0; i < exponent; i++) {
    value *= 10;
  }
  return value;
}

/// Division rounded down, like JavaScript's `Math.floor(a / b)`.
int _floorDiv(int a, int b) {
  final quotient = a ~/ b;
  return a.remainder(b) != 0 && (a < 0) != (b < 0) ? quotient - 1 : quotient;
}

/// Upper case for ASCII letters only, so a case-blind match on the result
/// matches what a JavaScript `/i` pattern without the `u` flag does.
String _asciiUpperCase(String text) =>
    String.fromCharCodes(text.codeUnits.map((unit) => unit >= 0x61 && unit <= 0x7a ? unit - 0x20 : unit));

// JavaScript's toUpperCase also turns these into several letters; Dart's
// keeps them as they are. They're the ones that come out as base32 letters.
const _upperSpecials = {'ß': 'SS', 'ﬀ': 'FF', 'ﬁ': 'FI', 'ﬂ': 'FL', 'ﬃ': 'FFI', 'ﬄ': 'FFL', 'ﬅ': 'ST', 'ﬆ': 'ST'};
final _upperSpecial = RegExp('[ßﬀ-ﬆ]');

String _jsUpperCase(String text) => text.replaceAllMapped(_upperSpecial, (m) => _upperSpecials[m[0]]!).toUpperCase();
