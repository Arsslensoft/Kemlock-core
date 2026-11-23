import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

final _random = Random.secure();

/// [n] bytes from the platform's secure random source, as
/// `crypto.getRandomValues` gives them in `crypto.ts`.
Uint8List randomBytes(int n) {
  final out = Uint8List(n);
  for (var i = 0; i < n; i++) {
    out[i] = _random.nextInt(256);
  }
  return out;
}

/// Standard base64 with padding, as `btoa` writes it in `crypto.ts`.
String b64(List<int> bytes) => base64.encode(bytes);

/// Reads standard base64 the way `atob` does: ASCII whitespace is skipped,
/// the padding may be left off, and any other character is a
/// [FormatException].
Uint8List unb64(String s) {
  var text = s.replaceAll(_asciiWhitespace, '');
  if (text.length % 4 == 0 && text.endsWith('=')) {
    text = text.substring(0, text.endsWith('==') ? text.length - 2 : text.length - 1);
  }
  if (text.length % 4 == 1 || !_standardAlphabet.hasMatch(text)) {
    throw FormatException('Invalid base64', s);
  }
  return base64.decode(base64.normalize(text));
}

/// Base64url without padding, as `b64url` writes WebAuthn credential ids and
/// QR export chunks in `crypto.ts` and `qrVault.ts`.
String b64url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

/// Reads base64url with or without padding. Like `unb64url` in `qrVault.ts`,
/// which maps the URL alphabet back and then calls `atob`, the standard
/// alphabet's `+` and `/` are read too.
Uint8List unb64url(String s) {
  final text = s.replaceAll(_asciiWhitespace, '');
  if (!_anyAlphabet.hasMatch(text)) throw FormatException('Invalid base64url', s);
  return base64Url.decode(base64Url.normalize(text));
}

/// The parts one after another, in a new list.
Uint8List concatBytes(List<List<int>> parts) {
  var length = 0;
  for (final part in parts) {
    length += part.length;
  }
  final out = Uint8List(length);
  var offset = 0;
  for (final part in parts) {
    out.setAll(offset, part);
    offset += part.length;
  }
  return out;
}

/// Whether [a] and [b] hold the same bytes, in a time that depends on
/// their lengths alone and not on where they first differ. For comparing a
/// proof with the one expected, so the comparison tells nothing of it.
bool constantTimeEquals(List<int> a, List<int> b) {
  var difference = a.length ^ b.length;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ (i < b.length ? b[i] : 0);
  }
  return difference == 0;
}

final _asciiWhitespace = RegExp('[\t\n\f\r ]');
final _standardAlphabet = RegExp(r'^[A-Za-z0-9+/]*$');
final _anyAlphabet = RegExp(r'^[A-Za-z0-9+/\-_]*={0,2}$');
