// How values are normalised before they are matched or tagged (the
// add-duplicate-cleaner plan, design 3). Pure Dart, no Flutter, so it moves
// into `kemlock_core` unchanged, and the server's web vault can make the
// same bytes.
import 'dart:convert';

import 'package:unorm_dart/unorm_dart.dart' as unorm;

import '../../core/websites.dart';
import '../../models/payment_card.dart' show cardDigits;
import '../accounts/otp.dart' show base32Decode, base32Encode;

final _ipv4 = RegExp(r'^\d{1,3}(?:\.\d{1,3}){3}$');

/// How a host becomes a site: the part of it that one owner holds. The
/// Public Suffix List and the shared hosts are the app's, so they come in as
/// functions and this file stays free of Flutter.
class SiteResolver {
  const SiteResolver({this.registrable, this.isShared});

  /// The registrable domain of a host, as `registrableDomain` works it out
  /// with the Public Suffix List. Without it a host stays whole.
  final String Function(String host)? registrable;

  /// Whether anyone can open a site under the host, so it stays whole.
  final bool Function(String host)? isShared;

  /// The site of the website [input], as `loginDomains` reads it: its
  /// registrable domain, and an address or a shared host as it is. Empty for
  /// text that is no host.
  String site(String input) {
    final host = normaliseWebsite(input) ?? '';
    if (host.isEmpty || _ipv4.hasMatch(host) || (isShared?.call(host) ?? false)) {
      return host;
    }
    return registrable?.call(host) ?? host;
  }
}

/// Whether [rune] is a Unicode White_Space code point, which Rust's `trim`
/// removes. Dart's `trim` also removes U+FEFF, which isn't one.
bool _isWhite(int rune) =>
    (rune >= 0x09 && rune <= 0x0d) ||
    rune == 0x20 ||
    rune == 0x85 ||
    rune == 0xa0 ||
    rune == 0x1680 ||
    (rune >= 0x2000 && rune <= 0x200a) ||
    rune == 0x2028 ||
    rune == 0x2029 ||
    rune == 0x202f ||
    rune == 0x205f ||
    rune == 0x3000;

/// [text] without the White_Space code points at both ends.
String trimWhite(String text) {
  final runes = text.runes.toList();
  var start = 0;
  var end = runes.length;
  while (start < end && _isWhite(runes[start])) {
    start++;
  }
  while (end > start && _isWhite(runes[end - 1])) {
    end--;
  }
  return String.fromCharCodes(runes.sublist(start, end));
}

/// [text] in lower case by the simple mapping of each code point (UnicodeData field 13), as
/// `crypto.md` "Normalisation" has it, so the server and every client make one value of it.
///
/// Dart's `toLowerCase` and Rust's `to_lowercase` don't do this: they apply SpecialCasing, which
/// turns `İ` (U+0130) into `i` and a combining dot above, and the final-sigma rule, which turns
/// `Σ` into `ς` at the end of a word. Here nothing depends on the letters around a code point:
///
/// - `İ` becomes `i`, written out because Dart's mapping of it is the two-code-point one;
/// - `Σ` becomes `σ` wherever it is;
/// - `ẞ` becomes `ß`, and `ß` stays `ß`, so `Straße` and `STRASSE` are not one;
/// - every other letter takes its own mapping.
///
/// Each code point goes through `toLowerCase` on its own: with no letter beside it, the only
/// unconditional SpecialCasing entry is `İ`, and a single `Σ` takes its plain `σ`.
String lowerCase(String text) {
  final out = StringBuffer();
  for (final rune in text.runes) {
    if (rune == 0x130) {
      out.writeCharCode(0x69);
    } else if (rune < 0x80) {
      out.writeCharCode(rune >= 0x41 && rune <= 0x5a ? rune + 0x20 : rune);
    } else {
      out.write(String.fromCharCode(rune).toLowerCase());
    }
  }
  return out.toString();
}

/// A username, or any name that is matched without regard to case: trimmed,
/// in NFC, then in lower case. ` Sam@Example.org` and `sam@example.org` are
/// one.
String normaliseUsername(String text) => lowerCase(unorm.nfc(trimWhite(text)));

/// The text of a note, as `crypto.md` "Normalisation" has it: NFC, CRLF and a lone CR as `\n`, the
/// spaces and tabs at the end of each line removed, and the blank lines at the end removed. Only
/// spaces and tabs go, so a line ending in a no-break space keeps it.
String normaliseNote(String text) {
  final lines = unorm.nfc(text).replaceAll('\r\n', '\n').replaceAll('\r', '\n').split('\n');
  final trimmed = [for (final line in lines) _trimEnd(line)];
  while (trimmed.isNotEmpty && trimmed.last.isEmpty) {
    trimmed.removeLast();
  }
  return trimmed.join('\n');
}

String _trimEnd(String line) {
  var end = line.length;
  while (end > 0 && (line.codeUnitAt(end - 1) == 0x20 || line.codeUnitAt(end - 1) == 0x09)) {
    end--;
  }
  return line.substring(0, end);
}

/// A code's secret as `crypto.md` "Normalisation" has it: the decoded bytes written again as RFC 4648
/// base32, in upper case and without padding. `JBSWY3DPEHPK3PXP` and `jbsw y3dp ehpk 3pxp=` are one.
/// Bits left over that don't fill a byte are dropped, as the decoder drops them.
///
/// A secret that isn't base32 makes no tag, as the server's vector `secret-not-base32` has it, and neither does an empty one:
/// both are null.
String? secretBase32(String secret) {
  final List<int> bytes;
  try {
    bytes = base32Decode(secret);
  } on FormatException {
    return null;
  }
  return bytes.isEmpty ? null : base32Encode(bytes);
}

/// A key's or a certificate's fingerprint, as `crypto.md` "Normalisation" has it: an OpenSSH `SHA256:…` (the prefix in
/// capitals) as it is, or 40 or 64 hexadecimal digits (a PGP v4 or v6 fingerprint, a certificate's SHA-1 or SHA-256
/// thumbprint) in upper case, without the white space, the colons and a leading `0x`, so `AB:CD:…` and `abcd…` are
/// one value. Null for anything else, which makes no tag.
String? normaliseFingerprint(String text) {
  final trimmed = trimWhite(text);
  if (trimmed.startsWith('SHA256:')) {
    return trimmed.length > 'SHA256:'.length ? trimmed : null;
  }
  final squeezed = trimmed.replaceAll(RegExp(r'[\s:]+'), '').toUpperCase();
  final hex = squeezed.startsWith('0X') ? squeezed.substring(2) : squeezed;
  return RegExp(r'^(?:[0-9A-F]{40}|[0-9A-F]{64})$').hasMatch(hex) ? hex : null;
}

/// A contact's phone number as its ASCII digits only, so `+1 (555) 0142` and `15550142` are one. May be empty.
String normalisePhone(String text) => text.replaceAll(RegExp(r'[^0-9]'), '');

/// The fewest letters and digits an identity document's number needs to make a tag.
const minDocumentNumberLength = 4;

final _notAlphanumeric = RegExp(r'[^\p{L}\p{N}\p{M}]', unicode: true);

/// An identity document's number as `crypto.md` "Normalisation" has it: in NFC, in lower case, and only its letters
/// and digits, so `X 1234-567` and `x1234567` are one. Null for one of fewer than [minDocumentNumberLength] letters and
/// digits: a placeholder would match unrelated papers. (Letters, numbers and the marks that join them, for Unicode's
/// alphabetic and numeric characters.)
String? normaliseDocumentNumber(String text) {
  final kept = lowerCase(unorm.nfc(text)).replaceAll(_notAlphanumeric, '');
  return kept.runes.length >= minDocumentNumberLength ? kept : null;
}

/// A card number as its digits, or null when it has none.
String? normaliseCardNumber(String? number) {
  final digits = cardDigits(number ?? '');
  return digits.isEmpty ? null : digits;
}

/// A card's expiry as `YYYY-MM`, or empty when the month or the year is unknown, as `crypto.md`
/// "Normalisation" has it.
String normaliseCardExpiry(int? month, int? year) {
  if (month == null || year == null) {
    return '';
  }
  return '${year.toString().padLeft(4, '0')}-${month.toString().padLeft(2, '0')}';
}

/// Backup codes as `crypto.md` "Normalisation" has them: each trimmed of Unicode white space, the
/// repeats dropped, and the list sorted by code point. A code is not put in NFC or in lower case.
/// A code that is empty once trimmed is no code and is left out.
///
/// The sort is by UTF-8 bytes, which is the order of code points. Dart's `compareTo` sorts by
/// UTF-16 code unit, which puts a character outside the Basic Multilingual Plane before one of
/// U+E000 and up.
List<String> normaliseCodes(Iterable<String> codes) {
  final seen = <String, List<int>>{};
  for (final code in codes) {
    final text = trimWhite(code);
    if (text.isNotEmpty) {
      seen[text] = utf8.encode(text);
    }
  }
  final entries = seen.entries.toList()..sort((a, b) => _compareBytes(a.value, b.value));
  return [for (final entry in entries) entry.key];
}

int _compareBytes(List<int> a, List<int> b) {
  final shared = a.length < b.length ? a.length : b.length;
  for (var i = 0; i < shared; i++) {
    if (a[i] != b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}
