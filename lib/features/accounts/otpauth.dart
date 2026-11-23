// otpauth:// links, read and written as `src/utils/otp.ts` does with the
// otpauth package's URI.parse and toString, so the links each app writes
// are the same strings and each app reads the other's.
//
// The patterns spell out both cases of each letter instead of matching
// case-blind: Dart's case-blind matching also folds some other letters onto
// ASCII ones (the Kelvin sign onto k), which JavaScript's doesn't.
import 'dart:convert';

import '../../models/otp_account.dart';
import 'otp.dart';

const _algorithms = {'SHA1', 'SHA256', 'SHA512'};

final _edgeSpace = RegExp(r'^\s+|\s+$');
final _bareSteam = RegExp(r'^[Ss][Tt][Ee][Aa][Mm]://([A-Za-z2-7]+)=*$');
final _steamScheme = RegExp(r'^[Oo][Tt][Pp][Aa][Uu][Tt][Hh]://[Ss][Tt][Ee][Aa][Mm]/');
final _steamName = RegExp(r'^[Ss][Tt][Ee][Aa][Mm]$');

/// Reads an otpauth:// link into a new account: an [OtpAccount] whose `id`
/// is '' and `addedAt` 0, for the caller to set with `copyWith` when it adds
/// the account. Returns null for anything else.
///
/// Besides standard totp and hotp links this reads the ways other apps write
/// Steam Guard accounts: Aegis's otpauth://steam/, KeePassXC's encoder=steam,
/// Bitwarden's steam://SECRET, and a 5-digit TOTP issued by Steam.
OtpAccount? parseOtpUri(String uri) {
  final raw = uri.replaceAll(_edgeSpace, '');

  if (_bareSteam.firstMatch(raw) case final bare?) {
    return _newAccount(type: OtpType.steam, issuer: 'Steam', label: '', secret: bare[1]!.toUpperCase());
  }

  final steamScheme = _steamScheme.hasMatch(raw);
  final otp = _KeyUri.parse(steamScheme ? raw.replaceFirst(_steamScheme, 'otpauth://totp/') : raw);
  if (otp == null || !_algorithms.contains(otp.algorithm)) return null;

  if (otp.hotp) {
    if (otp.digits != 6 && otp.digits != 8) return null;
    return _newAccount(
      type: OtpType.hotp,
      issuer: otp.issuer,
      label: otp.label,
      secret: otp.secret,
      algorithm: otp.algorithm,
      digits: otp.digits,
      counter: otp.counter,
    );
  }

  final encoder = _queryParameter(raw, 'encoder');
  final fromSteam = otp.digits == 5 && _steamName.hasMatch(otp.issuer.isNotEmpty ? otp.issuer : otp.label);
  if (steamScheme || encoder?.toLowerCase() == 'steam' || fromSteam) {
    return _newAccount(type: OtpType.steam, issuer: otp.issuer, label: otp.label, secret: otp.secret, period: otp.period);
  }

  // Any other length would show codes the service doesn't expect
  if (otp.digits != 6 && otp.digits != 8) return null;
  return _newAccount(
    type: OtpType.totp,
    issuer: otp.issuer,
    label: otp.label,
    secret: otp.secret,
    algorithm: otp.algorithm,
    digits: otp.digits,
    period: otp.period,
  );
}

OtpAccount _newAccount({
  required OtpType type,
  required String issuer,
  required String label,
  required String secret,
  String algorithm = 'SHA1',
  int digits = 6,
  int period = 30,
  int? counter,
}) => OtpAccount(
  id: '',
  type: type,
  issuer: issuer,
  label: label,
  secret: secret,
  algorithm: algorithm,
  digits: digits,
  period: period,
  counter: counter,
  addedAt: 0,
);

/// The otpauth:// link for an account, for its QR code and exports. The
/// secret is written in canonical base32 and the algorithm by its canonical
/// name. Steam accounts use Aegis's otpauth://steam/ scheme, which apps
/// without Steam support reject instead of showing wrong codes.
///
/// Throws a [FormatException] when the secret isn't base32, the algorithm
/// is unknown, or the issuer or label holds half a surrogate pair.
String buildOtpUri(OtpAccount account) {
  final secret = base32Encode(base32Decode(account.secret));
  final algorithm = canonicalAlgorithm(account.algorithm) ?? (throw FormatException('Unknown hash algorithm', account.algorithm));
  final (scheme, digits, last) = switch (account.kind) {
    OtpType.hotp => ('hotp', account.digits, 'counter=${account.counter ?? 0}'),
    OtpType.steam => ('steam', 5, 'period=${account.period}'),
    OtpType.totp => ('totp', account.digits, 'period=${account.period}'),
  };
  const e = _encodeUriComponent;
  final name = account.issuer.isNotEmpty ? '${e(account.issuer)}:${e(account.label)}?issuer=${e(account.issuer)}&' : '${e(account.label)}?';
  return 'otpauth://$scheme/${name}secret=${e(secret)}&algorithm=${e(algorithm)}&digits=$digits&$last';
}

// ─── Bitwarden's totp field ──────────────────────────────────────────────────

final _otpLink = RegExp(r'^(?:[Oo][Tt][Pp][Aa][Uu][Tt][Hh]|[Ss][Tt][Ee][Aa][Mm])://');
final _trailingPadding = RegExp(r'=+$');

/// Reads a Bitwarden login's `totp` value into a new account, as
/// [parseOtpUri] makes them: an otpauth:// link, Bitwarden's steam://SECRET,
/// or a bare base32 secret, which means SHA1, 6 digits and 30 seconds.
/// [name] and [username], the login's, stand in for an issuer and a label
/// the value doesn't have. Returns null for anything else.
OtpAccount? parseBitwardenTotp(String totp, {String name = '', String username = ''}) {
  final value = totp.replaceAll(_edgeSpace, '');
  if (_otpLink.hasMatch(value)) {
    final parsed = parseOtpUri(value);
    if (parsed == null) return null;
    return parsed.copyWith(issuer: parsed.issuer.isEmpty ? name : parsed.issuer, label: parsed.label.isEmpty ? username : parsed.label);
  }
  final secret = normalizeSecret(value);
  if (!isValidSecret(secret)) return null;
  return _newAccount(type: OtpType.totp, issuer: name, label: username, secret: secret.replaceFirst(_trailingPadding, ''));
}

/// What a Bitwarden login's `totp` holds for [account]: an otpauth://totp
/// link, or steam://SECRET for Steam, the two Bitwarden apps make codes
/// for. Null for HOTP, which they don't do.
String? buildBitwardenTotp(OtpAccount account) => switch (account.kind) {
  OtpType.hotp => null,
  OtpType.steam => 'steam://${base32Encode(base32Decode(account.secret))}',
  OtpType.totp => buildOtpUri(account),
};

/// What otpauth's URI.parse reads from a totp or hotp link.
class _KeyUri {
  _KeyUri({
    required this.hotp,
    required this.issuer,
    required this.label,
    required this.secret,
    required this.algorithm,
    required this.digits,
    required this.period,
    required this.counter,
  });

  static final _pattern = RegExp(
    r'^[Oo][Tt][Pp][Aa][Uu][Tt][Hh]://([HhTt][Oo][Tt][Pp])/(.+)\?([A-Za-z0-9.~_-]+=[^?&]*(?:&[A-Za-z0-9.~_-]+=[^?&]*)*)$',
  );
  static final _issuerPrefix = RegExp(r'(?::|%3[Aa]) *(.+)');
  static final _firstEquals = RegExp('=(.*)');
  static final _secret = RegExp(r'^[2-7A-Za-z]+=*$');
  static final _algorithm = RegExp(r'^[Ss][Hh][Aa](?:1|224|256|384|512|3-224|3-256|3-384|3-512)$');
  static final _integer = RegExp(r'^[+-]?\d+$');
  static final _positiveInteger = RegExp(r'^\+?[1-9]\d*$');

  final bool hotp;
  final String issuer;
  final String label;

  /// Canonical base32: upper case, without padding or leftover bits.
  final String secret;
  final String algorithm;
  final int digits;
  final int period;
  final int counter;

  /// Null when [uri] isn't one otpauth reads: a malformed link, percent
  /// escape or parameter, or no secret.
  static _KeyUri? parse(String uri) {
    final match = _pattern.firstMatch(uri);
    if (match == null) return null;
    try {
      final path = match[2]!;
      // "Issuer:account", where spaces after the colon don't count
      final prefix = _issuerPrefix.firstMatch(path);
      final names = (prefix == null ? [path] : [path.substring(0, prefix.start), prefix[1]!]).map(_decodeUriComponent).toList();
      final params = <String, String>{};
      for (final pair in match[3]!.split('&')) {
        // The value ends at a line break, as JavaScript's split(/=(.*)/) has it
        final value = _firstEquals.firstMatch(pair)!;
        params[pair.substring(0, value.start).toLowerCase()] = _decodeUriComponent(value[1]!);
      }

      final hotp = match[1]!.toLowerCase() == 'hotp';
      var counter = 0;
      var period = 30;
      if (hotp) {
        final text = params['counter'];
        if (text == null || !_integer.hasMatch(text)) return null;
        counter = int.parse(text);
      } else if (params['period'] case final text?) {
        if (!_positiveInteger.hasMatch(text)) return null;
        period = int.parse(text);
      }

      // An issuer parameter wins over the label's prefix, unless it's empty
      var issuer = params['issuer'] ?? '';
      final String label;
      if (names.length == 2) {
        label = names[1];
        if (issuer.isEmpty) issuer = names[0];
      } else {
        label = names[0];
      }

      final secret = params['secret'];
      if (secret == null || !_secret.hasMatch(secret)) return null;

      var algorithm = 'SHA1';
      if (params['algorithm'] case final text?) {
        if (!_algorithm.hasMatch(text)) return null;
        algorithm = canonicalAlgorithm(text)!;
      }

      var digits = 6;
      if (params['digits'] case final text?) {
        if (!_positiveInteger.hasMatch(text)) return null;
        digits = int.parse(text);
      }

      return _KeyUri(
        hotp: hotp,
        issuer: issuer,
        label: label,
        secret: base32Encode(base32Decode(secret)),
        algorithm: algorithm,
        digits: digits,
        period: period,
        counter: counter,
      );
    } on FormatException {
      // A bad percent escape, or a number too large for an int
      return null;
    }
  }
}

final _urlTrim = RegExp(r'^[\x00-\x20]+|[\x00-\x20]+$');
final _tabOrNewline = RegExp('[\t\n\r]');

/// The first value of [name] in [url]'s query, as JavaScript's
/// `new URL(url).searchParams.get(name)` reads it: names are case-sensitive,
/// `+` is a space, and the fragment isn't part of the query.
String? _queryParameter(String url, String name) {
  final text = url.replaceAll(_urlTrim, '').replaceAll(_tabOrNewline, '');
  final question = text.indexOf('?');
  final hash = text.indexOf('#');
  if (question < 0 || (hash >= 0 && hash < question)) return null;
  final query = text.substring(question + 1, hash < 0 ? text.length : hash);
  for (final pair in query.split('&')) {
    if (pair.isEmpty) continue;
    final equals = pair.indexOf('=');
    if (_formDecode(equals < 0 ? pair : pair.substring(0, equals)) == name) {
      return _formDecode(equals < 0 ? '' : pair.substring(equals + 1));
    }
  }
  return null;
}

/// application/x-www-form-urlencoded decoding, which never fails: a `%` that
/// doesn't start an escape stays, and bytes that aren't UTF-8 become U+FFFD.
String _formDecode(String text) {
  final bytes = utf8.encode(text);
  final out = <int>[];
  for (var i = 0; i < bytes.length; i++) {
    final byte = bytes[i];
    if (byte == 0x2b) {
      out.add(0x20);
    } else if (byte == 0x25 && i + 2 < bytes.length && _hexValue(bytes[i + 1]) >= 0 && _hexValue(bytes[i + 2]) >= 0) {
      out.add(_hexValue(bytes[i + 1]) << 4 | _hexValue(bytes[i + 2]));
      i += 2;
    } else {
      out.add(byte);
    }
  }
  // Dart drops a leading byte order mark, which the URL parser keeps
  return utf8.decode([0x20, ...out], allowMalformed: true).substring(1);
}

/// JavaScript's decodeURIComponent: other characters stay as they are, and a
/// bad escape or UTF-8 sequence throws a [FormatException]. Unlike
/// [Uri.decodeComponent], it accepts characters outside ASCII.
String _decodeUriComponent(String text) {
  if (!text.contains('%')) return text;
  final out = StringBuffer();
  for (var k = 0; k < text.length; k++) {
    if (text.codeUnitAt(k) != 0x25) {
      out.writeCharCode(text.codeUnitAt(k));
      continue;
    }
    var byte = _escapedByte(text, k);
    k += 2;
    if (byte < 0x80) {
      out.writeCharCode(byte);
      continue;
    }
    final length = byte >= 0xf8
        ? 0
        : byte >= 0xf0
        ? 4
        : byte >= 0xe0
        ? 3
        : byte >= 0xc0
        ? 2
        : 0;
    if (length == 0 || k + 3 * (length - 1) >= text.length) throw FormatException('Bad UTF-8 escape', text, k);
    var point = byte & 0xff >> length + 1;
    for (var j = 1; j < length; j++) {
      k++;
      if (text.codeUnitAt(k) != 0x25) throw FormatException('Bad UTF-8 escape', text, k);
      byte = _escapedByte(text, k);
      if (byte & 0xc0 != 0x80) throw FormatException('Bad UTF-8 escape', text, k);
      k += 2;
      point = point << 6 | byte & 0x3f;
    }
    // Overlong forms, surrogates and points past U+10FFFF aren't UTF-8
    const smallest = [0, 0, 0x80, 0x800, 0x10000];
    if (point < smallest[length] || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)) {
      throw FormatException('Bad UTF-8 escape', text, k);
    }
    out.writeCharCode(point);
  }
  return out.toString();
}

/// The byte of the `%XX` escape at [index].
int _escapedByte(String text, int index) {
  if (index + 2 >= text.length) throw FormatException('Truncated escape', text, index);
  final high = _hexValue(text.codeUnitAt(index + 1));
  final low = _hexValue(text.codeUnitAt(index + 2));
  if (high < 0 || low < 0) throw FormatException('Bad escape', text, index);
  return high << 4 | low;
}

int _hexValue(int unit) => switch (unit) {
  >= 0x30 && <= 0x39 => unit - 0x30,
  >= 0x41 && <= 0x46 => unit - 0x37,
  >= 0x61 && <= 0x66 => unit - 0x57,
  _ => -1,
};

/// JavaScript's encodeURIComponent: UTF-8 percent escapes, in upper-case hex,
/// for everything but letters, digits and `-_.!~*'()`. Half a surrogate pair
/// throws a [FormatException], where [Uri.encodeComponent] would write U+FFFD.
String _encodeUriComponent(String text) {
  final out = StringBuffer();
  for (var i = 0; i < text.length; i++) {
    final unit = text.codeUnitAt(i);
    if (_isUnreserved(unit)) {
      out.writeCharCode(unit);
      continue;
    }
    var point = unit;
    if (unit >= 0xd800 && unit <= 0xdfff) {
      final next = i + 1 < text.length ? text.codeUnitAt(i + 1) : 0;
      if (unit >= 0xdc00 || next < 0xdc00 || next > 0xdfff) throw FormatException('Half a surrogate pair', text, i);
      point = 0x10000 + (unit - 0xd800 << 10) + (next - 0xdc00);
      i++;
    }
    for (final byte in utf8.encode(String.fromCharCode(point))) {
      out.write('%${byte.toRadixString(16).toUpperCase().padLeft(2, '0')}');
    }
  }
  return out.toString();
}

bool _isUnreserved(int unit) =>
    (unit >= 0x41 && unit <= 0x5a) ||
    (unit >= 0x61 && unit <= 0x7a) ||
    (unit >= 0x30 && unit <= 0x39) ||
    "-_.!~*'()".contains(String.fromCharCode(unit));
