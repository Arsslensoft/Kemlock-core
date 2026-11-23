/// DPoP proofs (RFC 9449), signed by the device key with ES256.
///
/// A proof is a compact JWS in the `DPoP` header:
///
/// - header: `typ: dpop+jwt`, `alg: ES256`, `jwk`, the public key;
/// - claims: `jti`, `htm` (the method), `htu` (the exact URL without query or
///   fragment), `iat`, `ath` (the base64url SHA-256 of the access token) when
///   there is one, and the last `nonce` the server handed out.
///
/// The server hands out a nonce in `DPoP-Nonce` and refuses a proof without
/// the current one (401 `use_dpop_nonce`); `KmApi` retries once with the
/// new proof. The phone's clock may be wrong: when an answer's `Date` is more
/// than a minute from it, `iat` is corrected by the difference.
///
/// Pure Dart, no Flutter.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../../crypto/account/encoding.dart';
import '../../../crypto/bytes.dart' show randomBytes;
import 'km_api.dart' show KmProofs;
import 'km_device_key.dart';

const _months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const _dayName = '(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)';
const _monthName = '(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)';
final _imfFixdate = RegExp('^$_dayName, (\\d\\d) $_monthName (\\d{4}) (\\d\\d):(\\d\\d):(\\d\\d) GMT\$');
final _rfc850 = RegExp(
  '^(?:Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday), (\\d\\d)-$_monthName-(\\d\\d) (\\d\\d):(\\d\\d):(\\d\\d) GMT\$',
);
final _asctime = RegExp('^$_dayName $_monthName ([ \\d]\\d) (\\d\\d):(\\d\\d):(\\d\\d) (\\d{4})\$');

/// The instant in an HTTP `Date` header (RFC 9110 section 5.6.7), in UTC: `Sun, 06 Nov 1994 08:49:37 GMT`, or one of
/// the two obsolete forms a server may still send, `Sunday, 06-Nov-94 08:49:37 GMT` and `Sun Nov  6 08:49:37 1994`.
/// Pure Dart, so the browser build reads the same text as `HttpDate.parse` did on the phone. Throws a
/// [FormatException] for anything else.
DateTime parseHttpDate(String text) {
  final source = text.trim();
  int number(String? digits) => int.parse(digits!.trim());
  int month(String? name) => _months.indexOf(name!) + 1;
  if (_imfFixdate.firstMatch(source) case final m?) {
    return DateTime.utc(number(m[3]), month(m[2]), number(m[1]), number(m[4]), number(m[5]), number(m[6]));
  }
  if (_rfc850.firstMatch(source) case final m?) {
    final year = number(m[3]);
    return DateTime.utc(year + (year > 50 ? 1900 : 2000), month(m[2]), number(m[1]), number(m[4]), number(m[5]), number(m[6]));
  }
  if (_asctime.firstMatch(source) case final m?) {
    return DateTime.utc(number(m[6]), month(m[1]), number(m[2]), number(m[3]), number(m[4]), number(m[5]));
  }
  throw FormatException('Not an HTTP date', text);
}

/// How far the phone's clock may be from the server's before `iat` is corrected: the server accepts a minute.
const dpopClockTolerance = Duration(seconds: 60);

/// Makes the proofs one device key signs. Nonces and clock offsets are kept per server (scheme, host and port).
class KmDpop implements KmProofs {
  KmDpop(this.key, {this.clock = DateTime.now, this.newJti = _randomJti});

  final DeviceKey key;
  final DateTime Function() clock;

  /// A fresh `jti` for each proof; tests pass a counter.
  final String Function() newJti;

  final _nonces = <String, String>{};
  final _offsets = <String, int>{};

  static String _randomJti() => b64urlEncode(randomBytes(16));

  String _origin(Uri url) => '${url.scheme}://${url.host}:${url.hasPort ? url.port : (url.scheme == 'https' ? 443 : 80)}';

  /// The URL as a proof names it: scheme, host, port if given, and path, with no query or fragment.
  static String htu(Uri url) => Uri(scheme: url.scheme, host: url.host, port: url.hasPort ? url.port : null, path: url.path).toString();

  /// The nonce the server last handed out for [url]'s server, or null.
  String? nonceFor(Uri url) => _nonces[_origin(url)];

  /// Seconds to add to the phone's clock for [url]'s server, 0 when it is within a minute of it.
  int offsetFor(Uri url) => _offsets[_origin(url)] ?? 0;

  @override
  Future<String> proof(String method, Uri url, {String? accessToken}) async {
    final iat = clock().millisecondsSinceEpoch ~/ 1000 + offsetFor(url);
    final nonce = nonceFor(url);
    final header = {'typ': 'dpop+jwt', 'alg': 'ES256', 'jwk': key.publicJwk};
    final claims = {
      'jti': newJti(),
      'htm': method,
      'htu': htu(url),
      'iat': iat,
      if (accessToken != null) 'ath': b64urlEncode(hash.sha256.convert(utf8.encode(accessToken)).bytes),
      'nonce': ?nonce,
    };
    final signingInput = '${b64urlEncode(utf8.encode(jsonEncode(header)))}.${b64urlEncode(utf8.encode(jsonEncode(claims)))}';
    final signature = await key.sign(Uint8List.fromList(utf8.encode(signingInput)));
    return '$signingInput.${b64urlEncode(signature)}';
  }

  @override
  void observe(Uri url, Map<String, String> headers) {
    final origin = _origin(url);
    final nonce = headers['dpop-nonce'];
    if (nonce != null && nonce.isNotEmpty) _nonces[origin] = nonce;
    final date = headers['date'];
    if (date == null) return;
    try {
      final server = parseHttpDate(date).millisecondsSinceEpoch ~/ 1000;
      final difference = server - clock().millisecondsSinceEpoch ~/ 1000;
      if (difference.abs() > dpopClockTolerance.inSeconds) {
        _offsets[origin] = difference;
      } else {
        _offsets.remove(origin);
      }
    } on Object {
      // A date that doesn't read tells nothing about the clock
    }
  }
}
