// Websites as Kemlock keeps them on logins and accounts: the host alone, in
// lowercase, in the ASCII form browsers hand AutoFill.
import 'dart:math';

final _scheme = RegExp(r'^[a-zA-Z][a-zA-Z0-9+.-]*://');
final _label = RegExp(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)$');
final _ipv4 = RegExp(r'^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$');

/// The host [input] names, as a website is kept: no scheme, user, port,
/// path, query or `www.`, lowercase, each label in its ASCII form
/// (`bücher.example` is `xn--bcher-kva.example`). Null when [input] isn't
/// a host name of at least two labels or an IPv4 address.
String? normaliseWebsite(String input) {
  var s = input.trim();
  if (s.isEmpty || s.contains(RegExp(r'\s'))) return null;
  s = s.replaceFirst(_scheme, '');
  if (s.startsWith('//')) s = s.substring(2);
  final end = s.indexOf(RegExp(r'[/?#]'));
  if (end >= 0) s = s.substring(0, end);
  final at = s.lastIndexOf('@');
  if (at >= 0) s = s.substring(at + 1);
  if (s.startsWith('[')) return null; // IPv6: not a website people sign in to by name
  final port = s.lastIndexOf(':');
  if (port >= 0) {
    if (!RegExp(r'^\d{1,5}$').hasMatch(s.substring(port + 1))) return null;
    s = s.substring(0, port);
  }
  s = s.toLowerCase();
  if (s.endsWith('.')) s = s.substring(0, s.length - 1);
  if (_ipv4.hasMatch(s)) return s;
  if (s.startsWith('www.')) s = s.substring(4);
  final labels = s.split('.');
  if (labels.length < 2) return null;
  final ascii = <String>[];
  for (final label in labels) {
    final a = label.runes.every((c) => c < 0x80) ? label : 'xn--${punycodeEncode(label)}';
    if (!_label.hasMatch(a)) return null;
    ascii.add(a);
  }
  final host = ascii.join('.');
  if (host.length > 253 || RegExp(r'^\d+$').hasMatch(ascii.last)) return null;
  return host;
}

const _base = 36;
const _tMin = 1;
const _tMax = 26;
const _skew = 38;
const _damp = 700;
const _initialBias = 72;
const _initialN = 128;

/// [input] encoded with Punycode (RFC 3492), without the `xn--` prefix.
String punycodeEncode(String input) {
  final codePoints = input.runes.toList();
  final output = StringBuffer();
  for (final c in codePoints) {
    if (c < 0x80) output.writeCharCode(c);
  }
  final basic = output.length;
  var handled = basic;
  if (basic > 0) output.write('-');
  var n = _initialN;
  var delta = 0;
  var bias = _initialBias;
  while (handled < codePoints.length) {
    final m = codePoints.where((c) => c >= n).reduce(min);
    delta += (m - n) * (handled + 1);
    n = m;
    for (final c in codePoints) {
      if (c < n) delta++;
      if (c != n) continue;
      var q = delta;
      for (var k = _base; ; k += _base) {
        final t = k <= bias ? _tMin : (k >= bias + _tMax ? _tMax : k - bias);
        if (q < t) break;
        output.writeCharCode(_digit(t + (q - t) % (_base - t)));
        q = (q - t) ~/ (_base - t);
      }
      output.writeCharCode(_digit(q));
      bias = _adapt(delta, handled + 1, handled == basic);
      delta = 0;
      handled++;
    }
    delta++;
    n++;
  }
  return output.toString();
}

int _digit(int d) => d < 26 ? 0x61 + d : 0x30 + d - 26;

int _adapt(int delta, int points, bool first) {
  var d = first ? delta ~/ _damp : delta ~/ 2;
  d += d ~/ points;
  var k = 0;
  while (d > ((_base - _tMin) * _tMax) ~/ 2) {
    d ~/= _base - _tMin;
    k += _base;
  }
  return k + (_base - _tMin + 1) * d ~/ (d + _skew);
}
