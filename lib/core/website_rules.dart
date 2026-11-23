// Where a website rule fills (the add-cards-identities-and-websites plan,
// design decisions 6 and 7), in pure Dart so the app, the browser extension
// and the test box of the sheet answer the same.
//
// Regular expressions are not run by `RegExp`, which backtracks: neither the
// Dart VM nor a browser can stop one in the middle of a match, and `(a|a)*` or
// `.*.*.*x` take polynomial time on a long address. A pattern is parsed here
// into a small syntax tree and run as a Thompson NFA (a Pike VM), which takes
// time O(states x address) whatever the pattern.
import '../models/website_rule.dart';

/// The longest pattern accepted.
const maxPatternLength = 256;

/// The longest address that can match. A longer one never does.
const maxAddressLength = 2048;

/// The most states a pattern may compile to, since `{m,n}` expands.
const maxPatternStates = 4096;

/// The largest count a `{m,n}` repeat may hold.
const maxRepeatCount = 100;

/// Why a pattern is refused, so the sheet can say which.
enum PatternRefusal {
  /// Over [maxPatternLength] characters.
  tooLong,

  /// `\1`, `\k<name>`.
  backReference,

  /// `(?=`, `(?!`, `(?<=` and `(?<!`.
  lookaround,

  /// `\b` and `\B`, which are refused rather than matched wrongly.
  wordBoundary,

  /// `\p{...}` and `\P{...}`.
  unicodeProperty,

  /// `(?i)` and the other flags written inside the pattern.
  flags,

  /// A repeat over [maxRepeatCount].
  repeatTooBig,

  /// More than [maxPatternStates] states once repeats are expanded.
  tooLarge,

  /// Anything else that is not a pattern: an unbalanced bracket, nothing to repeat.
  syntax,
}

class _Refused implements Exception {
  const _Refused(this.reason);

  final PatternRefusal reason;
}

// ─── Syntax tree ───────────────────────────────────────────────────────────

sealed class _Node {
  const _Node();
}

class _Empty extends _Node {
  const _Empty();
}

class _Lit extends _Node {
  const _Lit(this.code);

  final int code;
}

class _Any extends _Node {
  const _Any();
}

class _Set extends _Node {
  const _Set(this.ranges, {required this.negated});

  /// Inclusive code point ranges, as `[low, high]` pairs flattened.
  final List<int> ranges;
  final bool negated;
}

class _Bol extends _Node {
  const _Bol();
}

class _Eol extends _Node {
  const _Eol();
}

class _Cat extends _Node {
  const _Cat(this.parts);

  final List<_Node> parts;
}

class _Alt extends _Node {
  const _Alt(this.options);

  final List<_Node> options;
}

class _Rep extends _Node {
  const _Rep(this.body, this.min, this.max);

  final _Node body;
  final int min;

  /// -1 for no upper bound.
  final int max;
}

// ─── Parser ────────────────────────────────────────────────────────────────

const _digitRanges = [0x30, 0x39];
const _wordRanges = [0x30, 0x39, 0x41, 0x5a, 0x5f, 0x5f, 0x61, 0x7a];
const _spaceRanges = [
  0x09,
  0x0d,
  0x20,
  0x20,
  0xa0,
  0xa0,
  0x1680,
  0x1680,
  0x2000,
  0x200a,
  0x2028,
  0x2029,
  0x202f,
  0x202f,
  0x205f,
  0x205f,
  0x3000,
  0x3000,
  0xfeff,
  0xfeff,
];

/// The code points outside [ranges] (inclusive pairs, in order).
List<int> _complement(List<int> ranges) {
  final out = <int>[];
  var next = 0;
  for (var i = 0; i < ranges.length; i += 2) {
    if (ranges[i] > next) {
      out
        ..add(next)
        ..add(ranges[i] - 1);
    }
    next = ranges[i + 1] + 1;
  }
  if (next <= 0x10ffff) {
    out
      ..add(next)
      ..add(0x10ffff);
  }
  return out;
}

class _Parser {
  _Parser(String pattern) : _p = pattern.runes.toList();

  final List<int> _p;
  var _i = 0;

  _Node parse() {
    final node = _alt();
    if (_i < _p.length) throw const _Refused(PatternRefusal.syntax); // an unmatched )
    return node;
  }

  bool get _done => _i >= _p.length;

  int _peek([int ahead = 0]) => _i + ahead < _p.length ? _p[_i + ahead] : -1;

  bool _at(String s, [int ahead = 0]) => _peek(ahead) == s.codeUnitAt(0);

  _Node _alt() {
    final options = [_cat()];
    while (!_done && _at('|')) {
      _i++;
      options.add(_cat());
    }
    return options.length == 1 ? options.single : _Alt(options);
  }

  _Node _cat() {
    final parts = <_Node>[];
    while (!_done && !_at('|') && !_at(')')) {
      parts.add(_repeat());
    }
    return switch (parts.length) {
      0 => const _Empty(),
      1 => parts.single,
      _ => _Cat(parts),
    };
  }

  _Node _repeat() {
    final atomStart = _i;
    final atom = _atom();
    final quantified = _quantifier(atom);
    if (identical(quantified, atom)) return atom;
    if (atom is _Bol || atom is _Eol) throw const _Refused(PatternRefusal.syntax);
    // A lazy `?` after it changes no yes-or-no answer, so it is read and ignored
    if (_at('?')) _i++;
    // `a**`, `a+*`, `a{2}{3}` and a possessive `+` are not patterns
    if (!_done && (_at('*') || _at('+') || (_at('?')) || _isCountAhead())) throw const _Refused(PatternRefusal.syntax);
    if (_i == atomStart) throw const _Refused(PatternRefusal.syntax);
    return quantified;
  }

  /// Whether a `{m}`, `{m,}` or `{m,n}` starts here.
  bool _isCountAhead() => _at('{') && _count() != null;

  /// Reads `{m}`, `{m,}` or `{m,n}` at [_i] without moving, as (length, min, max), or null.
  (int, int, int)? _count() {
    var j = _i + 1;
    int? number() {
      final start = j;
      var value = 0;
      while (j < _p.length && _p[j] >= 0x30 && _p[j] <= 0x39) {
        value = value * 10 + (_p[j] - 0x30);
        if (value > 100000) value = 100000;
        j++;
      }
      return j == start ? null : value;
    }

    final low = number();
    if (low == null) return null;
    var high = low;
    if (j < _p.length && _p[j] == 0x2c) {
      j++;
      high = number() ?? -1;
    }
    if (j >= _p.length || _p[j] != 0x7d) return null;
    return (j + 1 - _i, low, high);
  }

  _Node _quantifier(_Node atom) {
    if (_done) return atom;
    switch (_peek()) {
      case 0x2a: // *
        _i++;
        return _Rep(atom, 0, -1);
      case 0x2b: // +
        _i++;
        return _Rep(atom, 1, -1);
      case 0x3f: // ?
        _i++;
        return _Rep(atom, 0, 1);
      case 0x7b: // {
        final count = _count();
        if (count == null) return atom; // a lone { is a literal, as in JavaScript
        final (length, low, high) = count;
        if (low > maxRepeatCount || high > maxRepeatCount) throw const _Refused(PatternRefusal.repeatTooBig);
        if (high != -1 && high < low) throw const _Refused(PatternRefusal.syntax);
        _i += length;
        return _Rep(atom, low, high);
    }
    return atom;
  }

  _Node _atom() {
    final c = _peek();
    switch (c) {
      case 0x28: // (
        return _group();
      case 0x5b: // [
        return _class();
      case 0x2e: // .
        _i++;
        return const _Any();
      case 0x5e: // ^
        _i++;
        return const _Bol();
      case 0x24: // $
        _i++;
        return const _Eol();
      case 0x5c: // \
        return _escape();
      case 0x2a || 0x2b || 0x3f: // nothing to repeat
        throw const _Refused(PatternRefusal.syntax);
      case 0x7b: // { is a literal unless it starts a count with nothing before it
        if (_count() != null) throw const _Refused(PatternRefusal.syntax);
        _i++;
        return const _Lit(0x7b);
      case 0x29: // ) is never here: _cat stops at it
        throw const _Refused(PatternRefusal.syntax);
    }
    _i++;
    return _Lit(c);
  }

  _Node _group() {
    _i++; // (
    if (_at('?')) {
      _i++;
      if (_at(':')) {
        _i++;
      } else if (_at('=') || _at('!')) {
        throw const _Refused(PatternRefusal.lookaround);
      } else if (_at('<')) {
        if (_at('=', 1) || _at('!', 1)) throw const _Refused(PatternRefusal.lookaround);
        // A named group: read up to the >, and take it as a group
        while (!_done && !_at('>')) {
          _i++;
        }
        if (_done) throw const _Refused(PatternRefusal.syntax);
        _i++;
      } else {
        // (?i) and its kin
        throw const _Refused(PatternRefusal.flags);
      }
    }
    final inner = _alt();
    if (!_at(')')) throw const _Refused(PatternRefusal.syntax);
    _i++;
    return inner;
  }

  /// A backslash escape outside a class: a literal, a shorthand set, or a refusal.
  _Node _escape() {
    _i++; // the backslash
    if (_done) throw const _Refused(PatternRefusal.syntax);
    final c = _p[_i++];
    switch (String.fromCharCode(c)) {
      case 'd':
        return const _Set(_digitRanges, negated: false);
      case 'D':
        return const _Set(_digitRanges, negated: true);
      case 'w':
        return const _Set(_wordRanges, negated: false);
      case 'W':
        return const _Set(_wordRanges, negated: true);
      case 's':
        return const _Set(_spaceRanges, negated: false);
      case 'S':
        return const _Set(_spaceRanges, negated: true);
      case 'b' || 'B':
        throw const _Refused(PatternRefusal.wordBoundary);
      case 'p' || 'P':
        throw const _Refused(PatternRefusal.unicodeProperty);
      case 'k':
        throw const _Refused(PatternRefusal.backReference);
    }
    if (c >= 0x31 && c <= 0x39) throw const _Refused(PatternRefusal.backReference);
    return _Lit(_literalEscape(c));
  }

  /// The code point of an escape that is a literal: `\n`, `\x41`, `A`, `\.`.
  int _literalEscape(int c) {
    switch (String.fromCharCode(c)) {
      case 'n':
        return 0x0a;
      case 'r':
        return 0x0d;
      case 't':
        return 0x09;
      case 'f':
        return 0x0c;
      case 'v':
        return 0x0b;
      case '0':
        return 0;
      case 'x':
        return _hex(2) ?? c;
      case 'u':
        return _hex(4) ?? c;
    }
    return c;
  }

  /// [digits] hex digits at [_i], read and returned, or null (nothing read).
  int? _hex(int digits) {
    if (_i + digits > _p.length) return null;
    var value = 0;
    for (var k = 0; k < digits; k++) {
      final d = int.tryParse(String.fromCharCode(_p[_i + k]), radix: 16);
      if (d == null) return null;
      value = value * 16 + d;
    }
    _i += digits;
    return value;
  }

  _Node _class() {
    _i++; // [
    final negated = _at('^');
    if (negated) _i++;
    final ranges = <int>[];
    var first = true;
    while (true) {
      if (_done) throw const _Refused(PatternRefusal.syntax);
      if (_at(']') && !first) {
        _i++;
        break;
      }
      if (_at(']') && first) {
        // `[]` is an empty class in JavaScript, and `[^]` any character
        _i++;
        if (negated) return const _Any();
        return const _Set([], negated: false);
      }
      first = false;
      final low = _classAtom(ranges);
      if (low == null) continue; // a shorthand set was added
      if (_at('-') && _peek(1) != -1 && !_at(']', 1)) {
        final save = _i;
        _i++;
        final high = _classAtom(ranges);
        if (high == null) {
          // `a-\d`: the hyphen is a literal, as in JavaScript
          ranges
            ..add(low)
            ..add(low)
            ..add(0x2d)
            ..add(0x2d);
          continue;
        }
        if (high < low) {
          _i = save;
          throw const _Refused(PatternRefusal.syntax);
        }
        ranges
          ..add(low)
          ..add(high);
      } else {
        ranges
          ..add(low)
          ..add(low);
      }
    }
    return _Set(ranges, negated: negated);
  }

  /// One item of a class: its code point, or null when it was a shorthand
  /// set, whose ranges were added to [into].
  int? _classAtom(List<int> into) {
    final c = _p[_i++];
    if (c != 0x5c) return c;
    if (_done) throw const _Refused(PatternRefusal.syntax);
    final e = _p[_i++];
    switch (String.fromCharCode(e)) {
      case 'd':
        into.addAll(_digitRanges);
        return null;
      case 'D':
        into.addAll(_complement(_digitRanges));
        return null;
      case 'w':
        into.addAll(_wordRanges);
        return null;
      case 'W':
        into.addAll(_complement(_wordRanges));
        return null;
      case 's':
        into.addAll(_spaceRanges);
        return null;
      case 'S':
        into.addAll(_complement(_spaceRanges));
        return null;
      case 'b':
        return 0x08; // a backspace inside a class
      case 'p' || 'P':
        throw const _Refused(PatternRefusal.unicodeProperty);
      case 'k':
        throw const _Refused(PatternRefusal.backReference);
    }
    if (e >= 0x31 && e <= 0x39) throw const _Refused(PatternRefusal.backReference);
    return _literalEscape(e);
  }
}

// ─── Program ───────────────────────────────────────────────────────────────

enum _Op { char, any, set, split, jump, bol, eol, match }

class _Inst {
  _Inst(this.op, {this.x = 0, this.code = 0, this.ranges = const [], this.negated = false});

  final _Op op;

  /// The target of a jump, or the first branch of a split.
  int x;

  /// The second branch of a split.
  int y = 0;

  /// A literal, already folded to lowercase.
  final int code;
  final List<int> ranges;
  final bool negated;
}

int _fold(int c) {
  final s = String.fromCharCode(c).toLowerCase();
  final runes = s.runes;
  return runes.length == 1 ? runes.first : c;
}

int _upper(int c) {
  final s = String.fromCharCode(c).toUpperCase();
  final runes = s.runes;
  return runes.length == 1 ? runes.first : c;
}

class _Compiler {
  final program = <_Inst>[];

  int _emit(_Inst inst) {
    if (program.length >= maxPatternStates) throw const _Refused(PatternRefusal.tooLarge);
    program.add(inst);
    return program.length - 1;
  }

  void compile(_Node node) {
    switch (node) {
      case _Empty():
        break;
      case _Lit(:final code):
        _emit(_Inst(_Op.char, code: _fold(code)));
      case _Any():
        _emit(_Inst(_Op.any));
      case _Set(:final ranges, :final negated):
        _emit(_Inst(_Op.set, ranges: ranges, negated: negated));
      case _Bol():
        _emit(_Inst(_Op.bol));
      case _Eol():
        _emit(_Inst(_Op.eol));
      case _Cat(:final parts):
        for (final part in parts) {
          compile(part);
        }
      case _Alt(:final options):
        final jumps = <int>[];
        for (var k = 0; k < options.length; k++) {
          if (k < options.length - 1) {
            final split = _emit(_Inst(_Op.split));
            program[split].x = program.length;
            compile(options[k]);
            jumps.add(_emit(_Inst(_Op.jump)));
            program[split].y = program.length;
          } else {
            compile(options[k]);
          }
        }
        for (final jump in jumps) {
          program[jump].x = program.length;
        }
      case _Rep(:final body, :final min, :final max):
        for (var k = 0; k < min; k++) {
          compile(body);
        }
        if (max == -1) {
          final split = _emit(_Inst(_Op.split));
          program[split].x = program.length;
          compile(body);
          _emit(_Inst(_Op.jump, x: split));
          program[split].y = program.length;
        } else {
          final splits = <int>[];
          for (var k = min; k < max; k++) {
            final split = _emit(_Inst(_Op.split));
            program[split].x = program.length;
            splits.add(split);
            compile(body);
          }
          for (final split in splits) {
            program[split].y = program.length;
          }
        }
    }
  }
}

/// A pattern parsed and compiled, ready to search addresses.
class PatternProgram {
  PatternProgram._(this._program);

  final List<_Inst> _program;

  /// How many states the pattern compiled to.
  int get states => _program.length;

  /// Whether [text] holds a match of the pattern, ignoring case, as
  /// `new RegExp(pattern, "i").test(text)` says. An address over
  /// [maxAddressLength] characters never matches. [steps] is how many
  /// states the search took in all, never more than `states x (length + 1)`.
  ({bool matched, int steps}) search(String text) {
    if (text.length > maxAddressLength) return (matched: false, steps: 0);
    final codes = text.runes.toList();
    final run = _Run(_program, codes.length);
    var current = <int>[];
    var next = <int>[];
    for (var pos = 0; pos <= codes.length; pos++) {
      // A thread starts at every position, joining those carried over
      run.add(current, 0, pos, pos);
      if (run.matched) return (matched: true, steps: run.steps);
      if (pos == codes.length) break;
      final c = codes[pos];
      final lower = _fold(c);
      final upper = _upper(c);
      next.clear();
      for (final pc in current) {
        if (_consumes(_program[pc], c, lower, upper)) run.add(next, pc + 1, pos + 1, pos + 1);
        if (run.matched) return (matched: true, steps: run.steps);
      }
      final swap = current;
      current = next;
      next = swap;
    }
    return (matched: false, steps: run.steps);
  }

  /// [search] without the count.
  bool hasMatchIn(String text) => search(text).matched;
}

bool _consumes(_Inst inst, int c, int lower, int upper) {
  switch (inst.op) {
    case _Op.char:
      return inst.code == lower;
    case _Op.any:
      return c != 0x0a && c != 0x0d && c != 0x2028 && c != 0x2029;
    case _Op.set:
      final r = inst.ranges;
      var hit = false;
      for (var i = 0; i < r.length && !hit; i += 2) {
        hit = (c >= r[i] && c <= r[i + 1]) || (lower >= r[i] && lower <= r[i + 1]) || (upper >= r[i] && upper <= r[i + 1]);
      }
      return hit != inst.negated;
    default:
      return false;
  }
}

/// The state of one search: which states were reached at the position being built.
class _Run {
  _Run(this._program, this._length) : _mark = List<int>.filled(_program.length, -1);

  final List<_Inst> _program;
  final int _length;
  final List<int> _mark;
  var matched = false;
  var steps = 0;

  /// Adds the thread at [pc], and every state it reaches without consuming a
  /// character, to [list]; [pos] is the position they stand at, and [generation]
  /// which build of a list this is, so no state is added twice to one list.
  void add(List<int> list, int pc, int pos, int generation) {
    if (matched || _mark[pc] == generation) return;
    _mark[pc] = generation;
    steps++;
    final inst = _program[pc];
    switch (inst.op) {
      case _Op.jump:
        add(list, inst.x, pos, generation);
      case _Op.split:
        add(list, inst.x, pos, generation);
        add(list, inst.y, pos, generation);
      case _Op.bol:
        if (pos == 0) add(list, pc + 1, pos, generation);
      case _Op.eol:
        if (pos == _length) add(list, pc + 1, pos, generation);
      case _Op.match:
        matched = true;
      default:
        list.add(pc);
    }
  }
}

/// A pattern compiled, or why it was refused.
typedef CompiledPattern = ({PatternProgram? program, PatternRefusal? refusal});

final _compiled = <String, CompiledPattern>{};

/// Parses and compiles [pattern], or says why it can't: a pattern over
/// [maxPatternLength] characters, back-references, lookarounds, `\b`,
/// Unicode property escapes, flags inside the pattern, a repeat over
/// [maxRepeatCount], or more than [maxPatternStates] states.
CompiledPattern compilePattern(String pattern) {
  final cached = _compiled[pattern];
  if (cached != null) return cached;
  CompiledPattern result;
  if (pattern.length > maxPatternLength) {
    result = (program: null, refusal: PatternRefusal.tooLong);
  } else {
    try {
      final compiler = _Compiler()..compile(_Parser(pattern).parse());
      compiler.program.add(_Inst(_Op.match));
      result = (program: PatternProgram._(compiler.program), refusal: null);
    } on _Refused catch (refused) {
      result = (program: null, refusal: refused.reason);
    }
  }
  if (_compiled.length >= 64) _compiled.remove(_compiled.keys.first);
  return _compiled[pattern] = result;
}

/// Why [pattern] is refused, or null when it can be run.
PatternRefusal? patternRefusal(String pattern) => compilePattern(pattern).refusal;

// ─── Where a rule fills ────────────────────────────────────────────────────

final _ipv4 = RegExp(r'^\d{1,3}(?:\.\d{1,3}){3}$');
final _addressPattern = RegExp(r'^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)([\s\S]*)$');

/// An address taken apart: its scheme and host in lowercase, its explicit
/// port, and what follows the authority as written.
class _Address {
  _Address(this.scheme, this.host, this.port, this.rest, this.authority);

  final String? scheme;
  final String host;
  final int? port;
  final String rest;

  /// The host and port as typed, lowercase.
  final String authority;

  static _Address? parse(String text) {
    final address = text.trim();
    String? scheme;
    final match = _addressPattern.firstMatch(address);
    var authority = '';
    var rest = '';
    if (match != null) {
      scheme = match[1]!.toLowerCase();
      authority = match[2]!;
      rest = match[3]!;
    } else {
      // No scheme: what comes first is the authority
      final end = address.indexOf(RegExp(r'[/?#]'));
      authority = end < 0 ? address : address.substring(0, end);
      rest = end < 0 ? '' : address.substring(end);
    }
    final at = authority.lastIndexOf('@');
    if (at >= 0) authority = authority.substring(at + 1);
    authority = authority.toLowerCase();
    if (authority.isEmpty || authority.startsWith('[')) return null;
    var host = authority;
    int? port;
    final colon = authority.lastIndexOf(':');
    if (colon >= 0) {
      final digits = authority.substring(colon + 1);
      if (!RegExp(r'^\d{1,5}$').hasMatch(digits)) return null;
      port = int.parse(digits);
      host = authority.substring(0, colon);
    }
    if (host.endsWith('.')) host = host.substring(0, host.length - 1);
    if (host.isEmpty) return null;
    return _Address(scheme, host, port, rest, authority);
  }

  /// The port as it tells the address apart: none for an absent one and for 80 and 443.
  int? get effectivePort => port == null || port == 80 || port == 443 ? null : port;

  String get bareHost => host.startsWith('www.') ? host.substring(4) : host;

  /// Scheme and host in lowercase, the rest as written.
  String get canonical => '${scheme == null ? '' : '$scheme://'}$authority$rest';

  /// The same without the scheme, for a saved address that has none.
  String get withoutScheme => '$authority$rest';
}

/// Whether [host] is an address, or under a host anyone can open a site under.
bool _fillsOnItself(String host, bool Function(String host)? isShared) => _ipv4.hasMatch(host) || (isShared?.call(host) ?? false);

/// Whether [rule] fills on [address], a whole address as a browser shows it.
///
/// Default and Base domain fill on the registrable domain of the saved host
/// and every host under it, [registrable] telling what the Public Suffix List
/// says (without it, the saved host itself); a host [isShared] holds, and an
/// IP address, fill on themselves only, whatever the rule. Host compares host
/// and port, a default port being none. Starts with and Exact compare
/// addresses with the scheme and host in lowercase and the rest as written.
/// Regular expression is a search ignoring case. Never, and a rule of a later
/// version, fill nowhere. An address over [maxAddressLength] never matches.
bool fillsOn(WebsiteRule rule, String address, {String Function(String host)? registrable, bool Function(String host)? isShared}) {
  if (address.length > maxAddressLength) return false;
  switch (rule.match) {
    case WebsiteMatch.regularExpression:
      return compilePattern(rule.uri).program?.hasMatchIn(address) ?? false;
    case WebsiteMatch.never:
      return false;
  }
  if (!rule.isKnown) return false;
  final saved = _Address.parse(rule.uri);
  final seen = _Address.parse(address);
  if (saved == null || seen == null) return false;
  switch (rule.match) {
    case null || WebsiteMatch.baseDomain:
      final host = saved.bareHost;
      if (_fillsOnItself(host, isShared)) return seen.bareHost == host;
      final base = registrable?.call(host) ?? host;
      return seen.bareHost == base || seen.bareHost.endsWith('.$base');
    case WebsiteMatch.host:
      return seen.bareHost == saved.bareHost && seen.effectivePort == saved.effectivePort;
    case WebsiteMatch.startsWith:
      return saved.scheme == null ? seen.withoutScheme.startsWith(saved.withoutScheme) : seen.canonical.startsWith(saved.canonical);
    case WebsiteMatch.exact:
      return saved.scheme == null ? seen.withoutScheme == saved.withoutScheme : seen.canonical == saved.canonical;
  }
  return false;
}

/// What a rule is held on, which decides how a phone fills it.
enum WebsiteKind { login, account }

/// The domains the autofill copy holds for [rules], as the Kotlin and Swift
/// readers match them: a plain domain fills on it and the hosts under it, and
/// `=host` on that host alone.
///
/// Phones see only a host. Host, Starts with and Exact fill on their host
/// alone, Base domain on its registrable domain ([registrable]), and Regular
/// expression, Never and a rule of a later version nowhere. Default keeps
/// what the kind has always done: a login fills on the registrable domain of
/// the host, and an account on the host and its subdomains. On every rule a
/// host [isShared] holds, and an IP address, become `=host`.
List<String> phoneDomains(
  List<WebsiteRule> rules,
  WebsiteKind kind, {
  String Function(String host)? registrable,
  bool Function(String host)? isShared,
}) {
  final domains = <String>[];
  for (final rule in rules) {
    final host = rule.host;
    if (host == null) continue;
    final exact = _fillsOnItself(host, isShared);
    final String domain;
    switch (rule.match) {
      case null:
        domain = exact ? '=$host' : (kind == WebsiteKind.login ? (registrable?.call(host) ?? host) : host);
      case WebsiteMatch.baseDomain:
        domain = exact ? '=$host' : (registrable?.call(host) ?? host);
      default:
        domain = '=$host';
    }
    if (!domains.contains(domain)) domains.add(domain);
  }
  return domains;
}
