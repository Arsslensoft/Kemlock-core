// The strict subset of JSON a record of a space's chain is written in (the space chain
// section of docs/crypto.md, "Encoding"), so a record has exactly one spelling:
//
// - values are objects, arrays, strings, integers, `true` and `false`; `null` is never a value;
// - integers are `0` to 2^53 - 1 in decimal digits with no leading zero: a `-`, a `.`, an `e` or `E`
//   or a larger value is refused;
// - strings hold only `A-Z a-z 0-9 - _ :` between quotes, so no string has an escape, a lone
//   surrogate or any non-ASCII text;
// - member names are ASCII letters, each once and in byte order;
// - no whitespace, no byte-order mark and nothing after the closing brace; objects nest at most 6
//   deep.
//
// A reader that keeps the last of two equal names, or reads `1.0` as `1`, would accept two spellings
// of one record; this one refuses both as it reads. The sort order of an array is a rule of the kind
// it belongs to, which the kinds' readers check (`space_chain_body.dart`).
//
// Pure Dart, no Flutter.

library;

import '../../crypto/account/encoding.dart' show MalformedException;

/// The largest integer a record holds, 2^53 - 1.
const chainMaxInteger = 9007199254740991;

/// The most levels objects nest in a record.
const chainMaxObjectDepth = 6;

/// A guard against a long run of arrays, which no record has.
const _maxNesting = 32;

/// Reads [bytes] as one value of the subset. Anything outside it is a [MalformedException].
Object? readChainJson(List<int> bytes) {
  final reader = _Reader(bytes);
  final value = reader.value(0);
  reader.finish();
  return value;
}

final class _Reader {
  _Reader(this._bytes);

  final List<int> _bytes;
  var _at = 0;
  var _nesting = 0;

  int _peek() => _at < _bytes.length ? _bytes[_at] : -1;

  Never _fail(String why) => throw MalformedException('a chain record is canonical JSON: $why, at byte $_at');

  void _expect(int byte, String what) {
    if (_peek() != byte) {
      _fail('expected $what');
    }
    _at++;
  }

  void finish() {
    if (_at != _bytes.length) {
      _fail('nothing may follow the closing brace');
    }
  }

  Object? value(int objectDepth) {
    final byte = _peek();
    if (byte == 0x7b) {
      return _object(objectDepth + 1);
    }
    if (byte == 0x5b) {
      return _array(objectDepth);
    }
    if (byte == 0x22) {
      return _string();
    }
    if (byte == 0x74) {
      _word('true');
      return true;
    }
    if (byte == 0x66) {
      _word('false');
      return false;
    }
    if (byte >= 0x30 && byte <= 0x39) {
      return _integer();
    }
    _fail('expected a value');
  }

  void _word(String word) {
    for (final unit in word.codeUnits) {
      _expect(unit, word);
    }
  }

  void _enter() {
    _nesting++;
    if (_nesting > _maxNesting) {
      _fail('too deep');
    }
  }

  Map<String, Object?> _object(int objectDepth) {
    if (objectDepth > chainMaxObjectDepth) {
      _fail('objects nest at most $chainMaxObjectDepth deep');
    }
    _enter();
    _at++;
    final out = <String, Object?>{};
    if (_peek() == 0x7d) {
      _at++;
      _nesting--;
      return out;
    }
    String? last;
    while (true) {
      final name = _name();
      if (last != null && name.compareTo(last) <= 0) {
        _fail('member names are each once and in byte order');
      }
      last = name;
      _expect(0x3a, ':');
      out[name] = value(objectDepth);
      if (_peek() == 0x7d) {
        _at++;
        _nesting--;
        return out;
      }
      _expect(0x2c, ',');
    }
  }

  List<Object?> _array(int objectDepth) {
    _enter();
    _at++;
    final out = <Object?>[];
    if (_peek() == 0x5d) {
      _at++;
      _nesting--;
      return out;
    }
    while (true) {
      out.add(value(objectDepth));
      if (_peek() == 0x5d) {
        _at++;
        _nesting--;
        return out;
      }
      _expect(0x2c, ',');
    }
  }

  /// A member name: ASCII letters only.
  String _name() {
    final text = _string();
    if (text.isEmpty) {
      _fail('a member name is not empty');
    }
    for (final unit in text.codeUnits) {
      final letter = (unit >= 0x41 && unit <= 0x5a) || (unit >= 0x61 && unit <= 0x7a);
      if (!letter) {
        _fail('a member name is ASCII letters');
      }
    }
    return text;
  }

  /// A string of `A-Z a-z 0-9 - _ :` and nothing else, so a `\` is refused where it stands.
  String _string() {
    _expect(0x22, 'a string');
    final start = _at;
    while (true) {
      final byte = _peek();
      if (byte == 0x22) {
        final text = String.fromCharCodes(_bytes.sublist(start, _at));
        _at++;
        return text;
      }
      final allowed =
          (byte >= 0x41 && byte <= 0x5a) ||
          (byte >= 0x61 && byte <= 0x7a) ||
          (byte >= 0x30 && byte <= 0x39) ||
          byte == 0x2d ||
          byte == 0x5f ||
          byte == 0x3a;
      if (!allowed) {
        _fail('a string holds only letters, digits, - _ and :');
      }
      _at++;
    }
  }

  int _integer() {
    final start = _at;
    while (_peek() >= 0x30 && _peek() <= 0x39) {
      _at++;
    }
    final length = _at - start;
    if (length > 1 && _bytes[start] == 0x30) {
      _fail('an integer has no leading zero');
    }
    if (length > 16) {
      _fail('an integer is at most $chainMaxInteger');
    }
    final number = int.parse(String.fromCharCodes(_bytes.sublist(start, _at)));
    if (number > chainMaxInteger) {
      _fail('an integer is at most $chainMaxInteger');
    }
    return number;
  }
}
