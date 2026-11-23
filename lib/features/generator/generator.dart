// Passwords and passphrases, made the same way in Dart, Kotlin and Swift, so
// that equal choices, rules and random bytes give an equal password
// (openspec: password-generator; add-passwords, design decision 5). The
// shared test cases are test/fixtures/generator/cases.json.
import 'dart:math';

import 'password_rules.dart';

/// The symbols the generator uses by default.
const generatorSymbols = '!#%&-_?';

/// Characters people mistake for one another, left out when asked.
const lookAlikes = '0O1lI';

/// The shortest and longest password the generator makes, and its default.
const minPasswordLength = 8;
const maxPasswordLength = 64;
const defaultPasswordLength = 20;

/// The fewest and most words of a passphrase, and its default.
const minPassphraseWords = 3;
const maxPassphraseWords = 10;
const defaultPassphraseWords = 5;

/// Where random bytes come from: the platform's secure source in the app, a
/// fixed stream in the tests.
abstract interface class ByteSource {
  int nextByte();
}

/// The phone's cryptographically secure random source.
class SecureByteSource implements ByteSource {
  final _random = Random.secure();

  @override
  int nextByte() => _random.nextInt(256);
}

/// A fixed stream of bytes, for the shared test cases. Running out is an error.
class FixedByteSource implements ByteSource {
  FixedByteSource(this.bytes);

  final List<int> bytes;
  var _next = 0;

  @override
  int nextByte() {
    if (_next >= bytes.length) throw StateError('Out of random bytes after $_next');
    return bytes[_next++];
  }
}

/// A number below [n] with every value as likely: bytes that would favour
/// the low values are drawn again. Up to 256 values from one byte, more from
/// two, most significant first.
int pickBelow(ByteSource source, int n) {
  if (n <= 0) throw ArgumentError.value(n, 'n');
  if (n <= 256) {
    final limit = 256 - 256 % n;
    while (true) {
      final b = source.nextByte();
      if (b < limit) return b % n;
    }
  }
  final limit = 65536 - 65536 % n;
  while (true) {
    final v = (source.nextByte() << 8) | source.nextByte();
    if (v < limit) return v % n;
  }
}

/// What a random password is made of.
class PasswordChoices {
  const PasswordChoices({
    this.length = defaultPasswordLength,
    this.capitals = true,
    this.digits = true,
    this.symbols = true,
    this.avoidLookAlikes = true,
  });

  final int length;
  final bool capitals;
  final bool digits;
  final bool symbols;
  final bool avoidLookAlikes;

  PasswordChoices copyWith({int? length, bool? capitals, bool? digits, bool? symbols, bool? avoidLookAlikes}) => PasswordChoices(
    length: length ?? this.length,
    capitals: capitals ?? this.capitals,
    digits: digits ?? this.digits,
    symbols: symbols ?? this.symbols,
    avoidLookAlikes: avoidLookAlikes ?? this.avoidLookAlikes,
  );

  Map<String, Object?> toJson() => {
    'length': length,
    'capitals': capitals,
    'digits': digits,
    'symbols': symbols,
    'avoidLookAlikes': avoidLookAlikes,
  };

  factory PasswordChoices.fromJson(Map<String, Object?> json) {
    bool flag(String key, bool fallback) => json[key] is bool ? json[key]! as bool : fallback;
    final length = json['length'];
    return PasswordChoices(
      length: length is int ? length.clamp(minPasswordLength, maxPasswordLength) : defaultPasswordLength,
      capitals: flag('capitals', true),
      digits: flag('digits', true),
      symbols: flag('symbols', true),
      avoidLookAlikes: flag('avoidLookAlikes', true),
    );
  }
}

String _withoutLookAlikes(String chars, bool avoid) =>
    avoid ? String.fromCharCodes(chars.runes.where((c) => !lookAlikes.runes.contains(c))) : chars;

/// The sets one character of each must be in the password, and the
/// alphabet the rest is drawn from, for [choices] under [rules]. Rules that
/// can't be met are left out, and [choices] made alone.
({List<String> required, String alphabet, int length, int? maxConsecutive}) passwordPlan(PasswordChoices choices, [PasswordRules? rules]) {
  final avoid = choices.avoidLookAlikes;
  final chosen = [
    _withoutLookAlikes(lowerChars, avoid),
    if (choices.capitals) _withoutLookAlikes(upperChars, avoid),
    if (choices.digits) _withoutLookAlikes(digitChars, avoid),
    if (choices.symbols) generatorSymbols,
  ];
  final plain = (
    required: chosen,
    alphabet: unionOf(chosen),
    length: choices.length.clamp(minPasswordLength, maxPasswordLength).toInt(),
    maxConsecutive: null as int?,
  );
  if (rules == null || rules.isEmpty) return plain;

  // What the site takes: what it allows and requires, or any printable character when it says neither
  final allowed = rules.allowed != null || rules.required.isNotEmpty ? unionOf([...rules.required, ?rules.allowed]) : asciiPrintable;
  final kept = [
    for (final set in chosen)
      if (intersect(set, allowed) case final inSite when inSite.isNotEmpty) inSite,
  ];
  final ours = unionOf(chosen);
  final siteRequired = <String>[];
  for (final set in rules.required) {
    // From the site's set, the characters this generator uses when any, else the set without space, else all of it
    final preferred = _withoutLookAlikes(intersect(set, ours), avoid);
    final fallback = _withoutLookAlikes(set.replaceAll(' ', ''), avoid);
    final pick = preferred.isNotEmpty
        ? preferred
        : fallback.isNotEmpty
        ? fallback
        : set;
    if (!kept.any((k) => intersect(k, set).length == k.length)) siteRequired.add(pick);
  }
  final required = [...kept, ...siteRequired];
  final min = max(rules.minLength ?? 1, required.length);
  final top = rules.maxLength ?? maxPasswordLength;
  final length = choices.length.clamp(min, max(min, top)).toInt();
  if (required.isEmpty || required.any((set) => set.isEmpty) || (rules.maxLength != null && rules.maxLength! < min) || length > top) {
    return plain;
  }
  return (required: required, alphabet: unionOf(required), length: length, maxConsecutive: rules.maxConsecutive);
}

/// A random password: one character from each required set first, then
/// characters from the whole alphabet to the length, then shuffled (Fisher–
/// Yates), every draw from [source] by [pickBelow]. A character that would
/// make a run longer than the rules allow is drawn again.
String generatePassword(ByteSource source, PasswordChoices choices, [PasswordRules? rules]) {
  final plan = passwordPlan(choices, rules);
  final alphabet = plan.alphabet.runes.toList();
  final chars = <int>[];
  for (final set in plan.required) {
    final runes = set.runes.toList();
    chars.add(runes[pickBelow(source, runes.length)]);
  }
  while (chars.length < plan.length) {
    chars.add(alphabet[pickBelow(source, alphabet.length)]);
  }
  for (var i = chars.length - 1; i > 0; i--) {
    final j = pickBelow(source, i + 1);
    final swap = chars[i];
    chars[i] = chars[j];
    chars[j] = swap;
  }
  final most = plan.maxConsecutive;
  if (most != null && most > 0 && alphabet.length > 1) {
    var run = 1;
    for (var i = 1; i < chars.length; i++) {
      run = chars[i] == chars[i - 1] ? run + 1 : 1;
      while (run > most) {
        chars[i] = alphabet[pickBelow(source, alphabet.length)];
        run = chars[i] == chars[i - 1] ? run : 1;
      }
    }
  }
  return String.fromCharCodes(chars);
}

/// What a passphrase is made of.
class PassphraseChoices {
  const PassphraseChoices({this.words = defaultPassphraseWords, this.separator = '-', this.capitalise = false, this.digit = false});

  final int words;
  final String separator;
  final bool capitalise;
  final bool digit;

  PassphraseChoices copyWith({int? words, String? separator, bool? capitalise, bool? digit}) => PassphraseChoices(
    words: words ?? this.words,
    separator: separator ?? this.separator,
    capitalise: capitalise ?? this.capitalise,
    digit: digit ?? this.digit,
  );

  Map<String, Object?> toJson() => {'words': words, 'separator': separator, 'capitalise': capitalise, 'digit': digit};

  factory PassphraseChoices.fromJson(Map<String, Object?> json) {
    final words = json['words'];
    final separator = json['separator'];
    return PassphraseChoices(
      words: words is int ? words.clamp(minPassphraseWords, maxPassphraseWords) : defaultPassphraseWords,
      separator: separator is String && separator.length <= 1 ? separator : '-',
      capitalise: json['capitalise'] == true,
      digit: json['digit'] == true,
    );
  }
}

/// A passphrase of words from [wordList], each drawn by [pickBelow]; with
/// [PassphraseChoices.digit], a word drawn the same way is followed by a
/// digit drawn after it.
String generatePassphrase(ByteSource source, List<String> wordList, PassphraseChoices choices) {
  final count = choices.words.clamp(minPassphraseWords, maxPassphraseWords);
  final words = [for (var i = 0; i < count; i++) wordList[pickBelow(source, wordList.length)]];
  if (choices.capitalise) {
    for (var i = 0; i < words.length; i++) {
      words[i] = words[i].isEmpty ? words[i] : '${words[i][0].toUpperCase()}${words[i].substring(1)}';
    }
  }
  if (choices.digit) {
    final at = pickBelow(source, words.length);
    words[at] = '${words[at]}${pickBelow(source, 10)}';
  }
  return words.join(choices.separator);
}
