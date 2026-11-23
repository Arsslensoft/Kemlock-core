// A site's password rules, in the language Apple's `passwordrules` attribute
// and password-manager-resources use: `minlength: 8; maxlength: 16;
// required: lower; required: upper, digit; allowed: [-_]; max-consecutive: 2`.
// The Kotlin and Swift parsers read it the same way (openspec: add-passwords,
// design decision 5).

/// Characters of each named class, in the order the generator draws from them.
const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const digitChars = '0123456789';

/// Apple's `special`: `-~!@#$%^&*_+=`|(){}[:;"'<>,.?]` and space.
const specialChars = '-~!@#\$%^&*_+=`|(){}[:;"\'<>,.?] ';

/// Every printable ASCII character, space to tilde.
final asciiPrintable = String.fromCharCodes([for (var c = 0x20; c <= 0x7e; c++) c]);

/// A site's rules once read. A null field says nothing about it.
class PasswordRules {
  const PasswordRules({this.minLength, this.maxLength, this.required = const [], this.allowed, this.maxConsecutive});

  final int? minLength;
  final int? maxLength;

  /// Each a set of characters at least one of which the password must hold.
  final List<String> required;

  /// The characters the password may hold, besides the required ones; null when the rules name none.
  final String? allowed;
  final int? maxConsecutive;

  bool get isEmpty => minLength == null && maxLength == null && required.isEmpty && allowed == null && maxConsecutive == null;

  /// Reads [text]; a rule it doesn't know is skipped, as browsers do.
  factory PasswordRules.parse(String text) {
    int? minLength;
    int? maxLength;
    int? maxConsecutive;
    final required = <String>[];
    String? allowed;
    for (final rule in _splitRules(text)) {
      final colon = rule.indexOf(':');
      if (colon < 0) continue;
      final name = rule.substring(0, colon).trim().toLowerCase();
      final value = rule.substring(colon + 1).trim();
      switch (name) {
        case 'minlength':
          minLength = int.tryParse(value);
        case 'maxlength':
          maxLength = int.tryParse(value);
        case 'max-consecutive':
          maxConsecutive = int.tryParse(value);
        case 'required':
          final chars = _classes(value);
          if (chars.isNotEmpty) required.add(chars);
        case 'allowed':
          allowed = _union([?allowed, _classes(value)]);
      }
    }
    return PasswordRules(minLength: minLength, maxLength: maxLength, required: required, allowed: allowed, maxConsecutive: maxConsecutive);
  }

  /// Splits at the semicolons outside brackets: a custom class may hold one.
  static List<String> _splitRules(String text) {
    final rules = <String>[];
    var start = 0;
    var inClass = false;
    for (var i = 0; i < text.length; i++) {
      final c = text[i];
      if (c == '[' && !inClass) {
        inClass = true;
        // A ] right after the opening bracket is a character of the class
        if (i + 1 < text.length && text[i + 1] == ']') i++;
      } else if (c == ']' && inClass) {
        inClass = false;
      } else if (c == ';' && !inClass) {
        rules.add(text.substring(start, i));
        start = i + 1;
      }
    }
    rules.add(text.substring(start));
    return rules.where((rule) => rule.trim().isNotEmpty).toList();
  }

  /// The characters of a comma-separated list of classes and `[...]` sets.
  static String _classes(String value) {
    final parts = <String>[];
    var i = 0;
    while (i < value.length) {
      final c = value[i];
      // Classes are separated by commas and whitespace of any kind
      if (c == ',' || c.trim().isEmpty) {
        i++;
      } else if (c == '[') {
        // A custom set: everything up to the closing bracket, a ] first being one of its characters
        var end = i + 2 <= value.length ? value.indexOf(']', i + 2) : -1;
        if (end < 0) end = value.length;
        parts.add(value.substring(i + 1, end));
        i = end + 1;
      } else {
        var end = value.indexOf(RegExp(r'[,\s\[]'), i);
        if (end < 0) end = value.length;
        final named = switch (value.substring(i, end).toLowerCase()) {
          'lower' => lowerChars,
          'upper' => upperChars,
          'digit' => digitChars,
          'special' => specialChars,
          'ascii-printable' || 'unicode' => asciiPrintable,
          _ => '',
        };
        parts.add(named);
        i = end;
      }
    }
    return _union(parts);
  }
}

/// The characters of [sets], each once, in the order they first appear.
String _union(List<String> sets) {
  final seen = <int>{};
  final out = StringBuffer();
  for (final set in sets) {
    for (final c in set.runes) {
      if (seen.add(c)) out.writeCharCode(c);
    }
  }
  return out.toString();
}

/// [a]'s characters that are also in [b], in [a]'s order.
String intersect(String a, String b) => String.fromCharCodes(a.runes.where(b.runes.toSet().contains));

/// [sets] joined, each character once, in the order they first appear.
String unionOf(List<String> sets) => _union(sets);
