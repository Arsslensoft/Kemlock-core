import 'package:collection/collection.dart';

/// Marks a `copyWith` argument that wasn't passed, so the field keeps its value.
const keep = _Keep();

/// Pass to a `copyWith` argument to remove an optional field.
const unset = _Unset();

class _Keep {
  const _Keep();
}

class _Unset {
  const _Unset();
}

/// The new value of an optional field in a `copyWith`.
T? pick<T>(Object? value, T? current) => switch (value) {
  _Keep() => current,
  _Unset() => null,
  _ => value as T?,
};

String asString(Object? value, [String fallback = '']) => value is String ? value : fallback;

/// A whole number, also from a JSON number written with a fraction, such as `30.0`.
int? asInt(Object? value) => switch (value) {
  int() => value,
  double() when value.isFinite => value.round(),
  _ => null,
};

/// The keys of [json] outside [known], to be written back as they were.
Map<String, Object?> extraKeys(Map<String, Object?> json, Set<String> known) => {
  for (final MapEntry(:key, :value) in json.entries)
    if (!known.contains(key)) key: value,
};

const _deep = DeepCollectionEquality();

/// Whether two JSON values hold the same data.
bool jsonEquals(Object? a, Object? b) => _deep.equals(a, b);

bool? asBool(Object? value) => value is bool ? value : null;

/// The strings of a JSON list, or null when [value] isn't a list.
List<String>? asStrings(Object? value) => value is List ? value.whereType<String>().toList() : null;

String? asOptionalString(Object? value) => value is String ? value : null;

/// [extra] without its `links` or `fields` member when a copy sets that one ([links], [fields]). A model holds a member of that name among
/// the keys it doesn't know only when it isn't a list; written after the model's own, as the unknown keys are, it would overwrite
/// the list the copy sets. When nothing is set, or there is no such member, [extra] comes back as it is.
Map<String, Object?> extraSetting(Map<String, Object?> extra, {bool links = false, bool fields = false}) {
  if (!(links && extra.containsKey('links')) && !(fields && extra.containsKey('fields'))) {
    return extra;
  }
  return {
    for (final MapEntry(:key, :value) in extra.entries)
      if (!(links && key == 'links') && !(fields && key == 'fields')) key: value,
  };
}

/// The keys of [json] outside [known], and outside `links` and `fields` when a model reads them: those that
/// are lists. A member of another shape stays among the keys the model doesn't know, written back as it was.
/// [fields] is false for a kind that has no custom fields.
Map<String, Object?> extraKeysOfBody(Map<String, Object?> json, Set<String> known, {bool fields = true}) =>
    extraKeys(json, {...known, if (json['links'] is List) 'links', if (fields && json['fields'] is List) 'fields'});
