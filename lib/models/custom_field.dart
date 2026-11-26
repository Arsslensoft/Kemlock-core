import 'json.dart';

/// What a custom field holds (`crypto.md`, "`fields`: custom fields"): the words a field's `kind` is written as.
abstract final class CustomFieldKind {
  /// Any text.
  static const text = 'text';

  /// Any text, shown masked.
  static const hidden = 'hidden';

  /// `"true"` or `"false"`: a checkbox.
  static const boolean = 'boolean';

  /// Written by the Bitwarden importer; kept as it is, never edited.
  static const linked = 'linked';

  /// Whether a person can edit a field of [kind].
  static bool isEditable(String kind) => kind == text || kind == hidden || kind == boolean;

  /// The kind a stored `kind` (or `type`) means, as one of the words above. The importers write other words and
  /// numbers for the same ones: `password`, `checkbox`, and Bitwarden's `0` to `3`. A word this version doesn't know is
  /// returned as it was, an entry with no kind is [text], and anything but a word or a whole number is empty.
  static String read(Object? value) => switch (value is String ? value.toLowerCase() : value) {
    null || 'text' || 0 => text,
    'hidden' || 'password' || 1 => hidden,
    'boolean' || 'checkbox' || 2 => boolean,
    'linked' || 3 => linked,
    final String other => other,
    _ => '',
  };
}

/// One custom field of an item: `{ "name", "value", "kind", "adminField"? }`. A field is never required.
///
/// An entry that can't be edited (a `linked` one, a kind this version doesn't know, one with no name, one that isn't an
/// object) keeps its place and its JSON as it was. A field read from a body and not changed writes back exactly as it
/// was read (every key, in the same order); one that [copyWith] changed has only its edited members changed, and the
/// other keys of its entry stay. A field made here is written as `{ name, value, kind, adminField? }` and [extra].
class CustomField {
  /// A field made here. A name is what it needs to be written; a field with none is left out.
  const CustomField({required this.name, required this.value, required this.kind, this.adminField, Map<String, Object?>? extra})
    : extra = extra ?? const {},
      _source = null,
      _hasSource = false,
      _editable = kind == CustomFieldKind.text || kind == CustomFieldKind.hidden || kind == CustomFieldKind.boolean;

  const CustomField._(this.name, this.value, this.kind, this.adminField, this.extra, this._source, this._hasSource, this._editable);

  /// An entry of `fields`; never throws.
  factory CustomField.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      return CustomField._('', '', '', null, const {}, json, true, false);
    }
    final kind = CustomFieldKind.read(json['kind'] ?? json['type']);
    final name = asString(json['name']);
    final raw = json['value'];
    final value = kind == CustomFieldKind.boolean
        ? (raw == true || raw == 'true' ? 'true' : 'false')
        : switch (raw) {
            final String text => text,
            final num number => '$number',
            _ => '',
          };
    final admin = json['adminField'];
    final editable = CustomFieldKind.isEditable(kind) && name.trim().isNotEmpty;
    return CustomField._(
      name,
      value,
      kind,
      admin is String && admin.isNotEmpty ? admin : null,
      extraKeys(json, const {'name', 'value', 'kind', 'type', 'adminField'}),
      json,
      true,
      editable,
    );
  }

  /// The field's name, as the entry holds it.
  final String name;

  /// What it holds. A checkbox holds `"true"` or `"false"`.
  final String value;

  /// One of [CustomFieldKind], or a word this version doesn't know.
  final String kind;

  /// The id of the admin's definition the field was made from (`GET /kem/v1/custom-fields`); null for the person's own.
  /// A field with one has the admin's name and kind, and the person fills in the value.
  final String? adminField;

  /// Keys of the entry beyond the four above, as they were.
  final Map<String, Object?> extra;

  /// The entry as it was read, whatever it was.
  final Object? _source;
  final bool _hasSource;

  /// Whether this version can edit the entry: a text, hidden or checkbox field with a name.
  final bool _editable;

  /// Whether a person can edit the field. A linked field, one of a kind this version doesn't know, one with no name and
  /// an entry that isn't an object are kept and not edited.
  bool get isEditable => _editable;

  /// Whether the field is an admin's.
  bool get isAdmin => adminField != null;

  /// Whether the checkbox is ticked.
  bool get isChecked => value == 'true';

  /// The field with the given members changed. Pass [unset] as [adminField] to remove it. An entry that can't be
  /// edited is returned as it is.
  CustomField copyWith({String? name, String? value, String? kind, Object? adminField = keep}) {
    if (!_editable) {
      return this;
    }
    return CustomField._(
      name ?? this.name,
      value ?? this.value,
      kind ?? this.kind,
      pick(adminField, this.adminField),
      extra,
      _source,
      _hasSource,
      true,
    );
  }

  /// Whether the field is left out when written: an editable one whose name is blank, as an unnamed field is left out.
  bool get isBlank => _editable && name.trim().isEmpty;

  /// The entry: the one that was read when nothing was edited, that one with the edited members changed, or a new one.
  Object? toJson() {
    if (!_hasSource) {
      return _fresh();
    }
    final source = _source;
    if (!_editable || source is! Map<String, Object?>) {
      return source;
    }
    final read = CustomField.fromJson(source);
    final same = read.name == name && read.value == value && read.kind == kind && read.adminField == adminField;
    return same ? source : _edited(source, read);
  }

  Map<String, Object?> _fresh() => {
    'name': name.trim(),
    'value': kind == CustomFieldKind.boolean ? (isChecked ? 'true' : 'false') : value,
    'kind': kind,
    'adminField': ?adminField,
    ...extra,
  };

  /// [original] with only what was edited changed: its other keys, and their order, stay.
  Map<String, Object?> _edited(Map<String, Object?> original, CustomField read) {
    final out = {...original, 'name': name.trim()};
    if (kind == CustomFieldKind.boolean) {
      out['value'] = original['value'] is bool ? isChecked : (isChecked ? 'true' : 'false');
    } else {
      out['value'] = value;
    }
    if (kind != read.kind) {
      // A new kind is written the way the importer writes it, in the key the entry already used.
      final used = original.containsKey('type') && !original.containsKey('kind') ? 'type' : 'kind';
      out[used] = kind;
    }
    if (adminField != null && original['adminField'] != adminField) {
      out['adminField'] = adminField;
    } else if (adminField == null && original.containsKey('adminField')) {
      out.remove('adminField');
    }
    return out;
  }

  @override
  bool operator ==(Object other) => other is CustomField && jsonEquals(toJson(), other.toJson());

  @override
  int get hashCode => Object.hash(name, kind);

  /// Never the value, which can be a secret.
  @override
  String toString() => 'CustomField($name, $kind)';
}

/// The entries of a body's `fields`, in order, none for a member that isn't a list.
List<CustomField> readFields(Object? json) => json is List ? [for (final entry in json) CustomField.fromJson(entry)] : const [];

/// The `fields` member for [fields], or null when there are none (an empty member is left out). A new or edited field
/// with no name is left out.
List<Object?>? writeFields(List<CustomField> fields) {
  final out = [
    for (final field in fields)
      if (!field.isBlank) field.toJson(),
  ];
  return out.isEmpty ? null : out;
}
