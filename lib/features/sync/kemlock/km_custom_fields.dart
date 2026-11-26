/// The custom fields an admin offers (`docs/custom-fields.md`): `GET /kem/v1/custom-fields`, which every signed-in
/// device may read. Names and types are not secret, so the server holds them in the clear; a person's values live in
/// the sealed item bodies (`fields`, see `models/custom_field.dart`).
///
/// ```json
/// { "fields": [{ "id": "7d0f…", "name": "Employee ID", "type": "text", "kinds": "all" },
///               { "id": "1b9e…", "name": "Cost center", "type": "hidden", "kinds": ["login", "card"] }],
///   "allowOwn": true }
/// ```
///
/// `type` is `text`, `hidden` or `checkbox` (a field's `kind` in a body: `text`, `hidden`, `boolean`), and `kinds` the word
/// `all` or a list of item kinds. A definition with a type or kinds this version doesn't know is left out, and an
/// unknown kind in a list is ignored. A file and a passkey take no custom fields, whatever a definition says.
/// `allowOwn` is advisory: the server can't see an item's fields, so an app that reads it off hides "your own field".
///
/// Pure Dart, no Flutter. The request goes through [KmApi], so it uses whatever HTTP client that was given.
library;

import '../../../models/custom_field.dart';
import '../../../models/json.dart';
import 'km_api.dart';
import 'km_kinds.dart';

/// The kinds that take no custom fields, whatever a definition says.
const _noFields = {'file', 'passkey'};

/// The item kinds a definition may name (`custom-fields.md`).
const kmFieldItemKinds = {
  KmKind.login,
  KmKind.note,
  KmKind.otp,
  KmKind.backupCodes,
  KmKind.card,
  KmKind.identity,
  KmKind.contact,
  KmKind.certificate,
  KmKind.sshKey,
  KmKind.pgpKey,
};

/// One field an admin offers.
class KmFieldDefinition {
  const KmFieldDefinition({required this.id, required this.name, required this.kind, this.kinds});

  /// Reads one entry of `fields`; null for one this version can't use: no id or name, a type it doesn't know, or a
  /// `kinds` that is neither `all` nor a list.
  static KmFieldDefinition? tryParse(Object? json) {
    if (json is! Map<String, Object?>) {
      return null;
    }
    final id = json['id'];
    final name = json['name'];
    final kind = switch (json['type']) {
      'text' => CustomFieldKind.text,
      'hidden' => CustomFieldKind.hidden,
      'checkbox' => CustomFieldKind.boolean,
      _ => null,
    };
    final kinds = switch (json['kinds']) {
      'all' => const <String>[],
      final List<Object?> list => [
        for (final item in list)
          if (item is String && kmFieldItemKinds.contains(item)) item,
      ],
      _ => null,
    };
    if (id is! String || id.isEmpty || name is! String || name.trim().isEmpty || kind == null || kinds == null) {
      return null;
    }
    return KmFieldDefinition(id: id, name: name.trim(), kind: kind, kinds: json['kinds'] == 'all' ? null : kinds);
  }

  /// A UUID, stable across renames: what a field's `adminField` holds.
  final String id;

  /// 1 to 64 characters.
  final String name;

  /// The field's `kind` in a body, one of [CustomFieldKind]: `text`, `hidden` or `boolean` (the server's `checkbox`).
  final String kind;

  /// The item kinds the field is offered on; null for every kind that takes custom fields.
  final List<String>? kinds;

  /// Whether the field is offered on items of [itemKind] (a `KmKind`, such as `login`). Never on a file or a passkey.
  bool appliesTo(String itemKind) => !_noFields.contains(itemKind) && (kinds == null || kinds!.contains(itemKind));

  /// A new field of the person's item made from this definition, empty (a checkbox unticked).
  CustomField toField() => CustomField(name: name, value: kind == CustomFieldKind.boolean ? 'false' : '', kind: kind, adminField: id);

  @override
  bool operator ==(Object other) =>
      other is KmFieldDefinition && other.id == id && other.name == name && other.kind == kind && jsonEquals(other.kinds, kinds);

  @override
  int get hashCode => Object.hash(id, name, kind);

  @override
  String toString() => 'KmFieldDefinition($id, $name, $kind)';
}

/// What `GET /custom-fields` answers.
class KmCustomFields {
  const KmCustomFields({this.fields = const [], this.allowOwn = true});

  /// What a server with no custom fields, or one that is older, means: none, and people may add their own.
  static const none = KmCustomFields();

  /// Reads the answer. What isn't an object is [none], an entry that can't be read is left out, and `allowOwn` that isn't a
  /// boolean is true. Never throws.
  factory KmCustomFields.fromJson(Object? json) {
    if (json is! Map<String, Object?>) {
      return none;
    }
    final list = json['fields'];
    return KmCustomFields(
      fields: [
        if (list is List<Object?>)
          for (final entry in list) ?KmFieldDefinition.tryParse(entry),
      ],
      allowOwn: asBool(json['allowOwn']) ?? true,
    );
  }

  /// The admin's fields, oldest first.
  final List<KmFieldDefinition> fields;

  /// Whether people may add fields of their own to an item. Fields already on items stay either way.
  final bool allowOwn;

  /// The fields offered on items of [itemKind] (a `KmKind` such as `login`), in order.
  List<KmFieldDefinition> definitionsFor(String itemKind) => [
    for (final field in fields)
      if (field.appliesTo(itemKind)) field,
  ];

  /// The definition with [id], when it still exists.
  KmFieldDefinition? definition(String id) {
    for (final field in fields) {
      if (field.id == id) {
        return field;
      }
    }
    return null;
  }
}

/// The custom-fields route, over a [KmApi].
class KmCustomFieldsApi {
  KmCustomFieldsApi(this.api);

  final KmApi api;

  /// The admin's definitions on [server], read with the access [token]. A server without the route (a 404) offers none.
  Future<KmCustomFields> list(Uri server, String token) async {
    final json = await api.call('GET', server, '/custom-fields', token: token, absentIsNull: true);
    return KmCustomFields.fromJson(json);
  }
}

/// The definitions on [connection]'s server, with a live access token.
Future<KmCustomFields> fetchKmCustomFields(KmConnection connection) =>
    connection.call((token) => KmCustomFieldsApi(connection.api).list(connection.server, token));
