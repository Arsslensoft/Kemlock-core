@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/custom_field.dart';
import 'package:kemlock_core/models/json.dart';
import 'package:test/test.dart';

void main() {
  group('reading', () {
    test('reads a text, hidden, checkbox and linked field', () {
      final fields = readFields([
        {'name': 'Employee ID', 'value': 'E-1', 'kind': 'text'},
        {'name': 'PIN', 'value': '1234', 'kind': 'hidden'},
        {'name': 'Active', 'value': 'true', 'kind': 'boolean'},
        {'name': 'Ref', 'value': 'x', 'kind': 'linked'},
      ]);
      expect(fields.map((field) => field.kind), ['text', 'hidden', 'boolean', 'linked']);
      expect(fields.map((field) => field.isEditable), [true, true, true, false]);
      expect(fields[2].isChecked, isTrue);
    });

    test('reads the words and numbers the importers write for the same kinds', () {
      expect(CustomFieldKind.read('password'), CustomFieldKind.hidden);
      expect(CustomFieldKind.read('checkbox'), CustomFieldKind.boolean);
      expect(CustomFieldKind.read(0), CustomFieldKind.text);
      expect(CustomFieldKind.read(1), CustomFieldKind.hidden);
      expect(CustomFieldKind.read(2), CustomFieldKind.boolean);
      expect(CustomFieldKind.read(3), CustomFieldKind.linked);
      expect(CustomFieldKind.read(null), CustomFieldKind.text);
      expect(CustomFieldKind.read('future'), 'future');
      expect(CustomFieldKind.isEditable('future'), isFalse);
    });

    test('a checkbox holds true or false, whatever the entry wrote', () {
      expect(CustomField.fromJson({'name': 'a', 'value': true, 'kind': 'boolean'}).value, 'true');
      expect(CustomField.fromJson({'name': 'a', 'value': 'nope', 'kind': 'boolean'}).value, 'false');
      expect(CustomField.fromJson({'name': 'a', 'kind': 'boolean'}).value, 'false');
    });

    test('knows the admin field an entry was made from', () {
      final field = CustomField.fromJson({'name': 'Cost center', 'value': '', 'kind': 'text', 'adminField': 'f1'});
      expect(field.adminField, 'f1');
      expect(field.isAdmin, isTrue);
      expect(CustomField.fromJson({'name': 'a', 'value': '', 'kind': 'text', 'adminField': ''}).adminField, isNull);
    });
  });

  group('writing back what was not edited', () {
    final json = <Object?>[
      {'value': 'E-1', 'name': 'Employee ID', 'kind': 'text', 'adminField': 'f1', 'extra': 1},
      {'name': 'Pin', 'value': '1', 'type': 'password'},
      {'name': 'Active', 'value': true, 'kind': 'boolean'},
      {'name': 'Ref', 'value': 'x', 'kind': 'linked'},
      {'value': 'no name', 'kind': 'text'},
      {'name': '  ', 'value': 'blank', 'kind': 'text'},
      {'name': 'New', 'value': 'v', 'kind': 'from-the-future'},
      'not a map',
      null,
    ];

    test('every entry, every key, in the same order', () {
      final fields = readFields(json);
      expect(jsonEncode(writeFields(fields)), jsonEncode(json));
    });

    test('an entry that cannot be edited keeps its place and is not changed by copyWith', () {
      final fields = readFields(json);
      for (final index in [3, 4, 5, 6, 7, 8]) {
        expect(fields[index].isEditable, isFalse, reason: 'entry $index');
        expect(identical(fields[index].copyWith(name: 'x', value: 'y'), fields[index]), isTrue);
      }
    });
  });

  group('editing', () {
    test('changes only the edited members and keeps the other keys and their order', () {
      final field = CustomField.fromJson({'value': 'E-1', 'name': 'Employee ID', 'kind': 'text', 'adminField': 'f1', 'extra': 1});
      final edited = field.copyWith(value: 'E-2');
      expect(
        jsonEncode(edited.toJson()),
        jsonEncode({'value': 'E-2', 'name': 'Employee ID', 'kind': 'text', 'adminField': 'f1', 'extra': 1}),
      );
      expect(edited.value, 'E-2');
      expect(field.value, 'E-1');
    });

    test('a checkbox written as a boolean stays one, and one written as text stays text', () {
      expect(CustomField.fromJson({'name': 'a', 'value': true, 'kind': 'boolean'}).copyWith(value: 'false').toJson(), {
        'name': 'a',
        'value': false,
        'kind': 'boolean',
      });
      expect(CustomField.fromJson({'name': 'a', 'value': 'true', 'kind': 'boolean'}).copyWith(value: 'false').toJson(), {
        'name': 'a',
        'value': 'false',
        'kind': 'boolean',
      });
    });

    test('a new kind is written in the key the entry used', () {
      expect(CustomField.fromJson({'name': 'a', 'value': 'v', 'type': 'text'}).copyWith(kind: CustomFieldKind.hidden).toJson(), {
        'name': 'a',
        'value': 'v',
        'type': 'hidden',
      });
      expect(CustomField.fromJson({'name': 'a', 'value': 'v', 'kind': 'text'}).copyWith(kind: CustomFieldKind.hidden).toJson(), {
        'name': 'a',
        'value': 'v',
        'kind': 'hidden',
      });
    });

    test('the admin field can be taken off', () {
      final field = CustomField.fromJson({'name': 'a', 'value': 'v', 'kind': 'text', 'adminField': 'f1'});
      expect(field.copyWith(adminField: unset).toJson(), {'name': 'a', 'value': 'v', 'kind': 'text'});
    });

    test('a field made here is written as name, value, kind and adminField', () {
      const field = CustomField(name: ' Cost center ', value: 'A1', kind: CustomFieldKind.text, adminField: 'f2');
      expect(jsonEncode(field.toJson()), '{"name":"Cost center","value":"A1","kind":"text","adminField":"f2"}');
      expect(const CustomField(name: 'On', value: 'true', kind: CustomFieldKind.boolean).toJson(), {
        'name': 'On',
        'value': 'true',
        'kind': 'boolean',
      });
    });

    test('a field with no name is left out, and so is an empty list', () {
      final fields = [
        const CustomField(name: 'Kept', value: '1', kind: CustomFieldKind.text),
        const CustomField(name: '  ', value: 'x', kind: CustomFieldKind.text),
        CustomField.fromJson({'name': 'A', 'value': 'v', 'kind': 'text'}).copyWith(name: ''),
      ];
      expect(writeFields(fields), [
        {'name': 'Kept', 'value': '1', 'kind': 'text'},
      ]);
      expect(writeFields(const []), isNull);
      expect(writeFields([fields[1]]), isNull);
    });
  });
}
