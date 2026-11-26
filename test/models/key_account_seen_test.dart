@TestOn('vm')
library;

import 'package:kemlock_core/models/custom_field.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:test/test.dart';

void main() {
  group('KeyAccountSeen', () {
    test('brings no custom fields unless it is given some', () {
      const seen = KeyAccountSeen(name: 'GitHub:me', type: KeyAccountType.totp);

      expect(seen.fields, isEmpty);
    });

    test('carries the custom fields of an account moved from the vault, in order, for the account that is made from it', () {
      const moved = [
        CustomField(name: 'Employee ID', value: 'E-1', kind: CustomFieldKind.text),
        CustomField(name: 'Active', value: 'true', kind: CustomFieldKind.boolean),
      ];
      const seen = KeyAccountSeen(name: 'GitHub:me', type: KeyAccountType.totp, tags: ['work'], fields: moved);

      final account = KeyAccount(id: 'y1', device: 'd', name: seen.name, label: 'me', addedAt: 1, fields: seen.fields);

      expect(seen.fields.map((field) => field.name), ['Employee ID', 'Active']);
      expect(account.toJson()['fields'], [
        {'name': 'Employee ID', 'value': 'E-1', 'kind': 'text'},
        {'name': 'Active', 'value': 'true', 'kind': 'boolean'},
      ]);
    });
  });
}
