@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/identity.dart';
import 'package:test/test.dart';

void main() {
  const identity = Identity(id: 'i1', name: 'Me', givenName: 'Ada', familyName: 'Lovelace', email: 'ada@example.org', addedAt: 1);

  test('writes the fields that are set, in order, and reads them back', () {
    expect(
      jsonEncode(identity.toJson()),
      '{"id":"i1","name":"Me","givenName":"Ada","familyName":"Lovelace","email":"ada@example.org","addedAt":1}',
    );
    final full = identity.copyWith(
      title: 'Countess',
      middleName: 'Augusta',
      company: 'Analytical Engines',
      phone: '+44 20 7946 0000',
      username: 'ada',
      birthDate: '1815-12-10',
      address: const IdentityAddress(lines: ['1 Example Road'], city: 'London', region: 'England', postalCode: 'N1 1AA', country: 'GB'),
      documents: const [
        IdentityDocument(
          id: 'd1',
          type: 'passport',
          number: '123456789',
          issuingCountry: 'GB',
          issuingAuthority: 'HMPO',
          issuedOn: '2021-03-15',
          expiresOn: '2031-03-14',
        ),
        IdentityDocument(id: 'd2', type: 'taxNumber', number: 'QQ123456C'),
      ],
      note: 'n',
      tags: ['personal'],
      pinned: true,
      spaceId: 'fam',
      source: 'import',
      updatedAt: 6,
    );
    expect(Identity.fromJson(jsonDecode(jsonEncode(full.toJson())) as Map<String, Object?>), full);
  });

  test('keeps keys it does not know in the identity, its address and each document', () {
    final json = {
      ...identity.toJson(),
      'maiden': 'Byron',
      'address': {'city': 'London', 'what3words': 'a.b.c'},
      'documents': [
        {'id': 'd1', 'type': 'passport', 'number': '1', 'mrz': 'P<GBR'},
      ],
    };
    final read = Identity.fromJson(json);
    expect(read.extra, {'maiden': 'Byron'});
    expect(read.address!.extra, {'what3words': 'a.b.c'});
    expect(read.documents!.single.extra, {'mrz': 'P<GBR'});
    expect(read.copyWith(name: 'Ada').toJson()['documents'], json['documents']);
    expect(read.toJson(), json);
  });

  test('a document type from a later version reads as other and is written back as read', () {
    final json = {
      ...identity.toJson(),
      'documents': [
        {'id': 'd1', 'type': 'residencePermit', 'number': '77'},
      ],
    };
    final read = Identity.fromJson(json);
    expect(read.documents!.single.kind, IdentityDocumentType.other);
    expect(read.documents!.single.type, 'residencePermit');
    expect(Identity.fromJson(jsonDecode(jsonEncode(read.toJson())) as Map<String, Object?>).toJson(), json);
  });

  test('knows every document type', () {
    for (final type in IdentityDocumentType.values) {
      expect(IdentityDocumentType.fromWire(type.wire), type);
    }
    expect(IdentityDocumentType.fromWire(null), IdentityDocumentType.other);
  });

  test('leaves out an empty address and empty documents', () {
    final json = identity.copyWith(address: const IdentityAddress(), documents: <IdentityDocument>[]).toJson();
    expect(json.keys, isNot(contains('address')));
    expect(json.keys, isNot(contains('documents')));
  });

  test('marks a document expired from the day after its expiry date', () {
    const document = IdentityDocument(id: 'd', type: 'idCard', number: '1', expiresOn: '2026-11-20');
    expect(document.isExpired(DateTime(2026, 11, 20, 23, 59)), isFalse);
    expect(document.isExpired(DateTime(2026, 11, 21)), isTrue);
    expect(const IdentityDocument(id: 'd', number: '1').isExpired(DateTime(2099)), isFalse);
    expect(const IdentityDocument(id: 'd', number: '1', expiresOn: 'soon').isExpired(DateTime(2099)), isFalse);
  });

  test('needs a name and at least one detail', () {
    expect(const Identity(id: 'i', name: 'Me', addedAt: 1).isComplete, isFalse);
    expect(identity.isComplete, isTrue);
    expect(
      const Identity(
        id: 'i',
        name: 'Me',
        address: IdentityAddress(city: 'Paris'),
        addedAt: 1,
      ).isComplete,
      isTrue,
    );
    expect(
      const Identity(
        id: 'i',
        name: 'Me',
        documents: [IdentityDocument(id: 'd', number: '1')],
        addedAt: 1,
      ).isComplete,
      isTrue,
    );
    expect(const Identity(id: 'i', name: ' ', email: 'a@b.c', addedAt: 1).isComplete, isFalse);
  });

  test('joins the name parts that are set', () {
    expect(identity.fullName, 'Ada Lovelace');
    expect(identity.copyWith(middleName: 'Augusta').fullName, 'Ada Augusta Lovelace');
    expect(const Identity(id: 'i', name: 'Me', addedAt: 1).fullName, isNull);
  });

  test('stamps, moves into a space and compares by JSON', () {
    expect(identity.stamped(9).changedAt, 9);
    expect(identity.inSpace('fam').spaceId, 'fam');
    expect(identity.inSpace('fam').inSpace('').spaceId, isNull);
    expect(identity.copyWith(), identity);
    expect(identity.toString(), isNot(contains('ada@')));
  });
}
