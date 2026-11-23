@TestOn('vm')
library;

import 'dart:convert';

import 'package:kemlock_core/models/json.dart';
import 'package:kemlock_core/models/payment_card.dart';
import 'package:test/test.dart';

void main() {
  const card = PaymentCard(
    id: 'c1',
    name: 'Everyday Visa',
    cardholder: 'Ada Lovelace',
    number: '4111111111111111',
    expMonth: 5,
    expYear: 2029,
    code: '123',
    addedAt: 1,
  );

  test('writes the fields that are set, in order, and reads them back', () {
    expect(
      jsonEncode(card.toJson()),
      '{"id":"c1","name":"Everyday Visa","cardholder":"Ada Lovelace","number":"4111111111111111","expMonth":5,"expYear":2029,"code":"123","addedAt":1}',
    );
    final full = card.copyWith(
      brand: 'visa',
      pin: '4321',
      validFromMonth: 6,
      validFromYear: 2024,
      note: 'n',
      tags: ['bank'],
      pinned: true,
      spaceId: 'fam',
      source: 'import',
      updatedAt: 6,
    );
    expect(PaymentCard.fromJson(jsonDecode(jsonEncode(full.toJson())) as Map<String, Object?>), full);
  });

  test('keeps keys it does not know and writes them back', () {
    final json = {
      ...card.toJson(),
      'issuer': 'Example Bank',
      'limits': {'daily': 500},
    };
    final read = PaymentCard.fromJson(json);
    expect(read.extra.keys, ['issuer', 'limits']);
    expect(read.copyWith(name: 'Visa').toJson()['limits'], {'daily': 500});
    expect(read.toJson(), json);
  });

  test('copyWith removes an optional field with unset and keeps it otherwise', () {
    expect(card.copyWith(code: unset).toJson().keys, isNot(contains('code')));
    expect(card.copyWith(name: 'Visa').code, '123');
  });

  test('keeps only the digits of a pasted number', () {
    expect(cardDigits('4111-1111 1111-1111'), '4111111111111111');
    expect(isCardNumberText('4111-1111 1111-1111'), isTrue);
    expect(isCardNumberText('4111 abcd'), isFalse);
  });

  test('reads a two-digit year as 20xx and an expiry typed several ways', () {
    expect(cardYear(29), 2029);
    expect(cardYear(2029), 2029);
    expect(cardYear(202), isNull);
    expect(parseCardExpiry('05/29'), (month: 5, year: 2029));
    expect(parseCardExpiry('5/2029'), (month: 5, year: 2029));
    expect(parseCardExpiry('05-29'), (month: 5, year: 2029));
    expect(parseCardExpiry('0529'), (month: 5, year: 2029));
    expect(parseCardExpiry('13/29'), (month: null, year: 2029));
    expect(parseCardExpiry('ab/cd'), (month: null, year: null));
  });

  test('is expired from the day after the last day of the expiry month', () {
    expect(card.isExpired(DateTime(2029, 5, 31, 23, 59)), isFalse);
    expect(card.isExpired(DateTime(2029, 6, 1)), isTrue);
    expect(card.isExpired(DateTime(2028, 12, 31)), isFalse);
    expect(card.copyWith(expMonth: unset).isExpired(DateTime(2029, 12, 31)), isFalse);
    expect(card.copyWith(expMonth: unset).isExpired(DateTime(2030, 1, 1)), isTrue);
    expect(card.copyWith(expYear: unset).isExpired(DateTime(2099)), isFalse);
  });

  test('needs a name and a number or a cardholder', () {
    expect(const PaymentCard(id: 'c', name: 'Only a name', addedAt: 1).isComplete, isFalse);
    expect(const PaymentCard(id: 'c', name: 'N', number: '4111111111111111', addedAt: 1).isComplete, isTrue);
    expect(const PaymentCard(id: 'c', name: 'N', cardholder: 'Ada', addedAt: 1).isComplete, isTrue);
    expect(const PaymentCard(id: 'c', name: ' ', number: '4111111111111111', addedAt: 1).isComplete, isFalse);
  });

  test('gives the last four digits and never the number in toString', () {
    expect(card.lastFour, '1111');
    expect(const PaymentCard(id: 'c', name: 'N', addedAt: 1).lastFour, isNull);
    expect(card.toString(), isNot(contains('4111')));
  });

  test('stamps, moves into a space and compares by JSON', () {
    expect(card.stamped(9).changedAt, 9);
    expect(card.changedAt, 1);
    expect(card.inSpace('fam').spaceId, 'fam');
    expect(card.inSpace('fam').inSpace(null).spaceId, isNull);
    expect(card.copyWith(), card);
    expect(card.copyWith(name: 'x'), isNot(card));
  });
}
