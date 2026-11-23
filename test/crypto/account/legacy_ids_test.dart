@Tags(['wasm'])
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/legacy_ids.dart';
import 'package:test/test.dart';

/// `uuidv8(h)` of RFC 9562 section 5.8 as crypto.md has it, written out here
/// on the hash of an input put together by hand.
String _uuidv8(List<int> input) {
  final h = hash.sha256.convert(input).bytes.sublist(0, 16);
  h[6] = h[6] & 0x0f | 0x80;
  h[8] = h[8] & 0x3f | 0x80;
  final hex = [for (final b in h) b.toRadixString(16).padLeft(2, '0')].join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

List<int> _lp(String text) => [...u32be(utf8.encode(text).length), ...utf8.encode(text)];

void main() {
  final alice = Owner.user('11111111-2222-7333-8444-555555555555');
  final bob = Owner.user('99999999-2222-7333-8444-555555555555');

  test('an item id is the UUIDv8 of the label, "item", the owner and the old id', () {
    for (final id in ['acc-1', '3f2c9a71e4b0d856']) {
      final input = [...utf8.encode('kemlock/v1/legacy-id'), ..._lp('item'), ...alice.bytes, ..._lp(id)];
      expect(itemUuid(id, alice), _uuidv8(input), reason: id);
    }
  });

  test('a space id is the UUIDv8 of the label, "space" and the old id', () {
    final input = [...utf8.encode('kemlock/v1/legacy-id'), ..._lp('space'), ..._lp('family_2024')];
    expect(spaceUuid('family_2024'), _uuidv8(input));
  });

  test('sets the version 8 and the RFC variant', () {
    for (final id in ['acc-1', 'acc-2', '3f2c9a71e4b0d856']) {
      final uuid = itemUuid(id, alice);
      expect(uuid[14], '8', reason: id);
      expect('89ab'.contains(uuid[19]), isTrue, reason: id);
      expect(isUuidText(uuid), isTrue);
    }
  });

  test('is stable: the same id under the same owner always gives the same UUID', () {
    expect(itemUuid('acc-1', alice), itemUuid('acc-1', alice));
    expect(spaceUuid('family'), spaceUuid('family'));
  });

  test("acc-1 in two people's vaults maps to two different UUIDs", () {
    expect(itemUuid('acc-1', alice), isNot(itemUuid('acc-1', bob)));
    expect(itemUuid('acc-1', alice), isNot(itemUuid('acc-2', alice)));
  });

  test("a space's item uses the owner of the space's mapped UUID, and differs from a user's", () {
    final space = Owner.space(spaceUuid('family'));
    expect(itemUuid('acc-1', space), isNot(itemUuid('acc-1', alice)));
    expect(
      itemUuid('acc-1', space),
      _uuidv8([...utf8.encode('kemlock/v1/legacy-id'), ..._lp('item'), 2, ...uuidBytes(spaceUuid('family')), ..._lp('acc-1')]),
    );
  });

  test('an id that already is a UUID is never mapped', () {
    const uuid = '0189f7c2-5a3e-7b21-8d4f-0123456789ab';
    expect(itemUuid(uuid, alice), uuid);
    expect(spaceUuid(uuid), uuid);
  });

  test('an upper-case UUID is not a UUID here, so it is mapped as text', () {
    const upper = '0189F7C2-5A3E-7B21-8D4F-0123456789AB';
    expect(itemUuid(upper, alice), isNot(upper));
  });

  test('refuses a space id outside 1 to 64 characters of [A-Za-z0-9_-], and an empty item id', () {
    for (final id in ['', 'a b', 'family!', 'x' * 65, 'fämily']) {
      expect(() => spaceUuid(id), throwsA(isA<MalformedException>()), reason: id);
    }
    expect(spaceUuid('x' * 64), isNotEmpty);
    expect(() => itemUuid('', alice), throwsA(isA<MalformedException>()));
  });
}
