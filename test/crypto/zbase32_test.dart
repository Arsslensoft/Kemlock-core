@TestOn('vm')
library;

import 'dart:convert';

import 'package:crypto/crypto.dart' as hash;
import 'package:kemlock_core/crypto/zbase32.dart';
import 'package:test/test.dart';

void main() {
  test('writes the hash of the Web Key Directory draft’s example', () {
    // draft-koch-openpgp-webkey-service, section 3.1: Joe.Doe@Example.ORG, its local part in lower case
    expect(zBase32(hash.sha1.convert(utf8.encode('joe.doe')).bytes), 'iy9q119eutrkn8s1mk4r39qejnbu3n5q');
  });

  test('writes five bits to a character, the most significant first, and pads the last with zeros', () {
    expect(zBase32([]), '');
    expect(zBase32([0x00]), 'yy');
    expect(zBase32([0xff]), '9h');
    expect(zBase32([0xff, 0xff, 0xff, 0xff, 0xff]), '99999999');
    expect(zBase32(List.filled(20, 0)), 'y' * 32);
  });

  test('has 32 different characters', () {
    expect(zBase32Alphabet.split('').toSet(), hasLength(32));
  });
}
