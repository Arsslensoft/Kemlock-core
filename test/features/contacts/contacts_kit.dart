import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/crypto/keys/openpgp/armor.dart';
import 'package:kemlock_core/crypto/keys/openpgp/key_info.dart';
import 'package:kemlock_core/crypto/keys/pem.dart';
import 'package:kemlock_core/models/contact.dart';

// The public keys the contact tests use, all made by GnuPG and never regenerated: test/fixtures/keys/contacts
// (its README has the commands), and the expired and revoked keys of test/fixtures/keys/gnupg/expiry.

/// The fixed clock of the contact tests: Tuesday 17 November 2026, 10:00 UTC, the day the fixtures were made.
final contactsNow = DateTime.utc(2026, 11, 17, 10);

/// A key fixture's text, under `test/fixtures/keys`.
String keyText(String path) => File('test/fixtures/keys/$path').readAsStringSync();

/// The binary key of an armored fixture under `test/fixtures/keys`.
Uint8List keyBytes(String path) => readArmor(readPemBlocks(keyText(path)).single);

/// Grace Hopper's key as first made (expires 2027-11-17), a few seconds later (expires 2030-01-01, with a
/// signing subkey), and revoked.
const grace1 = 'contacts/grace-1.public.asc';
const grace2 = 'contacts/grace-2.public.asc';
const grace3 = 'contacts/grace-3.public.asc';
const graceFingerprint = '894F6AAC8FCE0FAF7EE21BB6B405E72AFBA23495';

/// Alan Turing's key, which never expires.
const alan = 'contacts/alan.public.asc';
const alanFingerprint = 'C677F2C26A5E4C4E78CD6003A8CFF189E65E4BDC';

/// A key that can only sign, an RSA 3072 key, and the keyring of [alan] and [signOnly].
const signOnly = 'contacts/sign-only.public.asc';
const rsa3072 = 'contacts/rsa3072-certified-photo.trimmed.public.asc';
const twoKeys = 'contacts/two-keys.public.asc';

/// Keys that expired on 2020-12-31 and that revoked themselves.
const expired = 'gnupg/expiry/expired.public.asc';
const revoked = 'gnupg/expiry/revoked.public.asc';

/// The version 6 key of RFC 9580, which has no user ID.
const v6 = 'rfc9580/v6-public.asc';

/// The upper-case hexadecimal fingerprint of the key in [path].
String fingerprintOf(String path) => readTransferableKey(keyBytes(path)).info.primary.fingerprintHex;

/// A contact holding the key of the fixture [path], checked at [checkedAt] when given.
Contact contactOf(
  String path, {
  String id = 'c1',
  String name = 'Grace Hopper',
  String source = ContactSource.qr,
  int? checkedAt,
  String? note,
  int addedAt = 1,
  int? updatedAt,
}) => Contact(
  id: id,
  name: name,
  publicKey: b64(keyBytes(path)),
  source: source,
  checkedAt: checkedAt,
  checkedFingerprint: checkedAt == null ? null : fingerprintOf(path),
  note: note,
  addedAt: addedAt,
  updatedAt: updatedAt,
);

/// Another key that says it is Grace Hopper's, for the same address: the key someone else might hand over.
const graceOther = 'contacts/grace-other.public.asc';
const graceOtherFingerprint = '877C60B601AFE3B57806CC99A828765639DB3D98';

/// A key file under `test/fixtures/keys`.
File keyFixtureFile(String path) => File('test/fixtures/keys/$path');
