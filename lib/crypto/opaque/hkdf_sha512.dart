// HKDF with SHA-512 (RFC 5869) and HMAC-SHA-512, the KDF and MAC of the OPAQUE
// configuration crypto.md fixes ("opaque1": KDF HKDF-SHA512, MAC HMAC-SHA512).
// `../hkdf.dart` is the SHA-256 one the account keys use.

library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

/// The output length of SHA-512, Nh.
const sha512Length = 64;

/// HMAC-SHA-512 of [data] under [key], 64 bytes.
Uint8List hmacSha512(List<int> key, List<int> data) => Uint8List.fromList(hash.Hmac(hash.sha512, key).convert(data).bytes);

/// SHA-512 of [data], 64 bytes.
Uint8List sha512Digest(List<int> data) => Uint8List.fromList(hash.sha512.convert(data).bytes);

/// HKDF-Extract (RFC 5869 section 2.2): the 64-byte pseudorandom key of
/// [ikm] and [salt]. An empty salt is a string of 64 zero bytes, which as an
/// HMAC key is the same as an empty one, so `Extract("", ikm)` of RFC 9807 is
/// `hkdfExtractSha512(const [], ikm)`.
Uint8List hkdfExtractSha512(List<int> salt, List<int> ikm) => hmacSha512(salt, ikm);

/// HKDF-Expand (RFC 5869 section 2.3): [length] bytes from the pseudorandom
/// key [prk], bound to [info].
Uint8List hkdfExpandSha512(List<int> prk, List<int> info, int length) {
  if (length < 0 || length > 255 * sha512Length) throw ArgumentError.value(length, 'length', 'out of range for HKDF-SHA512');
  final mac = hash.Hmac(hash.sha512, prk);
  final out = BytesBuilder(copy: false);
  var previous = <int>[];
  for (var i = 1; out.length < length; i++) {
    previous = mac.convert([...previous, ...info, i]).bytes;
    out.add(previous);
  }
  return Uint8List.sublistView(out.takeBytes(), 0, length);
}
