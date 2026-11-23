/// HKDF with SHA-256 (RFC 5869): a key from keying material that is not
/// one yet, such as a shared secret or two keys put together.
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

/// HKDF-Extract (RFC 5869, section 2.2): the pseudorandom key, 32 bytes,
/// of the input keying material [ikm] and [salt]. An empty salt stands for
/// 32 zero bytes, as the RFC has it.
Uint8List hkdfExtractSha256(List<int> salt, List<int> ikm) =>
    Uint8List.fromList(hash.Hmac(hash.sha256, salt.isEmpty ? Uint8List(32) : salt).convert(ikm).bytes);

/// HKDF-Expand (RFC 5869, section 2.3): [length] bytes from the
/// pseudorandom key [prk], bound to [info].
Uint8List hkdfExpandSha256(List<int> prk, List<int> info, int length) {
  if (length > 255 * 32) throw ArgumentError.value(length, 'length', 'too long for HKDF-SHA256');
  final mac = hash.Hmac(hash.sha256, prk);
  final out = BytesBuilder(copy: false);
  var previous = <int>[];
  for (var i = 1; out.length < length; i++) {
    previous = mac.convert([...previous, ...info, i]).bytes;
    out.add(previous);
  }
  return Uint8List.sublistView(out.takeBytes(), 0, length);
}

/// Extract then expand: [length] bytes from [ikm], [salt] and [info].
Uint8List hkdfSha256(List<int> ikm, {required List<int> salt, required List<int> info, int length = 32}) =>
    hkdfExpandSha256(hkdfExtractSha256(salt, ikm), info, length);
