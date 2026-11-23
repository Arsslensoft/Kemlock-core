// z-base-32, the human-oriented base-32 encoding of Zooko Wilcox-O'Hearn,
// in the form a Web Key Directory names a key by (draft-koch-openpgp-
// webkey-service, section 3.1): five bits to a character, the most
// significant first, the last character padded with zero bits, and no `=`.

/// The 32 characters, in the order of the five-bit values they stand for.
const zBase32Alphabet = 'ybndrfg8ejkmcpqxot1uwisza345h769';

/// [bytes] in z-base-32: 32 characters for the 20 bytes of a SHA-1 hash.
String zBase32(List<int> bytes) {
  final out = StringBuffer();
  var buffer = 0;
  var bits = 0;
  for (final byte in bytes) {
    buffer = (buffer << 8) | (byte & 0xff);
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.write(zBase32Alphabet[(buffer >> bits) & 0x1f]);
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out.write(zBase32Alphabet[(buffer << (5 - bits)) & 0x1f]);
  return out.toString();
}
