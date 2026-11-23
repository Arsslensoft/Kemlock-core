// SHA-3 and SHAKE (FIPS 202) over the Keccak-f[1600] permutation, for
// ML-KEM (FIPS 203) and ML-DSA (FIPS 204), and cSHAKE256 and KMAC256
// (SP 800-185) for the KMAC key combiner of LibrePGP's Kyber keys. The
// SHA-3 and SHAKE outputs match `@noble/hashes/sha3.js`, which the
// TypeScript app's ML-KEM uses; the tests check them against its vectors,
// and cSHAKE and KMAC against NIST's SP 800-185 examples.
//
// The 64-bit lanes are Dart ints, so this needs a 64-bit platform (no web
// build).

import 'dart:typed_data';

/// SHA3-256 of [data] (32 bytes), the `H` of FIPS 203.
Uint8List sha3_256(List<int> data) => (Keccak.sha3_256()..update(data)).squeeze(32);

/// SHA3-512 of [data] (64 bytes), the `G` of FIPS 203.
Uint8List sha3_512(List<int> data) => (Keccak.sha3_512()..update(data)).squeeze(64);

/// [outLength] bytes of SHAKE128 over [data].
Uint8List shake128(List<int> data, int outLength) => (Keccak.shake128()..update(data)).squeeze(outLength);

/// [outLength] bytes of SHAKE256 over [data], the `PRF` and `J` of FIPS 203.
Uint8List shake256(List<int> data, int outLength) => (Keccak.shake256()..update(data)).squeeze(outLength);

/// [outLength] bytes of cSHAKE256 (SP 800-185) over [data], with the
/// function [name] N and the [customization] string S. With both empty it
/// is SHAKE256.
Uint8List cshake256(List<int> data, int outLength, {List<int> name = const [], List<int> customization = const []}) {
  if (name.isEmpty && customization.isEmpty) return shake256(data, outLength);
  return (_cshakeSponge(name, customization)..update(data)).squeeze(outLength);
}

/// A KMAC256 tag (SP 800-185) of [data] under [key], [outLength] bytes long,
/// with the [customization] string S:
/// cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L,
/// "KMAC", S), L in bits.
Uint8List kmac256(List<int> key, List<int> data, int outLength, {List<int> customization = const []}) =>
    (_cshakeSponge(_kmac, customization)
          ..update(_bytepad(_encodeString(key), 136))
          ..update(data)
          ..update(_rightEncode(outLength * 8)))
        .squeeze(outLength);

/// "KMAC", the function name N of KMAC.
const _kmac = [0x4b, 0x4d, 0x41, 0x43];

/// A cSHAKE256 sponge that has absorbed bytepad(encode_string(N) ||
/// encode_string(S), 136), ready for the input.
Keccak _cshakeSponge(List<int> name, List<int> customization) =>
    Keccak._cshake256()..update(_bytepad([..._encodeString(name), ..._encodeString(customization)], 136));

/// The bytes of [x], big-endian, at least one.
List<int> _bigEndian(int x) {
  final out = <int>[];
  var rest = x;
  do {
    out.insert(0, rest & 0xff);
    rest >>= 8;
  } while (rest > 0);
  return out;
}

/// left_encode(x): the byte count of x, then x.
List<int> _leftEncode(int x) {
  final bytes = _bigEndian(x);
  return [bytes.length, ...bytes];
}

/// right_encode(x): x, then its byte count.
List<int> _rightEncode(int x) {
  final bytes = _bigEndian(x);
  return [...bytes, bytes.length];
}

/// encode_string(S): the bit length of S, left-encoded, then S.
List<int> _encodeString(List<int> s) => [..._leftEncode(s.length * 8), ...s];

/// bytepad(X, w): left_encode(w) || X, padded with zeros to a multiple of w.
List<int> _bytepad(List<int> x, int w) {
  final out = [..._leftEncode(w), ...x];
  while (out.length % w != 0) {
    out.add(0);
  }
  return out;
}

/// A Keccak sponge: [update] absorbs input, then [squeeze] and [squeezeInto]
/// read output, as much as wanted for SHAKE. Once output has been read,
/// nothing more can be absorbed.
///
/// ML-KEM reads its matrix out of SHAKE128 in blocks of [rate] bytes, as
/// noble's `XOF128` does.
class Keccak {
  Keccak._(this.rate, this._padding);

  /// SHA3-256: 136-byte blocks; read the first 32 bytes.
  Keccak.sha3_256() : this._(136, 0x06);

  /// SHA3-512: 72-byte blocks; read the first 64 bytes.
  Keccak.sha3_512() : this._(72, 0x06);

  /// SHAKE128: 168-byte blocks, any output length.
  Keccak.shake128() : this._(168, 0x1f);

  /// SHAKE256: 136-byte blocks, any output length.
  Keccak.shake256() : this._(136, 0x1f);

  /// cSHAKE256 (SP 800-185) with N or S given: SHAKE256's blocks, its own
  /// domain bits. [_cshakeSponge] absorbs N and S first.
  Keccak._cshake256() : this._(136, 0x04);

  /// Bytes absorbed or squeezed per permutation.
  final int rate;

  /// The domain bits and the first padding bit: 01 for SHA-3, 1111 for
  /// SHAKE, 00 for cSHAKE.
  final int _padding;

  final _state = Int64List(25);
  final _scratch = Int64List(5);

  /// Where the next byte goes in (or comes out of) the current block.
  int _pos = 0;
  bool _squeezing = false;

  /// Absorbs [data].
  void update(List<int> data) {
    if (_squeezing) throw StateError('Keccak: cannot absorb after squeezing');
    final state = _state;
    var pos = _pos;
    for (var i = 0; i < data.length; i++) {
      state[pos >> 3] ^= (data[i] & 0xff) << ((pos & 7) << 3);
      if (++pos == rate) {
        _permute(state, _scratch);
        pos = 0;
      }
    }
    _pos = pos;
  }

  /// Fills [out] with the next output bytes.
  void squeezeInto(Uint8List out) {
    final state = _state;
    if (!_squeezing) {
      state[_pos >> 3] ^= _padding << ((_pos & 7) << 3);
      state[(rate - 1) >> 3] ^= 0x80 << (((rate - 1) & 7) << 3);
      _permute(state, _scratch);
      _squeezing = true;
      _pos = 0;
    }
    var pos = _pos;
    for (var i = 0; i < out.length; i++) {
      if (pos == rate) {
        _permute(state, _scratch);
        pos = 0;
      }
      out[i] = state[pos >> 3] >> ((pos & 7) << 3);
      pos++;
    }
    _pos = pos;
  }

  /// The next [length] output bytes.
  Uint8List squeeze(int length) {
    final out = Uint8List(length);
    squeezeInto(out);
    return out;
  }
}

// Rotation amounts and lane order of the combined rho and pi steps, walking
// the lanes from 1, as in the compact Keccak reference code.
const _rotations = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const _piLanes = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];

// The iota round constants; those with the top bit set read as negative ints.
final _roundConstants = Int64List.fromList(const [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000, //
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]);

int _rotl64(int x, int n) => (x << n) | (x >>> (64 - n));

/// Keccak-f[1600] on the 25 lanes of [a], lane (x, y) at `x + 5 * y`.
void _permute(Int64List a, Int64List c) {
  for (var round = 0; round < 24; round++) {
    // Theta
    for (var x = 0; x < 5; x++) {
      c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    for (var x = 0; x < 5; x++) {
      final d = c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1);
      for (var y = 0; y < 25; y += 5) {
        a[y + x] ^= d;
      }
    }
    // Rho and pi
    var t = a[1];
    for (var i = 0; i < 24; i++) {
      final j = _piLanes[i];
      final next = a[j];
      a[j] = _rotl64(t, _rotations[i]);
      t = next;
    }
    // Chi
    for (var y = 0; y < 25; y += 5) {
      final a0 = a[y], a1 = a[y + 1], a2 = a[y + 2], a3 = a[y + 3], a4 = a[y + 4];
      a[y] = a0 ^ (~a1 & a2);
      a[y + 1] = a1 ^ (~a2 & a3);
      a[y + 2] = a2 ^ (~a3 & a4);
      a[y + 3] = a3 ^ (~a4 & a0);
      a[y + 4] = a4 ^ (~a0 & a1);
    }
    // Iota
    a[0] ^= _roundConstants[round];
  }
}
