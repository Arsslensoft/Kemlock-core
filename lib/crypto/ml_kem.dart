// ML-KEM-1024 and ML-KEM-768 (FIPS 203), ported from
// `@noble/post-quantum` 0.7.1 (`ml-kem.js` and `_crystals.js`), which the
// TypeScript app uses for the vault, its exports and sync. ML-KEM-1024's
// keys, ciphertexts and shared secrets are the same bytes as noble's for
// the same seed and message; the tests check noble's vectors, and NIST's
// ACVP vectors for ML-KEM-768, the parameter set of exchange keys.
//
// Polynomials have 256 coefficients modulo q = 3329, kept reduced in
// Uint16Lists. The transforms and the sampling follow the FIPS 203
// algorithms they are named after.

import 'dart:typed_data';

import 'bytes.dart';
import 'keccak.dart';

const _n = 256;
const _q = 3329;

/// 128^-1 mod q, the scale of the inverse NTT.
const _f = 3303;

const _polyBytes = 384; // 12 bits per coefficient

/// Module rank, noise widths and compression bits of a parameter set
/// (FIPS 203 Table 2).
final class _Params {
  const _Params(this.k, this.eta1, this.eta2, this.du, this.dv);

  final int k;
  final int eta1;
  final int eta2;
  final int du;
  final int dv;

  int get publicKeyLength => _polyBytes * k + 32;
  int get secretKeyLength => 768 * k + 96;
  int get cipherTextLength => 32 * (du * k + dv);
}

const _mlKem768 = _Params(3, 2, 2, 10, 4);
const _mlKem1024 = _Params(4, 2, 2, 11, 5);

/// ML-KEM-1024 key generation, encapsulation and decapsulation, matching
/// noble's `ml_kem1024`.
///
/// Decapsulation never fails on a ciphertext made for another key or
/// tampered with: it returns an unrelated shared secret ("implicit
/// rejection"), so a wrong key shows up when the AES-GCM tag doesn't verify.
/// Inputs of the wrong length, a public key with a coefficient out of range
/// and a secret key whose embedded hash doesn't match throw an
/// [ArgumentError], where noble throws.
abstract final class MlKem1024 {
  static const publicKeyLength = 1568;
  static const secretKeyLength = 3168;
  static const cipherTextLength = 1568;
  static const sharedSecretLength = 32;

  /// A key pair from the 64-byte [seed] `d || z` (FIPS 203 Algorithm 16),
  /// or from fresh random bytes. Public key 1568 bytes, secret key 3168:
  /// the K-PKE secret key, the public key, its SHA3-256 and z.
  static ({Uint8List publicKey, Uint8List secretKey}) keygen([Uint8List? seed]) => _keygen(_mlKem1024, seed);

  /// A fresh shared secret for [publicKey] and the ciphertext that carries
  /// it (FIPS 203 Algorithm 17). [message] is the 32 random bytes `m` the
  /// secret comes from; pass it only to reproduce a known answer.
  static ({Uint8List cipherText, Uint8List sharedSecret}) encapsulate(Uint8List publicKey, [Uint8List? message]) =>
      _encapsulate(_mlKem1024, publicKey, message);

  /// The shared secret in [cipherText] for [secretKey] (FIPS 203 Algorithm
  /// 18). A ciphertext the key didn't make gives SHAKE256(z || cipherText)
  /// instead, as noble does.
  static Uint8List decapsulate(Uint8List cipherText, Uint8List secretKey) => _decapsulate(_mlKem1024, cipherText, secretKey).sharedSecret;

  /// What [decapsulate] gives, and with it the message `m` [encapsulate]
  /// made [cipherText] from. Decapsulation finds that message anyway: it
  /// decrypts it and encrypts it again to check the ciphertext. [message]
  /// is null for a ciphertext the key didn't make, whose shared secret is
  /// the implicit rejection one.
  ///
  /// The message is as secret as the shared secret, which it gives. It lets
  /// the holder of the secret key tell who made a ciphertext: whoever sealed
  /// to the public key chose the message, and only someone who shares a
  /// secret with the key's holder can have chosen one derived from it.
  static ({Uint8List sharedSecret, Uint8List? message}) decapsulateWithMessage(Uint8List cipherText, Uint8List secretKey) =>
      _decapsulate(_mlKem1024, cipherText, secretKey);

  /// The public key [secretKey] holds, a copy. Throws an [ArgumentError] for
  /// a secret key of the wrong length or whose embedded hash doesn't match
  /// the public key beside it.
  static Uint8List publicKeyOf(Uint8List secretKey) => Uint8List.fromList(_publicKeyIn(_mlKem1024, secretKey));
}

/// ML-KEM-768: the operations of [MlKem1024] with k = 3, d_u = 10 and
/// d_v = 4, for a 1184-byte public key, a 2400-byte secret key and a
/// 1088-byte ciphertext.
abstract final class MlKem768 {
  static const publicKeyLength = 1184;
  static const secretKeyLength = 2400;
  static const cipherTextLength = 1088;
  static const sharedSecretLength = 32;

  static ({Uint8List publicKey, Uint8List secretKey}) keygen([Uint8List? seed]) => _keygen(_mlKem768, seed);

  static ({Uint8List cipherText, Uint8List sharedSecret}) encapsulate(Uint8List publicKey, [Uint8List? message]) =>
      _encapsulate(_mlKem768, publicKey, message);

  static Uint8List decapsulate(Uint8List cipherText, Uint8List secretKey) => _decapsulate(_mlKem768, cipherText, secretKey).sharedSecret;
}

({Uint8List publicKey, Uint8List secretKey}) _keygen(_Params p, Uint8List? seed) {
  final s = seed ?? randomBytes(64);
  _checkLength(s, 64, 'seed');
  final (:publicKey, secretKey: pkeSecretKey) = _pkeKeygen(p, Uint8List.sublistView(s, 0, 32));
  final secretKey = concatBytes([pkeSecretKey, publicKey, sha3_256(publicKey), Uint8List.sublistView(s, 32, 64)]);
  return (publicKey: publicKey, secretKey: secretKey);
}

({Uint8List cipherText, Uint8List sharedSecret}) _encapsulate(_Params p, Uint8List publicKey, Uint8List? message) {
  final m = message ?? randomBytes(32);
  _checkLength(publicKey, p.publicKeyLength, 'publicKey');
  _checkLength(m, 32, 'message');
  // Modulus check: every coefficient of the public key must be below q.
  final encoded = Uint8List.sublistView(publicKey, 0, _polyBytes * p.k);
  for (var i = 0; i < p.k; i++) {
    final poly = _byteDecode12(encoded, i * _polyBytes);
    final again = Uint8List(_polyBytes);
    _byteEncode(poly, 12, again, 0);
    for (var j = 0; j < _polyBytes; j++) {
      if (again[j] != encoded[i * _polyBytes + j]) {
        throw ArgumentError('ML-KEM.encapsulate: wrong publicKey modulus');
      }
    }
  }
  final kr = sha3_512(concatBytes([m, sha3_256(publicKey)]));
  final cipherText = _pkeEncrypt(p, publicKey, m, Uint8List.sublistView(kr, 32, 64));
  return (cipherText: cipherText, sharedSecret: Uint8List.fromList(kr.sublist(0, 32)));
}

/// The shared secret, and the message it came from unless the ciphertext
/// was rejected.
({Uint8List sharedSecret, Uint8List? message}) _decapsulate(_Params p, Uint8List cipherText, Uint8List secretKey) {
  final publicKey = _publicKeyIn(p, secretKey);
  _checkLength(cipherText, p.cipherTextLength, 'cipherText');
  final k768 = 768 * p.k;
  final publicKeyHash = Uint8List.sublistView(secretKey, k768 + 32, k768 + 64);
  final z = Uint8List.sublistView(secretKey, k768 + 64, k768 + 96);

  final m = _pkeDecrypt(p, cipherText, Uint8List.sublistView(secretKey, 0, k768 ~/ 2));
  final kr = sha3_512(concatBytes([m, publicKeyHash]));
  final again = _pkeEncrypt(p, publicKey, m, Uint8List.sublistView(kr, 32, 64));
  final rejected = shake256(concatBytes([z, cipherText]), 32);
  return _equal(cipherText, again)
      ? (sharedSecret: Uint8List.fromList(kr.sublist(0, 32)), message: m)
      : (sharedSecret: rejected, message: null);
}

/// The public key a secret key holds after its K-PKE half, as a view, once
/// its hash, which follows it, is found to match.
Uint8List _publicKeyIn(_Params p, Uint8List secretKey) {
  _checkLength(secretKey, p.secretKeyLength, 'secretKey');
  final k768 = 768 * p.k;
  final publicKey = Uint8List.sublistView(secretKey, k768 ~/ 2, k768 + 32);
  if (!_equal(sha3_256(publicKey), Uint8List.sublistView(secretKey, k768 + 32, k768 + 64))) {
    throw ArgumentError('invalid secretKey: hash check failed');
  }
  return publicKey;
}

void _checkLength(Uint8List bytes, int length, String name) {
  if (bytes.length != length) {
    throw ArgumentError.value(bytes.length, name, 'expected $length bytes, got ${bytes.length}');
  }
}

/// Compares without stopping at the first difference.
bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

// ─── K-PKE (FIPS 203 Algorithms 13 to 15) ─────────────────────────────────────

({Uint8List publicKey, Uint8List secretKey}) _pkeKeygen(_Params p, Uint8List d) {
  final k = p.k;
  // (rho, sigma) = G(d || k): the parameter set is part of the seed.
  final g = sha3_512([...d, k]);
  final rho = Uint8List.sublistView(g, 0, 32);
  final sigma = Uint8List.sublistView(g, 32, 64);

  final sHat = [for (var i = 0; i < k; i++) _ntt(_sampleCbd(_prf(sigma, i, p.eta1), p.eta1))];
  final publicKey = Uint8List(p.publicKeyLength);
  for (var i = 0; i < k; i++) {
    final t = _ntt(_sampleCbd(_prf(sigma, k + i, p.eta1), p.eta1));
    for (var j = 0; j < k; j++) {
      _addInPlace(t, _multiplyNtts(_sampleNtt(rho, j, i), sHat[j])); // t += A[i][j] * s[j]
    }
    _byteEncode(t, 12, publicKey, i * _polyBytes);
  }
  publicKey.setAll(_polyBytes * k, rho);

  final secretKey = Uint8List(_polyBytes * k);
  for (var i = 0; i < k; i++) {
    _byteEncode(sHat[i], 12, secretKey, i * _polyBytes);
  }
  return (publicKey: publicKey, secretKey: secretKey);
}

Uint8List _pkeEncrypt(_Params p, Uint8List publicKey, Uint8List message, Uint8List r) {
  final k = p.k;
  final tHat = [for (var i = 0; i < k; i++) _byteDecode12(publicKey, i * _polyBytes)];
  final rho = Uint8List.sublistView(publicKey, _polyBytes * k);

  final yHat = [for (var i = 0; i < k; i++) _ntt(_sampleCbd(_prf(r, i, p.eta1), p.eta1))];
  final cipherText = Uint8List(p.cipherTextLength);
  for (var i = 0; i < k; i++) {
    final sum = Uint16List(_n);
    for (var j = 0; j < k; j++) {
      _addInPlace(sum, _multiplyNtts(_sampleNtt(rho, i, j), yHat[j])); // sum += A[j][i] * y[j]
    }
    final u = _invNtt(sum);
    _addInPlace(u, _sampleCbd(_prf(r, k + i, p.eta2), p.eta2)); // u = NTT^-1(A^T y) + e1
    _compressInPlace(u, p.du);
    _byteEncode(u, p.du, cipherText, i * 32 * p.du);
  }

  final sum = Uint16List(_n);
  for (var i = 0; i < k; i++) {
    _addInPlace(sum, _multiplyNtts(tHat[i], yHat[i]));
  }
  final v = _invNtt(sum);
  _addInPlace(v, _sampleCbd(_prf(r, 2 * k, p.eta2), p.eta2)); // + e2
  final mu = _byteDecode(message, 0, 1);
  _decompressInPlace(mu, 1);
  _addInPlace(v, mu); // + Decompress_1(m)
  _compressInPlace(v, p.dv);
  _byteEncode(v, p.dv, cipherText, k * 32 * p.du);
  return cipherText;
}

Uint8List _pkeDecrypt(_Params p, Uint8List cipherText, Uint8List secretKey) {
  final w = _byteDecode(cipherText, p.k * 32 * p.du, p.dv);
  _decompressInPlace(w, p.dv);
  final sum = Uint16List(_n);
  for (var i = 0; i < p.k; i++) {
    final u = _byteDecode(cipherText, i * 32 * p.du, p.du);
    _decompressInPlace(u, p.du);
    _addInPlace(sum, _multiplyNtts(_byteDecode12(secretKey, i * _polyBytes), _ntt(u)));
  }
  _subInPlace(w, _invNtt(sum)); // w = v - NTT^-1(s^T u)
  _compressInPlace(w, 1);
  final m = Uint8List(32);
  _byteEncode(w, 1, m, 0);
  return m;
}

// ─── Sampling (FIPS 203 Algorithms 7 and 8) ───────────────────────────────────

/// PRF_eta(s, b) = SHAKE256(s || b), 64 * eta bytes.
Uint8List _prf(Uint8List s, int b, int eta) => shake256([...s, b & 0xff], 64 * eta);

/// SampleNTT(rho || x || y): a uniform polynomial in NTT form, from SHAKE128
/// read in 168-byte blocks, three bytes giving two 12-bit candidates.
Uint16List _sampleNtt(Uint8List rho, int x, int y) {
  final xof = Keccak.shake128()
    ..update(rho)
    ..update([x, y]);
  final block = Uint8List(xof.rate);
  final a = Uint16List(_n);
  var j = 0;
  while (j < _n) {
    xof.squeezeInto(block);
    for (var i = 0; j < _n && i + 3 <= block.length; i += 3) {
      final d1 = block[i] | ((block[i + 1] & 0x0f) << 8);
      final d2 = (block[i + 1] >> 4) | (block[i + 2] << 4);
      if (d1 < _q) a[j++] = d1;
      if (j < _n && d2 < _q) a[j++] = d2;
    }
  }
  return a;
}

/// SamplePolyCBD_eta: each coefficient is the number of set bits in eta
/// bits minus those in the next eta, modulo q; bits are read little-endian.
Uint16List _sampleCbd(Uint8List bytes, int eta) {
  final f = Uint16List(_n);
  var bit = 0;
  for (var i = 0; i < _n; i++) {
    var x = 0;
    var y = 0;
    for (var j = 0; j < eta; j++, bit++) {
      x += (bytes[bit >> 3] >> (bit & 7)) & 1;
    }
    for (var j = 0; j < eta; j++, bit++) {
      y += (bytes[bit >> 3] >> (bit & 7)) & 1;
    }
    f[i] = (x - y) % _q;
  }
  return f;
}

// ─── NTT (FIPS 203 Algorithms 9 to 12) ────────────────────────────────────────

int _bitRev7(int i) {
  var r = 0;
  for (var b = 0; b < 7; b++) {
    r |= ((i >> b) & 1) << (6 - b);
  }
  return r;
}

int _powMod(int base, int exp) {
  var result = 1;
  for (var i = 0; i < exp; i++) {
    result = (result * base) % _q;
  }
  return result;
}

/// zeta^BitRev7(i) for zeta = 17, the primitive 256th root of unity.
final _zetas = Uint16List.fromList([for (var i = 0; i < 128; i++) _powMod(17, _bitRev7(i))]);

/// zeta^(2 * BitRev7(i) + 1), for multiplying in NTT form.
final _gammas = Uint16List.fromList([for (var i = 0; i < 128; i++) _powMod(17, 2 * _bitRev7(i) + 1)]);

/// The NTT of [f], in place; returns [f].
Uint16List _ntt(Uint16List f) {
  var i = 1;
  for (var len = 128; len >= 2; len >>= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final zeta = _zetas[i++];
      for (var j = start; j < start + len; j++) {
        final t = (zeta * f[j + len]) % _q;
        final fj = f[j];
        f[j + len] = (fj - t) % _q;
        f[j] = (fj + t) % _q;
      }
    }
  }
  return f;
}

/// The inverse NTT of [f], in place; returns [f].
Uint16List _invNtt(Uint16List f) {
  var i = 127;
  for (var len = 2; len <= 128; len <<= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final zeta = _zetas[i--];
      for (var j = start; j < start + len; j++) {
        final t = f[j];
        f[j] = (t + f[j + len]) % _q;
        f[j + len] = (zeta * (f[j + len] - t)) % _q;
      }
    }
  }
  for (var j = 0; j < _n; j++) {
    f[j] = (f[j] * _f) % _q;
  }
  return f;
}

/// The product of two polynomials in NTT form, as 128 products of
/// degree-one polynomials modulo X^2 - gamma.
Uint16List _multiplyNtts(Uint16List f, Uint16List g) {
  final h = Uint16List(_n);
  for (var i = 0; i < 128; i++) {
    final a0 = f[2 * i], a1 = f[2 * i + 1];
    final b0 = g[2 * i], b1 = g[2 * i + 1];
    h[2 * i] = (a0 * b0 + ((a1 * b1) % _q) * _gammas[i]) % _q;
    h[2 * i + 1] = (a0 * b1 + a1 * b0) % _q;
  }
  return h;
}

void _addInPlace(Uint16List a, Uint16List b) {
  for (var i = 0; i < _n; i++) {
    final r = a[i] + b[i];
    a[i] = r >= _q ? r - _q : r;
  }
}

void _subInPlace(Uint16List a, Uint16List b) {
  for (var i = 0; i < _n; i++) {
    final r = a[i] - b[i];
    a[i] = r < 0 ? r + _q : r;
  }
}

// ─── Compression and encoding (FIPS 203 section 4.2.1, Algorithms 5 and 6) ───

/// Compress_d: round(2^d / q * x) mod 2^d, in integers.
void _compressInPlace(Uint16List f, int d) {
  final mask = (1 << d) - 1;
  for (var i = 0; i < _n; i++) {
    f[i] = (((f[i] << (d + 1)) + _q) ~/ (2 * _q)) & mask;
  }
}

/// Decompress_d: round(q / 2^d * y), halves rounded up.
void _decompressInPlace(Uint16List f, int d) {
  final half = 1 << (d - 1);
  for (var i = 0; i < _n; i++) {
    f[i] = (f[i] * _q + half) >> d;
  }
}

/// ByteEncode_d: 256 d-bit words, little-endian, into [out] at [offset].
void _byteEncode(Uint16List f, int d, Uint8List out, int offset) {
  var buffer = 0;
  var bits = 0;
  var pos = offset;
  for (var i = 0; i < _n; i++) {
    buffer |= f[i] << bits;
    bits += d;
    while (bits >= 8) {
      out[pos++] = buffer & 0xff;
      buffer >>= 8;
      bits -= 8;
    }
  }
}

/// ByteDecode_d of the 32 * d bytes at [offset].
Uint16List _byteDecode(Uint8List bytes, int offset, int d) {
  final f = Uint16List(_n);
  final mask = (1 << d) - 1;
  var buffer = 0;
  var bits = 0;
  var pos = offset;
  for (var i = 0; i < _n;) {
    buffer |= bytes[pos++] << bits;
    bits += 8;
    while (bits >= d && i < _n) {
      f[i++] = buffer & mask;
      buffer >>= d;
      bits -= d;
    }
  }
  return f;
}

/// ByteDecode_12, which reads each word modulo q (4095 becomes 766).
Uint16List _byteDecode12(Uint8List bytes, int offset) {
  final f = _byteDecode(bytes, offset, 12);
  for (var i = 0; i < _n; i++) {
    if (f[i] >= _q) f[i] -= _q;
  }
  return f;
}
