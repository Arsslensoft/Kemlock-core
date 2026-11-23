// ML-DSA-65 (FIPS 204), on the SHAKE of `keccak.dart`: key generation, the
// public key of a secret key given without its seed (OpenSSL's "expanded"
// PKCS#8 form), and signing and verifying (FIPS 204 Algorithms 2, 3, 7 and
// 8, the pure form with a context), as OpenPGP's composite
// ML-DSA-65+Ed25519 signatures (RFC 9980) need. Signing is hedged by
// default: 32 fresh random bytes go into each signature. The tests check
// NIST's ACVP vectors and keys OpenSSL made from a seed.
//
// Like the ML-KEM port, this is not constant-time: the reductions, the
// rejection loop and the hint packing branch on secret values.
//
// Polynomials have 256 coefficients modulo q = 8380417, kept reduced in
// Int32Lists; products of two fit in a Dart int. The functions follow the
// FIPS 204 algorithms they are named after.

import 'dart:typed_data';

import 'bytes.dart';
import 'keccak.dart';

const _n = 256;
const _q = 8380417;

/// Bits dropped from t (d), and the matrix and noise of ML-DSA-65.
const _d = 13;
const _k = 6;
const _l = 5;
const _eta = 4;

/// The signature's parameters: tau coefficients of the challenge c are
/// ±1, y has coefficients in (-gamma1, gamma1], w is rounded to multiples
/// of 2 * gamma2, and a signature holds at most omega hints.
const _tau = 49;
const _beta = _tau * _eta; // 196, the most a coefficient of c * s1 or c * s2 reaches
const _gamma1 = 1 << 19;
const _gamma2 = (_q - 1) ~/ 32; // 261888
const _omega = 55;
const _cTildeLength = 48; // lambda / 4 for lambda = 192

const _t1Bits = 10; // bitlen(q - 1) - d
const _etaBits = 4; // bitlen(2 * eta)
const _t0Bits = 13; // bitlen(2^d - 1)
const _zBits = 20; // 1 + bitlen(gamma1 - 1)
const _w1Bits = 4; // bitlen((q - 1) / (2 * gamma2) - 1)

/// ML-DSA-65 (FIPS 204): key generation, signing and verifying.
abstract final class MlDsa65 {
  static const seedLength = 32;
  static const publicKeyLength = 32 + 32 * _k * _t1Bits; // 1952
  static const secretKeyLength = 32 + 32 + 64 + 32 * ((_k + _l) * _etaBits + _k * _t0Bits); // 4032
  static const signatureLength = _cTildeLength + _l * 32 * _zBits + _omega + _k; // 3309

  /// The bytes of randomness signing takes.
  static const randomnessLength = 32;

  /// A key pair from the 32-byte [seed] xi, or from fresh random bytes
  /// (FIPS 204 Algorithm 6, ML-DSA.KeyGen_internal).
  static ({Uint8List publicKey, Uint8List secretKey}) keygen([Uint8List? seed]) {
    final xi = seed ?? randomBytes(seedLength);
    if (xi.length != seedLength) throw ArgumentError.value(xi.length, 'seed', 'expected $seedLength bytes');
    // (rho, rho', K) = H(xi || k || l, 128)
    final h = shake256([...xi, _k, _l], 128);
    final rho = Uint8List.sublistView(h, 0, 32);
    final rhoPrime = Uint8List.sublistView(h, 32, 96);
    final key = Uint8List.sublistView(h, 96, 128);
    final s1 = [for (var r = 0; r < _l; r++) _rejBoundedPoly(rhoPrime, r)];
    final s2 = [for (var r = 0; r < _k; r++) _rejBoundedPoly(rhoPrime, r + _l)];
    final (t1, t0) = _t(rho, s1, s2);
    final publicKey = _pkEncode(rho, t1);
    final tr = shake256(publicKey, 64);
    return (publicKey: publicKey, secretKey: _skEncode(rho, key, tr, s1, s2, t0));
  }

  /// The public key of [secretKey], worked out again from rho, s1 and s2.
  /// Throws an [ArgumentError] for a key of the wrong length, with
  /// coefficients out of range, or whose t0 or tr isn't the one its other
  /// parts give: it is not an ML-DSA-65 secret key.
  static Uint8List publicKeyOf(Uint8List secretKey) {
    _checkLength(secretKey, secretKeyLength, 'secretKey');
    final (:rho, key: _, :tr, :s1, :s2, :t0) = _skDecode(secretKey);
    final (t1, t0Again) = _t(rho, s1, s2);
    for (var i = 0; i < _k; i++) {
      if (!_samePoly(t0[i], t0Again[i])) throw ArgumentError('ML-DSA: t0 does not match s1 and s2');
    }
    final publicKey = _pkEncode(rho, t1);
    if (!_sameBytes(shake256(publicKey, 64), tr)) throw ArgumentError('ML-DSA: tr does not match the public key');
    return publicKey;
  }

  /// The signature of [message] under [secretKey], the 4032-byte expanded
  /// key [keygen] returns, in [context] (FIPS 204 Algorithm 2, ML-DSA.Sign,
  /// pure). Hedged with 32 fresh random bytes, or deterministic with the 32
  /// bytes of [randomness]: all zeros for FIPS 204's deterministic variant.
  ///
  /// Throws an [ArgumentError] for a key or randomness of the wrong length,
  /// a context over 255 bytes, or a key with s1 or s2 out of range.
  static Uint8List sign(Uint8List secretKey, List<int> message, {List<int> context = const [], Uint8List? randomness}) {
    _checkLength(secretKey, secretKeyLength, 'secretKey');
    if (randomness != null) _checkLength(randomness, randomnessLength, 'randomness');
    final mPrime = _messagePrime(message, context);
    return _signInternal(secretKey, mPrime, randomness ?? randomBytes(randomnessLength));
  }

  /// Whether [signature] signs [message] under [publicKey] in [context]
  /// (FIPS 204 Algorithm 3, ML-DSA.Verify, pure). False for a signature that
  /// does not verify, as for one whose hints are not validly encoded or
  /// whose z is out of range.
  ///
  /// Throws an [ArgumentError] for a key or signature of the wrong length,
  /// or a context over 255 bytes.
  static bool verify(Uint8List publicKey, List<int> message, Uint8List signature, {List<int> context = const []}) {
    _checkLength(publicKey, publicKeyLength, 'publicKey');
    _checkLength(signature, signatureLength, 'signature');
    return _verifyInternal(publicKey, _messagePrime(message, context), signature);
  }
}

void _checkLength(Uint8List bytes, int length, String name) {
  if (bytes.length != length) throw ArgumentError.value(bytes.length, name, 'expected $length bytes');
}

/// M' = 0 || |ctx| || ctx || M, the message pure ML-DSA signs (FIPS 204
/// Algorithms 2 and 3); the 0 marks it as not pre-hashed.
Uint8List _messagePrime(List<int> message, List<int> context) {
  if (context.length > 255) throw ArgumentError.value(context.length, 'context', 'expected at most 255 bytes');
  return Uint8List(2 + context.length + message.length)
    ..[1] = context.length
    ..setAll(2, context)
    ..setAll(2 + context.length, message);
}

// ─── Signing and verifying (FIPS 204 Algorithms 7 and 8) ─────────────────────

/// ML-DSA.Sign_internal: tries masks y, one counter kappa after another,
/// until z = y + c * s1 and the hints give nothing of s1, s2 or t0 away.
/// A, s1, s2 and t0 go into NTT form once, before the loop.
Uint8List _signInternal(Uint8List secretKey, Uint8List mPrime, Uint8List rnd) {
  final (:rho, :key, :tr, :s1, :s2, :t0) = _skDecode(secretKey);
  final aHat = _expandA(rho);
  final s1Hat = [for (final s in s1) _ntt(s)];
  final s2Hat = [for (final s in s2) _ntt(s)];
  final t0Hat = [for (final t in t0) _ntt(t)];
  // mu = H(tr || M', 64), rho'' = H(K || rnd || mu, 64)
  final mu =
      (Keccak.shake256()
            ..update(tr)
            ..update(mPrime))
          .squeeze(64);
  final rhoPrimePrime =
      (Keccak.shake256()
            ..update(key)
            ..update(rnd)
            ..update(mu))
          .squeeze(64);

  attempt:
  for (var kappa = 0; ; kappa += _l) {
    final y = _expandMask(rhoPrimePrime, kappa);
    final yHat = [for (final p in y) _ntt(Int32List.fromList(p))];
    final w = [for (final row in aHat) _invNtt(_rowTimes(row, yHat))];
    final cTilde = _commitment(mu, [for (final p in w) _highBitsOf(p)]);
    final cHat = _ntt(_sampleInBall(cTilde));

    // z = y + c * s1, centred; no coefficient may reach gamma1 - beta.
    final z = <Int32List>[];
    for (var i = 0; i < _l; i++) {
      final cs1 = _invNtt(_pointwise(cHat, s1Hat[i]));
      final zi = Int32List(_n);
      for (var j = 0; j < _n; j++) {
        final c = _centred((y[i][j] + cs1[j]) % _q);
        if (c.abs() >= _gamma1 - _beta) continue attempt;
        zi[j] = c;
      }
      z.add(zi);
    }

    // The low bits of w - c * s2 must stay below gamma2 - beta, and c * t0
    // below gamma2. The hints are MakeHint(-c * t0, w - c * s2 + c * t0):
    // where adding c * t0 changes the high bits of w - c * s2.
    final h = <Uint8List>[];
    var hints = 0;
    for (var i = 0; i < _k; i++) {
      final cs2 = _invNtt(_pointwise(cHat, s2Hat[i]));
      final ct0 = _invNtt(_pointwise(cHat, t0Hat[i]));
      final hi = Uint8List(_n);
      for (var j = 0; j < _n; j++) {
        final r = (w[i][j] - cs2[j]) % _q;
        final (r1, r0) = _decompose(r);
        if (r0.abs() >= _gamma2 - _beta || _centred(ct0[j]).abs() >= _gamma2) continue attempt;
        if (_decompose((r + ct0[j]) % _q).$1 != r1) {
          hi[j] = 1;
          hints++;
        }
      }
      h.add(hi);
    }
    if (hints > _omega) continue;
    return _sigEncode(cTilde, z, h);
  }
}

/// ML-DSA.Verify_internal: w' = A * z - c * t1 * 2^d, its high bits
/// corrected by the hints, must give the signature's commitment again.
bool _verifyInternal(Uint8List publicKey, Uint8List mPrime, Uint8List signature) {
  // sigDecode (Algorithm 27)
  final cTilde = Uint8List.sublistView(signature, 0, _cTildeLength);
  final z = [for (var i = 0; i < _l; i++) _bitUnpack(signature, _cTildeLength + i * 32 * _zBits, _zBits, _gamma1)];
  final h = _hintBitUnpack(signature, _cTildeLength + _l * 32 * _zBits);
  if (h == null) return false;
  for (final zi in z) {
    for (final c in zi) {
      if (c.abs() >= _gamma1 - _beta) return false;
    }
  }

  final aHat = _expandA(Uint8List.sublistView(publicKey, 0, 32));
  final tr = shake256(publicKey, 64);
  final mu =
      (Keccak.shake256()
            ..update(tr)
            ..update(mPrime))
          .squeeze(64);
  final cHat = _ntt(_sampleInBall(cTilde));
  final zHat = [for (final zi in z) _ntt(zi)];
  final w1 = <Int32List>[];
  for (var i = 0; i < _k; i++) {
    // pkDecode (Algorithm 23): t1, here times 2^d.
    final t1 = _simpleBitUnpack(publicKey, 32 + i * 32 * _t1Bits, _t1Bits);
    for (var j = 0; j < _n; j++) {
      t1[j] <<= _d;
    }
    final ct1 = _pointwise(cHat, _ntt(t1));
    final sum = _rowTimes(aHat[i], zHat);
    for (var j = 0; j < _n; j++) {
      sum[j] = (sum[j] - ct1[j]) % _q;
    }
    final wApprox = _invNtt(sum);
    final w1i = Int32List(_n);
    for (var j = 0; j < _n; j++) {
      w1i[j] = _useHint(h[i][j], wApprox[j]);
    }
    w1.add(w1i);
  }
  return _sameBytes(_commitment(mu, w1), cTilde);
}

/// c~ = H(mu || w1Encode(w1), lambda / 4), the commitment hash.
Uint8List _commitment(Uint8List mu, List<Int32List> w1) =>
    (Keccak.shake256()
          ..update(mu)
          ..update(_w1Encode(w1)))
        .squeeze(_cTildeLength);

/// t = NTT^-1(A * NTT(s1)) + s2, split by Power2Round into (t1, t0).
(List<Int32List>, List<Int32List>) _t(Uint8List rho, List<Int32List> s1, List<Int32List> s2) {
  final aHat = _expandA(rho);
  final s1Hat = [for (final s in s1) _ntt(Int32List.fromList(s))];
  final t1 = <Int32List>[];
  final t0 = <Int32List>[];
  for (var r = 0; r < _k; r++) {
    final t = _invNtt(_rowTimes(aHat[r], s1Hat));
    final high = Int32List(_n);
    final low = Int32List(_n);
    for (var j = 0; j < _n; j++) {
      final value = (t[j] + s2[r][j]) % _q;
      // Power2Round: value = high * 2^d + low, low in (-2^(d-1), 2^(d-1)].
      var r0 = value & ((1 << _d) - 1);
      if (r0 > 1 << (_d - 1)) r0 -= 1 << _d;
      high[j] = (value - r0) >> _d;
      low[j] = r0;
    }
    t1.add(high);
    t0.add(low);
  }
  return (t1, t0);
}

// ─── Sampling (FIPS 204 Algorithms 29 to 34, 14 and 15) ──────────────────────

/// ExpandA: the k x l matrix A-hat, row by row.
List<List<Int32List>> _expandA(Uint8List rho) => [
  for (var r = 0; r < _k; r++) [for (var s = 0; s < _l; s++) _rejNttPoly(rho, s, r)],
];

/// RejNTTPoly(rho || s || r): A[r][s] in NTT form, from SHAKE128 three
/// bytes at a time, the top bit of the third cleared.
Int32List _rejNttPoly(Uint8List rho, int s, int r) {
  final xof = Keccak.shake128()
    ..update(rho)
    ..update([s, r]);
  final block = Uint8List(xof.rate); // 168 bytes: 56 candidates
  final a = Int32List(_n);
  var j = 0;
  while (j < _n) {
    xof.squeezeInto(block);
    for (var i = 0; j < _n && i + 3 <= block.length; i += 3) {
      final z = block[i] | (block[i + 1] << 8) | ((block[i + 2] & 0x7f) << 16);
      if (z < _q) a[j++] = z;
    }
  }
  return a;
}

/// RejBoundedPoly(rho' || r as 2 bytes): a polynomial with coefficients in
/// [-eta, eta], from SHAKE256 half a byte at a time.
Int32List _rejBoundedPoly(Uint8List rhoPrime, int r) {
  final xof = Keccak.shake256()
    ..update(rhoPrime)
    ..update([r & 0xff, r >> 8]);
  final block = Uint8List(xof.rate);
  final a = Int32List(_n);
  var j = 0;
  while (j < _n) {
    xof.squeezeInto(block);
    for (var i = 0; j < _n && i < block.length; i++) {
      for (final half in [block[i] & 0x0f, block[i] >> 4]) {
        // CoeffFromHalfByte for eta = 4: 4 - b for b < 9.
        if (j < _n && half < 9) a[j++] = (_eta - half) % _q;
      }
    }
  }
  return a;
}

/// ExpandMask(rho'', kappa): the mask y, l polynomials with coefficients in
/// (-gamma1, gamma1], each from 640 bytes of SHAKE256 over rho'' and
/// kappa + r as 2 bytes.
List<Int32List> _expandMask(Uint8List rhoPrimePrime, int kappa) => [
  for (var r = kappa; r < kappa + _l; r++)
    _bitUnpack(
      (Keccak.shake256()
            ..update(rhoPrimePrime)
            ..update([r & 0xff, (r >> 8) & 0xff]))
          .squeeze(32 * _zBits),
      0,
      _zBits,
      _gamma1,
    ),
];

/// SampleInBall(c~): the challenge c, tau coefficients ±1 and the rest 0,
/// placed by a Fisher-Yates shuffle on SHAKE256 bytes after 8 bytes of signs.
Int32List _sampleInBall(Uint8List cTilde) {
  final xof = Keccak.shake256()..update(cTilde);
  final signs = xof.squeeze(8);
  final byte = Uint8List(1);
  final c = Int32List(_n);
  for (var i = _n - _tau; i < _n; i++) {
    do {
      xof.squeezeInto(byte);
    } while (byte[0] > i);
    final j = byte[0];
    final bit = i + _tau - _n;
    c[i] = c[j];
    c[j] = (signs[bit >> 3] >> (bit & 7)) & 1 == 1 ? _q - 1 : 1;
  }
  return c;
}

// ─── Rounding (FIPS 204 Algorithms 36 to 40) ──────────────────────────────────

/// Decompose(r): r = r1 * 2 * gamma2 + r0 with r0 in (-gamma2, gamma2],
/// except that r1 = 16 wraps to 0, r0 then one less. HighBits is r1 and
/// LowBits r0.
(int, int) _decompose(int r) {
  var r0 = r % (2 * _gamma2);
  if (r0 > _gamma2) r0 -= 2 * _gamma2;
  if (r - r0 == _q - 1) return (0, r0 - 1);
  return ((r - r0) ~/ (2 * _gamma2), r0);
}

/// HighBits of each coefficient of [w].
Int32List _highBitsOf(Int32List w) => Int32List.fromList([for (final r in w) _decompose(r).$1]);

/// UseHint(h, r): the high bits of r, moved one step towards r0, modulo
/// m = (q - 1) / (2 * gamma2) = 16, where the hint is set.
int _useHint(int hint, int r) {
  final (r1, r0) = _decompose(r);
  if (hint == 0) return r1;
  return (r0 > 0 ? r1 + 1 : r1 - 1) % ((_q - 1) ~/ (2 * _gamma2));
}

/// r mod± q: the coefficient in [-(q - 1) / 2, (q - 1) / 2].
int _centred(int r) => r > _q ~/ 2 ? r - _q : r;

// ─── NTT (FIPS 204 Algorithms 41 and 42) ──────────────────────────────────────

int _bitRev8(int i) {
  var r = 0;
  for (var b = 0; b < 8; b++) {
    r |= ((i >> b) & 1) << (7 - b);
  }
  return r;
}

int _powMod(int base, int exp) {
  var result = 1;
  var b = base % _q;
  for (var e = exp; e > 0; e >>= 1) {
    if (e & 1 == 1) result = (result * b) % _q;
    b = (b * b) % _q;
  }
  return result;
}

/// zeta^BitRev8(m) for zeta = 1753, the primitive 512th root of unity.
final _zetas = Int32List.fromList([for (var m = 0; m < 256; m++) _powMod(1753, _bitRev8(m))]);

/// 256^-1 mod q.
const _f = 8347681;

Int32List _ntt(Int32List w) {
  var m = 0;
  for (var len = 128; len >= 1; len >>= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final z = _zetas[++m];
      for (var j = start; j < start + len; j++) {
        final t = (z * w[j + len]) % _q;
        w[j + len] = (w[j] - t) % _q;
        w[j] = (w[j] + t) % _q;
      }
    }
  }
  return w;
}

Int32List _invNtt(Int32List w) {
  var m = 256;
  for (var len = 1; len < _n; len <<= 1) {
    for (var start = 0; start < _n; start += 2 * len) {
      final z = _q - _zetas[--m];
      for (var j = start; j < start + len; j++) {
        final t = w[j];
        w[j] = (t + w[j + len]) % _q;
        w[j + len] = (z * (t - w[j + len])) % _q;
      }
    }
  }
  for (var j = 0; j < _n; j++) {
    w[j] = (_f * w[j]) % _q;
  }
  return w;
}

/// The product of two polynomials in NTT form, coefficient by coefficient.
Int32List _pointwise(Int32List a, Int32List b) {
  final out = Int32List(_n);
  for (var j = 0; j < _n; j++) {
    out[j] = (a[j] * b[j]) % _q;
  }
  return out;
}

/// A row of A-hat times the vector [vHat], both in NTT form.
Int32List _rowTimes(List<Int32List> row, List<Int32List> vHat) {
  final sum = Int32List(_n);
  for (var s = 0; s < row.length; s++) {
    final a = row[s];
    final b = vHat[s];
    for (var j = 0; j < _n; j++) {
      sum[j] = (sum[j] + a[j] * b[j]) % _q;
    }
  }
  return sum;
}

// ─── Encoding (FIPS 204 Algorithms 16 to 28) ──────────────────────────────────

/// pkEncode: rho, then each t1 coefficient in 10 bits.
Uint8List _pkEncode(Uint8List rho, List<Int32List> t1) {
  final out = Uint8List(MlDsa65.publicKeyLength)..setAll(0, rho);
  for (var i = 0; i < _k; i++) {
    _pack(t1[i], _t1Bits, out, 32 + i * 32 * _t1Bits);
  }
  return out;
}

/// skEncode: rho, K, tr, then s1, s2 as eta - c in 4 bits and t0 as
/// 2^(d-1) - c in 13 bits.
Uint8List _skEncode(Uint8List rho, Uint8List key, Uint8List tr, List<Int32List> s1, List<Int32List> s2, List<Int32List> t0) {
  final out = Uint8List(MlDsa65.secretKeyLength)
    ..setAll(0, rho)
    ..setAll(32, key)
    ..setAll(64, tr);
  var offset = 128;
  void bitPack(Int32List poly, int bits, int bound) {
    // Coefficients are kept modulo q; centre them first.
    final values = Int32List(_n);
    for (var j = 0; j < _n; j++) {
      final c = poly[j] > _q ~/ 2 ? poly[j] - _q : poly[j];
      values[j] = bound - c;
    }
    _pack(values, bits, out, offset);
    offset += 32 * bits;
  }

  for (final s in s1) {
    bitPack(s, _etaBits, _eta);
  }
  for (final s in s2) {
    bitPack(s, _etaBits, _eta);
  }
  for (final t in t0) {
    bitPack(t, _t0Bits, 1 << (_d - 1));
  }
  return out;
}

/// skDecode: rho, K, tr, and s1, s2 and t0 with signed coefficients. Throws
/// an [ArgumentError] for an s1 or s2 coefficient out of range.
({Uint8List rho, Uint8List key, Uint8List tr, List<Int32List> s1, List<Int32List> s2, List<Int32List> t0}) _skDecode(Uint8List sk) {
  var offset = 128;
  List<Int32List> unpack(int count, int bits, int bound) => [
    for (var i = 0; i < count; i++, offset += 32 * bits) _bitUnpack(sk, offset, bits, bound),
  ];
  final s1 = unpack(_l, _etaBits, _eta);
  final s2 = unpack(_k, _etaBits, _eta);
  final t0 = unpack(_k, _t0Bits, 1 << (_d - 1));
  return (
    rho: Uint8List.sublistView(sk, 0, 32),
    key: Uint8List.sublistView(sk, 32, 64),
    tr: Uint8List.sublistView(sk, 64, 128),
    s1: s1,
    s2: s2,
    t0: t0,
  );
}

/// sigEncode: c~, then each z coefficient as gamma1 - c in 20 bits, then
/// HintBitPack: the positions of the hints of each polynomial in turn, and
/// in the last k bytes where each polynomial's positions end.
Uint8List _sigEncode(Uint8List cTilde, List<Int32List> z, List<Uint8List> h) {
  final out = Uint8List(MlDsa65.signatureLength)..setAll(0, cTilde);
  for (var i = 0; i < _l; i++) {
    final values = Int32List(_n);
    for (var j = 0; j < _n; j++) {
      values[j] = _gamma1 - z[i][j];
    }
    _pack(values, _zBits, out, _cTildeLength + i * 32 * _zBits);
  }
  final hints = _cTildeLength + _l * 32 * _zBits;
  var index = 0;
  for (var i = 0; i < _k; i++) {
    for (var j = 0; j < _n; j++) {
      if (h[i][j] != 0) out[hints + index++] = j;
    }
    out[hints + _omega + i] = index;
  }
  return out;
}

/// HintBitUnpack of the omega + k bytes at [offset]: null (FIPS 204's ⊥)
/// unless the ends never go back or past omega, each polynomial's
/// positions rise, and the unused position bytes are 0, so that a set of
/// hints has one encoding only.
List<Uint8List>? _hintBitUnpack(Uint8List bytes, int offset) {
  final h = [for (var i = 0; i < _k; i++) Uint8List(_n)];
  var index = 0;
  for (var i = 0; i < _k; i++) {
    final end = bytes[offset + _omega + i];
    if (end < index || end > _omega) return null;
    final first = index;
    for (; index < end; index++) {
      if (index > first && bytes[offset + index - 1] >= bytes[offset + index]) return null;
      h[i][bytes[offset + index]] = 1;
    }
  }
  for (; index < _omega; index++) {
    if (bytes[offset + index] != 0) return null;
  }
  return h;
}

/// w1Encode: each w1 coefficient, 0 to 15, in 4 bits.
Uint8List _w1Encode(List<Int32List> w1) {
  final out = Uint8List(_k * 32 * _w1Bits);
  for (var i = 0; i < _k; i++) {
    _pack(w1[i], _w1Bits, out, i * 32 * _w1Bits);
  }
  return out;
}

/// BitUnpack: the coefficients bound - v of [bits]-bit words v, signed (as
/// Power2Round gives t0; the NTT takes them as they are). Throws an
/// [ArgumentError] for a word above 2 * bound (an s1 or s2 coefficient out
/// of range).
Int32List _bitUnpack(Uint8List bytes, int offset, int bits, int bound) {
  final out = _simpleBitUnpack(bytes, offset, bits);
  for (var i = 0; i < _n; i++) {
    if (out[i] > 2 * bound) throw ArgumentError('ML-DSA: coefficient out of range');
    out[i] = bound - out[i];
  }
  return out;
}

/// SimpleBitUnpack: 256 [bits]-bit words, little-endian, from [bytes] at
/// [offset].
Int32List _simpleBitUnpack(Uint8List bytes, int offset, int bits) {
  final out = Int32List(_n);
  final mask = (1 << bits) - 1;
  var buffer = 0;
  var have = 0;
  var pos = offset;
  for (var i = 0; i < _n; i++) {
    while (have < bits) {
      buffer |= bytes[pos++] << have;
      have += 8;
    }
    out[i] = buffer & mask;
    buffer >>= bits;
    have -= bits;
  }
  return out;
}

/// 256 [bits]-bit words, little-endian, into [out] at [offset].
void _pack(Int32List values, int bits, Uint8List out, int offset) {
  var buffer = 0;
  var have = 0;
  var pos = offset;
  for (var i = 0; i < _n; i++) {
    buffer |= values[i] << have;
    have += bits;
    while (have >= 8) {
      out[pos++] = buffer & 0xff;
      buffer >>= 8;
      have -= 8;
    }
  }
}

bool _samePoly(Int32List a, Int32List b) {
  for (var j = 0; j < _n; j++) {
    if (a[j] != b[j]) return false;
  }
  return true;
}

bool _sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
