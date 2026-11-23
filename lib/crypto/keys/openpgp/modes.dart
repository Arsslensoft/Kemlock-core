// The ways OpenPGP encrypts data with AES (RFC 9580 sections 5.13 and
// 12): CFB as a stream, with the prefix and SHA-1 check of SEIPD version 1;
// OCB (RFC 7253) and EAX over the AES block, GCM through `cryptography`;
// and the chunked AEAD of SEIPD version 2 and of GnuPG's OCB packet.

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:cryptography/cryptography.dart' as c;
import 'package:cryptography/dart.dart' as cd;
// The AES block itself, which the package keeps to itself: OCB, EAX, CFB
// and key wrap are built on single blocks, and this one is seven times
// faster than pointycastle's when compiled ahead of time (74 MB/s against
// 11 on the machine decision 13 was measured on).
// ignore: implementation_imports
import 'package:cryptography/src/dart/aes_impl.dart' as block;

import 'packets.dart';
import 'pgp_error.dart';
import 'stream.dart';

// ─── Ciphers ──────────────────────────────────────────────────────────────────

const cipherAes128 = 7;
const cipherAes192 = 8;
const cipherAes256 = 9;

const _cipherNames = {
  0: 'no encryption',
  1: 'IDEA',
  2: '3DES',
  3: 'CAST5',
  4: 'Blowfish',
  7: 'AES-128',
  8: 'AES-192',
  9: 'AES-256',
  10: 'Twofish',
  11: 'Camellia-128',
  12: 'Camellia-192',
  13: 'Camellia-256',
};

/// The usual name of the symmetric cipher [id].
String cipherName(int id) => _cipherNames[id] ?? 'cipher $id';

/// The key length of AES-128, 192 or 256. Throws
/// [PgpProblem.unsupported], naming the cipher, for any other.
int cipherKeyLength(int id) => switch (id) {
  cipherAes128 => 16,
  cipherAes192 => 24,
  cipherAes256 => 32,
  _ => throw PgpException(PgpProblem.unsupported, detail: cipherName(id)),
};

/// The AES block cipher under one key, in both directions.
class AesBlock {
  AesBlock(Uint8List key) : _key = c.SecretKeyData(key), _encrypt = block.aesExpandKeyForEncrypting(c.SecretKeyData(key));

  final c.SecretKeyData _key;
  final Uint32List _encrypt;
  Uint32List? _decrypt;

  // The block functions work on 32-bit words: one block in, one out
  final _in = Uint32List(4);
  final _out = Uint32List(4);
  late final _inBytes = Uint8List.view(_in.buffer);
  late final _outBytes = Uint8List.view(_out.buffer);

  void encrypt(Uint8List input, int inOff, Uint8List out, int outOff) {
    final inBytes = _inBytes;
    for (var i = 0; i < 16; i++) {
      inBytes[i] = input[inOff + i];
    }
    block.aesEncryptBlock(_out, 0, _in, 0, _encrypt);
    final outBytes = _outBytes;
    for (var i = 0; i < 16; i++) {
      out[outOff + i] = outBytes[i];
    }
  }

  void decrypt(Uint8List input, int inOff, Uint8List out, int outOff) {
    final inBytes = _inBytes;
    for (var i = 0; i < 16; i++) {
      inBytes[i] = input[inOff + i];
    }
    block.aesDecryptBlock(_out, 0, _in, 0, _decrypt ??= block.aesExpandKeyForDecrypting(_key));
    final outBytes = _outBytes;
    for (var i = 0; i < 16; i++) {
      out[outOff + i] = outBytes[i];
    }
  }

  /// The encryption of one block.
  Uint8List encrypted(Uint8List input) {
    final out = Uint8List(16);
    encrypt(input, 0, out, 0);
    return out;
  }
}

// ─── CFB ──────────────────────────────────────────────────────────────────────

/// AES in CFB mode over data that comes in pieces of any size, with no
/// resynchronisation: what `writer.dart`'s `cfb` does to one buffer.
class CfbStream {
  CfbStream(Uint8List key, {required this.encrypt, Uint8List? iv}) : _aes = AesBlock(key) {
    if (iv != null) _register.setAll(0, iv);
  }

  final AesBlock _aes;
  final bool encrypt;
  final _register = Uint8List(16);
  final _stream = Uint8List(16);

  /// How much of [_stream] is used up; 16 when a new block is due.
  int _used = 16;

  Uint8List process(Uint8List data) {
    final length = data.length;
    final out = Uint8List(length);
    final register = _register;
    final stream = _stream;
    final encrypt = this.encrypt;
    var i = 0;
    // What is left of a block a previous piece began
    var used = _used;
    while (i < length && used < 16) {
      final b = data[i] ^ stream[used];
      out[i] = b;
      register[used++] = encrypt ? b : data[i];
      i++;
    }
    // Whole blocks
    while (length - i >= 16) {
      _aes.encrypt(register, 0, stream, 0);
      for (var j = 0; j < 16; j++) {
        final b = data[i + j] ^ stream[j];
        out[i + j] = b;
        register[j] = encrypt ? b : data[i + j];
      }
      i += 16;
      used = 16;
    }
    // The start of a block the next piece will finish
    if (i < length) {
      _aes.encrypt(register, 0, stream, 0);
      used = 0;
      while (i < length) {
        final b = data[i] ^ stream[used];
        out[i] = b;
        register[used++] = encrypt ? b : data[i];
        i++;
      }
    }
    _used = used;
    return out;
  }
}

/// The plain text of a version 1 SEIPD packet's body (after its version
/// octet), decrypted as it is read. The last 22 bytes, the MDC packet, are
/// held back and checked when the data ends: the end of this source means
/// the SHA-1 matched, and a mismatch throws [PgpProblem.damaged]. Whoever
/// reads it must not act on what it gives before that end.
class Seipd1Reader implements ByteSource {
  Seipd1Reader(Uint8List key, ByteSource cipherText, {this.wrongKeyIs = PgpProblem.damaged})
    : _cfb = CfbStream(key, encrypt: false),
      _in = cipherText {
    _hash = hash.sha1.startChunkedConversion(_digest);
  }

  /// What a prefix whose last two bytes do not repeat is reported as: with
  /// a key derived from a passphrase, [PgpProblem.wrongPassphrase].
  final PgpProblem wrongKeyIs;

  final CfbStream _cfb;
  final ByteSource _in;
  final _digest = _DigestSink();
  late final ByteConversionSink _hash;
  final _held = BytesBuilder(copy: true);
  bool _prefixRead = false;
  bool _done = false;

  static const _prefixLength = 18;
  static const _mdcLength = 22;

  @override
  Uint8List? next() {
    while (!_done) {
      final piece = _in.next();
      if (piece == null) {
        _done = true;
        final tail = _held.takeBytes();
        pgpCheck(_prefixRead && tail.length == _mdcLength, 'SEIPD: cut short');
        pgpCheck(tail[0] == 0xc0 | PgpTag.mdc && tail[1] == 20, 'SEIPD: no MDC');
        _hash
          ..add(Uint8List.sublistView(tail, 0, 2))
          ..close();
        final digest = _digest.value!.bytes;
        var diff = 0;
        for (var i = 0; i < 20; i++) {
          diff |= digest[i] ^ tail[2 + i];
        }
        pgpCheck(diff == 0, 'SEIPD: the MDC does not match');
        return null;
      }
      _held.add(_cfb.process(piece));
      if (!_prefixRead) {
        if (_held.length < _prefixLength) continue;
        final all = _held.takeBytes();
        // The last two bytes of the prefix repeat the two before them: a
        // wrong key is told from damaged data here, 65535 times in 65536.
        if (all[14] != all[16] || all[15] != all[17]) throw PgpException(wrongKeyIs, detail: 'SEIPD: prefix');
        _hash.add(Uint8List.sublistView(all, 0, _prefixLength));
        _held.add(Uint8List.sublistView(all, _prefixLength));
        _prefixRead = true;
      }
      if (_held.length > _mdcLength) {
        final all = _held.takeBytes();
        final out = Uint8List.sublistView(all, 0, all.length - _mdcLength);
        _held.add(Uint8List.sublistView(all, all.length - _mdcLength));
        _hash.add(out);
        return out;
      }
    }
    return null;
  }
}

/// Writes the body of a version 1 SEIPD packet into [_out]: the version
/// octet, then AES in CFB mode over the 16 random bytes of [prefix] with
/// its last two repeated, the data, and at [close] the MDC packet.
class Seipd1Writer implements ByteSink {
  Seipd1Writer(Uint8List key, Uint8List prefix, this._out) : _cfb = CfbStream(key, encrypt: true) {
    if (prefix.length != 16) throw ArgumentError.value(prefix.length, 'prefix', 'must be 16 bytes');
    _hash = hash.sha1.startChunkedConversion(_digest);
    _out.add(Uint8List.fromList([1]));
    add(Uint8List.fromList([...prefix, prefix[14], prefix[15]]));
  }

  final CfbStream _cfb;
  final ByteSink _out;
  final _digest = _DigestSink();
  late final ByteConversionSink _hash;

  @override
  void add(Uint8List data) {
    _hash.add(data);
    _out.add(_cfb.process(data));
  }

  void close() {
    final head = Uint8List.fromList([0xc0 | PgpTag.mdc, 20]);
    _hash
      ..add(head)
      ..close();
    _out.add(_cfb.process(Uint8List.fromList([...head, ..._digest.value!.bytes])));
  }
}

typedef ByteConversionSink = Sink<List<int>>;

class _DigestSink implements Sink<hash.Digest> {
  hash.Digest? value;

  @override
  void add(hash.Digest data) => value = data;

  @override
  void close() {}
}

// ─── AEAD ─────────────────────────────────────────────────────────────────────

const aeadEax = 1;
const aeadOcb = 2;
const aeadGcm = 3;

/// The usual name of the AEAD mode [id].
String aeadName(int id) => switch (id) {
  aeadEax => 'EAX',
  aeadOcb => 'OCB',
  aeadGcm => 'GCM',
  _ => 'AEAD mode $id',
};

/// An authenticated mode of AES with a 16-byte tag.
abstract class Aead {
  /// The mode [id] under [key]. Throws [PgpProblem.unsupported] for a mode
  /// other than EAX, OCB and GCM.
  factory Aead(int id, Uint8List key) => switch (id) {
    aeadEax => Eax(key),
    aeadOcb => Ocb(key),
    aeadGcm => Gcm(key),
    _ => throw PgpException(PgpProblem.unsupported, detail: aeadName(id)),
  };

  /// 16 for EAX, 15 for OCB, 12 for GCM.
  int get nonceLength;

  /// The cipher text of [plain], then the tag.
  Uint8List seal(Uint8List nonce, Uint8List plain, Uint8List ad);

  /// The plain text of [sealed] (cipher text and tag); null when the tag
  /// does not match.
  Uint8List? open(Uint8List nonce, Uint8List sealed, Uint8List ad);
}

const _tagLength = 16;

bool _sameTag(Uint8List a, Uint8List b, int bOffset) {
  var diff = 0;
  for (var i = 0; i < _tagLength; i++) {
    diff |= a[i] ^ b[bOffset + i];
  }
  return diff == 0;
}

/// Doubling in GF(2^128), as OCB and CMAC use it.
Uint8List _double(Uint8List block) {
  final out = Uint8List(16);
  var carry = 0;
  for (var i = 15; i >= 0; i--) {
    out[i] = ((block[i] << 1) | carry) & 0xff;
    carry = block[i] >> 7;
  }
  if (carry != 0) out[15] ^= 0x87;
  return out;
}

void _xorInto(Uint8List target, Uint8List other, [int otherOffset = 0]) {
  for (var i = 0; i < 16; i++) {
    target[i] ^= other[otherOffset + i];
  }
}

/// OCB3 (RFC 7253) with a 128-bit tag.
class Ocb implements Aead {
  Ocb(Uint8List key) : _aes = AesBlock(key) {
    _lStar = _aes.encrypted(Uint8List(16));
    _lDollar = _double(_lStar);
    _l.add(_double(_lDollar));
  }

  final AesBlock _aes;
  late final Uint8List _lStar;
  late final Uint8List _lDollar;
  final _l = <Uint8List>[];

  @override
  int get nonceLength => 15;

  /// L_i for i the number of trailing zero bits of [block] (from 1).
  Uint8List _lFor(int block) {
    var ntz = 0;
    while (block & 1 == 0) {
      block >>= 1;
      ntz++;
    }
    while (_l.length <= ntz) {
      _l.add(_double(_l.last));
    }
    return _l[ntz];
  }

  Uint8List _initialOffset(Uint8List nonce) {
    if (nonce.isEmpty || nonce.length > 15) throw ArgumentError.value(nonce.length, 'nonce', 'must be 1 to 15 bytes');
    final block = Uint8List(16);
    block[15 - nonce.length] = 1;
    block.setAll(16 - nonce.length, nonce);
    final bottom = block[15] & 0x3f;
    block[15] &= 0xc0;
    final ktop = _aes.encrypted(block);
    final stretch = Uint8List(24)..setAll(0, ktop);
    for (var i = 0; i < 8; i++) {
      stretch[16 + i] = ktop[i] ^ ktop[i + 1];
    }
    final bytes = bottom >> 3;
    final bits = bottom & 7;
    final offset = Uint8List(16);
    for (var i = 0; i < 16; i++) {
      offset[i] = bits == 0 ? stretch[i + bytes] : ((stretch[i + bytes] << bits) | (stretch[i + bytes + 1] >> (8 - bits))) & 0xff;
    }
    return offset;
  }

  Uint8List _hash(Uint8List ad) {
    final sum = Uint8List(16);
    final offset = Uint8List(16);
    final block = Uint8List(16);
    final full = ad.length >> 4;
    for (var i = 0; i < full; i++) {
      _xorInto(offset, _lFor(i + 1));
      for (var j = 0; j < 16; j++) {
        block[j] = ad[i * 16 + j] ^ offset[j];
      }
      _aes.encrypt(block, 0, block, 0);
      _xorInto(sum, block);
    }
    final rest = ad.length & 15;
    if (rest > 0) {
      _xorInto(offset, _lStar);
      block.fillRange(0, 16, 0);
      block.setRange(0, rest, ad, full * 16);
      block[rest] = 0x80;
      _xorInto(block, offset);
      _aes.encrypt(block, 0, block, 0);
      _xorInto(sum, block);
    }
    return sum;
  }

  Uint8List _crypt(Uint8List nonce, Uint8List input, int length, Uint8List ad, {required bool encrypt, required Uint8List out}) {
    final offset = _initialOffset(nonce);
    final checksum = Uint8List(16);
    final block = Uint8List(16);
    final full = length >> 4;
    for (var i = 0; i < full; i++) {
      final at = i * 16;
      _xorInto(offset, _lFor(i + 1));
      for (var j = 0; j < 16; j++) {
        block[j] = input[at + j] ^ offset[j];
      }
      if (encrypt) {
        _xorInto(checksum, input, at);
        _aes.encrypt(block, 0, block, 0);
      } else {
        _aes.decrypt(block, 0, block, 0);
      }
      for (var j = 0; j < 16; j++) {
        out[at + j] = block[j] ^ offset[j];
      }
      if (!encrypt) _xorInto(checksum, out, at);
    }
    final rest = length & 15;
    if (rest > 0) {
      final at = full * 16;
      _xorInto(offset, _lStar);
      final pad = _aes.encrypted(offset);
      for (var j = 0; j < rest; j++) {
        out[at + j] = input[at + j] ^ pad[j];
        checksum[j] ^= encrypt ? input[at + j] : out[at + j];
      }
      checksum[rest] ^= 0x80;
    }
    _xorInto(checksum, offset);
    _xorInto(checksum, _lDollar);
    final tag = _aes.encrypted(checksum);
    _xorInto(tag, _hash(ad));
    return tag;
  }

  @override
  Uint8List seal(Uint8List nonce, Uint8List plain, Uint8List ad) {
    final out = Uint8List(plain.length + _tagLength);
    final tag = _crypt(nonce, plain, plain.length, ad, encrypt: true, out: out);
    out.setAll(plain.length, tag);
    return out;
  }

  @override
  Uint8List? open(Uint8List nonce, Uint8List sealed, Uint8List ad) {
    if (sealed.length < _tagLength) return null;
    final length = sealed.length - _tagLength;
    final out = Uint8List(length);
    final tag = _crypt(nonce, sealed, length, ad, encrypt: false, out: out);
    return _sameTag(tag, sealed, length) ? out : null;
  }
}

/// EAX: CTR for the data and OMAC (CMAC) for the nonce, the header and
/// the cipher text.
class Eax implements Aead {
  Eax(Uint8List key) : _aes = AesBlock(key) {
    _k1 = _double(_aes.encrypted(Uint8List(16)));
    _k2 = _double(_k1);
  }

  final AesBlock _aes;
  late final Uint8List _k1;
  late final Uint8List _k2;

  @override
  int get nonceLength => 16;

  /// OMAC^t: the CMAC of a block holding [t], then [data] up to [length].
  Uint8List _omac(int t, Uint8List data, int length) {
    final state = Uint8List(16);
    final block = Uint8List(16)..[15] = t;
    if (length == 0) {
      _xorInto(block, _k1);
      return _aes.encrypted(block);
    }
    _aes.encrypt(block, 0, state, 0);
    var pos = 0;
    while (length - pos > 16) {
      _xorInto(state, data, pos);
      _aes.encrypt(state, 0, state, 0);
      pos += 16;
    }
    final rest = length - pos;
    for (var i = 0; i < rest; i++) {
      state[i] ^= data[pos + i];
    }
    if (rest == 16) {
      _xorInto(state, _k1);
    } else {
      state[rest] ^= 0x80;
      _xorInto(state, _k2);
    }
    _aes.encrypt(state, 0, state, 0);
    return state;
  }

  void _ctr(Uint8List start, Uint8List input, int length, Uint8List out) {
    final counter = Uint8List.fromList(start);
    final stream = Uint8List(16);
    for (var pos = 0; pos < length; pos += 16) {
      _aes.encrypt(counter, 0, stream, 0);
      final n = length - pos < 16 ? length - pos : 16;
      for (var i = 0; i < n; i++) {
        out[pos + i] = input[pos + i] ^ stream[i];
      }
      for (var i = 15; i >= 0; i--) {
        if (++counter[i] != 0) break;
      }
    }
  }

  Uint8List _tag(Uint8List n, Uint8List ad, Uint8List cipher, int length) {
    final tag = Uint8List.fromList(n);
    _xorInto(tag, _omac(1, ad, ad.length));
    _xorInto(tag, _omac(2, cipher, length));
    return tag;
  }

  @override
  Uint8List seal(Uint8List nonce, Uint8List plain, Uint8List ad) {
    final n = _omac(0, nonce, nonce.length);
    final out = Uint8List(plain.length + _tagLength);
    _ctr(n, plain, plain.length, out);
    out.setAll(plain.length, _tag(n, ad, out, plain.length));
    return out;
  }

  @override
  Uint8List? open(Uint8List nonce, Uint8List sealed, Uint8List ad) {
    if (sealed.length < _tagLength) return null;
    final length = sealed.length - _tagLength;
    final n = _omac(0, nonce, nonce.length);
    if (!_sameTag(_tag(n, ad, sealed, length), sealed, length)) return null;
    final out = Uint8List(length);
    _ctr(n, sealed, length, out);
    return out;
  }
}

/// AES-GCM with a 12-byte nonce, through `cryptography`'s Dart code, as
/// `crypto/aes_gcm.dart` uses it.
class Gcm implements Aead {
  Gcm(Uint8List key) : _key = c.SecretKeyData(key), _gcm = cd.DartAesGcm(secretKeyLength: key.length, nonceLength: 12);

  final c.SecretKeyData _key;
  final cd.DartAesGcm _gcm;

  @override
  int get nonceLength => 12;

  @override
  Uint8List seal(Uint8List nonce, Uint8List plain, Uint8List ad) {
    final box = _gcm.encryptSync(plain, secretKeyData: _key, nonce: nonce, aad: ad);
    return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
  }

  @override
  Uint8List? open(Uint8List nonce, Uint8List sealed, Uint8List ad) {
    if (sealed.length < _tagLength) return null;
    final length = sealed.length - _tagLength;
    try {
      final plain = _gcm.decryptSync(
        c.SecretBox(Uint8List.sublistView(sealed, 0, length), nonce: nonce, mac: c.Mac(Uint8List.sublistView(sealed, length))),
        secretKeyData: _key,
        aad: ad,
      );
      return Uint8List.fromList(plain);
    } on c.SecretBoxAuthenticationError {
      return null;
    }
  }
}

// ─── HKDF ─────────────────────────────────────────────────────────────────────

/// HKDF with SHA-256 (RFC 5869).
Uint8List hkdfSha256(List<int> ikm, {List<int> salt = const [], List<int> info = const [], required int length}) {
  final prk = hash.Hmac(hash.sha256, salt.isEmpty ? Uint8List(32) : salt).convert(ikm).bytes;
  final out = BytesBuilder();
  var block = <int>[];
  for (var i = 1; out.length < length; i++) {
    block = hash.Hmac(hash.sha256, prk).convert([...block, ...info, i]).bytes;
    out.add(block);
  }
  return Uint8List.sublistView(out.takeBytes(), 0, length);
}

// ─── Chunked AEAD ─────────────────────────────────────────────────────────────

/// The largest AEAD chunk read: 4 MiB, the cap of RFC 9580 and GnuPG's
/// default. A chunk is held whole until its tag is checked.
const maxAeadChunkOctet = 16;

Uint8List _be64(int v) => Uint8List(8)..buffer.asByteData().setUint64(0, v);

/// The plain text of data encrypted in AEAD chunks, each checked before it
/// is given out. The end of this source means the final tag, which covers
/// the total length, matched; a chunk or a final tag that does not match
/// throws [PgpProblem.damaged].
class AeadChunkReader implements ByteSource {
  AeadChunkReader._(this._aead, this._in, this._chunkSize, this._nonce, this._ad);

  /// The body of a version 2 SEIPD packet after its version octet (RFC
  /// 9580 section 5.13.2), under [sessionKey]. [cipher] and [aead] are
  /// read from it. Throws [PgpProblem.unsupported] for a cipher or mode
  /// that isn't read and for chunks over 4 MiB.
  factory AeadChunkReader.seipd2(PgpReader body, Uint8List sessionKey) {
    final head = body.bytes(3);
    final keyLength = cipherKeyLength(head[0]);
    final chunkSize = _chunkSizeOf(head[2]);
    final salt = body.bytes(32);
    final info = Uint8List.fromList([0xc0 | PgpTag.seipd, 2, ...head]);
    // The mode's nonce length, without making the mode under a wrong key
    final nonceLength = Aead(head[1], Uint8List(keyLength)).nonceLength;
    final derived = hkdfSha256(sessionKey, salt: salt, info: info, length: keyLength + nonceLength - 8);
    final aead = Aead(head[1], Uint8List.sublistView(derived, 0, keyLength));
    final iv = Uint8List.sublistView(derived, keyLength);
    return AeadChunkReader._(
      aead,
      body,
      chunkSize,
      (index) => Uint8List.fromList([...iv, ..._be64(index)]),
      (index, total) => total == null ? info : Uint8List.fromList([...info, ..._be64(total)]),
    );
  }

  /// The body of GnuPG's OCB packet, tag 20, after its version octet
  /// (LibrePGP section 5.16), under [sessionKey].
  factory AeadChunkReader.ocbPacket(PgpReader body, Uint8List sessionKey) {
    final head = body.bytes(3);
    pgpCheck(sessionKey.length == cipherKeyLength(head[0]), 'OCB packet: session key length');
    final chunkSize = _chunkSizeOf(head[2]);
    final aead = Aead(head[1], sessionKey);
    final iv = body.bytes(aead.nonceLength);
    final prefix = [0xc0 | PgpTag.ocbEncryptedData, 1, ...head];
    return AeadChunkReader._(aead, body, chunkSize, (index) {
      // The chunk index is xored into the last 8 bytes of the IV
      final nonce = Uint8List.fromList(iv);
      final count = _be64(index);
      for (var i = 0; i < 8; i++) {
        nonce[nonce.length - 8 + i] ^= count[i];
      }
      return nonce;
    }, (index, total) => Uint8List.fromList([...prefix, ..._be64(index), if (total != null) ..._be64(total)]));
  }

  static int _chunkSizeOf(int octet) {
    if (octet > maxAeadChunkOctet) throw const PgpException(PgpProblem.unsupported, detail: 'AEAD chunks over 4 MiB');
    return 1 << (octet + 6);
  }

  final Aead _aead;
  final PgpReader _in;
  final int _chunkSize;
  final Uint8List Function(int index) _nonce;
  final Uint8List Function(int index, int? total) _ad;

  Uint8List _held = Uint8List(0);
  int _index = 0;
  int _total = 0;
  bool _inEnded = false;
  bool _done = false;

  /// Reads until more than a whole chunk, its tag and the final tag are
  /// held, or the data ends.
  void _fill() {
    final want = _chunkSize + 2 * _tagLength + 1;
    if (_held.length >= want || _inEnded) return;
    final parts = BytesBuilder(copy: false)..add(_held);
    while (parts.length < want) {
      final piece = _in.some(want - parts.length);
      if (piece == null) {
        _inEnded = true;
        break;
      }
      parts.add(Uint8List.fromList(piece));
    }
    _held = parts.takeBytes();
  }

  @override
  Uint8List? next() {
    while (!_done) {
      _fill();
      final Uint8List sealed;
      if (_held.length > _chunkSize + 2 * _tagLength) {
        sealed = Uint8List.sublistView(_held, 0, _chunkSize + _tagLength);
      } else {
        // The last chunk, if any, and the final tag
        pgpCheck(_inEnded && _held.length >= _tagLength, 'AEAD: cut short');
        sealed = Uint8List.sublistView(_held, 0, _held.length - _tagLength);
        if (sealed.isEmpty) {
          final ok = _aead.open(_nonce(_index), _held, _ad(_index, _total));
          pgpCheck(ok != null, 'AEAD: the final tag does not match');
          _done = true;
          return null;
        }
        pgpCheck(sealed.length >= _tagLength, 'AEAD: cut short');
      }
      final plain = _aead.open(_nonce(_index), sealed, _ad(_index, null));
      pgpCheck(plain != null, 'AEAD: a chunk does not match');
      _held = Uint8List.sublistView(_held, sealed.length);
      _index++;
      _total += plain!.length;
      if (plain.isNotEmpty) return plain;
    }
    return null;
  }
}

/// Writes the body of a version 2 SEIPD packet (RFC 9580 section 5.13.2)
/// into [_out]: the version octet, AES-256, OCB, the chunk size octet and
/// [salt] (32 bytes), then the data sealed a chunk at a time and, at
/// [close], the final tag over the total length. The key and the IV come
/// from HKDF-SHA256 over [sessionKey] and the salt, as
/// [AeadChunkReader.seipd2] reads them.
class Seipd2Writer implements ByteSink {
  factory Seipd2Writer(Uint8List sessionKey, Uint8List salt, ByteSink out, {int chunkOctet = defaultAeadChunkOctet}) {
    if (sessionKey.length != 32) throw ArgumentError.value(sessionKey.length, 'sessionKey', 'must be 32 bytes, AES-256');
    if (salt.length != 32) throw ArgumentError.value(salt.length, 'salt', 'must be 32 bytes');
    if (chunkOctet > maxAeadChunkOctet) throw ArgumentError.value(chunkOctet, 'chunkOctet', 'must be at most $maxAeadChunkOctet');
    final head = [cipherAes256, aeadOcb, chunkOctet];
    final info = Uint8List.fromList([0xc0 | PgpTag.seipd, 2, ...head]);
    final derived = hkdfSha256(sessionKey, salt: salt, info: info, length: 32 + 15 - 8);
    out.add(Uint8List.fromList([2, ...head, ...salt]));
    return Seipd2Writer._(Ocb(Uint8List.sublistView(derived, 0, 32)), Uint8List.sublistView(derived, 32), info, 1 << (chunkOctet + 6), out);
  }

  Seipd2Writer._(this._ocb, this._iv, this._info, this._chunkSize, this._out);

  final Ocb _ocb;
  final Uint8List _iv;
  final Uint8List _info;
  final int _chunkSize;
  final ByteSink _out;
  final _held = BytesBuilder(copy: true);
  int _index = 0;
  int _total = 0;

  Uint8List _nonce(int index) => Uint8List.fromList([..._iv, ..._be64(index)]);

  void _seal(Uint8List chunk) {
    _out.add(_ocb.seal(_nonce(_index), chunk, _info));
    _index++;
    _total += chunk.length;
  }

  @override
  void add(Uint8List data) {
    _held.add(data);
    while (_held.length >= _chunkSize) {
      final all = _held.takeBytes();
      _seal(Uint8List.sublistView(all, 0, _chunkSize));
      _held.add(Uint8List.sublistView(all, _chunkSize));
    }
  }

  /// Seals what is left and writes the final tag.
  void close() {
    if (_held.length > 0) _seal(_held.takeBytes());
    _out.add(_ocb.seal(_nonce(_index), Uint8List(0), Uint8List.fromList([..._info, ..._be64(_total)])));
  }
}

/// The chunk size octet Kemlock writes: 10, chunks of 64 KiB.
const defaultAeadChunkOctet = 10;
