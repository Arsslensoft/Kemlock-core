// OpenSSH private keys (`openssh-key-v1`, OpenSSH's PROTOCOL.key) and the
// SSH wire form of public keys (RFC 4253, 5656, 8709): reading plain and
// protected Ed25519, ECDSA P-256 and P-384, and RSA keys, writing them
// with `aes256-ctr` and 16 rounds of bcrypt_pbkdf as `ssh-keygen` does,
// the `authorized_keys` line, and the `SHA256:` fingerprint `ssh-keygen -l`
// prints.

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;
import 'package:pointycastle/export.dart' as pc;

import '../bytes.dart';
import 'algorithms.dart';
import 'bcrypt_pbkdf.dart';
import 'der.dart';
import 'key_error.dart';
import 'pem.dart';

const opensshPemLabel = 'OPENSSH PRIVATE KEY';

final _magic = Uint8List.fromList('openssh-key-v1\x00'.codeUnits);

/// Whether [bytes] start with the binary OpenSSH private key magic.
bool hasOpenSshMagic(Uint8List bytes) => bytes.length >= _magic.length && _equal(Uint8List.sublistView(bytes, 0, _magic.length), _magic);

/// The ciphers read, and their key and block lengths. `ssh-keygen` writes
/// `aes256-ctr`; the others are what `-Z` offers.
const _ciphers = {
  'aes128-ctr': (16, 16),
  'aes192-ctr': (24, 16),
  'aes256-ctr': (32, 16),
  'aes128-cbc': (16, 16),
  'aes192-cbc': (24, 16),
  'aes256-cbc': (32, 16),
};

/// More bcrypt rounds than this are refused rather than run (`ssh-keygen`
/// uses 16, and `-a 100` is the most its manual suggests).
const maxBcryptRounds = 1000;

/// An OpenSSH private key: its parts and the comment stored with it.
class OpenSshKey {
  const OpenSshKey(this.material, this.comment);

  final KeyMaterial material;
  final String comment;
}

/// Reads an `openssh-key-v1` blob (the base64 of an `OPENSSH PRIVATE KEY`
/// block), decrypting it with [passphrase] when it is protected.
///
/// Throws [KeyFormatException]: [KeyProblem.unsupportedCipher] with the
/// cipher's name (`chacha20-poly1305@openssh.com`, ...),
/// [KeyProblem.unsupportedKeyType] with the key type's, a passphrase
/// needed or wrong, or [KeyProblem.damaged].
Future<OpenSshKey> readOpenSsh(Uint8List blob, String? passphrase) async {
  checkSize(blob.length);
  check(hasOpenSshMagic(blob), 'OpenSSH: no magic');
  final r = SshReader(Uint8List.sublistView(blob, _magic.length));
  final cipher = r.text();
  final kdf = r.text();
  final kdfOptions = SshReader(r.string());
  check(r.uint32() == 1, 'OpenSSH: not one key');
  final publicBlob = r.string();
  // The AEAD ciphers put a tag after this; they are refused below, before
  // anything that reads it.
  final cipherSpec = _ciphers[cipher];
  if (cipher != 'none' && cipherSpec == null) throw KeyFormatException(KeyProblem.unsupportedCipher, cipher);
  final encrypted = r.string();
  r.done();

  final type = SshReader(publicBlob).text();
  if (!_types.contains(type)) throw KeyFormatException(KeyProblem.unsupportedKeyType, type);

  final Uint8List private;
  if (cipherSpec == null) {
    check(kdf == 'none' && kdfOptions.isEmpty, 'OpenSSH: KDF without a cipher');
    private = encrypted;
  } else {
    if (kdf != 'bcrypt') throw KeyFormatException(KeyProblem.unsupportedCipher, kdf);
    final salt = kdfOptions.string();
    final rounds = kdfOptions.uint32();
    kdfOptions.done();
    check(salt.isNotEmpty && rounds >= 1, 'OpenSSH: bcrypt options');
    if (rounds > maxBcryptRounds) throw KeyFormatException(KeyProblem.unsupportedCipher, 'bcrypt with $rounds rounds');
    final (keyLength, blockLength) = cipherSpec;
    check(encrypted.isNotEmpty && encrypted.length % blockLength == 0, 'OpenSSH: encrypted length');
    if (passphrase == null) throw const KeyFormatException(KeyProblem.passphraseNeeded);
    if (passphrase.isEmpty) throw const KeyFormatException(KeyProblem.wrongPassphrase);
    final keyIv = bcryptPbkdf(utf8.encode(passphrase), salt, rounds, keyLength + 16);
    private = _crypt(
      cipher.endsWith('-ctr') ? _Mode.ctr : _Mode.cbcDecrypt,
      Uint8List.sublistView(keyIv, 0, keyLength),
      Uint8List.sublistView(keyIv, keyLength),
      encrypted,
    );
  }

  final p = SshReader(private);
  if (p.uint32() != p.uint32()) {
    throw KeyFormatException(cipherSpec == null ? KeyProblem.damaged : KeyProblem.wrongPassphrase, 'OpenSSH: check numbers differ');
  }
  check(p.text() == type, 'OpenSSH: private key type');
  final KeyMaterial material;
  switch (type) {
    case 'ssh-ed25519':
      final public = p.string();
      final both = p.string();
      check(public.length == 32 && both.length == 64, 'OpenSSH: Ed25519 lengths');
      check(_equal(Uint8List.sublistView(both, 32), public), 'OpenSSH: Ed25519 public keys differ');
      material = await ed25519Material(Uint8List.sublistView(both, 0, 32), public);
    case 'ssh-rsa':
      final n = p.mpint();
      final e = p.mpint();
      final d = p.mpint();
      final iqmp = p.mpint();
      final rsa = RsaMaterial.fromPrimes(n: n, e: e, d: d, p: p.mpint(), q: p.mpint());
      check(rsa.qinv == iqmp, 'OpenSSH: RSA iqmp');
      material = rsa;
    default:
      final curve = EcCurve.bySshName(p.text());
      check(curve != null && type == 'ecdsa-sha2-${curve.sshName}', 'OpenSSH: ECDSA curve');
      final point = p.string();
      final d = p.mpintBytes();
      check(d.length <= curve!.size, 'OpenSSH: ECDSA scalar');
      material = ecMaterial(curve, d, point);
  }
  final comment = utf8.decode(p.string(), allowMalformed: true);
  // Padding: 1, 2, 3, ... up to the block size.
  for (var i = 1; !p.isEmpty; i++) {
    check(p.byte() == i, 'OpenSSH: padding');
  }
  check(_equal(sshPublicBlob(material.publicHalf!), publicBlob), 'OpenSSH: public key differs from the private key');
  return OpenSshKey(material, comment);
}

const _types = {'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384'};

/// [material] as an `OPENSSH PRIVATE KEY` PEM block, as `ssh-keygen`
/// writes it: with a [passphrase], encrypted with `aes256-ctr` under
/// bcrypt_pbkdf with a random 16-byte salt and [rounds] rounds.
String writeOpenSsh(KeyMaterial material, {String comment = '', String? passphrase, int rounds = 16}) {
  final half = material.publicHalf;
  if (half == null || !half.algorithm.hasSshForm) throw ArgumentError.value(material, 'material', 'has no OpenSSH form');
  final checkNumber = randomBytes(4);
  final w = SshWriter()
    ..raw(checkNumber)
    ..raw(checkNumber)
    ..text(_sshType(half));
  switch (material) {
    case Ed25519Material(:final seed, :final publicKey):
      w
        ..string(publicKey)
        ..string(concatBytes([seed, publicKey]));
    case EcMaterial(:final curve, :final d, :final point):
      w
        ..text(curve.sshName)
        ..string(point)
        ..mpint(bytesToBigInt(d));
    case RsaMaterial():
      for (final v in [material.n, material.e, material.d, material.qinv, material.p, material.q]) {
        w.mpint(v);
      }
    default:
      throw ArgumentError.value(material, 'material', 'has no OpenSSH form');
  }
  w.string(utf8.encode(comment));
  final blockLength = passphrase == null ? 8 : 16;
  for (var i = 1; w.length % blockLength != 0; i++) {
    w.raw([i]);
  }

  final out = SshWriter()..raw(_magic);
  if (passphrase == null) {
    out
      ..text('none')
      ..text('none')
      ..string(const [])
      ..uint32(1)
      ..string(sshPublicBlob(half))
      ..string(w.bytes);
  } else {
    final salt = randomBytes(16);
    final keyIv = bcryptPbkdf(utf8.encode(passphrase), salt, rounds, 48);
    out
      ..text('aes256-ctr')
      ..text('bcrypt')
      ..string(
        (SshWriter()
              ..string(salt)
              ..uint32(rounds))
            .bytes,
      )
      ..uint32(1)
      ..string(sshPublicBlob(half))
      ..string(_crypt(_Mode.ctr, Uint8List.sublistView(keyIv, 0, 32), Uint8List.sublistView(keyIv, 32), w.bytes));
  }
  return writePem(opensshPemLabel, out.bytes, lineLength: 70);
}

// ─── Public keys ──────────────────────────────────────────────────────────────

String _sshType(PublicHalf half) => switch (half) {
  RsaPublicHalf() => 'ssh-rsa',
  EcPublicHalf(:final curve) => 'ecdsa-sha2-${curve.sshName}',
  RawPublicHalf(algorithm: KeyAlgorithm.ed25519) => 'ssh-ed25519',
  RawPublicHalf() => throw ArgumentError.value(half.algorithm, 'algorithm', 'has no OpenSSH form'),
};

/// The SSH wire form of [half]: what the `ssh-...` line carries in base64
/// and what `ssh-keygen -l` hashes. Throws an [ArgumentError] for an
/// algorithm SSH has no key type for.
Uint8List sshPublicBlob(PublicHalf half) {
  final w = SshWriter()..text(_sshType(half));
  switch (half) {
    case RsaPublicHalf(:final n, :final e):
      w
        ..mpint(e)
        ..mpint(n);
    case EcPublicHalf(:final curve, :final point):
      w
        ..text(curve.sshName)
        ..string(point);
    case RawPublicHalf(:final bytes):
      w.string(bytes);
  }
  return w.bytes;
}

/// The `authorized_keys` line: type, base64 and, when there is one,
/// [comment] with any line breaks turned into spaces.
String sshPublicLine(PublicHalf half, {String? comment}) {
  final line = '${_sshType(half)} ${base64.encode(sshPublicBlob(half))}';
  final note = comment?.replaceAll(RegExp(r'[\r\n]+'), ' ').trim() ?? '';
  return note.isEmpty ? line : '$line $note';
}

/// SHA-256 of [half]'s wire form, as `ssh-keygen -l` hashes it.
Uint8List sshFingerprint(PublicHalf half) => Uint8List.fromList(hash.sha256.convert(sshPublicBlob(half)).bytes);

// ─── The wire format ──────────────────────────────────────────────────────────

/// Reads RFC 4251 types; every length is checked against what is left, and
/// a short read throws [KeyProblem.damaged].
class SshReader {
  SshReader(this._bytes);

  final Uint8List _bytes;
  int _pos = 0;

  bool get isEmpty => _pos >= _bytes.length;

  int byte() {
    check(_pos < _bytes.length, 'SSH: cut short');
    return _bytes[_pos++];
  }

  int uint32() {
    check(_bytes.length - _pos >= 4, 'SSH: cut short');
    final value = _bytes.buffer.asByteData(_bytes.offsetInBytes).getUint32(_pos);
    _pos += 4;
    return value;
  }

  Uint8List string() {
    final length = uint32();
    check(length <= _bytes.length - _pos, 'SSH: length past the end');
    final out = Uint8List.sublistView(_bytes, _pos, _pos + length);
    _pos += length;
    return out;
  }

  String text() => utf8.decode(string(), allowMalformed: true);

  /// A non-negative mpint's magnitude, without leading zeros.
  Uint8List mpintBytes() {
    final bytes = string();
    check(bytes.isEmpty || bytes[0] & 0x80 == 0, 'SSH: negative mpint');
    var start = 0;
    while (start < bytes.length && bytes[start] == 0) {
      start++;
    }
    return Uint8List.sublistView(bytes, start);
  }

  BigInt mpint() => bytesToBigInt(mpintBytes());

  void done() => check(isEmpty, 'SSH: trailing data');
}

class SshWriter {
  final _out = BytesBuilder(copy: false);

  int get length => _out.length;

  Uint8List get bytes => _out.toBytes();

  void raw(List<int> bytes) => _out.add(bytes);

  void uint32(int value) => _out.add([value >>> 24 & 0xff, value >>> 16 & 0xff, value >>> 8 & 0xff, value & 0xff]);

  void string(List<int> bytes) {
    uint32(bytes.length);
    _out.add(bytes);
  }

  void text(String value) => string(utf8.encode(value));

  void mpint(BigInt value) {
    final magnitude = bigIntToBytes(value);
    string(magnitude.isNotEmpty && magnitude[0] & 0x80 != 0 ? [0, ...magnitude] : magnitude);
  }
}

enum _Mode { ctr, cbcDecrypt }

Uint8List _crypt(_Mode mode, Uint8List key, Uint8List iv, Uint8List data) {
  final params = pc.ParametersWithIV(pc.KeyParameter(key), iv);
  final out = Uint8List(data.length);
  switch (mode) {
    case _Mode.ctr:
      (pc.CTRStreamCipher(pc.AESEngine())..init(true, params)).processBytes(data, 0, data.length, out, 0);
    case _Mode.cbcDecrypt:
      final cbc = pc.CBCBlockCipher(pc.AESEngine())..init(false, params);
      for (var i = 0; i < data.length; i += 16) {
        cbc.processBlock(data, i, out, i);
      }
  }
  return out;
}

bool _equal(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
