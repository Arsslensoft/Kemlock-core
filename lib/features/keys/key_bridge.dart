/// Between the vault's [VaultKey] and the key code's [crypto.ParsedKey],
/// and how a key is named on screen.
library;

import 'dart:typed_data';

import '../../crypto/background.dart';
import '../../crypto/bytes.dart';
import '../../crypto/keys/keys.dart' as crypto;
import '../../models/vault_key.dart';

/// [key] as the vault keeps it, under [id] and [name].
VaultKey vaultKeyOf(crypto.ParsedKey key, {required String id, required String name, required String origin}) => VaultKey(
  id: id,
  name: name,
  kind: key.kind.name,
  algorithm: key.algorithm,
  bits: key.bits,
  privateKey: b64(key.private),
  publicKey: key.public == null ? null : b64(key.public!),
  origin: origin,
  protected: key.kind == crypto.KeyKind.pgp && (key.pgp?.protected ?? false) ? true : null,
  addedAt: 0,
);

/// [key] for the key code to show, fingerprint and export. A PGP key's
/// details are read again from its secret key, which says whether it keeps
/// its own passphrase, as its public half can't.
crypto.ParsedKey parsedKeyOf(VaultKey key) {
  final kind = crypto.KeyKind.values.where((kind) => kind.name == key.kind).firstOrNull ?? crypto.KeyKind.other;
  final public = key.publicKey == null ? null : unb64(key.publicKey!);
  final private = unb64(key.privateKey);
  crypto.PgpKeyInfo? pgp;
  if (kind == crypto.KeyKind.pgp) {
    try {
      pgp = crypto.readPgpKeyInfo(private);
    } on crypto.KeyFormatException {
      pgp = null;
    }
  }
  return crypto.ParsedKey(kind: kind, algorithm: key.algorithm, bits: key.bits, private: private, public: public, pgp: pgp);
}

/// Reads a key from [input], text or bytes, off the UI isolate: opening one
/// with a passphrase runs a key derivation. Throws [crypto.KeyFormatException].
Future<crypto.ParsedKey> readKeyInBackground(Object input, {String? passphrase}) =>
    runInBackground(() => crypto.readPrivateKey(input, passphrase: passphrase), debugName: 'readKey');

/// Writes [key]'s private half in its kind's form off the UI isolate,
/// protected by [passphrase] unless it is null.
Future<String> exportKeyInBackground(crypto.ParsedKey key, {String? passphrase, String? comment}) => runInBackground(
  () => crypto.exportPrivateKey(key, passphrase: passphrase, comment: comment),
  debugName: 'exportKey',
);

/// The message id of a key kind's name.
String keyKindLabelId(String kind) => switch (kind) {
  KeyKind.ssh => 'keys.kind.ssh',
  KeyKind.signing => 'keys.kind.signing',
  KeyKind.exchange => 'keys.kind.exchange',
  KeyKind.pgp => 'keys.kind.pgp',
  _ => 'keys.kind.other',
};

/// How an algorithm is written on screen: `Ed25519`, `RSA 4096`,
/// `ML-KEM-768`; an unknown one by its identifier.
String algorithmLabel(String algorithm, [int? bits]) => switch (algorithm) {
  'ed25519' => 'Ed25519',
  'ecdsa-p256' => 'ECDSA P-256',
  'ecdsa-p384' => 'ECDSA P-384',
  'rsa' => bits == null ? 'RSA' : 'RSA $bits',
  'x25519' => 'X25519',
  'ml-kem-768' => 'ML-KEM-768',
  'ml-kem-1024' => 'ML-KEM-1024',
  'ml-dsa-65' => 'ML-DSA-65',
  'pgp' => 'OpenPGP',
  _ => algorithm,
};

/// The algorithm of a [crypto.GeneratedAlgorithm] as the menu names it.
String generatedLabel(crypto.GeneratedAlgorithm algorithm) => algorithmLabel(algorithm.id, algorithm.bits);

/// The file name an exported private key is saved under.
String exportedKeyFileName(VaultKey key) {
  final base = key.name.replaceAll(RegExp(r'[^A-Za-z0-9._-]+'), '-').replaceAll(RegExp('^-+|-+\$'), '');
  final name = base.isEmpty ? 'key' : base;
  return switch (key.kind) {
    KeyKind.ssh => name,
    KeyKind.pgp => '$name.asc',
    _ => '$name.pem',
  };
}

/// How a PGP key's primary algorithm is written on screen, from the name
/// GnuPG gives it: `ed25519` as Ed25519, `rsa4096` as RSA 4096; one with no
/// better name as GnuPG writes it.
String pgpAlgorithmLabel(crypto.PgpKey key) {
  final bits = key.bits;
  if (bits != null && key.algorithm.startsWith('rsa')) return 'RSA $bits';
  return switch (key.algorithm) {
    'ed25519' => 'Ed25519',
    'ed448' => 'Ed448',
    'nistp256' => 'NIST P-256',
    'nistp384' => 'NIST P-384',
    'nistp521' => 'NIST P-521',
    final other => other,
  };
}

/// The email address of a PGP user ID, `Ada <ada@example.org>` or a bare
/// address; null for a user ID without one.
///
/// A user ID is whatever the key's owner wrote, and this runs on the UI
/// isolate for every key on screen: it is read in one pass, with no
/// pattern, since a pattern tries a long user ID again from each of its
/// characters.
String? userIdAddress(String userId) {
  // The first `<...>` that holds an address and nothing else
  for (var open = userId.indexOf('<'); open >= 0; open = userId.indexOf('<', open + 1)) {
    var end = open + 1;
    while (end < userId.length && _inAddress(userId.codeUnitAt(end))) {
      end++;
    }
    if (end < userId.length && userId.codeUnitAt(end) == 0x3e && _hasAt(userId, open + 1, end)) return userId.substring(open + 1, end);
  }
  final bare = userId.trim();
  for (var i = 0; i < bare.length; i++) {
    if (!_inAddress(bare.codeUnitAt(i))) return null;
  }
  return _hasAt(bare, 0, bare.length) ? bare : null;
}

/// Whether [unit], a UTF-16 code unit, is white space: a space, a tab, a
/// line ending, or one of Unicode's other spaces.
bool isSpaceUnit(int unit) =>
    (unit >= 0x09 && unit <= 0x0d) ||
    unit == 0x20 ||
    unit == 0xa0 ||
    unit == 0x1680 ||
    (unit >= 0x2000 && unit <= 0x200a) ||
    unit == 0x2028 ||
    unit == 0x2029 ||
    unit == 0x202f ||
    unit == 0x205f ||
    unit == 0x3000 ||
    unit == 0xfeff;

/// Whether [unit] may be part of an address: anything but `<`, `>` and
/// white space.
bool _inAddress(int unit) => unit != 0x3c && unit != 0x3e && !isSpaceUnit(unit);

/// Whether [text] from [start] to [end] has an `@` with something on each
/// side of it.
bool _hasAt(String text, int start, int end) {
  for (var i = start + 1; i < end - 1; i++) {
    if (text.codeUnitAt(i) == 0x40) return true;
  }
  return false;
}

/// What the Vault tab writes under a PGP key's name: the address of its
/// first user ID that has one, and its algorithm, as `ada@example.org ·
/// Ed25519`; for a post-quantum key the algorithm it is encrypted to with,
/// `ML-KEM-768 + X25519`.
String pgpListLine(crypto.PgpKeyInfo info) {
  final address = info.userIdsMainFirst.map(userIdAddress).nonNulls.firstOrNull;
  return [?address, pgpPostQuantumEncryption(info) ?? pgpAlgorithmLabel(info.primary)].join(' · ');
}

/// What tells a key the vault holds from another (openspec:
/// add-pgp-key-editing, design decision 2). A PGP key whose public half
/// reads is its primary key's fingerprint, `pgp:` and the hexadecimal, so
/// a copy with more user IDs, subkeys or signatures is the same key. Any
/// other key, and a PGP key whose public half does not read, is told by
/// its public half, or by its private half for an algorithm Kemlock
/// doesn't know, as before.
String keyIdentity(VaultKey key) {
  final public = key.publicKey;
  if (key.kind == KeyKind.pgp && public != null) {
    try {
      return 'pgp:${crypto.readPgpKeyInfo(unb64(public)).primary.fingerprintHex}';
    } on crypto.KeyFormatException {
      // Told by its bytes, as before
    } on FormatException {
      // Not even base64
    }
  }
  return public ?? key.privateKey;
}

/// [key], a PGP key, with the halves [private] and [public] a change to it
/// or a merge gave, once they are checked to be the same key grown: both
/// read, have the key's primary fingerprint, and the private half holds
/// every packet [key]'s did. Null otherwise, and for a key of another kind.
VaultKey? grownPgpKey(VaultKey key, Uint8List private, Uint8List public) {
  if (key.kind != KeyKind.pgp) return null;
  try {
    final info = crypto.readPgpKeyInfo(private);
    if (crypto.readPgpKeyInfo(public).primary.fingerprintHex != info.primary.fingerprintHex) return null;
    if (!crypto.isGrownFrom(private, unb64(key.privateKey))) return null;
    return key.withHalves(privateKey: b64(private), publicKey: b64(public), protected: info.protected);
  } on crypto.KeyFormatException {
    return null;
  } on FormatException {
    return null;
  }
}

/// The PGP key [held] combined with another copy of it, [incoming], the
/// held copy preferred (openspec: add-pgp-key-editing, design decision 9):
/// with what [incoming] adds, checked as [grownPgpKey] checks. Null when
/// [incoming] adds nothing, is another key or does not read, when what it
/// adds is not the key's own doing ([crypto.verifiesWhatItAdds]: a copy
/// from a file could otherwise put an address in the key, expire it or
/// revoke it), and for keys of other kinds.
Future<VaultKey?> combinedPgpKey(VaultKey held, VaultKey incoming) async {
  if (held.kind != KeyKind.pgp || incoming.kind != KeyKind.pgp || held.privateKey == incoming.privateKey) return null;
  if (keyIdentity(held) != keyIdentity(incoming)) return null;
  try {
    final mine = unb64(held.privateKey);
    final merged = await crypto.mergePgpKeys(mine, unb64(incoming.privateKey), preferA: true);
    if (merged.length == mine.length && b64(merged) == held.privateKey) return null;
    if (!await crypto.verifiesWhatItAdds(merged, mine)) return null;
    final public = (await crypto.readPrivateKey(merged)).public;
    return public == null ? null : grownPgpKey(held, merged, public);
  } on crypto.KeyFormatException {
    return null;
  } on FormatException {
    return null;
  } on ArgumentError {
    return null;
  }
}

// ─── Post-quantum PGP keys (add-post-quantum-pgp) ─────────────────────────────

/// A fingerprint in groups of four: `1FCD A135 ...`.
String groupedFingerprintOf(String hex) =>
    [for (var i = 0; i < hex.length; i += 4) hex.substring(i, i + 4 > hex.length ? hex.length : i + 4)].join(' ');

/// The curves of Kyber keys as they are written on screen.
const _kyberCurves = {
  'cv25519': 'X25519',
  'cv448': 'X448',
  'bp256': 'brainpoolP256r1',
  'bp384': 'brainpoolP384r1',
  'bp512': 'brainpoolP512r1',
  'nistp256': 'NIST P-256',
  'nistp384': 'NIST P-384',
  'nistp521': 'NIST P-521',
};

/// How the post-quantum algorithm GnuPG names [name] is written on screen
/// (design decision 13): `ML-DSA-65 + Ed25519`, `ML-KEM-768 + X25519`,
/// `Kyber-768 + X25519`, `Kyber-768 + brainpoolP256r1`; any other name as
/// it is.
String pgpKeyAlgorithmName(String name) {
  final kyber = RegExp(r'^ky(\d+)_(\w+)$').firstMatch(name);
  if (kyber != null) return 'Kyber-${kyber[1]} + ${_kyberCurves[kyber[2]] ?? kyber[2]}';
  return switch (name) {
    'mld65' => 'ML-DSA-65 + Ed25519',
    'mld87' => 'ML-DSA-87 + Ed448',
    'mlk768' => 'ML-KEM-768 + X25519',
    'mlk1024' => 'ML-KEM-1024 + X448',
    _ => name,
  };
}

/// Whether the key named [name] encrypts post-quantum: ML-KEM with X25519
/// or X448, or Kyber.
bool _postQuantumEncryption(String name) => name == 'mlk768' || name == 'mlk1024' || name.startsWith('ky');

bool _postQuantum(String name) => _postQuantumEncryption(name) || name == 'mld65' || name == 'mld87' || name.startsWith('SLH-DSA');

/// Whether [key] can be encrypted to at [now]: it may encrypt, the app
/// uses its algorithm, and it is neither revoked nor expired.
bool _encryptsAt(crypto.PgpKey key, DateTime now) =>
    key.canEncrypt && key.usable && !key.revoked && (key.expires == null || now.isBefore(key.expires!));

/// The algorithm, as written on screen, that a message to [info] would be
/// encrypted with when it is post-quantum: the subkey Kemlock takes, a
/// post-quantum one before any classical one; null for a key that is
/// encrypted to classically.
String? pgpPostQuantumEncryption(crypto.PgpKeyInfo info, {DateTime? now}) {
  final at = now ?? DateTime.now();
  final keys = [...info.subkeys, info.primary];
  final chosen =
      keys.where((k) => _encryptsAt(k, at) && _postQuantumEncryption(k.algorithm)).firstOrNull ??
      // A key whose subkeys are all past their date is still named by its kind
      keys.where((k) => k.canEncrypt && k.usable && _postQuantumEncryption(k.algorithm)).firstOrNull;
  return chosen == null ? null : pgpKeyAlgorithmName(chosen.algorithm);
}

/// Whether a message to [info] at [now] is post-quantum protected: the
/// encryption subkey Kemlock takes is ML-KEM or Kyber (design decision 3).
bool pgpEncryptsPostQuantum(crypto.PgpKeyInfo info, DateTime now) =>
    [...info.subkeys, info.primary].any((k) => _encryptsAt(k, now) && _postQuantumEncryption(k.algorithm));

/// Whether [info] is in GnuPG's post-quantum format: a Kyber subkey, and
/// signatures that stay Ed25519.
bool pgpIsGnupgFormat(crypto.PgpKeyInfo info) => info.subkeys.any((k) => k.algorithm.startsWith('ky'));

/// The message that says who reads a post-quantum key: GnuPG's format, or
/// RFC 9980's standard one; null for a key that is not post-quantum.
String? pgpReadersMessageId(crypto.PgpKeyInfo info) {
  if (pgpIsGnupgFormat(info)) return 'keys.pgp.readers.gnupg';
  if ([info.primary, ...info.subkeys].any((k) => _postQuantum(k.algorithm))) return 'keys.pgp.readers.standard';
  return null;
}

/// What the app cannot do with [info], as messages and the algorithm each
/// names: sign, when its primary key is of an algorithm not used; encrypt
/// and decrypt, when an encryption subkey is.
List<(String, String)> pgpCannotMessages(crypto.PgpKeyInfo info) => [
  if (!info.primary.usable) ('keys.pgp.cannotSign', pgpKeyAlgorithmName(info.primary.algorithm)),
  for (final subkey in info.subkeys.where((k) => k.canEncrypt && !k.usable).take(1))
    ('keys.pgp.cannotEncrypt', pgpKeyAlgorithmName(subkey.algorithm)),
];
