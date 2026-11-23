// The keys of a Kemlock account, from `docs/crypto.md` "Account keys":
//
//   root key       64 random bytes, shaped like Bitwarden's user key, so one
//                  account has one root whichever API it uses. On a
//                  Compatible account it is the Bitwarden user key.
//   user key       HKDF(ikm = root, salt = absent, info = "kemlock/v1/user", L = 32)
//   child keys     HKDF(ikm = user key or space key, salt = absent,
//                  info = label, L = 32), one label each.
//
// An absent salt is 32 zero bytes, which `hkdfSha256` does for an empty one.

library;

import 'dart:typed_data';

import '../bytes.dart';
import '../hkdf.dart';
import 'encoding.dart';

/// The labels of `crypto.md` "Account keys", as the ASCII text the HKDF `info`
/// is made of.
abstract final class KeyLabel {
  /// The user key's, from the root.
  static const user = 'kemlock/v1/user';

  /// Wraps the item keys of the owner.
  static const itemWrap = 'kemlock/v1/item-wrap';

  /// Seals the names of a space, its collections and its groups, from the space key.
  static const spaceName = 'kemlock/v1/space-name';

  /// Seals the account's exchange and signing private keys.
  static const privateKeys = 'kemlock/v1/private-keys';

  /// Reserved for the signed manifest's MAC-less parts.
  static const manifest = 'kemlock/v1/manifest';
}

const rootKeyLength = 64;
const derivedKeyLength = 32;

/// A fresh root key: 64 random bytes. A Compatible account keeps the
/// Bitwarden user key it already has instead.
Uint8List newRootKey() => randomBytes(rootKeyLength);

/// The Kemlock user key of [root]: `HKDF(root, "kemlock/v1/user")`, 32 bytes.
Uint8List deriveUserKey(List<int> root) {
  requireLength(root, rootKeyLength, 'the root key');
  return hkdfSha256(root, salt: const [], info: label(KeyLabel.user), length: derivedKeyLength);
}

/// A child of [parent], the user key or a space key, under one of the
/// [KeyLabel]s, 32 bytes.
Uint8List deriveChildKey(List<int> parent, String childLabel) {
  requireLength(parent, derivedKeyLength, 'the parent key');
  return hkdfSha256(parent, salt: const [], info: label(childLabel), length: derivedKeyLength);
}

/// The keys of one account in memory: the root, the user key and its three
/// children. [dispose] zeroes every buffer, which the session calls on
/// sign-out and lock.
final class AccountKeys {
  AccountKeys._(this._root, this._userKey, this._itemWrap, this._privateKeys, this._manifest);

  /// Derives the user key and its children from [root] (64 bytes). The root
  /// is copied, so the caller can wipe its own buffer.
  factory AccountKeys.fromRoot(List<int> root) {
    final rootCopy = copyBytes(requireLength(root, rootKeyLength, 'the root key'));
    final userKey = deriveUserKey(rootCopy);
    return AccountKeys._(
      rootCopy,
      userKey,
      deriveChildKey(userKey, KeyLabel.itemWrap),
      deriveChildKey(userKey, KeyLabel.privateKeys),
      deriveChildKey(userKey, KeyLabel.manifest),
    );
  }

  final Uint8List _root;
  final Uint8List _userKey;
  final Uint8List _itemWrap;
  final Uint8List _privateKeys;
  final Uint8List _manifest;
  bool _disposed = false;

  Uint8List get root => _live(_root);
  Uint8List get userKey => _live(_userKey);

  /// Wraps item keys of the owner.
  Uint8List get itemWrapKey => _live(_itemWrap);

  /// Seals the exchange and signing private keys.
  Uint8List get privateKeysKey => _live(_privateKeys);

  /// Reserved for the signed manifest.
  Uint8List get manifestKey => _live(_manifest);

  bool get isDisposed => _disposed;

  Uint8List _live(Uint8List key) {
    if (_disposed) throw StateError('the account keys were disposed');
    return key;
  }

  /// Zeroes every key. The object can't be used afterwards.
  void dispose() {
    for (final key in [_root, _userKey, _itemWrap, _privateKeys, _manifest]) {
      wipe(key);
    }
    _disposed = true;
  }
}
