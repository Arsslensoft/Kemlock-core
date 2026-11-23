// The secrets of one signed-in account while they are in memory: the root, the
// user key and its children, the `kx1` and `sig1` private keys and the OPAQUE
// export key. The session takes ownership of the buffers it is given and
// [AccountSession.dispose] zeroes every one, which the sync plan calls on
// sign-out and lock (design 10: this also covers, for the new keys, the audit's
// note that `lock()` drops keys without wiping them).
//
// Dart can't promise wiping, because the garbage collector may have copied a
// buffer; so keys live in `Uint8List`s, never `String`s, and are cleared as
// soon as they are done with.

library;

import 'dart:typed_data';

import 'encoding.dart';
import 'keys.dart';

/// The secrets of one signed-in account, until [dispose].
final class AccountSession {
  /// A session over [keys] (see [AccountKeys.fromRoot]), the 96-byte `kx1`
  /// private key and the 64-byte `sig1` private key, and the 64-byte OPAQUE
  /// [exportKey] when the account has one. The session owns them all.
  AccountSession({required this.keys, required Uint8List kx1PrivateKey, required Uint8List sig1PrivateKey, Uint8List? exportKey})
    : _kx1PrivateKey = requireLength(kx1PrivateKey, 96, 'a kx1 private key'),
      _sig1PrivateKey = requireLength(sig1PrivateKey, 64, 'a sig1 private key'),
      _exportKey = exportKey == null ? null : requireLength(exportKey, 64, 'the export key');

  /// The root, the user key and the children.
  final AccountKeys keys;

  final Uint8List _kx1PrivateKey;
  final Uint8List _sig1PrivateKey;
  final Uint8List? _exportKey;
  bool _disposed = false;

  bool get isDisposed => _disposed;

  Uint8List get kx1PrivateKey => _live(_kx1PrivateKey);
  Uint8List get sig1PrivateKey => _live(_sig1PrivateKey);

  /// The OPAQUE export key, or null for an account that signed in another way.
  Uint8List? get exportKey => _exportKey == null ? null : _live(_exportKey);

  Uint8List _live(Uint8List key) {
    if (_disposed) throw StateError('the account session was disposed');
    return key;
  }

  /// Zeroes the root, the user key and its children, both private keys and the
  /// export key. The session can't be used afterwards.
  void dispose() {
    keys.dispose();
    wipe(_kx1PrivateKey);
    wipe(_sig1PrivateKey);
    final export = _exportKey;
    if (export != null) wipe(export);
    _disposed = true;
  }
}
