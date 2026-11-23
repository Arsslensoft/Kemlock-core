/// The account as this phone holds it once signed in and opened: the root
/// key, the two private keys and the two public ones, sealed in the vault as
/// [keyKemlockAccount] (`km_session.dart`) with the `opaqueEnrolled` record
/// that closes the Bitwarden-hash route for good. The primitives are
/// `lib/crypto/account`'s; this is the record around them and the one place an
/// account is opened from a root key and what the server holds.
///
/// Pure Dart, no Flutter.
library;

import 'dart:typed_data';

import '../../../crypto/account/bundle.dart';
import '../../../crypto/account/encoding.dart';
import '../../../crypto/account/keys.dart';
import '../../../crypto/account/kx1.dart';
import '../../../crypto/account/private_keys.dart';
import '../../../crypto/account/session.dart';
import '../../../crypto/account/sig1.dart';
import '../../../crypto/bytes.dart' show constantTimeEquals;
import '../../../models/json.dart';
import 'km_auth_api.dart' show KmAccountMaterial;
import 'km_crypto.dart';

/// The account's keys can't be read: they don't match what the server holds, or the server's bundle
/// isn't signed by the account's own key. The sign-in stops, and nothing is stored.
class KmAccountUnreadable implements Exception {
  const KmAccountUnreadable(this.reason);

  final String reason;

  @override
  String toString() => 'The account’s keys can’t be opened: $reason.';
}

/// The account's secrets and public keys, as stored. It is sealed in the vault, so nothing here is
/// encrypted again.
class KmAccount {
  KmAccount({
    required this.accountId,
    required this.keyVersion,
    required this.rootKey,
    required this.kx1PrivateKey,
    required this.sig1PrivateKey,
    required this.kx1PublicKey,
    required this.sig1PublicKey,
    this.opaqueEnrolled = false,
    this.extra = const {},
  });

  factory KmAccount.fromJson(Map<String, Object?> json) {
    Uint8List bytes(String name, int length) {
      final value = json[name];
      if (value is! String) throw FormatException('$name is missing');
      final decoded = b64urlDecode(value);
      if (decoded.length != length) throw FormatException('$name is $length bytes');
      return decoded;
    }

    final accountId = json['accountId'];
    if (accountId is! String || !isUuidText(accountId)) throw const FormatException('the account id is a UUID');
    return KmAccount(
      accountId: accountId,
      keyVersion: asInt(json['keyVersion']) ?? 1,
      rootKey: bytes('rootKey', rootKeyLength),
      kx1PrivateKey: bytes('kx1PrivateKey', Kx1.privateKeyLength),
      sig1PrivateKey: bytes('sig1PrivateKey', Sig1.privateKeyLength),
      kx1PublicKey: bytes('kx1PublicKey', Kx1.publicKeyLength),
      sig1PublicKey: bytes('sig1PublicKey', Sig1.publicKeyLength),
      opaqueEnrolled: json['opaqueEnrolled'] == true,
      extra: extraKeys(json, _known),
    );
  }

  static const _known = {
    'accountId',
    'keyVersion',
    'rootKey',
    'kx1PrivateKey',
    'sig1PrivateKey',
    'kx1PublicKey',
    'sig1PublicKey',
    'opaqueEnrolled',
  };

  /// The account's id, a UUID.
  final String accountId;
  final int keyVersion;
  final Uint8List rootKey;
  final Uint8List kx1PrivateKey;
  final Uint8List sig1PrivateKey;
  final Uint8List kx1PublicKey;
  final Uint8List sig1PublicKey;

  /// This phone has seen the account enrolled in OPAQUE (a successful OPAQUE sign-in or registration), so
  /// it refuses the Bitwarden-hash route for it from now on, whatever the server says.
  final bool opaqueEnrolled;

  /// Keys this version doesn't know, kept as they were.
  final Map<String, Object?> extra;

  Map<String, Object?> toJson() => {
    'accountId': accountId,
    'keyVersion': keyVersion,
    'rootKey': b64urlEncode(rootKey),
    'kx1PrivateKey': b64urlEncode(kx1PrivateKey),
    'sig1PrivateKey': b64urlEncode(sig1PrivateKey),
    'kx1PublicKey': b64urlEncode(kx1PublicKey),
    'sig1PublicKey': b64urlEncode(sig1PublicKey),
    if (opaqueEnrolled) 'opaqueEnrolled': true,
    ...extra,
  };

  KmAccount withOpaqueEnrolled() => KmAccount(
    accountId: accountId,
    keyVersion: keyVersion,
    rootKey: rootKey,
    kx1PrivateKey: kx1PrivateKey,
    sig1PrivateKey: sig1PrivateKey,
    kx1PublicKey: kx1PublicKey,
    sig1PublicKey: sig1PublicKey,
    opaqueEnrolled: true,
    extra: extra,
  );

  /// An [AccountSession] over copies of the keys, so disposing it wipes the copies and not this record.
  AccountSession openSession() => AccountSession(
    keys: AccountKeys.fromRoot(rootKey),
    kx1PrivateKey: copyBytes(kx1PrivateKey),
    sig1PrivateKey: copyBytes(sig1PrivateKey),
  );

  /// Seals and opens this account's items, over [session] (from [openSession]).
  AccountItemCrypto itemCrypto(AccountSession session) =>
      AccountItemCrypto(session: session, sig1PublicKey: sig1PublicKey, owner: Owner.user(accountId), keyVersion: keyVersion);

  /// Zeroes the secrets.
  void wipeSecrets() {
    for (final key in [rootKey, kx1PrivateKey, sig1PrivateKey]) {
      wipe(key);
    }
  }

  /// Leaves the keys out, so they never end up in a log.
  @override
  String toString() => 'KmAccount($accountId)';
}

/// Whether a stored account record, which may hold only the `opaqueEnrolled` mark of a sign-in that
/// didn't get as far as keys, says OPAQUE was seen.
bool storedOpaqueSeen(Object? stored) => stored is Map<String, Object?> && stored['opaqueEnrolled'] == true;

/// Opens the account from its [rootKey] and what the server holds, checking that the keys are the
/// account's own: the private keys open under the user key and give the public keys of the bundle, and the
/// bundle is signed by the `sig1` key it names, for this account and key version. The caller wipes
/// [rootKey]; the returned account holds its own copy.
Future<KmAccount> openKmAccount({
  required String accountId,
  required Uint8List rootKey,
  required KmAccountMaterial material,
  bool opaqueEnrolled = false,
}) async {
  final bundleBytes = material.publicBundle;
  final signature = material.bundleSignature;
  final sealed = material.sealedPrivateKeys;
  if (bundleBytes == null || signature == null || sealed == null || bundleBytes.isEmpty || sealed.isEmpty) {
    throw const KmAccountUnreadable('the server holds no keys for this account');
  }
  final keys = AccountKeys.fromRoot(rootKey);
  try {
    final bundle = KeyBundle.parse(bundleBytes);
    if (uuidText(bundle.accountId) != accountId) throw const KmAccountUnreadable('the keys belong to another account');
    if (bundle.keyVersion != material.keyVersion) throw const KmAccountUnreadable('the key version differs');
    if (!await verifyBundle(bundle, signature)) throw const KmAccountUnreadable('the key bundle isn’t signed by the account’s own key');
    final privateKeys = await openPrivateKeys(
      privateKeysKey: keys.privateKeysKey,
      accountId: uuidBytes(accountId),
      keyVersion: bundle.keyVersion,
      sealed: sealed,
    );
    if (!constantTimeEquals(await Kx1.publicKeyOf(privateKeys.kx1PrivateKey), bundle.kx1PublicKey) ||
        !constantTimeEquals(await Sig1.publicKeyOf(privateKeys.sig1PrivateKey), bundle.sig1PublicKey)) {
      wipe(privateKeys.kx1PrivateKey);
      wipe(privateKeys.sig1PrivateKey);
      throw const KmAccountUnreadable('the private keys don’t match the bundle');
    }
    return KmAccount(
      accountId: accountId,
      keyVersion: bundle.keyVersion,
      rootKey: copyBytes(rootKey),
      kx1PrivateKey: privateKeys.kx1PrivateKey,
      sig1PrivateKey: privateKeys.sig1PrivateKey,
      kx1PublicKey: bundle.kx1PublicKey,
      sig1PublicKey: bundle.sig1PublicKey,
      opaqueEnrolled: opaqueEnrolled,
    );
  } on MalformedException catch (e) {
    throw KmAccountUnreadable(e.message);
  } on CorruptedException {
    throw const KmAccountUnreadable('a key doesn’t open');
  } finally {
    keys.dispose();
  }
}
