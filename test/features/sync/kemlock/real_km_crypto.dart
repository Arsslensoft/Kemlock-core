import 'dart:typed_data';

import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/kem1.dart';
import 'package:kemlock_core/crypto/account/keys.dart';
import 'package:kemlock_core/crypto/account/manifest.dart';
import 'package:kemlock_core/crypto/account/session.dart';
import 'package:kemlock_core/features/sync/kemlock/km_crypto.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_km_crypto.dart';
import 'km_sync_kit.dart';

/// What the production code seals and signs with, for the sync tests (add-kemlock-server-sync, task 13.1): the real
/// [AccountItemCrypto] over the keys of a [KmTestAccount], where [FakeKmCrypto] has `kem1` under a random wrap key
/// and a MAC in place of `sig1`. It is a [FakeKmCrypto] to the kit and the tests that use one, and two made over
/// one account are two phones of it.
class RealKmCrypto implements FakeKmCrypto {
  RealKmCrypto(this.account) : owner = Owner.user(account.userId), keyVersion = account.keyVersion {
    _inner = AccountItemCrypto(
      session: AccountSession(
        keys: AccountKeys.fromRoot(copyBytes(account.root)),
        kx1PrivateKey: copyBytes(account.kx1.privateKey),
        sig1PrivateKey: copyBytes(account.sig1.privateKey),
      ),
      sig1PublicKey: account.sig1.publicKey,
      owner: owner,
      keyVersion: keyVersion,
    );
  }

  final KmTestAccount account;
  late final AccountItemCrypto _inner;

  @override
  final Owner owner;

  @override
  final int keyVersion;

  @override
  int sealed = 0;

  @override
  RealKmCrypto alike() => RealKmCrypto(account);

  @override
  Future<KmSealedItem> sealItem({required String itemId, required int revision, required String kind, required Uint8List plaintext}) {
    sealed++;
    return _inner.sealItem(itemId: itemId, revision: revision, kind: kind, plaintext: plaintext);
  }

  @override
  Future<Uint8List> openItem(Kem1Item item) => _inner.openItem(item);

  @override
  Future<KmSignedManifest> signManifest(Manifest manifest) => _inner.signManifest(manifest);

  @override
  Future<Manifest> verifyManifest(Uint8List bytes, Uint8List signature) => _inner.verifyManifest(bytes, signature);
}

/// Makes every phone of the kit seal and sign with the real crypto of [account] from now on, until [useFakeCrypto].
void useRealCrypto(KmTestAccount account) => kmDefaultCrypto = () => RealKmCrypto(account);

/// Puts the fake back as what the kit's phones seal with.
void useFakeCrypto() => kmDefaultCrypto = FakeKmCrypto.new;
