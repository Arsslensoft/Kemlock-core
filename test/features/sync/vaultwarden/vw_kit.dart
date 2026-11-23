import 'dart:convert';

import 'package:kemlock_core/crypto/bitwarden.dart';
import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_api.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_codec.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_formats.dart';
import 'package:kemlock_core/features/sync/vaultwarden/vw_models.dart';

import 'fake_vaultwarden.dart';

/// Every kind added after codes, as a plain home's settings name them once
/// the user agreed to all of them.
const agreedToAll = {'key', 'note', 'passkey'};

/// Makes a home in [server]'s vault, as setup does, and the settings for it.
/// [plainKinds] are the kinds the user agreed to have written in the clear.
Future<VaultwardenTarget> makeHome(
  FakeVaultwarden server,
  VaultwardenMode mode, {
  bool pickUp = false,
  Set<String> plainKinds = const {},
}) async {
  final writer = VwWriter(userKey: server.userKey, userId: FakeVaultwarden.userId);
  final folder = await VwApi(server.client).createFolder(FakeVaultwarden.url, 'token', await bwEncryptString('Kemlock', server.userKey));
  final id = newHomeId();
  VwSeal? seal;
  Map<String, Object?>? sealFile;
  if (mode == VaultwardenMode.sealed) {
    final key = randomBytes(32);
    final kdf = newKdf();
    seal = VwSeal(key: b64(key), kdf: kdf);
    sealFile = jsonDecode(await encryptSyncFile(const SyncDoc(), key, kdf: kdf)) as Map<String, Object?>;
  }
  server.put(
    await writer.createHome(
      HomeNote(id: id, name: 'Kemlock', mode: mode, seal: sealFile),
      folderId: folder['id']! as String,
    ),
  );
  return VaultwardenTarget(
    server: FakeVaultwarden.url.toString(),
    email: server.email,
    home: id,
    mode: mode,
    folderId: folder['id']! as String,
    seal: seal,
    pickUp: pickUp,
    plainKinds: plainKinds,
  );
}

/// Puts the user's own GitHub login in [server]'s vault, as a Bitwarden
/// app would: a username, a password, a website and a code.
Future<Map<String, Object?>> putUserLogin(FakeVaultwarden server, BwKey key, {String secret = 'JBSWY3DPEHPK3PXP'}) async => server.put({
  'type': 1,
  'name': await bwEncryptString('GitHub', key),
  'login': {
    'username': await bwEncryptString('octocat', key),
    'password': await bwEncryptString('correct-horse-battery', key),
    'totp': await bwEncryptString(secret, key),
    'uris': [
      {'uri': await bwEncryptString('https://github.com', key), 'match': null},
    ],
  },
});
