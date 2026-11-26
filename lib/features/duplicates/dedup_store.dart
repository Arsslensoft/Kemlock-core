// Reads and writes the vault's two sealed values for duplicate matching
// (the add-duplicate-cleaner plan, design 4), as `MailAppsStore` does the
// mail apps: through `VaultStore.saveEncryptedValue`, so each is sealed
// to the vault's key pair, sealed again by a replacement of that pair
// (`sealedValueKeys` finds it by its shape) and deleted with the vault
// (`VaultRegistry.removeVaultData` deletes every key of the vault).
library;

import 'dart:typed_data';

import 'package:crypto/crypto.dart' as hash;

import '../../crypto/account/encoding.dart' show wipe;
import '../../crypto/bytes.dart' show unb64;
import '../../crypto/keys/keys.dart' as crypto;
import '../../crypto/keys/pem.dart' show readPemBlocks;
import '../../models/contact.dart';
import '../../models/vault_key.dart';
import '../../vault/vault_store.dart';
import '../keys/key_bridge.dart' show keyIdentity;
import '../sync/sync.dart' show Space;
import 'dedup_cache.dart';
import 'dedup_tagger.dart';
import 'duplicate_normalise.dart';

/// What tells a key or a contact, as `crypto.md` "Normalisation" has the `key` tag's value: a PGP
/// key's primary fingerprint as upper-case hex (version 4 or 6), and an SSH key's OpenSSH
/// `SHA256:` fingerprint, the one `ssh-keygen -l` prints. A contact is a PGP key.
///
/// A key that holds a certificate is a certificate, told by the certificate's fingerprint: the one its body stores, else the
/// SHA-256 thumbprint of its DER, as upper-case hexadecimal; null when neither can be read, which makes no tag.
///
/// `crypto.md` names no other key kind. One that has no fingerprint of those two forms, or whose
/// public half can't be read, is told by its public half, else its private one, as import tells
/// keys (`keyIdentity`). Null for a contact whose key can't be read. Other items have none.
String? dedupKeyIdentity(Object item) => switch (item) {
  VaultKey() => _keyFingerprint(item),
  Contact() => _contactFingerprint(item),
  _ => null,
};

String? _keyFingerprint(VaultKey key) {
  final certificate = key.extra['certificate'];
  if (certificate is String) {
    return _certificateFingerprint(key, certificate);
  }
  final public = key.publicKey;
  if (public != null) {
    try {
      if (key.kind == KeyKind.pgp) {
        return crypto.readPgpKeyInfo(unb64(public)).primary.fingerprintHex;
      }
      if (key.kind == KeyKind.ssh) {
        final fingerprint = crypto.sshFingerprintOfSpki(unb64(public));
        if (fingerprint != null) {
          return fingerprint;
        }
      }
    } on crypto.KeyFormatException {
      // Told by its bytes, as import tells it
    } on FormatException {
      // Not even base64
    }
  }
  return keyIdentity(key);
}

/// The fingerprint of the certificate [pem] that [key] holds: the `fingerprint` its body stores, as `normaliseFingerprint` reads
/// it, else the SHA-256 of the certificate's DER as upper-case hexadecimal. Null when neither reads.
String? _certificateFingerprint(VaultKey key, String pem) {
  final stored = key.extra['fingerprint'];
  if (stored is String && normaliseFingerprint(stored) != null) {
    return normaliseFingerprint(stored);
  }
  try {
    for (final block in readPemBlocks(pem)) {
      if (block.label == 'CERTIFICATE') {
        return hash.sha256.convert(block.decode()).toString().toUpperCase();
      }
    }
  } on crypto.KeyFormatException {
    return null;
  }
  return null;
}

String? _contactFingerprint(Contact contact) {
  if (!contact.hasKey) {
    return null;
  }
  try {
    return crypto.readPgpKeyInfo(unb64(contact.publicKey)).primary.fingerprintHex;
  } on crypto.KeyFormatException {
    return null;
  } on FormatException {
    return null;
  }
}

/// The app id and 32-byte key of each WebDAV space of [spaces], which is its `target.key`. A key that
/// isn't base64 leaves its space out. The caller wipes the keys.
List<({String id, Uint8List key})> dedupSpaceKeys(Iterable<Space> spaces) {
  final keys = <({String id, Uint8List key})>[];
  for (final space in spaces) {
    try {
      keys.add((id: space.id, key: unb64(space.target.key)));
    } on FormatException {
      // Not a key: the space's items are not tagged
    }
  }
  return keys;
}

/// The vault's duplicate cache and answers.
class DedupStore {
  const DedupStore(this._store);

  final VaultStore _store;

  /// The cache to work with, for tags made with the Public Suffix List whose hash is [listHash].
  ///
  /// It is the stored one when that reads and was made with the same list. One that is missing or
  /// can't be read gives a new cache with a new root, made now, at the first match: the tags it
  /// held are made again and nothing else is lost. One made with another list keeps its root and
  /// none of its tags, since a site may now read differently.
  Future<DedupCache> loadCache(VaultSession session, {required String listHash}) async {
    DedupCache? stored;
    try {
      stored = DedupCache.fromJson(await _store.loadEncryptedValue(keyDedup, session));
    } catch (_) {
      // Sealed to another key, or damaged: it is a cache, and is made again
    }
    if (stored == null) {
      return DedupCache.fresh(listHash);
    }
    if (stored.listHash != listHash) {
      return DedupCache(root: stored.root, rootId: stored.rootId, listHash: listHash);
    }
    return stored;
  }

  /// Brings the tags up to date with [items], the vault's items and its spaces' [spaces], and
  /// gives them back by owner slot and item id.
  ///
  /// The root is made if there is none, each item whose change time moved is tagged again, and what
  /// changed is saved. The dedup keys are held only while the tags are made, and wiped with the
  /// root and the space keys after.
  Future<Map<String, Map<String, DedupItemTags>>> refresh(
    VaultSession session, {
    required List<DedupItem> items,
    required Iterable<Space> spaces,
    required String listHash,
    SiteResolver sites = const SiteResolver(),
  }) async {
    final cache = await loadCache(session, listHash: listHash);
    final spaceKeys = dedupSpaceKeys(spaces);
    try {
      final result = refreshTags(cache, items, dedupOwners(cache, spaceKeys), sites: sites, keyIdentityOf: dedupKeyIdentity);
      if (result.changed) {
        await saveCache(result.cache, session);
      }
      return {for (final MapEntry(:key, :value) in result.cache.owners.entries) key: value.items};
    } finally {
      wipe(cache.root);
      for (final space in spaceKeys) {
        wipe(space.key);
      }
    }
  }

  Future<void> saveCache(DedupCache cache, VaultSession session) => _store.saveEncryptedValue(keyDedup, cache.toJson(), session);

  /// Deletes the cache, root and tags, which are made again at the next match.
  void clearCache() => _store.removeEncryptedValue(keyDedup);

  /// The dismissals and merge records, empty when there are none. A value that can't be opened
  /// throws rather than reads as empty, as a later save would then wipe what can't be made again.
  Future<DedupAnswers> loadAnswers(VaultSession session) async =>
      DedupAnswers.fromJson(await _store.loadEncryptedValue(keyDedupAnswers, session));

  /// Saves [answers], or removes the value when there are none, so a vault that never used the
  /// cleaner holds neither value.
  Future<void> saveAnswers(DedupAnswers answers, VaultSession session) async {
    if (answers.isEmpty) {
      _store.removeEncryptedValue(keyDedupAnswers);
      return;
    }
    await _store.saveEncryptedValue(keyDedupAnswers, answers.toJson(), session);
  }
}
