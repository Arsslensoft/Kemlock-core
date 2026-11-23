@TestOn('vm')
library;

// The anchors of the account's server spaces in the vault's own WebDAV file (docs/plans/add-server-spaces.md, design 2
// point 1): the file's `extra` carries them under `spaceAnchors`, older builds pass the key through, and the merge
// keeps the union of the two sides' anchors for that key alone.
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/spaces/space_head_store.dart';
import 'package:kemlock_core/features/spaces/space_verify.dart';
import 'package:kemlock_core/features/sync/sync.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/features/sync/webdav.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../spaces/chain_kit.dart';
import 'fake_webdav.dart';

const _dav = DavAccount(url: 'https://dav.example.com/files/me/Kemlock/', username: 'me', password: 'app-pw');
const _path = '/files/me/Kemlock/$syncFile';

ChainAnchor _anchor(int seq, int fill, {int epoch = 1}) =>
    ChainAnchor(epoch: epoch, links: [for (var i = 0; i <= seq; i++) Uint8List(32)..fillRange(0, 32, fill + i)]);

Map<String, Object?> _anchors(Map<String, ChainAnchor> anchors) => SpaceAnchors(anchors).toJson();

OtpAccount _acct(String id) => OtpAccount(id: id, issuer: id, label: '', secret: 'S$id', addedAt: 1);

void main() {
  group('the merge', () {
    final remote = SyncDoc(accounts: [_acct('a')], extra: const {'later': 7});

    test('keeps the remote file’s extra exactly as it was when this device has no anchors', () {
      final merged = mergeScope(const Lists(), const [], remote, now: 1000).doc;

      expect(merged.extra, {'later': 7});
      expect(merged.toJson().containsKey(syncAnchorsKey), isFalse);
    });

    test('keeps the remote file’s anchors as they were when this device has none', () {
      final theirs = _anchors({uuid(1): _anchor(2, 1)});
      final file = SyncDoc(extra: {'later': 7, syncAnchorsKey: theirs});

      expect(mergeScope(const Lists(), const [], file, now: 1000).doc.extra, {'later': 7, syncAnchorsKey: theirs});
    });

    test('writes this device’s anchors into a file that has none, and leaves every other key alone', () {
      final mine = _anchors({uuid(1): _anchor(2, 1)});

      final merged = mergeScope(const Lists(), const [], remote, now: 1000, anchors: mine).doc;

      expect(merged.extra['later'], 7);
      expect(merged.extra[syncAnchorsKey], mine);
    });

    test('keeps the union of both sides’ anchors: the longer chain of each space, and the spaces of both', () {
      final mine = _anchors({uuid(1): _anchor(5, 1), uuid(2): _anchor(0, 7)});
      final file = SyncDoc(
        extra: {
          syncAnchorsKey: _anchors({uuid(1): _anchor(2, 1), uuid(3): _anchor(1, 9)}),
          'later': 7,
        },
      );

      final merged = mergeScope(const Lists(), const [], file, now: 1000, anchors: mine).doc;
      final anchors = SpaceAnchors.fromJson(merged.extra[syncAnchorsKey]);

      expect(anchors.of(uuid(1)), _anchor(5, 1));
      expect(anchors.of(uuid(2)), _anchor(0, 7));
      expect(anchors.of(uuid(3)), _anchor(1, 9));
      expect(merged.extra['later'], 7);
    });

    test('leaves a copy it can’t read as it was, and writes nothing over it', () {
      final later = {'v': 3, 'anchors': const <String, Object?>{}};
      final file = SyncDoc(extra: {syncAnchorsKey: later});

      final merged = mergeScope(const Lists(), const [], file, now: 1000, anchors: _anchors({uuid(1): _anchor(0, 1)})).doc;

      expect(merged.extra[syncAnchorsKey], later);
    });

    test('is read and written by a build that doesn’t know the key, which passes it through', () {
      final json = {
        ...SyncDoc(accounts: [_acct('a')]).toJson(),
        syncAnchorsKey: _anchors({uuid(1): _anchor(1, 1)}),
      };

      expect(SyncDoc.fromJson(json).toJson()[syncAnchorsKey], json[syncAnchorsKey]);
    });
  });

  group('syncing through one folder', () {
    late FakeWebDav server;
    late WebDav webDav;
    late SyncTarget target;

    setUp(() {
      server = FakeWebDav();
      webDav = WebDav(server.client);
      target = SyncTarget(dav: _dav, file: syncFile, key: b64(randomBytes(32)));
    });

    int puts() => server.requests.where((r) => r.method == 'PUT').length;

    Future<SyncDoc> file() => decryptSyncFile(server.files[_path]!.text, unb64(target.key));

    test('carries one device’s anchors to another, and writes the file again for them alone', () async {
      final mine = _anchors({uuid(1): _anchor(3, 1)});

      final first = await syncScope(webDav, target, Lists(accounts: [_acct('a')]), const [], now: 1000, anchors: mine);
      expect((await file()).extra[syncAnchorsKey], mine);
      expect(first.doc.extra[syncAnchorsKey], mine);

      // A second device with no anchors takes them, and writes nothing
      final writes = puts();
      final second = await syncScope(webDav, target, const Lists(), const [], now: 2000, seen: first.seq);
      expect(second.doc.extra[syncAnchorsKey], mine);
      expect(puts(), writes);

      // A device that has gone further writes the file for its anchors alone
      final further = _anchors({uuid(1): _anchor(6, 1)});
      await syncScope(
        webDav,
        target,
        Lists(accounts: [_acct('a')]),
        ['a'],
        now: 3000,
        seen: second.seq,
        anchors: further,
      );
      expect(puts(), writes + 1);
      expect(SpaceAnchors.fromJson((await file()).extra[syncAnchorsKey]).of(uuid(1)), _anchor(6, 1));
    });

    test('writes a file with no anchors key when no device has any', () async {
      await syncScope(webDav, target, Lists(accounts: [_acct('a')]), const [], now: 1000);

      expect((await file()).extra.containsKey(syncAnchorsKey), isFalse);
    });
  });
}
