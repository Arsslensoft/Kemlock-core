@TestOn('vm')
library;

// The sync file and space invites, ported from the first cases of
// src/lib/sync.test.ts. scrypt runs with tiny parameters here; the real
// ones are checked against the TypeScript app's files in
// sync_fixtures_test.dart.
import 'dart:convert';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:test/test.dart';

import '../../vault/fast_kdf.dart';

OtpAccount acct(String id) => OtpAccount(id: id, issuer: id, label: '', secret: 'S$id', addedAt: 1);

Matcher syncFileError(SyncFileProblem problem) => isA<SyncFileError>().having((e) => e.problem, 'problem', problem);

String _spaceFile(String id) => 'backmycodes-space-$id.json';

Matcher inviteError(InviteProblem problem) => isA<InviteError>().having((e) => e.problem, 'problem', problem);

/// A derivation that must not run.
Future<Uint8List> noDerive(String password, Uint8List salt) => throw StateError('derived a key');

void main() {
  group('the sync file', () {
    test('round-trips a document and reads nothing without the right key', () async {
      final key = randomBytes(32);
      final text = await encryptSyncFile(SyncDoc(accounts: [acct('a')]), key);

      // The account's JSON never appears; base64 ciphertext has no quotes to match
      expect(text, isNot(contains('"secret"')));
      expect((await decryptSyncFile(text, key)).accounts, [acct('a')]);
      await expectLater(decryptSyncFile(text, randomBytes(32)), throwsA(syncFileError(SyncFileProblem.key)));
      await expectLater(decryptSyncFile('{"hello":1}', key), throwsA(isA<SyncFileError>()));
    });

    test('keeps the passphrase salt in the file, so every device derives the same key', () async {
      final kdf = newKdf();
      final key = await deriveSyncKey('correct horse', kdf, derive: fastKdf);
      final text = await encryptSyncFile(const SyncDoc(), key, kdf: kdf);

      final again = await deriveSyncKey('correct horse', readKdf(text)!, derive: fastKdf);
      expect(again, key);
      expect((await decryptSyncFile(text, again)).accounts, isEmpty);
    });

    test('writes the shape the TypeScript app reads, with a fresh nonce each time', () async {
      final key = randomBytes(32);
      final kdf = newKdf();
      final first = jsonDecode(await encryptSyncFile(const SyncDoc(), key, kdf: kdf)) as Map<String, Object?>;
      final second = jsonDecode(await encryptSyncFile(const SyncDoc(), key)) as Map<String, Object?>;

      expect(first.keys, ['app', 'kind', 'version', 'kdf', 'nonce', 'ct']);
      expect([first['app'], first['kind'], first['version'], first['kdf']], ['BackMyCodes', 'sync', 1, kdf.toJson()]);
      expect((first['kdf']! as Map<String, Object?>).keys, ['salt', 'N', 'r', 'p']);
      expect(unb64(first['nonce']! as String), hasLength(12));
      // A space's file has no salt
      expect(second.keys, ['app', 'kind', 'version', 'nonce', 'ct']);
      expect(second['nonce'], isNot(first['nonce']));
    });

    test('reads a space file as having no salt, and something else as no sync file', () async {
      expect(readKdf(await encryptSyncFile(const SyncDoc(), randomBytes(32))), isNull);
      expect(
        () => readKdf('{"app":"BackMyCodes","kind":"sync","version":1,"nonce":"","ct":"","kdf":"salt"}'),
        throwsA(syncFileError(SyncFileProblem.format)),
      );
      expect(() => readKdf('not json'), throwsA(syncFileError(SyncFileProblem.format)));
    });

    test('refuses a salt made with other scrypt parameters before deriving anything', () async {
      final kdf = newKdf();
      for (final other in [
        Kdf(salt: kdf.salt, n: 16384),
        Kdf(salt: kdf.salt, r: 1),
        Kdf(salt: kdf.salt, p: 2),
        Kdf.fromJson({'salt': kdf.salt}),
        Kdf.fromJson({'salt': kdf.salt, 'N': '131072', 'r': 8, 'p': 1}),
        Kdf.fromJson({'salt': kdf.salt, 'N': 131072.5, 'r': 8, 'p': 1}),
      ]) {
        await expectLater(deriveSyncKey('pw', other, derive: noDerive), throwsA(syncFileError(SyncFileProblem.format)), reason: '$other');
      }
      // The same number written with a fraction is the same parameter
      final whole = Kdf.fromJson({'salt': kdf.salt, 'N': 131072.0, 'r': 8.0, 'p': 1});
      expect(await deriveSyncKey('pw', whole, derive: fastKdf), await fastKdf('pw', unb64(kdf.salt)));
    });

    test('keeps keys of the salt it does not know', () {
      final json = {'salt': 'c2FsdA==', 'N': 131072, 'r': 8, 'p': 1, 'v': 2};
      expect(Kdf.fromJson(json).toJson(), json);
      expect(Kdf.fromJson(json), Kdf.fromJson({...json}));
    });

    test('reads lists that are missing or are not lists as empty, and keeps unknown keys', () async {
      final key = randomBytes(32);
      final doc = SyncDoc.fromJson({
        'accounts': [acct('a').toJson()],
        'later': {'x': 1},
      });
      final opened = await decryptSyncFile(await encryptSyncFile(doc, key), key);

      expect(opened.accounts, [acct('a')]);
      expect(opened.backupServices, isEmpty);
      expect(opened.deleted, isEmpty);
      expect(opened.extra, {
        'later': {'x': 1},
      });
    });
  });

  group('space invites', () {
    test('opens only with the invite code, however it is typed', () async {
      final invite = SpaceInvite(id: 'fam', name: 'Family', file: 'backmycodes-space-fam.json', key: randomBytes(32));
      final code = newInviteCode();
      final text = await sealInvite(invite, code, derive: fastKdf);

      expect(code, matches(RegExp(r'^[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$')));
      expect(isInvite(text), isTrue);
      expect(text, isNot(contains('Family')));
      expect(await openInvite(text, code.toLowerCase().replaceAll('-', ' '), derive: fastKdf), invite);
      await expectLater(openInvite(text, 'AAAA-AAAA-AAAA', derive: fastKdf), throwsA(inviteError(InviteProblem.code)));
      await expectLater(openInvite('hello', code, derive: noDerive), throwsA(isA<InviteError>()));
    });

    test('refuses an invite whose space takes one of the vault’s own scope names, or no id a space has', () async {
      final code = newInviteCode();
      for (final id in ['personal', 'vaultwarden', '', 'a b', '../x', 'é', 'a' * 65]) {
        final text = await sealInvite(
          SpaceInvite(id: id, name: 'X', file: _spaceFile(id), key: randomBytes(32)),
          code,
          derive: fastKdf,
        );
        await expectLater(openInvite(text, code, derive: fastKdf), throwsA(inviteError(InviteProblem.format)), reason: '"$id"');
        expect(isSpaceId(id), isFalse, reason: '"$id"');
      }
      // The ids both apps make and the tests use
      for (final id in ['fam', 'x', '3f2c9a71e4b0d856', 'a1b2c3d4e5f6', 'A_b-9', 'a' * 64, 'personal2']) {
        expect(isSpaceId(id), isTrue, reason: id);
      }
      // A key that is not an AES-256 key
      final short = await sealInvite(
        SpaceInvite(id: 'fam', name: 'X', file: _spaceFile('fam'), key: randomBytes(16)),
        code,
        derive: fastKdf,
      );
      await expectLater(openInvite(short, code, derive: fastKdf), throwsA(inviteError(InviteProblem.format)));
    });

    test('is one line of URL-safe text', () async {
      final invite = SpaceInvite(id: 'x', name: 'Ünïcødé 👪', file: 'f.json', key: randomBytes(32));
      final text = await sealInvite(invite, newInviteCode(), derive: fastKdf);

      expect(text, matches(RegExp(r'^bmc-space:[A-Za-z0-9_-]+$')));
      expect(isInvite('  $text\n'), isTrue);
      expect(isInvite('BMC-SPACE:${text.substring(10)}'), isFalse);
    });

    test('says which invite text is not an invite, without deriving a key', () async {
      for (final text in ['', 'hello', 'bmc-space:', 'bmc-space:!!!!', 'bmc-space:${b64url(utf8.encode('{"v":2}'))}']) {
        await expectLater(openInvite(text, 'AAAA-AAAA-AAAA', derive: noDerive), throwsA(inviteError(InviteProblem.format)), reason: text);
      }
    });

    test('draws invite codes from the alphabet, skipping bytes that would favour its first letters', () {
      // 240 to 255 are skipped; 239 is the last letter, 30 the first again
      final bytes = [240, 255, 239, 0, 30, 29, 59, 60, 249, 1, 2, 3, 4, 5, 6, 7];
      expect(newInviteCode(random: (n) => Uint8List.fromList(bytes.take(n).toList())), '9AA9-9ABC-DEFG');
      expect(inviteCodeAlphabet, hasLength(30));
      expect(inviteCodeAlphabet, isNot(matches(RegExp('[01ILOU]'))));
    });

    test('draws again when the bytes run short', () {
      var calls = 0;
      Uint8List random(int n) {
        calls++;
        // Only every other byte is usable
        return Uint8List.fromList([for (var i = 0; i < n; i++) i.isEven ? 250 : i]);
      }

      // Letters 1, 3, 5 … 15 of the alphabet, then the first four again
      expect(newInviteCode(random: random), 'BDFH-KNQS-BDFH');
      expect(calls, 2);
    });

    test('keys a code by its letters and digits, in upper case', () {
      expect(normalizeInviteCode(' k7pq-2m9x darf\n'), 'K7PQ2M9XDARF');
      expect(normalizeInviteCode('straße ﬁx'), 'STRASSEFIX');
      expect(normalizeInviteCode('çé-ＡＢ'), '');
    });

    test('keeps the key out of its text', () {
      final invite = SpaceInvite(id: 'fam', name: 'Family', file: 'f.json', key: Uint8List(32));
      expect('$invite', isNot(contains('AAAA')));
      expect(invite, isNot(SpaceInvite(id: 'fam', name: 'Family', file: 'f.json', key: Uint8List(32)..[0] = 1)));
    });
  });
}
