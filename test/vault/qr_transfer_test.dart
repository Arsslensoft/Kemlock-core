@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/keys/keys.dart' as crypto;
import 'package:kemlock_core/features/keys/key_bridge.dart' show vaultKeyOf;
import 'package:kemlock_core/features/sync/sync_merge.dart';
import 'package:kemlock_core/models/backup_service.dart';
import 'package:kemlock_core/models/key_account.dart';
import 'package:kemlock_core/models/otp_account.dart';
import 'package:kemlock_core/models/vault_key.dart';
import 'package:kemlock_core/vault/qr_transfer.dart';
import 'package:test/test.dart';

const _base32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
final _random = Random.secure();

String randomSecret([int length = 32]) => List.generate(length, (_) => _base32[_random.nextInt(32)]).join();

List<OtpAccount> makeAccounts(int count) => [
  for (var i = 0; i < count; i++)
    OtpAccount(
      id: 'id-$i',
      issuer: 'Service $i — 🔐',
      label: 'user$i@example.com',
      secret: randomSecret(),
      algorithm: const ['SHA1', 'SHA256', 'SHA512'][i % 3],
      digits: i.isOdd ? 8 : 6,
      period: i.isOdd ? 60 : 30,
      addedAt: i,
    ),
];

const _services = [
  BackupService(
    id: 'svc',
    serviceName: 'GitHub',
    codes: [
      BackupCode(code: 'aaaa-1111'),
      BackupCode(code: 'bbbb-2222', used: true),
    ],
    addedAt: 0,
  ),
];

/// The JSON of each entry without its id and added time, which a transfer makes anew.
List<Map<String, Object?>> withoutIds(Iterable<Object> items) => [
  for (final item in items)
    {...(item is OtpAccount ? item.toJson() : (item as BackupService).toJson())}
      ..remove('id')
      ..remove('addedAt'),
];

Matcher throwsTransferError(String message) => throwsA(isA<QrTransferError>().having((e) => e.message, 'message', message));

void main() {
  group('parseQrChunk', () {
    test('parses index, total and the base64url payload', () {
      final chunk = parseQrChunk('BMC1:02/03:AAEC_w')!;

      expect(chunk.index, 2);
      expect(chunk.total, 3);
      expect(chunk.payload, Uint8List.fromList([0, 1, 2, 255]));
    });

    for (final input in [
      'BMCP:01/01:AAEC',
      'otpauth://totp/x?secret=ABC',
      'BMC1:0101:AAEC',
      'BMC1:01/01AAEC',
      'BMC1:00/01:AAEC',
      'BMC1:02/01:AAEC',
      'BMC1:01/00:AAEC',
      'BMC1:xx/01:AAEC',
    ]) {
      test('rejects $input', () => expect(parseQrChunk(input), isNull));
    }

    test('refuses a total above the most codes a transfer has, or with more digits than a number holds', () {
      expect(parseQrChunk('BMC1:1/$maxQrChunks:AAEC')?.total, maxQrChunks);
      expect(parseQrChunk('BMC1:1/${maxQrChunks + 1}:AAEC'), isNull);
      expect(parseQrChunk('BMC1:1/999999999:AAEC'), isNull);
      expect(parseQrChunkPlaintext('BMCP:1/999999999:AA'), isNull);
      expect(parseQrChunk('BMC1:1/99999999999999999999999999:AAEC'), isNull);
      expect(parseQrChunk('BMC1:99999999999999999999999999/2:AAEC'), isNull);
    });

    test('reads the leading digits as parseInt does', () {
      expect(parseQrChunk('BMC1:1x/2y:AAEC')?.index, 1);
    });
  });

  test('parseQrChunkPlaintext only accepts BMCP chunks', () {
    expect(parseQrChunkPlaintext('BMCP:01/01:AAEC')?.total, 1);
    expect(parseQrChunkPlaintext('BMC1:01/01:AAEC'), isNull);
  });

  group('encrypted QR export', () {
    final small = makeAccounts(3);

    test('fits a small vault in a single QR code', () async {
      final chunks = await exportVaultQr(small, _services, 'pw');

      expect(chunks, hasLength(1));
      expect(chunks.single, matches(RegExp(r'^BMC1:01/01:[A-Za-z0-9_-]+$')));
      expect(isEncryptedQrChunk(chunks.single), isTrue);
    });

    test('round-trips accounts and backup services with fresh ids', () async {
      final chunks = await exportVaultQr(small, _services, 'pw');
      final result = await importVaultQr(chunks, 'pw');

      expect(withoutIds(result.accounts), withoutIds(small));
      expect(withoutIds(result.backupServices), withoutIds(_services));
      expect(result.accounts.map((a) => a.id), isNot(small.map((a) => a.id)));
    });

    test('does not leak secrets into the QR payload', () async {
      final [chunk] = await exportVaultQr(small, _services, 'pw');
      final decoded = latin1.decode(parseQrChunk(chunk)!.payload);

      for (final a in small) {
        expect(decoded, isNot(contains(a.secret)));
      }
      expect(decoded, isNot(contains('aaaa-1111')));
    });

    test('exports an empty vault', () async {
      final result = await importVaultQr(await exportVaultQr([], [], 'pw'), 'pw');

      expect(result.accounts, isEmpty);
      expect(result.backupServices, isEmpty);
    });

    test('rejects the wrong password', () async {
      final chunks = await exportVaultQr(small, _services, 'pw');

      await expectLater(importVaultQr(chunks, 'wrong'), throwsTransferError('Wrong password or corrupted QR data.'));
    });

    test('rejects input with no BMC1 chunks', () async {
      await expectLater(importVaultQr(['hello', 'BMCP:01/01:AA'], 'pw'), throwsTransferError('No valid BMC1 QR chunks provided.'));
    });

    // openspec: add-post-quantum-pgp, task 8.6
    test('moves a vault holding a standard post-quantum key: its codes go in one QR code, and the key stays out', () async {
      final parsed = await crypto.readPrivateKey(File('test/fixtures/keys/kemlock/pgp-pq-standard.unprotected.asc').readAsStringSync());
      final lists = Lists(
        accounts: small,
        backupServices: _services,
        keys: [vaultKeyOf(parsed, id: 'k-pq', name: 'Ada, post-quantum', origin: KeyOrigin.generated)],
      );

      // What the QR export sheet hands over from the vault
      final chunks = await exportVaultQr(lists.accounts, lists.backupServices, 'pw');

      expect(chunks, hasLength(1));
      final result = await importVaultQr(chunks, 'pw');
      expect(withoutIds(result.accounts), withoutIds(small));
      expect(withoutIds(result.backupServices), withoutIds(_services));
      final [plain] = exportVaultQrPlaintext(lists.accounts, lists.backupServices);
      final payload = utf8.decode(parseQrChunkPlaintext(plain)!.payload);
      expect(payload, isNot(contains('Ada, post-quantum')));
      expect(payload, isNot(contains(lists.keys.single.privateKey.substring(0, 40))));
    });

    group('large vaults', () {
      final many = makeAccounts(120);
      late List<String> chunks;
      setUpAll(() async => chunks = await exportVaultQr(many, _services, 'pw'));

      test('split across several QR codes of at most 2048 bytes each', () {
        expect(chunks.length, greaterThan(1));
        for (final (i, chunk) in chunks.indexed) {
          final parsed = parseQrChunk(chunk)!;
          expect(parsed.index, i + 1);
          expect(parsed.total, chunks.length);
          expect(parsed.payload.length, lessThanOrEqualTo(2048));
        }
      });

      test('reassemble from chunks scanned in any order', () async {
        final result = await importVaultQr(chunks.reversed.toList(), 'pw');

        expect(withoutIds(result.accounts), withoutIds(many));
      });

      test('report exactly which chunks are missing', () async {
        await expectLater(importVaultQr(chunks.sublist(1), 'pw'), throwsTransferError('Missing QR code(s): 1 of ${chunks.length}.'));
      });
    });
  });

  group('plaintext QR export', () {
    // openspec: add-security-key-codes, task 8.5
    test('carries no account on a security key: its compact form holds accounts and backup codes alone', () async {
      const lists = Lists(
        accounts: [OtpAccount(id: 'a1', issuer: 'GitHub', label: 'octocat', secret: 'JBSWY3DPEHPK3PXP', addedAt: 1)],
        keyAccounts: [KeyAccount(id: 'ka1', device: '0102030405060708', name: 'Bank:ada', issuer: 'Bank', label: 'ada', addedAt: 1)],
      );

      // What the QR export sheet hands over from the vault.
      final chunks = exportVaultQrPlaintext(lists.accounts, lists.backupServices);

      final payload = jsonDecode(utf8.decode(parseQrChunkPlaintext(chunks.single)!.payload)) as Map<String, Object?>;
      expect(payload.keys, ['a', 'b']);
      expect(jsonEncode(payload), isNot(contains('Bank')));
      final result = await importVaultQrPlaintext(chunks);
      expect([for (final account in result.accounts) account.issuer], ['GitHub']);
    });

    test('round-trips accounts and backup services', () async {
      final accounts = makeAccounts(4);
      final chunks = exportVaultQrPlaintext(accounts, _services);

      expect(chunks.first, startsWith('BMCP:01/01:'));
      expect(isEncryptedQrChunk(chunks.first), isFalse);
      final result = await importVaultQrPlaintext(chunks);
      expect(withoutIds(result.accounts), withoutIds(accounts));
      expect(withoutIds(result.backupServices), withoutIds(_services));
    });

    test('splits large payloads, even through multi-byte characters, and reassembles in any order', () async {
      final accounts = makeAccounts(60);
      final chunks = exportVaultQrPlaintext(accounts, []);

      expect(chunks.length, greaterThan(1));
      final result = await importVaultQrPlaintext(chunks.reversed.toList());
      expect(withoutIds(result.accounts), withoutIds(accounts));
    });

    test('always makes at least one chunk', () {
      expect(exportVaultQrPlaintext([], []), hasLength(1));
    });

    test('reports missing chunks', () async {
      final chunks = exportVaultQrPlaintext(makeAccounts(60), []);

      await expectLater(
        importVaultQrPlaintext(chunks.sublist(0, chunks.length - 1)),
        throwsTransferError('Missing QR code(s): ${chunks.length} of ${chunks.length}.'),
      );
    });

    test('rejects input with no BMCP chunks', () async {
      await expectLater(importVaultQrPlaintext(['BMC1:01/01:AA']), throwsTransferError('No valid BMCP QR chunks provided.'));
    });

    test('carries a Steam account’s type and an HOTP one’s counter, which older readers pass over', () async {
      const steam = OtpAccount(id: 's', type: OtpType.steam, issuer: 'Steam', label: 'gaben', secret: 'JBSWY3DPEHPK3PXP', addedAt: 0);
      const hotp = OtpAccount(id: 'h', type: OtpType.hotp, issuer: 'Bank', label: 'ada', secret: 'GEZDGNBV', counter: 42, addedAt: 0);
      final [chunk] = exportVaultQrPlaintext([steam, hotp], []);

      // The six keys qrVault.ts reads come first, as it wrote them; it maps those alone
      expect(
        utf8.decode(parseQrChunkPlaintext(chunk)!.payload),
        '{"a":[{"i":"Steam","l":"gaben","s":"JBSWY3DPEHPK3PXP","a":"SHA1","d":6,"p":30,"t":"steam"},'
        '{"i":"Bank","l":"ada","s":"GEZDGNBV","a":"SHA1","d":6,"p":30,"t":"hotp","c":42}],"b":[]}',
      );
      final result = await importVaultQrPlaintext([chunk]);
      expect(withoutIds(result.accounts), withoutIds([steam, hotp]));
      // Encrypted the same way
      final sealed = await importVaultQr(await exportVaultQr([steam, hotp], [], 'pw'), 'pw');
      expect([for (final a in sealed.accounts) (a.kind, a.counter)], [(OtpType.steam, null), (OtpType.hotp, 42)]);
    });

    test('reads a type it does not know, or a counter that is none, as an older transfer', () async {
      final payload = jsonEncode({
        'a': [
          {'i': 'A', 'l': '', 's': 'S', 'a': 'SHA1', 'd': 6, 'p': 30, 't': 'motp', 'c': 3},
          {'i': 'B', 'l': '', 's': 'S', 'a': 'SHA1', 'd': 6, 'p': 30, 't': 'hotp', 'c': -1},
          {'i': 'C', 'l': '', 's': 'S', 'a': 'SHA1', 'd': 6, 'p': 30, 't': 'totp', 'c': '7'},
        ],
      });
      final [chunk] = exportVaultQrPlaintext([], []);
      final forged = '${chunk.substring(0, chunk.lastIndexOf(':') + 1)}${base64Url.encode(utf8.encode(payload)).replaceAll('=', '')}';

      final result = await importVaultQrPlaintext([forged]);

      expect([for (final a in result.accounts) (a.type, a.counter)], [(null, null), (OtpType.hotp, null), (null, null)]);
    });

    test('writes the compact JSON qrVault.ts writes', () async {
      const account = OtpAccount(id: 'x', issuer: 'I', label: 'L', secret: 'S', addedAt: 0);
      final [chunk] = exportVaultQrPlaintext([account], _services);

      expect(
        utf8.decode(parseQrChunkPlaintext(chunk)!.payload),
        '{"a":[{"i":"I","l":"L","s":"S","a":"SHA1","d":6,"p":30}],'
        '"b":[{"n":"GitHub","c":[{"code":"aaaa-1111","used":false},{"code":"bbbb-2222","used":true}]}]}',
      );
    });
  });
}
