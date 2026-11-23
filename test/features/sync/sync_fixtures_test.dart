@TestOn('vm')
library;

// Sync files and space invites against what the Capacitor app made
// (test/fixtures/sync, written by src/utils/syncCrypto.ts itself through
// tool/fixtures/sync_fixtures.mjs). If any of these fail, a sync file or an
// invite from the current app would not open in this one, or the other way
// round. Two keys are derived with scrypt at the real parameters.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:kemlock_core/crypto/bytes.dart';
import 'package:kemlock_core/features/sync/sync_crypto.dart';
import 'package:kemlock_core/vault/vault_store.dart';
import 'package:test/test.dart';

typedef _Json = Map<String, Object?>;

final _fixtures = jsonDecode(File('test/fixtures/sync/sync.json').readAsStringSync()) as _Json;

List<_Json> _list(Object? list) => [for (final item in list! as List<Object?>) item! as _Json];

Uint8List _hex(String text) =>
    Uint8List.fromList([for (var i = 0; i < text.length; i += 2) int.parse(text.substring(i, i + 2), radix: 16)]);

/// Hands out, in order, the bytes the TypeScript drew from `crypto.getRandomValues`.
class _Replay {
  _Replay(String hex) : _bytes = _hex(hex);

  final Uint8List _bytes;
  var _next = 0;

  /// Whether every byte was drawn, no more and no fewer.
  bool get done => _next == _bytes.length;

  Uint8List call(int length) {
    if (_next + length > _bytes.length) throw StateError('Drew more bytes than the TypeScript did');
    return Uint8List.fromList(_bytes.sublist(_next, _next += length));
  }
}

// scrypt at the real parameters, once for each password and salt.
final _derived = <String, Future<Uint8List>>{};
Future<Uint8List> _derive(String password, Uint8List salt) =>
    _derived.putIfAbsent('$password ${b64(salt)}', () => deriveVaultKey(password, salt));

/// The problem [run] fails with, as the fixture script names it, or 'ok'.
Future<String> _verdict(Future<Object?> Function() run) async {
  try {
    await run();
    return 'ok';
  } on SyncFileError catch (e) {
    return e.problem.name;
  } on InviteError catch (e) {
    return e.problem.name;
  } catch (e) {
    return 'error: ${e.runtimeType}';
  }
}

void main() {
  group('sync files', () {
    final files = {for (final file in _list(_fixtures['files'])) file['name']! as String: file};

    for (final name in ['personal', 'space', 'empty']) {
      test('opens the $name file and writes it again byte for byte', () async {
        final file = files[name]!;
        final text = file['text']! as String;
        final key = unb64(file['key']! as String);

        final doc = await decryptSyncFile(text, key);
        expect(doc.toJson(), file['decrypted']);

        final random = _Replay(file['random']! as String);
        expect(await encryptSyncFile(doc, key, kdf: readKdf(text), random: random.call), text);
        expect(random.done, isTrue);
      });
    }

    test('reads lists that are missing or are not lists as empty', () async {
      final file = files['partial']!;
      final doc = await decryptSyncFile(file['text']! as String, unb64(file['key']! as String));

      expect(doc.toJson(), file['decrypted']);
      expect(doc.accounts, hasLength(1));
    });

    test('derives the key of a passphrase with the salt in the file', () async {
      final file = files['personal']!;
      final kdf = readKdf(file['text']! as String)!;

      expect(b64(await deriveSyncKey(file['passphrase']! as String, kdf, derive: _derive)), file['key']);
      // The salt is the one newKdf made from the same bytes
      final random = _Replay(file['kdfRandom']! as String);
      expect(newKdf(random: random.call), kdf);
      expect(random.done, isTrue);
    });

    test('reads broken files, and files of other kinds, as the TypeScript does', () async {
      final key = unb64(files['space']!['key']! as String);
      for (final verdict in _list(_fixtures['fileVerdicts'])) {
        final text = verdict['text']! as String;
        expect(await _verdict(() => decryptSyncFile(text, key)), verdict['decrypt'], reason: text);
        Object? kdf;
        try {
          kdf = {'value': readKdf(text)?.toJson()};
        } on SyncFileError catch (e) {
          kdf = {'problem': e.problem.name};
        }
        expect(kdf, verdict['kdf'], reason: text);
      }
    });

    test('refuses salts made with other scrypt parameters', () async {
      for (final refused in _list(_fixtures['refusedKdfs'])) {
        final kdf = Kdf.fromJson(refused['kdf']! as _Json);
        expect(await _verdict(() => deriveSyncKey('pw', kdf, derive: (_, _) => throw StateError('derived'))), refused['problem']);
      }
    });
  });

  group('invites', () {
    final fixture = _fixtures['invite']! as _Json;
    final text = fixture['text']! as String;
    final code = fixture['code']! as String;
    final json = fixture['invite']! as _Json;
    final invite = SpaceInvite(
      id: json['id']! as String,
      name: json['name']! as String,
      file: json['file']! as String,
      key: unb64(json['key']! as String),
    );

    test('opens the invite with its code, and seals it again byte for byte', () async {
      expect(await openInvite(text, code, derive: _derive), invite);

      final random = _Replay(fixture['sealRandom']! as String);
      expect(await sealInvite(invite, code, derive: _derive, random: random.call), text);
      expect(random.done, isTrue);
    });

    test('opens the invite however the code is typed', () async {
      for (final typed in _list(fixture['typed'])) {
        expect(
          await _verdict(() => openInvite(text, typed['code']! as String, derive: _derive)),
          typed['open'],
          reason: '${typed['code']}',
        );
      }
    });

    test('reads invite text as the TypeScript does', () async {
      for (final verdict in _list(fixture['verdicts'])) {
        final input = verdict['text']! as String;
        expect(isInvite(input), verdict['isInvite'], reason: input);
        expect(await _verdict(() => openInvite(input, code, derive: _derive)), verdict['open'], reason: input);
      }
    });

    test('makes the same codes from the same random bytes', () {
      final cases = [
        {'random': fixture['codeRandom'], 'code': code},
        ..._list(_fixtures['codes']),
      ];
      for (final item in cases) {
        final random = _Replay(item['random']! as String);
        expect(newInviteCode(random: random.call), item['code']);
        expect(random.done, isTrue, reason: '${item['code']}');
      }
    });

    test('keys codes as typed the way the TypeScript does', () {
      for (final item in _list(_fixtures['normalize'])) {
        expect(normalizeInviteCode(item['input']! as String), item['output'], reason: '${item['input']}');
      }
    });
  });
}
