@TestOn('vm')
library;

// Making, listing, editing and deleting Sends over the fake Kemlock server: what the server receives is ciphertext
// and the proof of a password, never the link key, the payload key or the plaintext; what it holds opens from a link;
// and an edit keeps the key, so the old link opens the new text.
import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/argon2id.dart';
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/send.dart';
import 'package:kemlock_core/crypto/attachment_format.dart';
import 'package:kemlock_core/features/sends/send_link.dart';
import 'package:kemlock_core/features/sends/sends_recipient.dart';
import 'package:kemlock_core/features/sends/sends_service.dart';
import 'package:kemlock_core/features/sync/kemlock/km_account.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_host.dart';
import 'package:kemlock_core/features/sync/kemlock/km_sends_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_session.dart';
import 'package:test/test.dart';

import '../sync/kemlock/fake_kemlock_accounts.dart';
import '../sync/kemlock/fake_kemlock_server.dart';
import '../sync/kemlock/fake_sends.dart';
import '../sync/kemlock/km_sync_kit.dart';

class _Values implements KmVaultValues {
  final values = <String, Object?>{};

  @override
  Future<Object?> load(String key) async => values[key] == null ? null : jsonDecode(jsonEncode(values[key]));

  @override
  Future<void> save(String key, Object? value) async => values[key] = jsonDecode(jsonEncode(value));

  @override
  void remove(String key) => values.remove(key);
}

late KmTestAccount _test;

KmAccount _account() => KmAccount(
  accountId: _test.userId,
  keyVersion: 1,
  rootKey: _test.root,
  kx1PrivateKey: _test.kx1.privateKey,
  sig1PrivateKey: _test.sig1.privateKey,
  kx1PublicKey: _test.kx1.publicKey,
  sig1PublicKey: _test.sig1.publicKey,
  opaqueEnrolled: true,
);

/// A cheap stand-in for Argon2id: its output depends on the password and the salt, and it records what it was given.
class _Argon {
  final seen = <({String password, Argon2idSettings settings, Uint8List salt})>[];

  Future<Uint8List> run(Uint8List password, Uint8List salt, Argon2idSettings settings) async {
    seen.add((password: utf8.decode(password), settings: settings, salt: Uint8List.fromList(salt)));
    final out = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      out[i] = (i < password.length ? password[i] : 7) ^ salt[i % salt.length];
    }
    return out;
  }
}

class _Rig {
  _Rig(this.server, this.service, this.argon);

  final FakeKemlockAccountServer server;
  final SendsService service;
  final _Argon argon;

  FakeSends get sends => server.sends;
}

Future<_Rig> _rig() async {
  final server = FakeKemlockAccountServer(userId: _test.userId);
  final key = SoftwareDeviceKey.generate();
  final tokens = server.issueTokens(FakeKemlockServer.thumbprint(key.publicJwk));
  final values = _Values();
  await values.save(
    keyKemlockSession,
    KmSession(
      userId: _test.userId,
      deviceId: FakeKemlockServer.deviceId,
      tokens: KmTokens(
        access: tokens['accessToken']! as String,
        refresh: tokens['refreshToken']! as String,
        accessExpiresAt: 1 << 50,
        refreshExpiresAt: 1 << 50,
      ),
      deviceKey: const {'protection': 'software'},
    ).toJson(),
  );
  await values.save(keyKemlockAccount, _account().toJson());
  final host = KmHost(values: values, clientFor: (pin) => server.client, proofsFor: (session) async => KmDpop(key));
  final argon = _Argon();
  return _Rig(server, SendsService(host: host, target: kmTarget, proofRunner: argon.run), argon);
}

/// What a recipient does with [link]: asks the server's public route and opens the payload with the key from the link.
Future<SendPayload> _open(_Rig rig, String link, {String? password}) async {
  final parsed = SendLink.parse(link)! as SendLink;
  final api = KmSendsApi(KmApi(rig.server.client));
  Uint8List? proof;
  if (password != null) proof = await sendProof(password, parsed.key, parsed.sendId, runner: rig.argon.run);
  final access = await api.access(parsed.server, parsed.accessId, password: proof);
  final payloadKey = sendPayloadKey(parsed.key);
  final plain = await openSendPart(
    sealLabel: SendLabel.payload,
    key: payloadKey,
    sendId: parsed.sendId,
    kind: access.kind,
    sealed: access.payload,
  );
  return SendPayload.parse(plain, access.kind);
}

Future<Object?> _error(Future<Object?> Function() action) async {
  try {
    await action();
  } on Object catch (e) {
    return e;
  }
  return null;
}

void main() {
  setUpAll(() async {
    _test = await KmTestAccount.create('00000000-0000-4000-8000-000000000001');
  });

  group('making', () {
    test('a text Send opens from its link, and the server saw only ciphertext', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Wi-Fi', text: 'the password is on the fridge', notes: 'for the guests'));
      expect(made.link, matches(RegExp(r'^https://kem\.example\.com/#/send/[A-Za-z0-9_-]{22}/[A-Za-z0-9_-]{43}$')));
      final opened = await _open(rig, made.link);
      expect(opened.name, 'Wi-Fi');
      expect(opened.text, 'the password is on the fridge');
      final link = SendLink.parse(made.link)! as SendLink;
      expect(rig.sends.requestsHold(link.key), isFalse, reason: 'the link key');
      expect(rig.sends.requestsHold(sendPayloadKey(link.key)), isFalse, reason: 'the payload key');
      expect(rig.sends.requestsHoldText('the password is on the fridge'), isFalse);
      expect(rig.sends.requestsHoldText('for the guests'), isFalse);
      expect(rig.sends.requestsHoldText('Wi-Fi'), isFalse);
      final stored = rig.sends.sends.values.single;
      expect(stored.sealedKey, hasLength(sendSealedKeyLength));
      expect(sealedKeyVersion(stored.sealedKey), 1);
      expect(stored.deletionAt - stored.createdAt, closeTo(7 * 86400, 5));
    });

    test('carries a password only as its proof', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Code', text: 'hunter2 is not it', password: 'hunter2', maxAccess: 2));
      expect(rig.argon.seen.single.settings, sendProofSettings);
      expect(rig.argon.seen.single.password, 'hunter2');
      expect(rig.argon.seen.single.salt, hasLength(16));
      expect(rig.sends.requestsHoldText('hunter2'), isFalse);
      final stored = rig.sends.sends.values.single;
      expect(stored.maxAccess, 2);
      final link = SendLink.parse(made.link)! as SendLink;
      final proof = await sendProof('hunter2', link.key, link.sendId, runner: rig.argon.run);
      expect(stored.proof, proof);
      expect((await _open(rig, made.link, password: 'hunter2')).text, 'hunter2 is not it');
      final wrong = await _error(() => _open(rig, made.link, password: 'nope'));
      expect(wrong, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.wrongPassword));
      final none = await _error(() => _open(rig, made.link));
      expect(none, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.passwordRequired));
    });

    test('an empty password is no password', () async {
      final rig = await _rig();
      await rig.service.make(NewSend.text(name: 'a', text: 'b', password: ''));
      expect(rig.sends.sends.values.single.proof, isNull);
      expect(rig.argon.seen, isEmpty);
    });

    test('a 3 MB file Send goes up after it is made, and opens from its link', () async {
      final rig = await _rig();
      final plain = Uint8List.fromList(List.generate(3 * 1000 * 1000, (i) => (i * 7) & 0xff));
      final made = await rig.service.make(NewSend.file(name: 'scan.pdf', bytes: plain, mime: 'application/pdf'));
      final stored = rig.sends.sends.values.single;
      expect(stored.fileSize, kma1Length(plain.length));
      expect(stored.fileBytes, hasLength(kma1Length(plain.length)));
      expect(made.send.file!.ready, isTrue);
      final link = SendLink.parse(made.link)! as SendLink;
      final api = KmSendsApi(KmApi(rig.server.client));
      final access = await api.access(link.server, link.accessId);
      final payloadKey = sendPayloadKey(link.key);
      final payload = SendPayload.parse(
        await openSendPart(sealLabel: SendLabel.payload, key: payloadKey, sendId: link.sendId, kind: access.kind, sealed: access.payload),
        access.kind,
      );
      expect((payload.name, payload.mime, payload.size), ('scan.pdf', 'application/pdf', plain.length));
      expect(sendFileLengthMatches(payload.size!, access.fileSize!), isTrue);
      final file = await api.download(link.server, link.accessId, fileSize: access.fileSize!);
      expect(await openSendFile(file, link.key, payload.size!), plain);
      expect(rig.sends.requestsHold(link.key), isFalse);
      expect(rig.sends.requestsHold(payloadKey), isFalse);
    });

    test('a file that fails to go up twice still goes up on the third try', () async {
      final rig = await _rig();
      rig.sends.failUploads = 2;
      final made = await rig.service.make(NewSend.file(name: 'a.txt', bytes: Uint8List(10), mime: 'text/plain'));
      expect(made.send.file!.ready, isTrue);
      expect(rig.sends.requests.where((r) => r.method == 'PUT'), hasLength(3));
    });

    test('three failed uploads leave no Send, and say the file did not go up', () async {
      final rig = await _rig();
      rig.sends.failUploads = 3;
      final error = await _error(() => rig.service.make(NewSend.file(name: 'a.txt', bytes: Uint8List(10), mime: 'text/plain')));
      expect(error, isA<SendsUploadFailed>());
      expect(rig.sends.sends, isEmpty);
      expect(rig.sends.requests.where((r) => r.method == 'DELETE'), hasLength(1));
    });

    test('a taken id is answered once with a new one', () async {
      final rig = await _rig();
      var first = true;
      rig.server.respond = (request) async {
        if (first && request.method == 'POST' && request.url.path == '/kem/v1/sends') {
          first = false;
          return rig.server.problem(409, 'already-exists');
        }
        return rig.server.handle(request);
      };
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      final posts = rig.server.requests.where((r) => r.method == 'POST' && r.url.path == '/kem/v1/sends').toList();
      expect(posts, hasLength(2));
      String idOf(String body) => (jsonDecode(body) as Map<String, Object?>)['id']! as String;
      expect(idOf(posts[0].body), isNot(idOf(posts[1].body)));
      expect((await _open(rig, made.link)).text, 'b');
    });

    test("the server's refusals reach the caller with their words", () async {
      final rig = await _rig();
      rig.sends.policyRemoveSend = 'Sends are removed in a space of yours';
      final error = await _error(() => rig.service.make(NewSend.text(name: 'a', text: 'b')));
      expect(error, isA<SendsError>().having((e) => e.detail, 'detail', 'Sends are removed in a space of yours'));
      rig.sends.policyRemoveSend = null;
      rig.sends.maxFileSize = 100;
      final big = await _error(() => rig.service.make(NewSend.file(name: 'a', bytes: Uint8List(1000), mime: 'x/y')));
      expect(big, isA<SendsError>().having((e) => e.maxSize, 'maxSize', 100));
    });

    test('refuses a bad input before anything is sealed or sent', () async {
      final rig = await _rig();
      Future<void> refused(NewSend input, SendsInvalid reason) async {
        final error = await _error(() => rig.service.make(input));
        expect(error, isA<SendsInvalidInput>().having((e) => e.reason, 'reason', reason));
      }

      await refused(NewSend.text(name: ' ', text: 'b'), SendsInvalid.noName);
      await refused(NewSend.text(name: 'a', text: ''), SendsInvalid.noText);
      await refused(NewSend.text(name: 'a', text: 'b', deleteInDays: 0), SendsInvalid.deletion);
      await refused(NewSend.text(name: 'a', text: 'b', deleteInDays: 31), SendsInvalid.deletion);
      await refused(NewSend.text(name: 'a', text: 'b', maxAccess: 0), SendsInvalid.maxAccess);
      await refused(NewSend.text(name: 'a', text: 'x' * (300 * 1024)), SendsInvalid.textTooLong);
      await refused(NewSend.text(name: 'a', text: 'b', notes: 'n' * (17 * 1024)), SendsInvalid.notesTooLong);
      await refused(
        NewSend.text(name: 'a', text: 'b', deleteInDays: 2, expiresAt: DateTime.now().add(const Duration(days: 3))),
        SendsInvalid.expiry,
      );
      await refused(NewSend.file(name: 'a', bytes: Uint8List(60 * 1024 * 1024), mime: 'x/y'), SendsInvalid.fileTooBig);
      expect(rig.server.requests, isEmpty);
    });

    test('accepts a deletion 30 days ahead and an expiry before it', () async {
      final rig = await _rig();
      final expires = DateTime.now().add(const Duration(days: 10));
      await rig.service.make(NewSend.text(name: 'a', text: 'b', deleteInDays: 30, expiresAt: expires));
      final stored = rig.sends.sends.values.single;
      expect(stored.deletionAt - stored.createdAt, closeTo(30 * 86400, 5));
      expect(stored.expiresAt, expires.millisecondsSinceEpoch ~/ 1000);
    });
  });

  group("the owner's list", () {
    test('shows each Send with its name and notes, and a status from the DTO alone', () async {
      final rig = await _rig();
      await rig.service.make(NewSend.text(name: 'Active', text: 'a', notes: 'n1'));
      final one = await rig.service.make(NewSend.text(name: 'One open', text: 'b', maxAccess: 1));
      final off = await rig.service.make(NewSend.text(name: 'Off', text: 'c'));
      await _open(rig, one.link);
      final listed = await rig.service.list();
      expect(listed.map((s) => s.meta?.name), ['Off', 'One open', 'Active']);
      expect(listed.last.meta!.notes, 'n1');
      expect(listed[1].status, SendStatus.usedUp);
      expect(listed[1].send.accessCount, 1);
      expect(listed.last.status, SendStatus.active);
      final ownedOff = listed.first;
      await rig.service.update(ownedOff, SendEdit(name: 'Off', notes: '', deletionAt: ownedOff.send.deletionAt, disabled: true));
      expect((await rig.service.list()).first.status, SendStatus.off);
      expect(off.send.id, ownedOff.send.id);
    });

    test('shows a file Send whose upload never finished as waiting for its file', () async {
      final rig = await _rig();
      await rig.service.make(NewSend.file(name: 'a.txt', bytes: Uint8List(10), mime: 'text/plain'));
      rig.sends.sends.values.single.fileBytes = null;
      expect((await rig.service.list()).single.status, SendStatus.waitingForFile);
    });

    test('shows a Send whose meta does not open as unreadable, with no meta', () async {
      final rig = await _rig();
      await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      final stored = rig.sends.sends.values.single;
      stored.meta = Uint8List.fromList(stored.meta)..[20] ^= 1;
      final row = (await rig.service.list()).single;
      expect(row.readable, isFalse);
      expect(row.meta, isNull);
    });

    test('rebuilds the link of any row from its sealed key, as the one made', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      final row = (await rig.service.list()).single;
      expect(await rig.service.linkOf(row), made.link);
    });

    test('views a text Send from its DTO without spending an open', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'secret text', maxAccess: 1));
      final row = (await rig.service.list()).single;
      final text = await rig.service.view(row);
      expect(text.text, 'secret text');
      expect(rig.sends.sends.values.single.accessCount, 0);
      expect((await _open(rig, made.link)).text, 'secret text');
    });
  });

  group('editing and deleting', () {
    test('a text edit keeps the key: the old link opens the new text', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Old name', text: 'old text'));
      final row = (await rig.service.list()).single;
      await rig.service.update(
        row,
        SendEdit(name: 'New name', notes: 'a note', text: 'new text', deletionAt: row.send.deletionAt, hideEmail: true),
      );
      final opened = await _open(rig, made.link);
      expect((opened.name, opened.text), ('New name', 'new text'));
      final after = (await rig.service.list()).single;
      expect((after.meta!.name, after.meta!.notes), ('New name', 'a note'));
      expect(after.send.hideEmail, isTrue);
      expect(after.send.sealedKey, row.send.sealedKey);
      expect(await rig.service.linkOf(after), made.link);
    });

    test('removing the password lets the link open with none, and a new one is asked for', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b', password: 'old'));
      var row = (await rig.service.list()).single;
      expect(row.send.hasPassword, isTrue);
      await rig.service.update(row, SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt, removePassword: true));
      expect((await _open(rig, made.link)).text, 'b');
      row = (await rig.service.list()).single;
      expect(row.send.hasPassword, isFalse);
      await rig.service.update(row, SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt, newPassword: 'fresh'));
      expect((await _open(rig, made.link, password: 'fresh')).text, 'b');
      final none = await _error(() => _open(rig, made.link));
      expect(none, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.passwordRequired));
    });

    test('keeping the password sends none, and the Send still asks for it', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b', password: 'kept'));
      final row = (await rig.service.list()).single;
      await rig.service.update(row, SendEdit(name: 'a', notes: 'x', deletionAt: row.send.deletionAt));
      expect((await _open(rig, made.link, password: 'kept')).text, 'b');
    });

    test('turning a Send off makes the link answer "not available" until it is turned back on', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      var row = (await rig.service.list()).single;
      await rig.service.update(row, SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt, disabled: true));
      final closed = await _error(() => _open(rig, made.link));
      expect(closed, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.notFound));
      row = (await rig.service.list()).single;
      await rig.service.update(row, SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt));
      expect((await _open(rig, made.link)).text, 'b');
    });

    test('a file Send keeps its name and its file, and its meta notes change', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.file(name: 'a.txt', bytes: Uint8List(10), mime: 'text/plain'));
      final row = (await rig.service.list()).single;
      await rig.service.update(row, SendEdit(name: 'other', notes: 'only me', deletionAt: row.send.deletionAt));
      final after = (await rig.service.list()).single;
      expect(after.meta!.name, 'a.txt');
      expect(after.meta!.notes, 'only me');
      expect(after.send.payload, row.send.payload);
      expect((await _open(rig, made.link)).name, 'a.txt');
    });

    test('lists a Send a Bitwarden app made apart from the Kemlock ones, and opens nothing of it', () async {
      final rig = await _rig();
      await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      const bitwardenId = '3f2c9a71-e4b0-4856-8a00-000000000002';
      rig.sends.addBitwardenSend(bitwardenId, kind: 'file', maxAccess: 3, accessCount: 3);
      final listing = await rig.service.listing();
      expect(listing.owned.single.meta!.name, 'a');
      final foreign = listing.foreign.single;
      expect(foreign.send.id, bitwardenId);
      expect(foreign.isFile, isTrue);
      expect(foreign.status, SendStatus.usedUp);
      // The Kemlock list keeps only its own
      expect((await rig.service.list()).single.meta!.name, 'a');
    });

    test('deletes a Send a Bitwarden app made with the delete route', () async {
      final rig = await _rig();
      const bitwardenId = '3f2c9a71-e4b0-4856-8a00-000000000002';
      rig.sends.addBitwardenSend(bitwardenId);
      final foreign = (await rig.service.listing()).foreign.single;
      await rig.service.deleteForeign(foreign);
      expect(rig.sends.sends, isEmpty);
      expect(rig.sends.requests.where((request) => request.method == 'DELETE').map((request) => request.url.path), [
        '/kem/v1/sends/$bitwardenId',
      ]);
      expect((await rig.service.listing()).foreign, isEmpty);
    });

    test('refuses an edit that the server would, before it is sent', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b', maxAccess: 3));
      await _open(rig, made.link);
      await _open(rig, made.link);
      final row = (await rig.service.list()).single;
      final before = rig.server.requests.length;
      Future<void> refused(SendEdit edit, SendsInvalid reason) async {
        final error = await _error(() => rig.service.update(row, edit));
        expect(error, isA<SendsInvalidInput>().having((e) => e.reason, 'reason', reason));
      }

      await refused(SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt, maxAccess: 1), SendsInvalid.maxAccess);
      await refused(SendEdit(name: 'a', notes: '', deletionAt: DateTime.now().add(const Duration(days: 31))), SendsInvalid.deletion);
      await refused(
        SendEdit(name: 'a', notes: '', deletionAt: row.send.deletionAt, expiresAt: row.send.deletionAt.add(const Duration(days: 1))),
        SendsInvalid.expiry,
      );
      await refused(SendEdit(name: '', notes: '', deletionAt: row.send.deletionAt), SendsInvalid.noName);
      expect(rig.server.requests.length, before);
    });

    test('deleting removes the Send, and a Send that is gone already counts as deleted', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'a', text: 'b'));
      final row = (await rig.service.list()).single;
      await rig.service.delete(row);
      expect(rig.sends.sends, isEmpty);
      expect(await rig.service.list(), isEmpty);
      final gone = await _error(() => _open(rig, made.link));
      expect(gone, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.notFound));
      await rig.service.delete(row);
    });
  });

  test('the status order is off, expired, used up, waiting for its file, then active', () {
    KmSend send({bool disabled = false, int? expires, int? max, int count = 0, KmSendFile? file}) => KmSend(
      id: '3f2c9a71-e4b0-4a56-8a00-000000000001',
      accessId: sendAccessId(uuidBytes('3f2c9a71-e4b0-4a56-8a00-000000000001')),
      kind: file == null ? sendKindText : sendKindFile,
      meta: Uint8List(40),
      sealedKey: Uint8List(64),
      payload: Uint8List(40),
      hasPassword: false,
      accessCount: count,
      hideEmail: false,
      disabled: disabled,
      deletionAt: DateTime.utc(2031),
      createdAt: DateTime.utc(2030),
      revisedAt: DateTime.utc(2030),
      maxAccess: max,
      expiresAt: expires == null ? null : DateTime.utc(2030, 6, 1).add(Duration(days: expires)),
      file: file,
    );
    final now = DateTime.utc(2030, 6, 1);
    expect(sendStatus(send(), now), SendStatus.active);
    expect(sendStatus(send(disabled: true, expires: -1, max: 1, count: 1), now), SendStatus.off);
    expect(sendStatus(send(expires: -1, max: 1, count: 1), now), SendStatus.expired);
    expect(sendStatus(send(expires: 1), now), SendStatus.active);
    expect(sendStatus(send(max: 1, count: 1, file: const KmSendFile(size: 30, ready: false)), now), SendStatus.usedUp);
    expect(sendStatus(send(file: const KmSendFile(size: 30, ready: false)), now), SendStatus.waitingForFile);
    expect(sendStatus(send(file: const KmSendFile(size: 30, ready: true)), now), SendStatus.active);
  });

  group('opening as a recipient', () {
    SendsRecipient recipient(_Rig rig, {http.Client Function(String? pin)? clientFor}) =>
        SendsRecipient(clientFor: clientFor ?? (pin) => rig.server.client, proofRunner: rig.argon.run);

    SendLink linkOf(String text) => SendLink.parse(text)! as SendLink;

    Iterable<http.Request> publicRequests(_Rig rig) => rig.sends.requests.where((request) => request.url.path.contains('/send-access/'));

    /// Puts a Send in the fake server that the owner's service wouldn't make: [payload] sealed as it is given.
    Future<SendLink> planted(
      _Rig rig, {
      required String kind,
      required List<int> plaintext,
      String? sealedKind,
      int? fileSize,
      Uint8List? fileBytes,
    }) async {
      final id = newSendId();
      final key = newSendLinkKey();
      final payloadKey = sendPayloadKey(key);
      final sealed = await sealSendPart(
        sealLabel: SendLabel.payload,
        key: payloadKey,
        sendId: id,
        kind: sealedKind ?? kind,
        plaintext: plaintext,
      );
      final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      rig.sends.sends[uuidText(id)] = FakeSend(
        id: uuidText(id),
        kind: kind,
        meta: Uint8List(40),
        sealedKey: Uint8List(sendSealedKeyLength),
        payload: sealed,
        deletionAt: now + 86400,
        createdAt: now,
        fileSize: fileSize,
      )..fileBytes = fileBytes;
      return linkOf(sendLink(Uri.parse('https://kem.example.com'), id, key));
    }

    test('opens a text Send with no account, no token and no proof of device', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Wi-Fi', text: 'on the fridge', notes: 'private'));
      rig.sends.requests.clear();
      final link = linkOf(made.link);
      final received = await recipient(rig).open(link);
      expect(received.payload.name, 'Wi-Fi');
      expect(received.payload.text, 'on the fridge');
      expect(received.senderEmail, 'ann@example.com');
      final sent = publicRequests(rig).single;
      expect(sent.headers.keys.map((key) => key.toLowerCase()), isNot(anyOf(contains('authorization'), contains('dpop'))));
      expect(rig.sends.requestsHold(link.key), isFalse);
      expect(rig.sends.sends.values.single.accessCount, 1);
      received.dispose();
      expect(link.key.every((byte) => byte == 0), isTrue, reason: 'the key is zeroed when the sheet lets go');
    });

    test('asks for a password only when the server says so, and again after a wrong one', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Code', text: 'seven', password: 'hunter2'));
      final link = linkOf(made.link);
      final none = await _error(() => recipient(rig).open(link));
      expect(none, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.passwordRequired));
      final wrong = await _error(() => recipient(rig).open(link, password: 'nope'));
      expect(wrong, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.wrongPassword));
      final received = await recipient(rig).open(link, password: 'hunter2');
      expect(received.payload.text, 'seven');
      expect(rig.sends.requestsHoldText('hunter2'), isFalse);
    });

    test('the eleventh wrong try in a minute is told to wait', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Code', text: 'seven', password: 'hunter2'));
      final link = linkOf(made.link);
      for (var i = 0; i < 10; i++) {
        final wrong = await _error(() => recipient(rig).open(link, password: 'wrong $i'));
        expect(wrong, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.wrongPassword));
      }
      final limited = await _error(() => recipient(rig).open(link, password: 'wrong 11'));
      expect(
        limited,
        isA<SendsError>()
            .having((e) => e.problem, 'problem', SendsProblem.rateLimited)
            .having((e) => e.retryAfter, 'wait', inInclusiveRange(1, 60)),
      );
    });

    test('a closed Send says only that it is not available', () async {
      final rig = await _rig();
      final made = await rig.service.make(NewSend.text(name: 'Once', text: 'x', maxAccess: 1));
      final link = linkOf(made.link);
      await recipient(rig).open(link);
      final closed = await _error(() => recipient(rig).open(link));
      expect(closed, isA<SendsError>().having((e) => e.problem, 'problem', SendsProblem.notFound));
    });

    test('a payload sealed for another kind, or with another field, shows nothing', () async {
      final rig = await _rig();
      final otherKind = await planted(rig, kind: sendKindText, sealedKind: sendKindFile, plaintext: utf8.encode('{"name":"a","text":"b"}'));
      expect(await _error(() => recipient(rig).open(otherKind)), isA<SendsDoesntOpen>());
      final extra = await planted(rig, kind: sendKindText, plaintext: utf8.encode('{"name":"a","text":"b","extra":1}'));
      expect(await _error(() => recipient(rig).open(extra)), isA<SendsDoesntOpen>());
      final fine = await planted(rig, kind: sendKindText, plaintext: utf8.encode('{"name":"a","text":"b"}'));
      expect((await recipient(rig).open(fine)).payload.text, 'b');
    });

    test("a file Send counts an open only when its bytes are downloaded, and refuses a length that isn't its payload's", () async {
      final rig = await _rig();
      final plain = Uint8List.fromList(List.generate(1000, (i) => i & 0xff));
      final made = await rig.service.make(NewSend.file(name: 'scan.pdf', bytes: plain, mime: 'application/pdf'));
      final link = linkOf(made.link);
      final received = await recipient(rig).open(link);
      expect((received.payload.name, received.payload.mime, received.payload.size), ('scan.pdf', 'application/pdf', 1000));
      expect(rig.sends.sends.values.single.accessCount, 0);
      expect(publicRequests(rig).where((request) => request.url.path.endsWith('/file')), isEmpty);
      expect(await recipient(rig).download(received), plain);
      expect(rig.sends.sends.values.single.accessCount, 1);
      expect(rig.sends.requestsHold(link.key), isFalse);
      // A payload that names another size than the file's length is refused before any download
      final wrongSize = await planted(
        rig,
        kind: sendKindFile,
        plaintext: utf8.encode('{"name":"a","mime":"text/plain","size":1001}'),
        fileSize: kma1Length(1000),
        fileBytes: Uint8List(kma1Length(1000)),
      );
      expect(await _error(() => recipient(rig).open(wrongSize)), isA<SendsDoesntOpen>());
    });

    test('a file over 50 MiB is refused before its download, and one of 50 MiB is not', () async {
      final rig = await _rig();
      Future<SendLink> file(int size) => planted(
        rig,
        kind: sendKindFile,
        plaintext: utf8.encode('{"name":"big.bin","mime":"application/octet-stream","size":$size}'),
        fileSize: kma1Length(size),
        fileBytes: Uint8List(1),
      );
      final over = await recipient(rig).open(await file(sendFileLimit + 1));
      expect(over.tooBig, isTrue);
      rig.sends.requests.clear();
      expect(await _error(() => recipient(rig).download(over)), isA<SendsFileTooBig>());
      expect(publicRequests(rig), isEmpty);
      final exact = await recipient(rig).open(await file(sendFileLimit));
      expect(exact.tooBig, isFalse);
    });

    test('an http link is refused before any request', () async {
      final rig = await _rig();
      final link = SendLink(server: Uri.parse('http://kem.example.com'), sendId: newSendId(), key: newSendLinkKey());
      rig.sends.requests.clear();
      expect(await _error(() => recipient(rig).open(link)), isA<KmError>().having((e) => e.problem, 'problem', KmProblem.insecure));
      expect(rig.sends.requests, isEmpty);
    });
  });
}
