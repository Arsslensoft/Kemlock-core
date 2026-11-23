@TestOn('vm')
library;

import 'dart:async';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:kemlock_core/crypto/account/encoding.dart';
import 'package:kemlock_core/crypto/account/sig1.dart';
import 'package:kemlock_core/features/sync/kemlock/km_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_auth_api.dart';
import 'package:kemlock_core/features/sync/kemlock/km_device_key.dart';
import 'package:kemlock_core/features/sync/kemlock/km_dpop.dart';
import 'package:kemlock_core/features/sync/kemlock/km_failover.dart';
import 'package:kemlock_core/features/sync/kemlock/km_models.dart';
import 'package:kemlock_core/security_key/cbor.dart';
import 'package:test/test.dart';

import 'fake_kemlock_accounts.dart';
import 'fake_kemlock_server.dart';

const _home = KemlockServer(url: 'https://home.example.com');
const _one = KemlockServer(url: 'https://one.example.com', role: KemlockServer.replica);
const _two = KemlockServer(url: 'https://two.example.com', role: KemlockServer.replica);

class _Clock {
  var now = DateTime.utc(2026, 11, 22, 9);

  DateTime call() => now;

  void pass(Duration duration) => now = now.add(duration);
}

const _down = KmError(KmProblem.network);

KmFailover _failover(_Clock clock, [List<KemlockServer> servers = const [_home, _one], Duration? firstByte]) =>
    KmFailover(servers, clock: clock.call, firstByte: firstByte ?? failoverFirstByte);

Future<void> _signedIn(KemlockServer server) async {}

void main() {
  group('failures', () {
    test('two failures in a row move the phone to the next server, which signs this device in without a prompt', () async {
      final failover = _failover(_Clock());
      final seen = <String>[];
      final signedIn = <String>[];
      final result = await failover.send<String>((server) async {
        seen.add(server.url);
        if (server.url == _home.url) throw _down;
        return 'ok from ${server.url}';
      }, signInTo: (server) async => signedIn.add(server.url));
      expect(result, 'ok from ${_one.url}');
      expect(seen, [_home.url, _home.url, _one.url], reason: 'the home was tried twice');
      expect(signedIn, [_one.url]);
      expect(failover.onHome, isFalse);
      expect(failover.current.url, _one.url);
      expect(failover.mode, KmFailoverMode.onReplica);
    });

    test('one failure then an answer is not enough to move, and the count starts again', () async {
      final failover = _failover(_Clock());
      var calls = 0;
      expect(await failover.send<int>((server) async => ++calls == 1 ? throw _down : calls, signInTo: _signedIn), 2);
      expect(failover.onHome, isTrue);
      calls = 0;
      expect(await failover.send<int>((server) async => ++calls == 1 ? throw _down : calls, signInTo: _signedIn), 2);
      expect(failover.onHome, isTrue, reason: 'two failures that weren\'t in a row never moved it');
    });

    test('a timeout moves the phone at once', () async {
      final failover = _failover(_Clock());
      final seen = <String>[];
      final result = await failover.send<String>(
        (server) {
          seen.add(server.url);
          return server.url == _home.url ? Completer<String>().future : Future.value('replica');
        },
        signInTo: _signedIn,
        timeout: const Duration(milliseconds: 20),
      );
      expect(result, 'replica');
      expect(seen, [_home.url, _one.url], reason: 'one timeout, not two failures');
    });

    test('an answer of any status counts as reached: a 409 or a 500 never moves the phone', () async {
      final failover = _failover(_Clock());
      for (var i = 0; i < 5; i++) {
        await expectLater(
          failover.send<void>((server) async => throw const KmError(KmProblem.stale, status: 409), signInTo: _signedIn),
          throwsA(isA<KmError>().having((e) => e.problem, 'problem', KmProblem.stale)),
        );
        await expectLater(
          failover.send<void>((server) async => throw const KmError(KmProblem.server, status: 500), signInTo: _signedIn),
          throwsA(isA<KmError>()),
        );
      }
      expect(failover.onHome, isTrue);
    });

    test('a replica that doesn\'t know the device is reported and the others are tried', () async {
      final failover = _failover(_Clock(), const [_home, _one, _two]);
      final tried = <String>[];
      final result = await failover.send<String>(
        (server) async => server.url == _home.url ? throw _down : 'from ${server.url}',
        signInTo: (server) async {
          tried.add(server.url);
          if (server.url == _one.url) throw const KmError(KmProblem.auth, status: 401);
        },
      );
      expect(result, 'from ${_two.url}');
      expect(tried, [_one.url, _two.url]);
      expect(failover.unknown, {_one.url});
    });

    test('when every server fails the request ends as exhausted, and the phone stays where it is', () async {
      final failover = _failover(_Clock());
      await expectLater(failover.send<void>((server) async => throw _down, signInTo: _signedIn), throwsA(isA<KmFailoverExhausted>()));
      expect(failover.onHome, isFalse, reason: 'it moved to the replica, whose requests also failed');
    });
  });

  group('returning home', () {
    Future<(KmFailover, _Clock)> onReplica() async {
      final clock = _Clock();
      // A short first-byte wait, so the probe that never answers ends at once
      final failover = _failover(clock, const [_home, _one], const Duration(milliseconds: 20));
      await failover.send<void>((server) async => server.url == _home.url ? throw _down : null, signInTo: _signedIn);
      expect(failover.onHome, isFalse);
      return (failover, clock);
    }

    test('five minutes of unbroken answers return the phone to the home', () async {
      final (failover, clock) = await onReplica();
      var returned = false;
      for (var minute = 0; minute < 5; minute++) {
        returned = await failover.checkHome((home) async => true);
        expect(returned, isFalse, reason: 'minute $minute');
        clock.pass(const Duration(minutes: 1));
      }
      expect(failover.mode, KmFailoverMode.returning);
      expect(await failover.checkHome((home) async => true), isTrue);
      expect(failover.onHome, isTrue);
      expect(failover.since, isNull);
    });

    test('three minutes up, one miss, then up again: five more healthy minutes are needed', () async {
      final (failover, clock) = await onReplica();
      for (var minute = 0; minute < 4; minute++) {
        await failover.checkHome((home) async => true);
        clock.pass(const Duration(minutes: 1));
      }
      expect(failover.mode, KmFailoverMode.returning);
      // A miss
      expect(await failover.checkHome((home) async => false), isFalse);
      expect(failover.mode, KmFailoverMode.onReplica);
      expect(failover.healthySince, isNull);
      clock.pass(const Duration(minutes: 1));
      // Up again, but the five minutes start over
      for (var minute = 0; minute < 5; minute++) {
        expect(await failover.checkHome((home) async => true), isFalse, reason: 'minute $minute after the miss');
        clock.pass(const Duration(minutes: 1));
      }
      expect(failover.onHome, isFalse);
      expect(await failover.checkHome((home) async => true), isTrue);
    });

    test('the home is checked at most once a minute', () async {
      final (failover, clock) = await onReplica();
      var probes = 0;
      Future<bool> probe(KemlockServer home) async {
        probes++;
        return true;
      }

      await failover.checkHome(probe);
      clock.pass(const Duration(seconds: 30));
      await failover.checkHome(probe);
      expect(probes, 1);
      clock.pass(const Duration(seconds: 30));
      await failover.checkHome(probe);
      expect(probes, 2);
    });

    test('a probe that fails or times out is a miss, and on the home nothing is checked', () async {
      final (failover, clock) = await onReplica();
      expect(await failover.checkHome((home) async => throw _down), isFalse);
      expect(failover.healthySince, isNull);
      clock.pass(const Duration(minutes: 1));
      expect(await failover.checkHome((home) => Completer<bool>().future), isFalse);
      final onHome = _failover(_Clock());
      var probes = 0;
      await onHome.checkHome((home) async => ++probes > 0);
      expect(probes, 0);
    });
  });

  group('home-only changes', () {
    test('are refused on a replica with where it is and since when, and allowed on the home', () async {
      final clock = _Clock();
      final failover = _failover(clock);
      failover.requireHome();
      await failover.send<void>((server) async => server.url == _home.url ? throw _down : null, signInTo: _signedIn);
      clock.pass(const Duration(minutes: 3));
      try {
        failover.requireHome();
        fail('a home-only change went through');
      } on KmHomeAway catch (away) {
        expect(away.using.url, _one.url);
        expect(clock.now.difference(away.since), const Duration(minutes: 3));
      }
    });
  });

  group('against two fake servers', () {
    test('switching signs the device in by its key, with no password, and the request goes on', () async {
      final key = SoftwareDeviceKey.generate();
      final homeServer = FakeKemlockAccountServer();
      final replica = FakeKemlockAccountServer()..knownDevices.add(FakeKemlockServer.deviceId);
      homeServer.respond = (request) async => throw http.ClientException('the home is down');
      final apis = {_home.url: KmApi(homeServer.client, proofs: KmDpop(key)), _one.url: KmApi(replica.client, proofs: KmDpop(key))};
      final failover = _failover(_Clock());
      final grants = <String, KmGrant>{};
      final config = await failover.send<KmConfig>(
        (server) => apis[server.url]!.config(Uri.parse(server.url)),
        signInTo: (server) async =>
            grants[server.url] = await kmReplicaSignIn(KmAuthApi(apis[server.url]!), Uri.parse(server.url), FakeKemlockServer.deviceId),
      );
      expect(config.serverId, isNotEmpty);
      expect(grants.keys, [_one.url]);
      expect(grants[_one.url]!.tokens.access, isNotEmpty);
      expect(replica.requests.map((r) => r.url.path), containsAll(['/kem/v1/auth/device-key/challenge', '/kem/v1/auth/device-key/verify']));
      for (final request in replica.requests) {
        expect(request.body, isNot(contains('password')));
      }
    });

    test('a replica that doesn\'t know the device refuses, and the failover reports it', () async {
      final key = SoftwareDeviceKey.generate();
      final homeServer = FakeKemlockAccountServer()..respond = (request) async => throw http.ClientException('down');
      final replica = FakeKemlockAccountServer();
      final apis = {_home.url: KmApi(homeServer.client, proofs: KmDpop(key)), _one.url: KmApi(replica.client, proofs: KmDpop(key))};
      final failover = _failover(_Clock());
      await expectLater(
        failover.send<KmConfig>(
          (server) => apis[server.url]!.config(Uri.parse(server.url)),
          signInTo: (server) async => kmReplicaSignIn(KmAuthApi(apis[server.url]!), Uri.parse(server.url), FakeKemlockServer.deviceId),
        ),
        throwsA(isA<KmFailoverExhausted>()),
      );
      expect(failover.unknown, {_one.url});
    });
  });

  group('a new server list', () {
    const homeId = '00000000-0000-4000-8000-0000000000a1';
    const oneId = '00000000-0000-4000-8000-0000000000a2';
    const twoId = '00000000-0000-4000-8000-0000000000a3';
    const account = '00000000-0000-4000-8000-000000000001';

    late ({Uint8List publicKey, Uint8List privateKey}) homePair;
    late ({Uint8List publicKey, Uint8List privateKey}) onePair;
    // The record of the move to `one` at epoch 4, signed by `one`: the one most tests start from
    late Uint8List good;

    KemlockTarget target({int epoch = 3, bool oneKnown = true}) => KemlockTarget(
      accountId: account,
      email: 'me@example.com',
      servers: [
        KemlockServer(url: _home.url, identityKey: b64urlEncode(homePair.publicKey), pin: 'AA:BB'),
        KemlockServer(url: _one.url, role: KemlockServer.replica, identityKey: oneKnown ? b64urlEncode(onePair.publicKey) : null),
      ],
      deviceId: FakeKemlockServer.deviceId,
      homeEpoch: epoch,
    );

    KmServerEntry entry(String id, String url, String role, Uint8List key) =>
        KmServerEntry(serverId: id, address: url, identityKey: key, role: role);
    KmServerEntry homeEntry([String role = KemlockServer.home]) => entry(homeId, _home.url, role, homePair.publicKey);
    KmServerEntry oneEntry([String role = KemlockServer.replica]) => entry(oneId, _one.url, role, onePair.publicKey);

    KmVaultServers list(List<KmServerEntry> servers, {int epoch = 3, Uint8List? promotion, String vault = 'user:$account'}) =>
        KmVaultServers(vault: vault, epoch: epoch, servers: servers, promotion: promotion);

    /// The envelope of `docs/federation.md`: the body's CBOR, and the signature over those exact bytes.
    Future<Uint8List> record({
      required Uint8List signer,
      int epoch = 4,
      String context = promotionContext,
      List<int>? vault,
      List<String> replicas = const [homeId],
    }) async {
      final body = cborEncode({
        0: 1,
        1: Uint8List.fromList(vault ?? [1, ...uuidBytes(account)]),
        2: epoch,
        3: uuidBytes(oneId),
        4: uuidBytes(homeId),
        5: 1790000000,
        6: [for (final id in replicas) uuidBytes(id)],
      });
      return cborEncode({0: body, 1: await Sig1.sign(signer, body, context: context)});
    }

    setUpAll(() async {
      homePair = await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 1)));
      onePair = await Sig1.generate(Uint8List.fromList(List.generate(64, (i) => i + 101)));
      good = await record(signer: onePair.privateKey);
    });

    Future<KmListIssue> refused(Future<KemlockTarget> taken) async {
      try {
        await taken;
      } on KmListRefused catch (e) {
        return e.issue;
      }
      fail('the list was taken');
    }

    // The home moves to `one`, which keeps `home` as its last replica: what a promotion makes
    List<KmServerEntry> moved() => [oneEntry(KemlockServer.home), homeEntry(KemlockServer.replica)];

    test('one replica more: both kept, home first, and the first-seen key and pin stay', () async {
      final next = await acceptServerList(
        target(),
        list([homeEntry(), oneEntry(), entry(twoId, _two.url, KemlockServer.replica, Uint8List(1984)..[0] = 9)]),
      );
      expect(next.servers.map((s) => s.url), [_home.url, _one.url, _two.url]);
      expect(next.home.pin, 'AA:BB');
      expect(next.home.identityKey, b64urlEncode(homePair.publicKey));
      expect(next.servers.last.identityKey, b64urlEncode(Uint8List(1984)..[0] = 9), reason: 'a new server\'s key is pinned at first sight');
      expect(next.homeEpoch, 3);
    });

    test('a phone that never took a list takes the first it reads, at any epoch, when the home is the same', () async {
      final bare = target(epoch: 0).copyWith(
        servers: [
          const KemlockServer(url: 'https://home.example.com'),
          target().servers.last,
        ],
      );
      final next = await acceptServerList(bare, list([homeEntry(), oneEntry()], epoch: 5));
      expect(next.homeEpoch, 5);
      expect(next.home.identityKey, b64urlEncode(homePair.publicKey));
    });

    test('a list of strangers, or for another vault, is refused and the old one is kept', () async {
      expect(
        await refused(
          acceptServerList(
            target(),
            list([
              entry(twoId, 'https://evil.example.net', KemlockServer.home, Uint8List(1984)),
              entry(oneId, 'https://evil2.example.net', KemlockServer.replica, Uint8List(1984)),
            ]),
          ),
        ),
        KmListIssue.strangers,
      );
      expect(
        await refused(acceptServerList(target(), list([homeEntry(), oneEntry()], vault: 'user:00000000-0000-4000-8000-000000000002'))),
        KmListIssue.strangers,
      );
      expect(await refused(acceptServerList(target(), list([homeEntry(), oneEntry()], vault: 'space:$account'))), KmListIssue.strangers);
    });

    test('a known server whose identity key changed is refused', () async {
      expect(
        await refused(
          acceptServerList(target(), list([entry(homeId, _home.url, KemlockServer.home, Uint8List(1984)..[0] = 1), oneEntry()])),
        ),
        KmListIssue.keyChanged,
      );
    });

    test('an epoch below the stored one is refused, even for the same home', () async {
      expect(await refused(acceptServerList(target(), list([homeEntry(), oneEntry()], epoch: 2))), KmListIssue.oldEpoch);
    });

    test('a move to a new home with the record its new home signed, at a higher epoch, is taken', () async {
      final next = await acceptServerList(target(), list(moved(), epoch: 4, promotion: good));
      expect(next.home.url, _one.url);
      expect(next.servers.map((s) => s.role), [KemlockServer.home, KemlockServer.replica]);
      expect(next.homeEpoch, 4);
      expect(next.servers.last.pin, 'AA:BB', reason: 'the old home keeps its pin');
    });

    test('a higher epoch with the same home needs a record that names that home', () async {
      final bumped = list([homeEntry(), oneEntry()], epoch: 4);
      expect(await refused(acceptServerList(target(), bumped)), KmListIssue.noPromotion);
      // The record names `one` as the new home, so a list that keeps `home` doesn't match it
      expect(
        await refused(acceptServerList(target(), list([homeEntry(), oneEntry()], epoch: 4, promotion: good))),
        KmListIssue.badPromotion,
      );
    });

    test('a new home without a record, or at an epoch that is not above the stored one, is refused', () async {
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 4))), KmListIssue.noPromotion);
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 3, promotion: null))), KmListIssue.oldEpoch);
    });

    test('a record that is not for this list, this vault, this epoch or these replicas is refused', () async {
      // The list says epoch 5, the record 4
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 5, promotion: good))), KmListIssue.badPromotion);
      // A record made for another vault, with a valid signature
      final other = await record(signer: onePair.privateKey, vault: [1, ...uuidBytes('00000000-0000-4000-8000-000000000002')]);
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: other))), KmListIssue.badPromotion);
      // The list drops `home`, which the record keeps as its last replica
      expect(
        await refused(
          acceptServerList(
            target(),
            list([oneEntry(KemlockServer.home), entry(twoId, _two.url, KemlockServer.replica, Uint8List(1984))], epoch: 4, promotion: good),
          ),
        ),
        KmListIssue.badPromotion,
      );
    });

    test('a record signed by another key, in another context, or with a changed byte does not verify', () async {
      final byHome = await record(signer: homePair.privateKey);
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: byHome))), KmListIssue.badPromotion);
      final wrongContext = await record(signer: onePair.privateKey, context: 'manifest');
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: wrongContext))), KmListIssue.badPromotion);
      final changed = Uint8List.fromList(good)..[good.length - 1] ^= 1;
      expect(await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: changed))), KmListIssue.badPromotion);
    });

    test('bytes that are no record, and a signer with no pinned identity key, are refused', () async {
      expect(
        await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: Uint8List.fromList([1, 2, 3])))),
        KmListIssue.badPromotion,
      );
      expect(
        await refused(acceptServerList(target(), list(moved(), epoch: 4, promotion: cborEncode({0: Uint8List(2), 1: Uint8List(3373)})))),
        KmListIssue.badPromotion,
      );
      // The key the signer holds on file is the one pinned, not the one the list brings: none is pinned here
      final keyless = target(oneKnown: false);
      expect(
        await refused(acceptServerList(keyless, list(moved(), epoch: 4, promotion: good), verify: (key, body, signature) async => true)),
        KmListIssue.badPromotion,
      );
    });

    test('the record is read from the envelope: version 1, 17-byte vault, ids of 16 bytes, no extra members', () async {
      final read = KmPromotion.parse(good);
      expect(read.epoch, 4);
      expect(read.newHome, oneId);
      expect(read.previousHome, homeId);
      expect(read.replicas, [homeId]);
      expect(read.signature, hasLength(3373));
      Uint8List envelope(Map<int, Object?> body) => cborEncode({0: cborEncode(body), 1: Uint8List(3373)});
      final fields = <int, Object?>{
        0: 1,
        1: Uint8List(17),
        2: 4,
        3: Uint8List(16),
        4: Uint8List(16),
        5: 1,
        6: [Uint8List(16)],
      };
      expect(KmPromotion.parse(envelope(fields)).epoch, 4);
      expect(() => KmPromotion.parse(envelope({...fields, 0: 2})), throwsFormatException);
      expect(() => KmPromotion.parse(envelope({...fields, 1: Uint8List(16)})), throwsFormatException);
      expect(() => KmPromotion.parse(envelope({...fields, 3: Uint8List(17)})), throwsFormatException);
      expect(() => KmPromotion.parse(envelope({...fields, 2: 0})), throwsFormatException);
      expect(
        () => KmPromotion.parse(
          envelope({
            ...fields,
            6: [Uint8List(15)],
          }),
        ),
        throwsFormatException,
      );
      expect(() => KmPromotion.parse(envelope({...fields, 7: 1})), throwsFormatException);
      expect(() => KmPromotion.parse(cborEncode({0: cborEncode(fields), 1: Uint8List(3373), 2: 0})), throwsFormatException);
      expect(() => KmPromotion.parse(cborEncode({0: cborEncode(fields), 1: Uint8List(10)})), throwsFormatException);
    });
  });
}
